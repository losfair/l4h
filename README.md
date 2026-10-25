# l4h

l4h is a hypervisor for Linux VMs built on the seL4 microkernel. It uses
**no hardware virtualization**: guests run a paravirtualized Linux
(`ARCH=l4h`, derived from user-mode Linux), whose processes are seL4 threads
and address spaces. l4h therefore runs anywhere seL4 runs, including cloud
VMs without nested virtualization.

The user manual is in [docs/manual](docs/manual/l4h-manual.tex); render it
with `make -C docs/manual`. See [DESIGN.md](DESIGN.md) for the design, the decisions behind it and the
current status of each part.

## License

Unless otherwise noted, l4h is licensed under the GNU General Public License
version 2 only (`GPL-2.0-only`). See [LICENSE](LICENSE) for the full text.

The guest userspace CLI and Rust client library in `tools/l4hctl`, and the
attestation verifier `tools/l4h-attest.py`, are licensed under the BSD
2-Clause license (`BSD-2-Clause`). See [tools/l4hctl/LICENSE](tools/l4hctl/LICENSE);
the standalone verifier also carries the full license text.

Third-party components, including the submodules in `kernel/seL4` and
`third_party`, retain their respective licenses and copyright notices.

## What works

- **Guests.**
  - Linux 6.18 guests with SMP: tested up to 4 vCPUs.
  - Debian 13 with systemd boots, gets DHCP and installs packages with
    apt.
  - 30 guests of 256 MiB run on 4 cores, with CPU caps, a vCPU balancer
    and steal time.
  - Every guest runs the kernel l4h ships, and gets its modules and the
    tree to build more against, read-only, as `/dev/l4hkmod` (an EROFS
    image of `/lib/modules`).
  - The kernel has what Android's userspace needs from it (Binder,
    SELinux, PSI, bootconfig, userfaultfd, an RTC with alarms, dma-buf
    heaps, ashmem, metadata encryption, BPF on tracepoints, a vkms display
    as a module), off for other guests unless they ask.
  - Android 17 boots in a VM to its lock screen: Cuttlefish's 64-bit-only
    x86_64 build, unchanged but for its boot properties and ODM partition
    (`tools/mkandroid.sh`, `tests/run-android.sh`), rendering in software
    (SwiftShader) onto the VM's virtio-gpu display.
  - A virtio-gpu display (2D) for VMs, `l4hctl create --gpu WxH`, which dom0
    reads with `l4hctl screenshot`.
- **Block.** Passed-through virtio-blk, virtio-scsi and NVMe disks, or read-only and
  partial (LBA window) slices of them. I/O is zero-copy: devices DMA
  straight into guest memory.
- **Network.**
  - L2 virtual switches with MAC learning and MAC lock.
  - Multiple vNICs per VM, and a physical NIC as a switch's uplink:
    virtio-net, gVNIC on GCE C3, N4, C4 and later, or ENA on AWS EC2.
  - Checksum and TSO offloads.
  - Routing and NAT are done by a VM, for example Debian with nftables.
- **Device confinement.** Root drives AMD-Vi and Intel VT-d for per-device
  DMA mappings and interrupt remapping (`iommu` and `iommu_intremap`).
- **Control.** dom0, the first guest, controls the host through
  `/dev/l4hctl` and the `l4hctl` CLI: create, start (with an initramfs
  and a command line), shutdown and destroy VMs; console access; disks; switches; NICs; CPU caps;
  memory hotplug (`l4hctl mem`: a running VM's memory grows and shrinks
  128 MiB at a time). Destroying a VM returns all its memory. `l4hctl rtc-set` saves dom0's time to the
  machine's real-time clock.
- **Memory under QEMU/KVM.** Memory not given to guests is reported
  free through virtio-balloon free page reporting, so QEMU drops it.
- **Boot.** Multiboot under QEMU, or l4h as one UEFI application
  (`tools/mkefi.sh`, one per seL4 variant with `tools/build-efi.sh`), with
  the guest kernel in it, that loads dom0's initramfs and the settings from
  the EFI system partition; a UEFI disk
  image for GCE (`tools/mkimage.sh`, `tools/gce-image.sh`; tested on N2 and
  C3 with `tests/gce-test.sh`), and a private UEFI/ENA AMI for AWS EC2
  (`tools/ec2-image.py`; tested on c6i.xlarge with ENA, NVMe and four-vCPU
  guests; see [the EC2 workflow](tests/ec2.md)). On a host with a display
  the UEFI image shows a read-only status dashboard.
- **Attestation.** On a host with a TPM 2.0 (FIFO, CRB, AMD fTPM through
  the firmware's ACPI `_DSM`, or Pluton), `l4h-trustd` has the TPM
  quote its signing key along with the measured boot (the l4h application,
  then dom0's files). It signs CBOR (COSE) reports on each guest with that
  key, giving the guest's launch digest and the guest's own nonce. Guests
  get them through configfs-tsm or `l4hctl attest`; `tools/l4h-attest.py`
  verifies them. Per-instance taint and seal flags record console access
  and let guests lock it out; local seals and workload gates also work
  on hosts without a TPM.
- **aarch64.** seL4 and the host components run on QEMU `virt` at EL1. Native AArch64 Linux guests support SMP, signals, TLS,
  kernel modules, PCI virtio-blk/net and NVMe; virtualization is disabled.

## Layout

```
DESIGN.md            design, decisions, status
docs/manual/         user manual (LaTeX; make -C docs/manual renders the PDF)
include/l4h/abi.h    guest <-> host ABI (single source of truth)
kernel/              seL4 submodule, l4h patches (kernel/patches), configs
guest/linux/         arch/l4h for Linux 6.18 and patches outside arch/
host/                Rust workspace: l4h-root (root task), l4h-vmm (per guest),
                     l4h-blkd (disks), l4h-netd (switches, NICs), shared crates
tools/               build and run scripts, l4hctl (dom0 CLI)
tests/               integration tests (QEMU) and fuzzing
third_party/         rust-sel4, sDDF, kemu submodules; patches/ for rust-sel4
```

## Building and running

The host needs:

- QEMU with KVM, which is used only as a fast CPU: VMX is hidden from the
  guest;
- gcc, Rust (stable, plus the nightly pinned by rust-sel4), cmake, ninja
  and the Python modules seL4 needs, in `.venv`;
- Rust's `rust-src` component, Clang/libclang and `bindgen-cli` 0.71.1 for
  kemu in the x86_64 guest kernel (`rustup component add rust-src` and
  `cargo install --locked bindgen-cli --version 0.71.1`);
- busybox, e2fsprogs and erofs-utils;
- for the UEFI image: GRUB EFI, mtools, sfdisk and OVMF;
- for aarch64: `gcc-aarch64-linux-gnu`, cross libc headers,
  `qemu-system-arm` and a static AArch64 BusyBox for guest initramfs images.
  `tools/ci-setup.sh aarch64` prepares these on Debian 13 (run as root).

```sh
git submodule update --init
tools/build-kernel.sh                 # patched seL4 -> build/sel4
tests/run-selftest.sh 4               # build Linux + host, boot a 4-vCPU guest self-test
```

For AArch64, build the kernel and loader once, then select the guest ISA
with `L4H_ARCH`. The Linux outputs are kept separately in
`build/linux-l4h-aarch64`; the host uses `build/sel4-aarch64`.

```sh
tools/build-kernel-aarch64.sh
tools/build-loader-aarch64.sh
L4H_ARCH=aarch64 tests/run-selftest.sh 4
L4H_ARCH=aarch64 tests/run-blktest.sh
L4H_ARCH=aarch64 tests/run-nettest.sh
```

The same selection works with `tools/build-linux.sh`, `tools/run-dom0.sh`,
`tools/mkinitramfs.sh` and the control, memory and scheduler tests.
`L4H_BUSYBOX` can name another static AArch64 BusyBox. QEMU starts at EL1;
`L4H_QEMU_VIRTUALIZATION=on` also exercises entry from EL2. UEFI/GCE
image scripts remain specific to x86_64. `L4H_MEM` accepts MiB, `M` or `G`;
`run-dom0.sh` rebuilds the seL4 RAM map and loader when its size changes.

The x86_64 guest kernel includes [kemu](https://github.com/losfair/kemu)
to run AArch64 Linux userspace directly. `tools/build-linux.sh` imports its
patches and source overlay, then applies l4h's kernel patches.
`CONFIG_KEMU=y` and `CONFIG_RUST=y` are enabled by default on x86_64.
AArch64 guest kernels continue to execute AArch64 programs natively.
`tests/run-kemutest.sh` checks the emulated ABI, tagged addresses, vector
state across threads and signals, and FP exception flags in signal contexts
(requires `gcc-aarch64-linux-gnu` and cross libc headers);
`KEMU_CMDLINE=kemu.jit=0` checks the interpreter instead.

An assembled `build/l4h-aarch64.img` also boots directly on Apple Silicon
macOS with QEMU installed (`brew install qemu`):

```sh
tools/run-image-aarch64.sh build/l4h-aarch64.img
```

On macOS the script selects HVF with an emulated GICv2
(`kernel-irqchip=off`); no intermediate Linux VM is required. Tart's EFI
machine requires a different platform port.

To run your own dom0 initramfs:

```sh
tools/mkinitramfs.sh build/my.cpio.gz my-init-script
tools/run-dom0.sh build/my.cpio.gz "console=hvc0" 600   # output in build/qemu.log
```

Inside dom0, `l4hctl help` lists the control commands, for example:

```sh
l4hctl version                       # running host's version, e.g. v2026.10.1
l4hctl create web --initrd /web.cpio.gz --mem 512 --vcpus 2 \
    --disk 0 --nic 0
l4hctl console 1 --follow
```

Host builds use `L4H_VERSION` when set; otherwise the build scripts derive
it from `git describe --tags --match 'v*' --always --dirty`, or use `unknown`
without Git metadata. Release builds set it to the tag being published.
When building `l4h-root` directly with Cargo, set `L4H_VERSION` explicitly;
without it, the host reports `unknown`.

## Tests

| Test | What it checks |
|------|----------------|
| `tests/run-versiontest.sh` | host version metadata: release tags, development builds, overrides and worktrees |
| `tests/run-flagstest.sh` | focused flags-only boot: console/display seals, kernel taints, userspace gates and instance reuse, on either architecture |
| `tests/run-trusttest.sh` | taint/seal permissions, atomic gates, instances, seqlock snapshots and verifier policy |
| `tests/run-alloctest.sh` | host allocator growth under fragmentation, reclaim and fixed-container panic safety |
| `tests/run-abitest.sh` | guest ABI and seL4 extensions, from a module built against the module tree |
| `tests/run-selftest.sh [vcpus]` | syscalls, memory, signals, fork, threads, futex, SMP stress |
| `tests/run-kemutest.sh [vcpus]` | AArch64 userspace on x86_64: kemu syscalls, signals, TLS, threads, fork/exec, ptrace, single-step, vector state and FP exception flags |
| `tests/run-reclaimtest.sh [secs]` | 128 MiB checking workload in a 64 MiB memcg, with 32 MiB read-only hot data and swap; `RECLAIM_SWAP_DIR=/dev/shm` puts swap in host RAM |
| `tests/run-objtest.sh [vcpus]` | object memory growth under fragmentation, block conversion, SMP memory stress, OOM recovery |
| `tests/run-cryptotest.sh [vcpus] [secs] [MiB]` | dm-crypt with AES-NI (x86_64) or the ARMv8 Crypto Extensions (aarch64) vs generic C (cross-check, throughput), user SIMD state under concurrent kernel crypto |
| `tests/run-futexbench.sh [vcpus] [rounds]` | process-shared futex handoff latency |
| `tests/run-nodetest.sh /path/to/node [vcpus]` | Node startup/JIT, string internalization, worker threads and concurrent GC |
| `tests/run-modtest.sh` | external kernel module relocation, load and unload |
| `tests/run-bpftest.sh [vcpus]` | BPF JIT: the kernel's BPF test vectors, verified XDP and tc programs, direct tail calls patched in and out, XDP (generic) and tcx on lo |
| `tests/run-blktest.sh` (`BLKTEST_DEV=nvme`, `scsi`, `scsi-legacy`, `scsi-luns`) | disk pass-through, data integrity |
| `tests/run-ctltest.sh` | VM lifecycle, console, clean shutdown, disk re-attach, windows, reclaim |
| `tests/run-nettest.sh`, `tests/run-router.sh` | switches, uplink, multi-NIC, isolation, MAC lock, NAT router VM |
| `tests/run-density.sh 30 256` | 30 guests on 4 cores stay responsive |
| `tests/run-m6test.sh` | dom0 restart, CPU caps, steal time |
| `tests/run-vtdtest.sh [--qemu]` | VT-d DMAR parsing, table/interrupt formats and address bounds; with QEMU, DMA, lifecycle, NIC and serial tests |
| `python3 tests/vtd-net-qemu.py --iommu amd` | AMD-Vi bridge aliases with two NICs and disk controllers; `--no-intremap` checks DMA-only confinement, `--controllers 17` checks shared interrupt capacity |
| `python3 tests/amdvi-qemu.py` | AMD-Vi shared tables, DMA bounds and interrupt isolation using QEMU EDU devices |
| `tests/run-schedtest.sh` | host-side SMT topology, initial placement and migration policy tests |
| `tests/run-rtctest.sh [--qemu]` | RTC calendar, BCD/binary and 12/24-hour modes, bounds and error recovery; with `--qemu`, dom0 writes verified against the emulated hardware |
| `tests/run-smttest.sh` | QEMU boot with SMT: CPU discovery, initial placement and busy-vCPU migration |
| `tests/run-captest.sh [cap%] [rounds]` | self-test and fork loops in a guest capped from boot |
| `tests/run-capperf.sh [caps]` | fork/exec and CPU-bound timings, uncapped and under each cap (use a release seL4) |
| `tests/run-limits.sh` | the root task refuses what it cannot afford and recovers |
| `tests/run-balloontest.sh` | free memory reported to QEMU (virtio-balloon) is dropped: QEMU's memory use idle, with a guest and after destroying it |
| `tests/run-hotplugtest.sh` | memory hotplug: a VM grows from 256 MiB to 2 GiB and shrinks again under `l4hctl mem`, falling short while its data needs the memory; host memory comes back |
| `tests/run-hotplugstress.sh [rounds]` | memory hotplug under stress: three VMs under memory load resized at random, oversubscribing the host, destroyed mid-resize; data checked, all memory back |
| `tests/run-monitor.sh` | serial monitor (`list`, `restart-dom0`), continued operation with an absent UART |
| `tests/run-uefitest.sh` | UEFI/GRUB boot image with NVMe and virtio-net, as on GCE |
| `tests/run-xentest.sh` | two l4h partitions as Xen HVM guests, nested in KVM, each with a passed-through NIC, ping each other (DESIGN.md §10.2) |
| `tests/run-attesttest.sh` | attestation with swtpm over CRB, FIFO and the AMD fTPM ACPI start method: reports on dom0 and a guest, host evidence, AK credential |
| `tests/run-debian.sh`, `tests/run-workload.sh` | Debian + systemd, fio verify, parallel build, fsck (`tests/mkdebian.sh` first) |
| `tests/run-bench.sh` | micro-benchmarks |
| `tests/run-fuzz.sh` | hostile-guest virtqueue fuzzing of l4h-vmm |
