# l4h

l4h is a hypervisor for Linux VMs built on the seL4 microkernel. It uses
**no hardware virtualization**: guests run a paravirtualized Linux
(`ARCH=l4h`, derived from user-mode Linux), whose processes are seL4 threads
and address spaces. l4h therefore runs anywhere seL4 runs, including cloud
VMs without nested virtualization.

The user manual is in [docs/manual](docs/manual/l4h-manual.tex); render it
with `make -C docs/manual`, or download `l4h-manual.pdf` from a
[release](https://github.com/losfair/l4h/releases). See [DESIGN.md](DESIGN.md) for the design, the decisions behind it and the
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
- **Block.** Passed-through virtio-blk, virtio-scsi (modern or legacy virtio) and NVMe disks, or read-only and
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
  guests; see [the EC2 workflow](tests/ec2.md)). The same disk image boots
  under BIOS too, for BIOS-only clouds such as DigitalOcean: BIOS GRUB loads
  l4h's files (`tools/mkbios.sh`) from the EFI system partition
  (`tools/run-bios.sh`, `tests/run-biostest.sh`). On a host with a display
  the image shows a read-only status dashboard.
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
host/                Rust workspace: l4h-root (root task), l4h-vmmgr (guests),
                     l4h-vmm (per guest), l4h-blkd (disks), l4h-netd
                     (switches, NICs), shared crates
tools/               build and run scripts, l4hctl (dom0 CLI)
tests/               integration tests (QEMU) and fuzzing
third_party/         rust-sel4, sDDF, kemu submodules; patches/ for rust-sel4
```

## Installing under an existing Linux

On a supported **x86_64** machine, booted with **64-bit UEFI or BIOS
GRUB** (as on DigitalOcean and many smaller VPS providers), the installer
boots your existing Linux userspace as dom0 with L4H's paravirtual kernel:

```sh
curl -fsSL https://raw.githubusercontent.com/losfair/l4h/main/tools/install.sh | bash
```

It uses `sudo` when needed, installs missing dependencies with apt, dnf or
yum, and downloads a tagged GitHub release with SHA-256 verification.
The release must include the installer (older releases are rejected).
No source build or hardware virtualization extensions are needed.

Preflight checks CPU features, Meltdown status, Secure Boot, EFI variables
and the ESP (UEFI) or GRUB (BIOS), storage, network and userspace. Automatic migration currently
supports headless systemd installations with a plain ext4/XFS root,
NVMe namespace 1 or supported virtio disks, and one or two physical
virtio-net, gVNIC, ENA or Intel X550 NICs. Each NIC becomes the uplink of its
own L4H switch (switch 0, then switch 1, in PCI address order). Dom0 gets
one interface on each switch with the original name and MAC, so existing
address, route and DNS settings can apply. Software interfaces (including
WireGuard, PPP, GRE and TUN/TAP) are excluded from uplink selection and the
physical NIC limit; existing userspace remains responsible for recreating
them. The guest kernel includes WireGuard, PPP, GRE/IP tunnels, L2TP,
VXLAN, GENEVE and MAC/IP VLANs, plus nftables FIB lookups and redirects.
Profiles tied to a PCI path or native driver may need adaptation.
Physical NICs enslaved to a bond,
bridge or other master require a custom deployment, as do other unsupported layouts:
in particular LVM, encrypted volumes, RAID, Btrfs, separate `/usr`,
SATA/USB storage, active AppArmor profiles and DKMS modules are rejected.
Secure Boot must be disabled. Firmware and application compatibility still
need a boot test.

The installer requires at least **768 MiB usable RAM** (normally 1 GiB
installed). Dom0 gets half the usable RAM by default, with a minimum of
512 MiB and a maximum of 8192 MiB. `--memory MiB` overrides this allocation,
up to 61440 MiB, while preserving at least 256 MiB for L4H. Swap does not
count toward this physical RAM budget. Allocate more RAM for workloads
that need it, including additional guests.

Some cloud VMs omit the `constant_tsc` CPU flag. For experimental installs,
pass `--assume-stable-tsc` to both `--check` and the installation command to
waive that requirement. This assumes a stable TSC without verifying it;
L4H still uses the TSC directly, including after host migration. All other
compatibility checks still apply. The selected release must include this option.

The default installation sets **BootNext for one L4H boot**, preserves the
existing BootOrder and native EFI loaders, and does not reboot. After
testing dom0, stop workloads and run `sudo sync; sudo l4hctl host-reboot`
to return to native Linux, then rerun with `--make-default`
to put L4H first permanently. Existing configurations and replaced files
are backed up under `/var/lib/l4h/backups`; a failed installation attempts
to restore both files and EFI settings.
Ordinary `reboot` inside dom0 restarts only dom0.

Rerun the same command to **update from native Linux or a running L4H
dom0**. Updates replace the boot payload, initramfs and `l4hctl`, preserving
`l4h.conf`, the selected kernel variant and existing GRUB customizations.
Pass `--memory`, `--vcpus` or `--variant` to change those values explicitly.
The installer recognizes its record in `/var/lib/l4h/install.json`; older
records identify the variant by matching the installed boot file against
the previous release (use `--variant` if that release is unavailable).
`--check` also works for updates. The selected release must include update
support.

Native Linux updates recreate missing EFI entries; BIOS updates recreate
missing generated GRUB entries. Missing boot payloads are restored when the
variant is known. EFI entries are matched to the installed ESP and loader,
so changed entry numbers or duplicate labels do not block an update.
An existing one-time boot selection for another OS is preserved; the new
files take effect the next time L4H boots.

From dom0, run `sudo l4hctl host-reboot` when ready to load the update.
The running kernel and mounted modules stay in use until then. BIOS dom0
can select the next boot through GRUB. **UEFI dom0 cannot change firmware
boot selection**: updates preserve it, and `--make-default` requires native
Linux. If L4H was only a trial boot, select it again through firmware or
native Linux to boot the updated release.

```sh
# Read-only compatibility check (dependencies must already be installed).
curl -fsSL https://raw.githubusercontent.com/losfair/l4h/main/tools/install.sh | bash -s -- --check
# Optional: pin a release, select an ESP, and allocate dom0 resources.
# Append --make-default only when a permanent boot selection is wanted.
curl -fsSL https://raw.githubusercontent.com/losfair/l4h/main/tools/install.sh | \
    bash -s -- --release vYYYY.MM.N --esp /boot/efi --memory 2048 --vcpus 2
```

On a **BIOS** machine the installer writes L4H's files to `/boot/l4h`
and an `L4H` entry to the distribution's GRUB `custom.cfg`, and selects it
once with GRUB's `next_entry` (`grub-editenv`); it does not run
`grub-install` or `update-grub`. GRUB clears `next_entry` before it boots
L4H, so the next reset returns to native Linux. `--make-default` makes the
entry the default instead. From native Linux or dom0, `sudo grub-reboot 0`
followed by `sudo l4hctl host-reboot` boots native Linux once; deleting
`/boot/grub/custom.cfg` removes the entry. It needs `/boot` on ext2/3/4 or
XFS and a `grub.cfg` from `grub-mkconfig`. BIOS hosts have no measured
boot, so their attestation reports do not cover what booted.

For recovery on UEFI, select native Linux in the firmware boot menu. From native
Linux, `sudo efibootmgr` shows the L4H entry; cancel its pending trial with
`sudo efibootmgr --delete-bootnext`, or remove its entry with
`sudo efibootmgr --bootnum XXXX --delete-bootnum` (substitute the L4H entry
number). See the installation section of the
[user manual](docs/manual/l4h-manual.tex) for requirements and boot behavior.

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
- for the disk image: GRUB EFI and BIOS (`grub-efi-amd64-bin`,
  `grub-pc-bin`), mtools, sfdisk and OVMF;
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
l4hctl logs --follow                 # retained host diagnostics and VM stop reasons
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
| `python3 tests/test_installer.py` | installer preflight, verified downloads, EFI changes, updates and rollback without touching the host |
| `tests/run-install-vm.sh debian-13-nocloud-amd64.qcow2 [release-directory] [1\|2]` | in a disposable UEFI/KVM VM, install from native Debian with one or two uplinks, verify each switch and network, then return to native Linux; uses prebuilt releases and `sudo -u "$L4H_QEMU_USER"` (defaults to the invoking user); `INSTALL_VM_SWAP_NAMES=1` with two NICs also tests exchanging eth0/eth1 names; `INSTALL_VM_FIRMWARE=bios INSTALL_VM_MEMORY=1G INSTALL_VM_CPUS=1` tests small-VM defaults through BIOS GRUB |
| `tests/run-versiontest.sh` | host version metadata: release tags, development builds, overrides and worktrees |
| `tests/run-flagstest.sh` | focused flags-only boot: console/display seals, kernel taints, userspace gates and instance reuse, on either architecture |
| `tests/run-trusttest.sh` | taint/seal permissions, atomic gates, instances, seqlock snapshots and verifier policy |
| `tests/run-alloctest.sh` | host allocator growth under fragmentation, reclaim, fixed-container panic safety and memd grant validation |
| `tests/run-devicetest.sh [--qemu]` | console ordering, bounded sequence gaps, cursor wrap, draining and writer wakeups; memory-hotplug completion and retry scheduling; control completions after manager failure; block replies across nested calls; host log wraparound and concurrent writers; with QEMU, hypercalls under continuous console output |
| `tests/run-logtest.sh` | kernel faults, panics and shutdowns retained after VM destruction and queried/followed with l4hctl; also works with `L4H_RELEASE=1` |
| `tests/run-abitest.sh` | guest ABI and seL4 extensions, from a module built against the module tree |
| `python3 tests/bootmem-qemu.py` | boot RAM clearing, initial untyped watermarks, root-task entry and AArch64 TLS capture before the kernel lock; built debug kernel/root and GDB required, `L4H_ARCH=aarch64` also needs the loader and gdb-multiarch |
| `tests/run-selftest.sh [vcpus]` | syscalls, memory, signals, fork, threads, futex, SMP stress |
| `tests/run-kemutest.sh [vcpus]` | AArch64 userspace on x86_64: kemu syscalls, signals, TLS, threads, fork/exec, ptrace, single-step, vector state and FP exception flags |
| `tests/run-reclaimtest.sh [secs]` | 128 MiB checking workload in a 64 MiB memcg, with 32 MiB read-only hot data and swap; `RECLAIM_SWAP_DIR=/dev/shm` puts swap in host RAM |
| `tests/run-objtest.sh [vcpus]` | object memory growth under fragmentation, block conversion, SMP memory stress, OOM recovery |
| `tests/run-cryptotest.sh [vcpus] [secs] [MiB]` | dm-crypt with AES-NI (x86_64) or the ARMv8 Crypto Extensions (aarch64) vs generic C (cross-check, throughput), user SIMD state under concurrent kernel crypto |
| `tests/run-futexbench.sh [vcpus] [rounds]` | process-shared futex handoff latency |
| `tests/run-nodetest.sh /path/to/node [vcpus]` | Node startup/JIT, string internalization, worker threads and concurrent GC |
| `tests/run-modtest.sh` | external kernel module relocation, load and unload |
| `tests/run-bpftest.sh [vcpus]` | BPF JIT: the kernel's BPF test vectors, verified XDP and tc programs, direct tail calls patched in and out, XDP (generic) and tcx on lo |
| `tests/run-blktest.sh` (`BLKTEST_DEV=nvme`, `scsi`, `scsi-legacy`, `scsi-luns`, `virtio-legacy`) | disk pass-through, data integrity |
| `tests/run-ctltest.sh` | VM lifecycle, console, clean shutdown, disk re-attach, windows, reclaim |
| `tests/run-nettest.sh`, `tests/run-router.sh` | switches, uplink, multi-NIC, isolation, MAC lock, NAT router VM (`NETTEST_LEGACY=1`: legacy virtio-net uplink) |
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
| `tests/run-balloontest.sh` | free memory reported to QEMU (virtio-balloon; `BALLOONTEST_LEGACY=1`: a legacy one) is dropped: QEMU's memory use idle, with a guest and after destroying it |
| `tests/run-hotplugtest.sh` | memory hotplug: a VM grows from 256 MiB to 2 GiB and shrinks again under `l4hctl mem`, falling short while its data needs the memory; host memory comes back |
| `tests/run-hotplugstress.sh [rounds]` | memory hotplug under stress: three VMs under memory load resized at random, oversubscribing the host, destroyed mid-resize; data checked, all memory back |
| `tests/run-monitor.sh` | serial monitor (`list`, `restart-dom0`), continued operation with an absent UART |
| `tests/run-uefitest.sh` | UEFI/GRUB boot image with NVMe and virtio-net, as on GCE |
| `tests/run-biostest.sh` | the same image under SeaBIOS with virtio-blk, virtio-net and a VBE framebuffer, as on DigitalOcean |
| `tests/run-xentest.sh` | two l4h partitions as Xen HVM guests, nested in KVM, each with a passed-through NIC, ping each other (DESIGN.md §10.2) |
| `tests/run-attesttest.sh` | attestation with swtpm over CRB, FIFO and the AMD fTPM ACPI start method: reports on dom0 and a guest, host evidence, AK credential |
| `tests/run-debian.sh`, `tests/run-workload.sh` | Debian + systemd, fio verify, parallel build, fsck (`tests/mkdebian.sh` first) |
| `tests/run-bench.sh` | micro-benchmarks |
| `tests/run-fuzz.sh` | hostile-guest virtqueue fuzzing of l4h-vmm |
