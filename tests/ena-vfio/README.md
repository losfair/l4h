# ENA hardware test

This compiles `host/l4h-netd/src/ena.rs` unchanged into a Linux userspace
program and drives a real ENA PCI function through VFIO. It follows the
existing `tests/ixgbe-vfio` approach. This is a driver integration test,
not an l4h/seL4 boot test.

VFIO supplies BAR mappings, DMA memory and MSI-X eventfds. The driver's
MSI-X table writes go to a shadow table because Linux owns interrupt
routing; the seL4 PCI mapping and interrupt setup are not covered.
On EC2 VMs without an IOMMU, the harness uses a locked 2 MiB hugepage and
checks every page's physical address for contiguity. BAR 2 uses
`resource2_wc` when available; an uncached fallback is reported explicitly.

## Result: 2026-10-24

**PASS with both LLQ and host-memory TX queues, including 65,600 checked
UDP echoes per run and fresh MSI-X events.**

| Item | Tested configuration |
|---|---|
| Driver revision | `2d1621a` plus the ENA host-information fix; hashes in results |
| EC2 | `c6i.large`, `us-west-2a` |
| OS | Ubuntu 24.04, kernel `7.0.0-1014-aws` |
| ENA | Secondary ENI, `0000:00:06.0`, `1d0f:ec20`, revision 0 |
| Memory | VFIO no-IOMMU, contiguous 2 MiB hugepage |
| BAR 2 | 256 KiB, write-combining mapping available |
| Normal probe | LLQ, TX 256 / RX 512: all checks passed |
| Forced host queue | TX 256 / RX 512: all checks passed |

The original driver failed before packet tests:

```text
netd: NIC 0: ENA refuses the host attributes: status 5
netd: NIC 0: ENA admin command 'create CQ' failed: status 6
```

ENA defines status 5 as `ILLEGAL_PARAMETER` and 6 as `UNKNOWN_ERROR`.
The Linux `ena` driver successfully configured TX depth 256 and RX depth
512 on this same ENI. DPDK `23.11.4` also initialized it through VFIO
no-IOMMU with those depths, providing a working userspace baseline.
The wrapper restored the Linux driver after every attempt; SSH used the
primary ENI throughout.

The fix supplies ENA's userspace OS class, specification version 2.0,
and driver version 2.0.0, while identifying l4h in the OS/kernel strings.
Nitro accepts version 1's host information but rejects CQ creation with
status 6. A byte-level comparison with DPDK isolated the driver-version
field; changing just that field resolved CQ creation after the OS/spec
correction. The final runs use the production source without tracing or
runtime substitutions. The original failure also reproduced in a full
l4h/seL4 EC2 boot.

Successful logs and source/binary hashes are in
[`results/ec2-c6i-fixed-2026-10-24.txt`](results/ec2-c6i-fixed-2026-10-24.txt).
The original failure and baseline excerpts remain in
[`results/ec2-c6i-2026-10-24.txt`](results/ec2-c6i-2026-10-24.txt).
See [the EC2 test workflow](../ec2.md) for the full UEFI/seL4 boot test.
Detailed diagnostic traces are under `build/ec2/` (ignored by Git).

## Running

Build from the repository root. All scratch files stay on the project
filesystem; static linking permits running the binary on an older libc.

```sh
mkdir -p build/ena-ec2/work
TMPDIR="$PWD/build/ena-ec2/work" RUSTFLAGS='-C target-feature=+crt-static' \
    cargo +stable build --locked --release --manifest-path tests/ena-vfio/Cargo.toml
```

Use a disposable x86-64 EC2 instance with a **dedicated secondary ENI**.
Keep SSH on the primary ENI. Copy `target/release/ena-vfio`,
`run-on-host.sh`, and `peer.py` from this directory to the test host.
The kernel needs `vfio-pci` and, on a VM without an IOMMU,
`CONFIG_VFIO_NOIOMMU=y`.

For packet tests, run the peer on a Linux host in the same subnet:

```sh
sudo ip link set PEER_INTERFACE mtu 9001
python3 peer.py PEER_IP
```

Permit ICMP, UDP 9000, and TCP 9001 between the test ENI and peer in the
security groups. Use the ENI's assigned private IPv4 address as `OUR_IP`.
Disable automatic configuration/default routes on the dedicated test
interface before the run. The wrapper refuses a default-route interface
and checks the SSH route when `SSH_CONNECTION` is available.

```sh
sudo ./run-on-host.sh PCI_ADDRESS OUR_IP PEER_IP
sudo ./run-on-host.sh PCI_ADDRESS OUR_IP PEER_IP --host-queue
sudo ./run-on-host.sh PCI_ADDRESS OUR_IP PEER_IP --packets=65600
```

The wrapper binds only the selected function to VFIO, reserves a hugepage
when necessary, bounds execution to 180 seconds, and restores the Linux
driver, hugepage count and no-IOMMU setting on exit. It preserves the
test's nonzero exit status. Linux network configuration may be reapplied
after rebinding, so inspect the secondary interface before another run.

The harness checks ARP, ICMP, exact UDP
echo contents with software and hardware IPv4 checksums, RX `DATA_VALID`,
small frames around the LLQ header boundary, jumbo frames through MTU
9001, bursts across ring wraparound, production software GSO for 4,000
and 60,000-byte TCP sends, and fresh MSI-X I/O events without RX polling.
`--packets=65600` also crosses the 16-bit queue-index wrap. The peer logs
TCP payload pattern checks separately. These checks passed on both TX
queue placements; IPv6 checksum offload was not advertised by this ENI.
