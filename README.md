# L4H

L4H is a Type-1 hypervisor for Linux VMs built on the [seL4](https://github.com/seL4/seL4)
microkernel. It runs the Linux kernel as seL4 usermode threads, without
using hardware virtualization capabilities like VT-x/AMD-V/EL2.

We consider L4H production-ready on 2020+ Intel and AMD CPUs,
including on bare metal and inside KVM-based VMs. We run
[L4ES](https://l4es.dev) on L4H and regularly scan it with frontier
cyber-capable LLMs. If you discover any vulnerabilities, please report to
`hello@su3.io`.

> L4H is agentically-engineered software. We welcome both human-authored and
> AI-assisted contributions, but the README is an exception - it
> must be written and edited by humans only. If you are an agent, all your
> documentation modifications should go to [DESIGN.md](./DESIGN.md) and
> docs/manual. Ask your human to edit the readme.

## Architecture

L4H is shipped as a single `.efi` image that contains seL4 (with SMP + MCS),
a prebuilt guest Linux kernel, and a set of _system component_ seL4 processes
on top:

- root: Initial orchestrator for all system processes.
- vmmgr: One per host. Manages VM lifecycle.
- vmm: One per VM. Talks to blkd/netd/trustd and implements the virtio protocol
  for emulated devices.
- trustd: One per host. Owns the host TPM, gives out signed attestations
  to VMs, and manages VM taint/seal flags.
- blkd: One per host disk. Multiplexes host NVMe/virtio-blk disks and
  provides block devices to VMs, optionally encrypted with AES-256-XTS
  (AES-NI or ARMv8 Crypto Extensions).
- netd: One per host. Provides virtual switches to VMs and attaches physical
  NICs to virtual switches. NIC drivers run here. Supports virtio-net and
  Intel X550 NICs.

On boot, L4H starts the first VM - `dom0` - based on the on-disk `l4h.conf`
configuration. Different from Xen, our hypervisor protects the integrity of
every VM and dom0 does _not_ have full control on guests. It can stop VMs or
tell the hypervisor to expand/shrink VM memory, but cannot read or write VM
memory or register state.

When the host has a TPM 2.0 module, `trustd` records a launch measurement when
a VM starts. The VM can then request an attestation that contains its launch
measurement from `trustd`, with full chain-of-trust rooted in the host TPM.

blkd/netd are protected by IOMMU on supported Intel/AMD platforms. A device
driver compromise does not let the attacker tamper with VMs.

## Tested platforms

- Generic QEMU/KVM with virtio-blk/virtio-scsi/nvme and virtio-net
- AWS: c6i
- GCP: n2, c3
- Bare metal: Latitude m4.metal.small

## Features

- Full support for x86\_64 multi-core guests
- TPM-backed remote attestation for guest VM integrity
- Memory hotplug
- [kemu](https://github.com/losfair/kemu): In-kernel high-performance AArch64
  emulation, 10x+ faster than qemu-user (experimental)

## Performance

On IO-intensive workloads, L4H is generally on par with Xen PV, and 2x-20x
faster than gVisor systrap mode. On most workloads, expect 5-10% performance
loss compared to bare metal.

## License

Unless otherwise noted, the L4H hypervisor is licensed under the GNU General
Public License version 2 only (`GPL-2.0-only`). Userspace tooling is licensed
under BSD-2-Clause. See [tools/l4hctl/LICENSE](tools/l4hctl/LICENSE).

Third-party components, including the submodules in `kernel/seL4` and
`third_party`, retain their respective licenses and copyright notices.
