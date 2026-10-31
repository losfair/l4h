# l4h: Design and implementation

l4h is a hypervisor built on seL4 that runs Linux VMs without hardware
virtualization. It targets public-cloud instances where VT-x and SVM are
unavailable or nested virtualization is disabled. Guests are paravirtualized:
the guest Linux kernel is ported to run as an ordinary seL4 user-level program,
and guest user processes run natively in their own seL4 address spaces. The
host does not emulate guest instructions; x86_64 guest kernels can run
AArch64 userspace with kemu (§5.9).

This document describes the design as implemented. On x86_64 that covers
SMP Linux guests, block and network I/O, dom0 control, CPU caps and
balancing, guest-owned memory and memory hotplug, IOMMU confinement,
attestation, and deployment on QEMU, GCE, EC2 and bare metal. AArch64 runs
the host and native Linux guests on QEMU `virt`, including SMP and PCI
block/network drivers, with virtualization disabled (§12). Known gaps are
stated where they apply.

The user manual is in [docs/manual](docs/manual/l4h-manual.tex); render it
with `make -C docs/manual`, or download `l4h-manual.pdf` from a
[release](https://github.com/losfair/l4h/releases).

---

## 1. Requirements

| # | Requirement | How the design meets it |
|---|-------------|-------------------------|
| R1 | No hardware virtualization. Paravirtualize, as Xen PV does. Avoid instruction emulation. | The guest kernel is a new Linux architecture, `ARCH=l4h`, that runs in ring 3 as an seL4 thread and calls seL4 directly. Guest user code runs unmodified. Its `syscall` instructions and exceptions reach the guest kernel as seL4 fault IPC. |
| R2 | x86_64 first, but friendly to aarch64. | Each layer is split into ISA-independent and ISA-specific parts (§12). Nothing relies on an x86-only mechanism such as segmentation, rings 1/2 or Xen-style page-table validation. |
| R3 | virtio-blk and virtio-net. Block devices are passed through. Network is multiplexed by virtual switches. | The guest runs stock Linux `virtio_blk`/`virtio_net` drivers over a paravirtual transport, `virtio-l4h`, with no trapped MMIO (§9). All device buffers live in a host-owned I/O pool (§8.1). The hypervisor provides **only L2 virtual switches**; a physical NIC is an uplink port on a switch, and routing and NAT are done by a VM. |
| R4 | SMP guests. | Each vCPU is an seL4 kernel-context thread with its own scheduling context. IPIs are seL4 notifications (§6). |
| R5 | Many guests per host, e.g. 30 guests on 4 CPUs. | MCS scheduling contexts give each vCPU a budget. Idle guests consume no CPU: the guest kernel is tickless and idle means blocked in `seL4_Recv`. A balancer moves vCPUs between cores (§7). Each guest makes its kernel objects from its own RAM (§8). |
| R6 | A runtime management API for "dom0", the first guest started at boot. | `l4h-vmmgr` serves a control API through an `l4hctl` device that only dom0 receives (§10.1). dom0 has no device-driver duties. |
| R7 | Targets: QEMU with virtio devices, then clouds. | QEMU with virtio-net, virtio-blk, virtio-scsi and NVMe; GCE N2 (virtio-net) and C3 (gVNIC); EC2 (ENA); Latitude.sh bare metal (X550) (§11). |

Non-goals: running unmodified guest *kernels*, live migration, memory
overcommit, 32-bit guest userspace, PCI passthrough into guests, Windows
guests, and any L3 networking (routing, NAT, IP filtering) inside the
hypervisor.

---

## 2. Prior art and why this shape

| Approach | Verdict |
|----------|---------|
| **Xen PV ABI on seL4.** Reuse upstream `CONFIG_XEN_PV`. | Rejected. Xen PV gives the guest control of real hardware page tables, which the hypervisor validates through `mmu_update`. It also uses a hypervisor-assisted syscall bounce, `iret` hypercalls, event channels, grant tables and xenstore. Implementing this would mean writing Xen inside the seL4 kernel. Xen PV exists only on x86, which fails R2, and upstream treats it as legacy. |
| **lguest-style `pv_ops` subarch of x86.** | Rejected. It is x86-only and needs the guest kernel in a privileged ring. lguest was removed from Linux in 4.14. |
| **UML (User-Mode Linux) on seL4.** | Rejected as a base, but used as a source of code. Its host layer (`arch/um/os-Linux`) assumes a POSIX host with libc, signals and mmap of a physmem file. Its separate-address-space kernel model is the same as ours, so `arch/l4h` reuses its `uaccess`, `pt_regs`, signal frames and software page tables. |
| **L4Linux** (TU Dresden / Kernkonzept, Linux on Fiasco.OC). | **The closest model.** The guest kernel is a user-level task, and each guest process is a microkernel task whose syscalls and faults arrive as IPC. It relies on Fiasco's *vCPU mode*, which seL4 lacks; §5.4 shows how seL4 threads, priorities and the kernel extensions replace it. |
| **Wombat / OK Linux** (NICTA). | A historical precedent for Linux para-virtualized on L4-family kernels. |
| **gVisor systrap.** | Different goal: it reimplements Linux rather than running it. It confirms that trapping syscalls from unmodified binaries without VT-x is practical in production. |
| **seL4 Microkit / LionsOS / sDDF / libvmm.** | **sDDF is a design reference.** l4h's Rust drivers and shared queues follow its shape but support dynamic guest attachment; they do not link sDDF's C drivers. libvmm (hardware virtualization) and Microkit's static system model do not fit dynamic cloud guests. |

The result: **a new Linux architecture (`arch/l4h`), modelled on L4Linux and
UML, running on an MCS SMP seL4 kernel with three kernel extensions and a
set of fixes. Host components and device drivers are written in Rust on
rust-sel4.**

---

## 3. System overview

```
 ┌───────────────────── seL4 user level ───────────────────────────────────────┐
 │                                                                             │
 │  Guest A (untrusted)                  dom0 (guest #0)        Host services  │
 │  ┌──────────────────────────────┐     same as any guest,     (trusted)      │
 │  │ guest procs: one seL4 VSpace │     plus an l4hctl device  ┌───────────┐  │
 │  │ + one TCB per Linux thread   │     ──── control API ────► │ l4h-vmmgr │  │
 │  │ (trap-syscall flag)          │                            │ guests    │  │
 │  │   │ fault IPC  ▲ reply       │                            │ lifecycle │  │
 │  │   ▼            │             │                            │ ctl API   │  │
 │  │ guest kernel: ARCH=l4h vmlinux                            │ balancer  │  │
 │  │ one VSpace, one kernel TCB per vCPU                       └───────────┘  │
 │  │ virtio_blk / virtio_net over virtio-l4h                   l4h-memd       │
 │  └───────┬──────────────────────┘                            l4h-trustd     │
 │          │ shared vrings + notifications                     l4h-root       │
 │  ┌───────▼──────────┐                                                       │
 │  │ l4h-vmm (A)      │ one per guest, maps its I/O pool, never guest RAM     │
 │  │ virtio backends  │                                                       │
 │  └──┬────────────┬──┘                                                       │
 │     │ blk queue  │ net port rings                                           │
 │  ┌──▼───────┐  ┌─▼─────────────┐                                            │
 │  │ l4h-blkd │  │ l4h-netd      │  switches and uplink NIC drivers           │
 │  └──┬───────┘  └──────┬────────┘                                            │
 │  ┌──▼───────────┐  ┌──▼──────────────────┐                                  │
 │  │ NVMe / virtio│  │ virtio-net / gVNIC /│                                  │
 │  │ -blk / -scsi │  │ ENA / X550 uplinks  │                                  │
 │  └──────────────┘  └─────────────────────┘                                  │
 └─────────────────────────────────────────────────────────────────────────────┘
   seL4 microkernel (MCS, SMP, x86_64 or aarch64), plus l4h extensions (§4)
   Cloud VM or bare-metal hardware, with no VT-x used
```

- `l4h-root` spawns the host services and keeps the hardware: PCI, the
  IOMMU, interrupts, reset, the RTC, and what devices reach (each guest's
  I/O pool, disk channels and netd ports), which it makes when `l4h-vmmgr`
  asks (§10.3). Nothing a guest, its VMM or dom0 sends reaches root.
- `l4h-vmmgr` builds and runs guests: CSpaces, VSpaces, vCPUs, image
  loading and launch measurement, lifecycle, the control API and the
  balancer.
- `l4h-memd` owns all free RAM and every guest's RAM blocks (§8.4).
- `l4h-trustd` owns the TPM and the guests' taint/seal flags (§10.2).
- One `l4h-blkd` drives each PCI disk controller and multiplexes its disks
  among guests. `l4h-netd` combines all switches and uplink NIC drivers in
  one component.

**Trust.** The seL4 kernel, `l4h-root`, `l4h-vmmgr`, `l4h-memd`,
`l4h-blkd`, `l4h-netd` and `l4h-trustd` form the host TCB, which a TPM can
attest (§10.2). dom0 is trusted for control-plane decisions (§10.1) but
cannot read other guests' memory or registers. Each `l4h-vmm` is trusted
only by its own guest: it maps that guest's I/O pool and host-owned device,
event and queue pages, never its RAM (§8), so a compromised VMM can harm
only that guest. Guest kernels are untrusted; capabilities confine them,
and the hypervisor never validates guest page tables.

---

## 4. seL4 kernel configuration and extensions

The kernel is pinned to the seL4 17.0.0 release (`62e345c`). l4h carries a
patch set in `kernel/patches/`, built as independent commits intended for
upstreaming through the seL4 RFC process. They have no sel4test cases yet;
l4h's integration tests (`tests/guest/abitest` and the rest of `tests/`)
exercise them through the guest. Patch numbers are stable: 0026 (aarch64,
save TLS before taking the kernel lock) went upstream in 17.0.0 and was
dropped without renumbering the rest.

### 4.1 Configuration

- `KernelIsMCS=ON`: scheduling contexts with budget and period, for
  multi-tenant fairness (§7).
- `KernelMaxNumNodes=64`.
- `KernelFastpath=OFF`.
- `KernelFSGSBase=inst`.
- `KernelXSave=XSAVEOPT`, `KernelXSaveFeatureSet=7` (x87, SSE, AVX). The
  guest hides AVX-512, AMX and PKU, which seL4 does not enable.
- `KernelIRQReporting=OFF`: the kernel never prints spurious interrupts
  (QEMU/HVF raises tens of thousands of them).
- `KernelIOMMU=OFF`: root drives the IOMMU itself (§9.5).
- `KernelSkimWindow=OFF` in the default variants, which require a CPU
  unaffected by Meltdown. The `skim-xapic-nopcid` variant sets it `ON`,
  uses xAPIC and disables PCID. Builds without SKIM refuse to boot when
  `IA32_ARCH_CAPABILITIES.RDCL_NO` is clear, or on Intel CPUs that do not
  enumerate that MSR (patch 0024). The PCID variant requires INVPCID too.
  The installer picks the variant (§11.3).
- Development builds keep `KernelDebugBuild` on. `L4H_RELEASE=1
  tools/build-kernel.sh` turns the debug build off but keeps kernel
  printing for the host components' serial log.

Debug syscalls (including `seL4_DebugHalt`, which stops the machine) need
no capability in seL4. Patch 0008 reserves them to threads with an MCP of
at least `KernelDebugSyscallMinMCP` (101 for l4h). Guest threads are
confined to MCP 100, so in a guest they are unknown syscalls in every
build. The same threshold silences the kernel's `userError` messages and
reports of threads that fault without a handler: every kernel print is a
synchronous serial write under the kernel lock, so a guest could otherwise
stall every core by failing invocations in a loop. With
`KernelInvocationReportErrorIPC` (off in l4h), error replies to such
threads carry an empty message rather than the IPC buffer.

### 4.2 E1: `seL4_TCBFlag_trapSyscalls`

On x86_64 seL4 takes the syscall number in `rdx`, which Linux uses for
argument 3; on aarch64 seL4 uses `x7` and Linux `x8`. Without E1, a Linux
syscall whose number register happens to hold a valid seL4 syscall number
runs as an seL4 syscall (seL4 issue #477, still open upstream), and several
(NBSend\*, Yield, SetTLSBase, the debug calls) do not fault without
capabilities.

E1 adds a flag to `seL4_TCB_SetFlags`. When it is set, *every* syscall
instruction from that thread raises `seL4_Fault_UnknownSyscall`, which
carries FaultIP, SP, FLAGS and the argument registers (all GPRs on x86_64;
X0–X7 on aarch64, where patch 0007 puts x8, Linux's syscall number, in
the Syscall word instead of seL4's). The check sits with the syscall range
test in the slowpath, and before any fastpath dispatch.

On x86, seL4 opens its spare IDT vectors (above the IRQs) to user level and
reports `int $N` on them as an unknown syscall, which a trapping thread's
handler could not tell from `syscall`. For a trapping thread they raise
#GP instead, with the vector in the error code, as closed gates do
natively, and the guest delivers SIGSEGV. `tests/guest/abitest` sweeps
all seL4 syscall numbers.

### 4.3 E2: TCB FPU state access

Linux needs a user thread's FPU and XSAVE state for signal frames,
`sigreturn`, `ptrace`, core dumps and `fork`. E2 adds
`seL4_TCB_ReadFPU(tcb, frame_cap, offset)` and
`seL4_TCB_WriteFPU(tcb, frame_cap, offset)`, which copy the arch FPU save
area (XSAVE format on x86, V0–V31 + FPSR/FPCR on arm64) to or from a frame
the caller owns. The kernel validates the frame, offset and alignment. On
write it sanitises the XSAVE header and masks MXCSR with the CPU's
MXCSR_MASK (read with `fxsave` at boot), so loading the image cannot fault
in the kernel. A caller that targets itself gets its FPU reloaded; a
target running on another core is stalled off it first, as for every TCB
invocation.

### 4.4 E3: kernel deadline timers

GCE guests are not guaranteed an HPET, and the PIT is too coarse to
multiplex. The MCS kernel already programs the per-core LAPIC TSC-deadline
timer (or LAPIC countdown, or the generic timer on arm64) for budget
enforcement, so E3 lets user level share it:

- `seL4_TCB_SetTimer(tcb, deadline, badge)` arms or re-arms a TCB's timer;
  a zero deadline disarms it. The deadline is in kernel timer ticks (TSC on
  x86, the generic timer counter on aarch64).
- At the deadline the kernel signals the badge on the TCB's bound
  notification, if any, and disarms the timer. It never signals early: the
  hardware is programmed for the deadline itself (not one timer precision
  earlier, as for budget events), and APIC countdowns round up.
- Armed TCBs sit in a per-core red-black tree ordered by deadline, with
  its first node cached. The hardware is programmed with the minimum of the
  next budget event and that node. Arming and disarming are O(log n); guests
  arm timers on TCBs retyped from their own memory, so n is theirs to
  choose, and a sorted list would let one guest hold the kernel lock for
  milliseconds.
- At most 32 timers fire per kernel entry; the rest fire on the next,
  immediate, timer interrupt. Kernel time spent firing is charged to
  whatever runs on the core, as for any interrupt, so a guest with many
  timers on one deadline can make a co-located vCPU absorb about N/32
  bounded entries.
- A timer fires on the core it was last armed on; migrated vCPUs re-arm.
- Timers fire from the scheduler, so the woken thread may have blocked in
  the same kernel entry and still hold the current scheduling context.
  `sendSignal()` already skips the refill check then; its two debug
  assertions that this cannot happen are removed.

The guest clockevent invokes `seL4_TCB_SetTimer` on its vCPU's kernel TCB:
there is no user-level timer server and no IPC hop.

No new interrupt-injection primitive is needed (§5.4), and no kernel IOMMU
support, since no device is passed into a guest.

### 4.5 Other patches

**Upstream bugs fixed:**

| Patch | Fix |
|-------|-----|
| 0004 | x86_64 `syscall` entry never saved the user RSP and `sysretq` cleared it (libsel4 keeps RSP in RBX, which hid this). RSP is now saved through a per-node scratch slot and restored on both the slow path and the fastpath. 0027 does the same with SKIM: RSP is saved before loading the kernel CR3 and carried through the per-CPU SKIM scratch word, cleared after each read, with no user-stack access and no extra SKIM mappings. |
| 0005 | `ipi_wait()` reset its arrival counter and released waiters with two unordered plain stores, which GCC emits in the wrong order; a following remote call could lose arrivals and every core spun forever. |
| 0010 | `handleIPI()` read a remote call's arguments before checking the call was pending for this core, so a late IPI could replay the previous call: skipped TLB invalidations or invalidation of a reused VSpace root. |
| 0012 | (x86, MCS) The LAPIC latches a timer interrupt that fires while a core waits for the kernel lock; it was then handled as a new event after the next deadline was armed, meaning another lock wait. Under host load every core looped on stale interrupts and user threads never ran. A timer interrupt that finds the timer still armed is now acknowledged and dropped before the lock (checking 0006's `ksArmedDeadline` first). The patch is x86-only. |
| 0013 | `SchedControl_ConfigureFlags` on an SC whose runnable thread is on another core could enqueue a postponed thread in the remote ready queue too. Only a schedulable thread is enqueued now. The balancer can hit this when it changes the budget of a capped vCPU that is running on another core and has used up its budget. |
| 0014 | (x86, MCS) Every core re-measured the TSC and APIC timer rates from one PIT wraparound and overwrote the shared values; a virtualised PIT can end that wait early (about one GCE boot in three). Rates are measured once, on the boot core, as the median of 5 wraparounds. Countdown conversion from TSC to APIC ticks uses both rates rather than their truncated ratio, and a delay too long for the 32-bit count fires early and is reprogrammed. |
| 0028 | (x86_64) seL4's user segments are laid out as Linux's, so `sysretq` and `iretq` both return with CS 0x33 / SS 0x2b. `sysretq` previously returned with a data-slot CS that faulted when user code reloaded it with `iretq` (.NET's `RtlRestoreContext`). |

**Performance:**

| Patch | Change |
|-------|--------|
| 0006 | `setNextInterrupt()` no longer reprograms the timer when a deadline still pending (`ksArmedDeadline`) is not later than the new one; the interrupt fires early at most once and reprograms. On x86 each reprogram is a write to IA32_TSC_DEADLINE, a VM exit when seL4 runs virtualised; trapped syscalls are 16× faster under nested KVM. |
| 0017 | (x86_64) Maps into a not-present entry invalidate nothing; remaps that only raise rights invalidate on the current core only; a remap with `seL4_X86_DeferFlush` that only lowers rights (same frame, same memory type) leaves TLBs alone, and `seL4_X64_PML4_Flush` flushes the ASID once afterwards. Stale entries can only grant rights the same frame cap had at the same address; unmapping still invalidates at once. After a raise another core can take a spurious fault, which a user thread survives but a guest kernel thread does not, so the guest never raises rights in place in its kernel VSpace. A 16 MiB fork with three busy threads takes 6 ms instead of 140. |
| 0019 | At boot, before any user code runs, the kernel scans the free RAM it hands out as Untypeds and clears only pages with a non-zero word, then issues them with a zero free index so their first use does not clear them again. Under a hypervisor, unbacked memory then stays unbacked until written. Device regions and recycled boot memory are excluded; runtime Untyped reset is unchanged and clears unconditionally. On Arm the secondaries switch to the kernel's tables before the scan, and the scan cleans and invalidates the cache range first. |
| 0030 | Untyped reset clears 64 KiB (`KernelResetChunkBits` 16, was 8) and then returns as preempted, restarting the retype, instead of clearing 256 bytes at a time and checking for a pending interrupt every 100 chunks. With MCS on x86 each check reads the TSC and the x2APIC's interrupt request registers, MSRs that can trap to the hypervisor when seL4 runs virtualised. A guest started on a destroyed guest's 4 GiB spent about 0.3 s on bare metal and 1.9 s in a KVM guest in these resets, before its clock started. Cherry-picked from upstream seL4 PR #1842 (open). |

**Features:**

| Patch | Feature |
|-------|---------|
| 0007 | (aarch64) UnknownSyscall faults of trapping threads report x8, Linux's syscall number, in the Syscall word. |
| 0009 | `seL4_X86_ExecuteNever`: sets XD on 4 KiB, 2 MiB and 1 GiB mappings; boot enables EFER.NXE. The guest maps non-`PROT_EXEC` pages with it, and heap, `.bss` and stack are executable only with `READ_IMPLIES_EXEC` or an executable `PT_GNU_STACK`. Without NX (or with `IA32_MISC_ENABLE.XD_DISABLE`) the attribute is dropped silently. |
| 0011 | (x86) The multiboot2 header requests a linear framebuffer, for the dashboard (§7.7). |
| 0015 | (aarch64) Inner-shareable broadcast TLB maintenance at EL1 on 16-bit ASIDs. The kernel refuses to boot unless `TCR_EL1.AS` is set (with 8-bit ASIDs, address spaces differing only in the upper bits would share TLB entries); secondaries check too. The loader gives every core VMID 0, since broadcasts reach only the issuer's VMID. |
| 0016 | (aarch64) The counter frequency is read at boot for MCS conversions (TCG's 62.5 MHz, Apple M4 HVF's 24 MHz). |
| 0018 | (aarch64) ID_AA64ISAR0/1/2 and PFR0/1 of the boot CPU are passed to root as a bootinfo chunk, for guest HWCAPs (§5). |
| 0020 | (x86) `fb_console`: kernel output is also drawn on the lower half of a 32-bpp direct-RGB multiboot2 framebuffer below 4 GiB, 8x8 glyphs doubled vertically, wrapping rather than scrolling so the framebuffer is never read. Refused if it overlaps usable RAM or starts below 1 MiB. For machines whose screen is reachable but not their serial port. |
| 0021 | (x86) Multiboot modules after the root task (up to 8) are copied to page-aligned memory above the root task's image and below 4 GiB, kept out of managed RAM so they reach root as device Untypeds (frames without clearing), and listed with their loader strings in a bootinfo chunk (`SEL4_BOOTINFO_HEADER_X86_BOOT_MODULES`). This is how dom0's files are loaded (§10.1). |
| 0022 | (x86) Intel CPUs that enumerate the TSC rate in CPUID 0x15 (or 0x16) take it from there, rounded to the nearest MHz; with TSC-deadline the PIT is then unused. Alder Lake and later may gate the 8254, so the PIT wait never ended. VMs (leaf 0x15 zero) still measure with the PIT. |
| 0023, 0029 | `Page_TestAndClearAccessed` (x86_64, and AArch64 without hypervisor support) atomically clears and returns the A/AF bit of a frame cap's mapping, for 4 KiB frames (0023) and 2 MiB frames (0029), after verifying the mapped ASID, address, size and physical frame. It does not invalidate TLBs, as with native x86 aging. On AArch64 without hardware AF updates (and without hypervisor support), seL4 repairs EL0 access-flag faults itself (setting AF and restarting) without fault IPC; `TCR_EL1.HA` stays off. 0029 also adds `Page_DeriveSubframe` (x86_64 and AArch64), which derives up to 512 consecutive unmapped 4 KiB capabilities from a RAM-backed 2 MiB frame into a validated window of CNode slots, with intersected rights, allocating nothing. Aliases are smaller regions in the derivation tree: deleting the large cap leaves them valid, and revoking the backing Untyped removes all of them and their mappings. |
| 0024 | (x86) No boot without SKIM unless the CPU reports RDCL_NO (above). |
| 0025 | (x86) `GetIOAPICRemapped` adds a 16-bit interrupt-remapping table index to the I/O APIC handler arguments and writes the remappable RTE format. Root publishes the matching VT-d IRTE first; seL4 keeps pin masking, acknowledgement and capability lifecycle and does not manage the IOMMU. |

**Verification.** The MCS SMP x86_64 configuration is not covered by the
seL4 proofs, with or without these patches. l4h benefits from seL4's design
and capability isolation but does not claim a verified configuration on
x86. aarch64 is the better long-term path to proof coverage.

---

## 5. The guest kernel: `ARCH=l4h`

`arch/l4h` is derived from `arch/um` and `arch/x86/um`, which provide the
separate-address-space kernel, x86 signal frames, ptrace, the syscall
table, software page tables and a batched "TLB sync" to the host. The UML
host layer (`os-Linux`) is replaced by `os-sel4`, built against libsel4.
The Kconfig keeps `CONFIG_UML` defined, so generic code treats l4h like
UML. The Linux base is 6.18 LTS.

**Kernel-mode SIMD.** Each vCPU's kernel TCB has its own seL4 FPU context,
separate from every user TCB's, so kernel SIMD never sees or clobbers user
state and `kernel_fpu_begin()` saves nothing. Its registers are shared only
by the guest-kernel contexts on that vCPU: tasks switched with
`setjmp`/`longjmp` (which keep no vector state) and the softirqs and
interrupt handlers the guest runs when it polls for events. So, as on x86,
`kernel_fpu_begin()` disables bottom halves and preemption, sets a per-CPU
busy flag that makes `irq_fpu_usable()` false, and loads the default MXCSR
(`arch/l4h/x86/fpu.c`). CPU features come from CPUID masked by the XCR0
seL4 sets, and `cpu_has_xfeatures()` checks that XCR0. Skylake-X, Ice Lake
and Tiger Lake get `X86_FEATURE_PREFER_YMM`. `arch/x86/crypto` (AES-NI,
VAES/AVX2 XTS for dm-crypt) is built for l4h. AArch64 does the same in
`kernel_neon_begin()` (`arch/l4h/arm64/neon.c`), which `may_use_simd()`
also asks; the rest of the kernel is built with `-mgeneral-regs-only`.
`arch/arm64/crypto` (ARMv8 Crypto Extensions AES, bit-sliced NEON without
them) is built with a small `asm/assembler.h`. EL0 cannot read the ID
registers, so root reads those of patch 0018 and vmmgr copies them into each guest's
`l4h_bootinfo.cpu_id`, the guest derives `AT_HWCAP` from them, and the AES
drivers bind through `module_cpu_feature_match()`.

### 5.1 Layout in the Linux tree

```
arch/l4h/
  kernel/   boot, setup, irq, time, smp, process (switch_to), signal glue, ptrace glue
  kernel/   also the software page tables, TLB sync and VSpace mirror (tlb.c, vspace.c)
  kernel/skas/   uaccess, mm context and process/syscall glue
  os-sel4/  freestanding boot, event and user-thread operations against libsel4
  drivers/  virtio_l4h transport, hvc console, l4hctl, attestation, memory hotplug, RTC, RNG, kmod
  include/  kernel, shared and UAPI headers
  x86/      x86_64 signal frames, TLS, syscall table, vDSO and register glue
  arm64/    native AArch64 ABI, atomics, context switching and module relocations
  configs/defconfig
guest/linux/patches/              changes outside arch/l4h
```

`tools/build-linux.sh` builds with `ARCH=l4h`, using `SUBARCH=x86_64` by
default or `SUBARCH=aarch64` when `L4H_ARCH=aarch64`. Each subarchitecture
uses its native UAPI headers, syscall table and signal-frame layout.
AArch64 exports the HWCAPs of the ID registers (AES, PMULL, SHA\*, CRC32,
LSE atomics and others; nothing that needs state seL4 does not keep, such
as SVE or pointer authentication), preserves TPIDR_EL0 and all 31 general
registers, and supplies a versioned vDSO with the signal-return
trampoline. Its first syscall argument is saved separately from the x0
return value, including across restarted syscalls. Executable mappings get
instruction-cache maintenance through seL4.

Patches outside `arch/l4h` (`guest/linux/patches`) cover kbuild's UML-style
UAPI headers, restricted DMA pools without a device tree (§8.1), the
HRTICK default, the x86 SIMD crypto menu, event polling in `cond_resched`
(§5.4), the BPF JITs (§5.7), Rust targets for kemu, attestation taint
hooks (§10.2) and the Android features of §5.8.

### 5.2 Address spaces

- **Guest-kernel VSpace**, one per guest, shared by all its vCPU kernel
  TCBs:
  - the kernel image, whose text and rodata are shared read-only between
    guests (§5.6);
  - a **direct map of frame-backed guest RAM**: guest-physical address
    (GPA) *g* maps to `PAGE_OFFSET + g` (§5.3, §8.2);
  - vmalloc/module area and the vmemmap;
  - on x86_64, BPF JIT images in the 1 GiB below the kernel image (§5.7);
  - per-vCPU event pages and virtio-l4h device pages;
  - the I/O pool (§8.1) and the shared module image (§5.6).
- **Guest-process VSpaces** cache Linux `mm_struct` mappings in a fixed
  pool of 64 host-provided VSpace roots (§5.3). The guest makes their page
  tables and mapping slots from its own RAM. They hold only user mappings,
  plus vDSO and vvar. Userspace extends to `0x7ffffffff000` (exclusive) on
  both ISAs, leaving the final page below 2^47 reserved as seL4 requires
  on x86_64.
- The two kinds are disjoint, and that is what isolates the guest kernel
  from guest user code: every seL4 mapping is user-accessible, so kernel
  memory must not be mapped into a process VSpace at all. Kernel and user
  VSpaces can use the same numeric addresses independently. The x86_64
  guest kernel is linked at `0x60000000`; host-provided special pages start
  at `L4H_SPECIAL_BASE`.
- **uaccess** (`copy_{to,from}_user`, `get_user` and the rest) walks the
  guest's Linux page tables in software and goes through the direct map,
  as UML and L4Linux do. A missing page calls `handle_mm_fault` inline,
  without `FAULT_FLAG_USER` (so a `UFFD_USER_MODE_ONLY` userfaultfd cannot
  hold up kernel copies), though it waits for `mmap_lock` as user faults
  do. Each page is looked up under `mmap_lock` (VMA present) and the PTE
  (or PMD) lock, checked like a hardware access (present, readable and not
  `PROT_NONE`, or writable) and pinned with a page reference for the copy,
  so an unmap on another vCPU cannot free it meanwhile. In atomic context
  (futex operations, `*_nofault`) `mmap_lock` is only tried and nothing
  faults: callers fault the page in and retry.
- Kernel `*_nofault` accesses check that the address is mapped in the
  guest-kernel VSpace, since a fault there stops the guest. The direct map
  has holes where RAM blocks became seL4 objects (§8.3), so its range is
  checked block by block (`l4h_kernel_range_ok()`, used by `/dev/mem` and
  BPF `probe_read_kernel`). A block being converted is marked busy first,
  and its frames are revoked only once no access that found it mapped is
  still between its check and its access.

### 5.3 Memory management: Linux page tables mirrored into seL4

- The guest kernel keeps ordinary Linux 4-level software page tables. The
  PTE format belongs to `arch/l4h`.
- The seL4 VSpace of each mm is a **cache** of those page tables, filled
  lazily:
  1. A user access to an unmapped address raises an seL4 VMFault, which
     reaches the vCPU's kernel TCB.
  2. The kernel runs `handle_mm_fault`.
  3. It copies the frame cap into a free slot of the guest's slot CNodes
     (`l4h_cap_copy`) and maps it with the rights from the PTE, under the
     PTE lock.
  4. It replies to the fault.
- **Accessed and dirty bits.** Dirty is software: clean writable pages are
  mapped read-only until the first write, whose fault sets `pte_dirty`
  (losing a dirty bit could lose data). Young combines software and
  hardware state: `ptep_test_and_clear_young()` returns and clears the
  software young bit OR the hardware accessed bit, using patch 0023 on the
  frame cap recorded for the mapping, protected against unmapping and pool
  eviction by the mm's VSpace lock. `ptep_clear_flush_young()` is the same
  operation, with no remap or TLB flush. Each reclaim sample costs one
  seL4 invocation per mapped page; reads need no Linux fault, and AArch64
  without hardware AF updates pays one seL4 entry after a new walk.
  - A remap or VSpace eviction can lose one accessed sample; on aarch64,
    where seL4 maps every page with AF set, a rights-only remap (fork's
    write-protect, `mprotect`, `page_mkclean`) adds one.
  - Callers that inspect only `pte_young()` see the software bit: smaps'
    `Referenced`, `MADV_COLD` and the unmapping of file pages. Reclaim and
    `clear_refs` use test-and-clear.
  - MGLRU, DAMON, idle-page tracking and NUMA balancing are disabled; they
    would need hardware-bit support.
- **Cap-slot tracking.** Every seL4 mapping needs its own frame-cap copy.
  Each address space records every mapping's slot in an xarray (virtual
  page → slot | rights | pfn; a second xarray, `as->large`, for 2 MiB
  leaves), so an unmap deletes the slot without a search and a remap with
  unchanged rights is skipped.
- **Emptying a VSpace.** When the last user leaves an mm (exit, or exec
  replacing it), `arch_exit_mmap()` → `l4h_mm_release()` empties its pool
  VSpace rather than unmapping page by page; `munmap` and `mprotect` sync
  per page, and fork's write-protect remaps are batched with `DeferFlush`
  (below). A VSpace that leaves its mm (exit, or eviction from the pool) is
  emptied after the entry is detached, outside
  the pool lock, so other vCPUs keep running. Its page tables go first,
  highest level first: unmapping one invalidates the ASID once and removes
  everything below it, so the frame capabilities are then deleted without a
  TLB shootdown each.
- **TLB sync.** `flush_tlb_*` and every return to user sync the mm's
  pending range into seL4: unmaps and remaps for changed PTEs, with
  rights-only downgrades batched through `seL4_X86_DeferFlush` and one
  ASID flush (patch 0017).
  - A sync takes the whole pending range at once, and syncs of an mm are
    serialised by a per-mm lock held until the range is applied. A flush
    that finds its range already taken by a sync on another vCPU therefore
    waits for it, rather than returning while the old mappings are still
    live, and two syncs cannot race on one PTE.
  - A full flush (`flush_tlb_mm`) marks all of user space, not the mm's
    VMAs: overlapping mmu_gathers (`munmap` racing `MADV_DONTNEED`) end
    with a full flush after `munmap` has removed its VMAs.
  - The walk reads each entry once, since `munmap` may clear entries
    concurrently.
  - A sync that cannot map a page (no memory for a page table) leaves it
    unmapped and goes on, so every unmap in the range still happens.
- **TLB coherence** across cores is seL4's job: unmap shoots down the
  ASID's TLB entries, so a page is never freed while another vCPU can still
  reach it.
- **VSpace pool.** x86_64 seL4 has only 4096 ASIDs (8 pools of 512), so
  each guest gets a fixed pool of 64 pre-assigned VSpace roots, recycled
  least recently used first. An mm that loses its VSpace simply refaults.
  `arch_exit_mmap()` releases its VSpace and page-table objects when the
  last user exits, not at `destroy_context()`: lazy `active_mm` references
  and OOM bookkeeping can outlive `waitpid()`. A vCPU that finds every
  entry either running or being emptied gives its CPU away and retries,
  since the tasks emptying them may be queued on it.
- **CSpace naming.** A CNode capability held directly in a root slot cannot
  be named by a 64-bit CPtr, because seL4 keeps resolving through it.
  Capabilities that must be named, such as the root CNode itself and user
  threads' CSpaces, live in a "meta" CNode in root slot 1 (see `abi.h`).
- **Transparent huge pages.** Linux allocates 2 MiB anonymous THPs and
  collapses base pages through `khugepaged` or `MADV_COLLAPSE`. The default
  is `transparent_hugepage=madvise` (Linux disables THP at boot below
  512 MiB of RAM; sysfs can enable it). Smaller PTE-mapped THP sizes are
  disabled by default.
  - Guest-owned and hotplug RAM blocks have one canonical 2 MiB seL4 frame
    plus 512 derived 4 KiB aliases (patch 0029). Base-page mappings use
    the aliases; a huge Linux PMD uses a copy of the large cap, giving one
    native 2 MiB leaf. The direct map maps a guest-owned block with the
    canonical large cap itself, one leaf and one system call instead of
    512 (a mapped cap still copies unmapped), and falls back to the
    aliases where a 4 KiB page table already covers the block. Hotplug
    blocks map the aliases under page tables of their own, which unplug
    deletes. Boot-image blocks the host fills keep their small caps and use
    the 512-mapping fallback.
  - User VSpaces track small and large leaves separately, with table
    coverage indexed by level and address, so neither adding a table nor
    promotion scans the address space. A partial update drops the whole
    overlapping large leaf before installing any small replacement (no
    allocation needed); unaffected pages refault. Promotion removes the old
    leaf table, invalidating once, before deleting its small caps and
    mapping the large frame. Accounting, eviction, teardown and failed
    mappings include both sizes. ARM executable mappings synchronize the
    instruction cache over the full frame.
  - The TLB sync applies a huge leaf's entire 2 MiB range, even for a
    partial flush, before clearing `NEEDSYNC` with a compare-and-exchange.
    A split's temporarily invalid PMD keeps its huge marker with all its
    seL4 mappings removed. Under a PMD that points to a PTE table, the sync
    also drops any 2 MiB leaf left there (a zapped huge PMD can lose
    `NEEDSYNC` if another thread installs a table before the zap's flush).
  - Faults, kernel user copies and futexes take the PMD lock and resolve
    the correct tail page. Aging combines the PMD's software young bit with
    its large leaf's A/AF bit, or all 512 small leaves in the fallback.
    Ordinary folio splitting and migration handle reclaim and object-block
    conversion; native PMD migration and whole-THP swap are not enabled.
  - `tests/run-thptest.sh` covers allocation, COW, user copies, futexes,
    VSpace eviction, promotion among thousands of page tables, splitting
    with pinned pages, partial protection/unmap/discard, collapse, moving
    mappings, concurrent writes, aging, swap, execute permissions, shared
    memory and allocation fallback. `tests/run-thpbench.sh` compares advised
    THP with `MADV_NOHUGEPAGE` (§13); its test module counts native large
    leaves independently of `AnonHugePages`.

### 5.4 Execution model: vCPUs, tasks, syscalls and interrupts

Each guest **vCPU** has:

- a **kernel-context TCB** (kTCB) at priority `P_K`, running in the
  guest-kernel VSpace, with its own scheduling context `SC_K`;
- a fault/IPC **endpoint** `EP_v` and a bound **notification** `N_v`;
- a user scheduling context `SC_U`, bound to whichever guest task runs on
  that vCPU.

Each **Linux thread with a user context** has a **user-context TCB** (uTCB)
at priority `P_U < P_K`:

- its VSpace is the mm's VSpace and its CSpace is empty;
- `trapSyscalls` (E1) is set;
- its fault handler is a badged copy of `EP_v` for the vCPU it runs on,
  the badge identifying the user context (`L4H_EP_BADGE_TASK` plus a
  per-context ID);
- it has its own MCS reply object, into which the kTCB receives its
  faults.

uTCBs are created lazily from the guest's own object memory (§8.3). One TCB
per thread means seL4 holds each thread's register and FPU context, so a
context switch never copies FPU state.

```
 user thread T runs on core c ───syscall──► seL4 ──UnknownSyscall fault IPC──► kTCB(v)
   (uTCB_T, SC_U, prio P_U)                                                     │
                                                                  Linux syscall │
   ◄──────────── reply (new regs) ◄── seL4_ReplyRecv(EP_v) ◄────────────────────┘
```

**Return to user, switching from task A to task B:**

```
seL4_SchedContext_UnbindObject(SC_U, uTCB_A)
seL4_TCB_SetSchedParams(uTCB_B, …, SC=SC_U, fault_ep=EP_v[badge B])
seL4_ReplyRecv(B's reply object, …)   (or seL4_Recv if B was preempted)
```

The second call also migrates B to v's core, because in MCS the core
follows the scheduling context. A preempted B is runnable, so binding
`SC_U` is what resumes it. Under a CPU cap, SC_K can be out of budget
while SC_U is not, and the context bound to SC_U then runs even though
`P_K > P_U`, so the guest writes a preempted context's registers before it
binds SC_U to it, never after.

**Interrupts and preemption:**

- **While a user task runs**, kTCB is blocked in `Recv` on `EP_v`. A signal
  on `N_v` wakes it, and because `P_K > P_U` it preempts the uTCB at once.
  The preempted uTCB is not in a fault state; the kernel leaves it, so it
  resumes when kTCB blocks again, or unbinds `SC_U` to deschedule it, saving
  nothing because the registers stay in the TCB.
- **While kTCB runs guest-kernel code**, notifications cannot interrupt it.
  Interrupt sources therefore **set a bit in the vCPU's event page** (as
  with Xen's `evtchn_pending`) and then signal `N_v`. The guest checks the
  event word, a cheap memory load, when it re-enables interrupts, in
  `cond_resched` (patch 0005, so also in every `might_sleep` under
  `CONFIG_PREEMPT_VOLUNTARY`), in `cpu_relax()` when interrupts are on,
  and before blocking.
  - The `cond_resched` poll is needed because a loop that waits for another
    task with `cond_resched` and plain spinlocks otherwise never sees the
    timer (`shrink_dcache_parent` spinning in `d_walk` froze 1-vCPU guests).
  - The `cpu_relax()` poll is needed because two vCPUs waiting in
    `csd_lock_wait()` for each other's `smp_call_function()`, or spinning
    on a lock the other holds while it waits so, would never take the IPI.
  - The E3 timer only signals `N_v`, so the check also compares `rdtsc`
    against the vCPU's armed deadline.
  - Events delivered on the way back to user mode can set work flags after
    they were checked, so the flags are checked again just before the user
    context runs; events taken off `N_v` while waiting for `SC_U` budget
    signal it again, so the user run returns for them at once.
  - The guest uses `CONFIG_PREEMPT_VOLUNTARY`. `CONFIG_PREEMPT` compiles
    `cond_resched` out, so `arch/l4h` refuses to build with it.
- **Interrupted context.** Events delivered at a polling point interrupted
  the kernel, and their handlers see kernel-mode registers. Only events that
  stopped a uTCB see the task's user registers (otherwise every tick would
  look like a user tick, and RCU would take quiescent states inside
  read-side critical sections).
- **No upcall backstop.** There is no mechanism to interrupt a kTCB that
  runs too long without polling; interrupt delivery relies on the guest's
  polling points.
- **Idle.** kTCB calls `seL4_Wait(N_v)`, consuming no CPU, which is what
  makes 30 mostly-idle guests on 4 cores practical.

**Exceptions.** A UserException fault carries the vector and error code,
mapped to signals: #GP to SIGSEGV, #UD to SIGILL, #DE to SIGFPE, `int3` to
SIGTRAP. `int 0x80` is rejected (no 32-bit compat). The legacy vsyscall
page is not supported (`vsyscall=none`).

**TLS and FS/GS.** `arch_prctl(ARCH_SET_FS)` updates the saved `fs_base`,
marked dirty, which reaches the uTCB through WriteRegisters. With `KernelFSGSBase=inst`, userspace
`wrfsbase` works natively, and HWCAP2_FSGSBASE is advertised.

**Time.**

- The clocksource is the TSC, read with `rdtsc` (on aarch64, the counter).
  Root passes the frequency from seL4 bootinfo. Rates go to Linux in kHz
  and the clockevent counts in units of 8 TSC ticks, since Linux takes
  32-bit Hz values that TSCs of 4.3 GHz and more overflow. `udelay` and
  `ndelay` wait on the counter.
- On x86_64 the vDSO is Linux's generic one: `update_vsyscall()` keeps a
  time page current, mapped read-only four pages below the vDSO text, so
  `clock_gettime`, `gettimeofday`, `time` and `clock_getres` do not trap
  (~40 ns instead of a ~1.4 µs syscall on nested KVM). The vDSO and its
  data live in the top 64 KiB of user space (`L4H_VDSO_AREA`), and
  `STACK_TOP` is a guard page below that, so a randomized stack can never
  collide with them. Time namespaces are off (they would need the page
  remapped per namespace). The aarch64 vDSO has no time functions yet.
- The clockevent is a per-vCPU one-shot deadline,
  `seL4_TCB_SetTimer(kTCB, deadline, L4H_BADGE_TIMER)`. A migrated vCPU
  may read a TSC slightly behind the core that fired its timer, so the
  guest takes the timer badge itself as the expiry, not only `rdtsc` past
  the deadline.
- The wall clock at boot comes from `L4H_HC_GET_TIME`: root reads the CMOS
  RTC (PL031 on aarch64) once at boot, and each VMM adds the TSC time
  since; without an RTC it is the epoch. Guests may correct it with NTP.
  dom0 can save its time to the machine RTC with `l4hctl rtc-set`
  (`CTL_RTC_SET`, UTC epoch seconds); on x86 root inhibits calendar updates
  while writing, preserves the data and hour modes, and writes a century
  register only if the FADT advertises one. The write affects the next host
  boot, not the running host's anchor or guests' clocks.

**Signals.** The kernel builds the native `rt_sigframe` in user memory
through the direct map, fetches FPU and XSAVE state with E2, and rewrites
the uTCB's registers with `WriteRegisters`; `rt_sigreturn` reverses this.
As on x86, the handler starts with DF, TF and RF clear and the initial FPU
state; a handler without `SA_RESTORER`, or a frame that cannot be written
or does not fit on the alternate stack, gets SIGSEGV. The XSAVE area is
64-byte aligned above the frame, `uc_flags` and the software bytes say
what it holds, and `rt_sigreturn` re-arms an `SS_AUTODISARM` alternate
stack. Signals are delivered on registers read back from the uTCB when the
work flags are handled, since another vCPU may raise one at any time. On
aarch64 a syscall's restart is prepared before the signal is dequeued, so
a tracer at the signal stop sees the rewound PC. A user fault interrupted
by any signal (not only a fatal one) returns, delivers the signal and
faults again, as `fault_signal_pending()` does elsewhere: ART suspends
threads with signals while userfaultfd waits.

**ptrace and coredump** use ReadRegisters/WriteRegisters and E2.

- seL4 clears TF in user flags and l4h has no hardware debug API, so
  `PTRACE_SINGLESTEP` and debug-register breakpoints fail with EIO;
  debuggers use `int3`.
- CS and SS read as Linux's 64-bit user selectors (0x33, 0x2b), which are
  the selectors user code really runs with (patch 0028).
- `NT_X86_XSTATE` carries XCR0 in its software bytes.
- Seccomp filters and `SIGSYS` see the user instruction pointer
  (`KSTK_EIP`), and `SECCOMP_RET_TRAP` leaves the syscall number in RAX, as
  x86's `syscall_rollback()` does; Chromium's sandbox checks both. The
  syscall-restart checks use the low 32 bits of RAX.
- `PTRACE_ARCH_PRCTL` and the fs/gs base in `PEEKUSER`/`POKEUSER` and
  `GETREGS`/`SETREGS` act on the tracee: its base is read back from its TCB
  (user code may have used `wrfsbase`), and a new value is kept in its
  saved registers, marked dirty, until it resumes.

### 5.5 Calls from the guest to the host

The guest kernel makes plain seL4 invocations on capabilities it holds:
Map and Unmap; TCB and SchedContext Bind/Unbind; Signal (IPIs and its
devices' kick notifications, the attestation device included); and Call
to its VMM endpoint for device configuration, power-off and reboot.

The CSpace that the host gives a guest contains its own frames and RAM
block Untypeds, its vCPU SCs (which it can bind but not configure, holding
no SchedControl), its own endpoints and notifications, and an MCP no
higher than `P_K`. Direct invocations are therefore safe by capability
checks alone. Host hypercalls and device requests validate their
arguments, including pool addresses, device indices and lifecycle state.

### 5.6 One guest kernel, and its module tree

- **l4h ships the guest kernel.** seL4's ABI is not stable: syscall
  numbers, invocation labels, object types, message layouts and the user
  context are compiled into `os-sel4` from l4h's seL4 build, and the guest
  relies on the kernel extensions. A guest kernel only works with the host
  it was built with, so guests do not bring their own. The UEFI application
  holds one `vmlinux` (boot module `guest-kernel`), which dom0 and every VM
  run. `vm_start` takes an initramfs and a command line; vmmgr parses the
  kernel ELF once, at boot (`kimage.rs`), and loads it itself.
- **Its module tree.** `tools/build-kmods.sh` builds an EROFS image (LZMA,
  about 9 MiB) of the kernel's `/lib/modules`: modules, depmod's files, and
  `<release>/build`, the tree to build external modules against (kbuild's
  `install-extmod-build` plus the headers it misses for `ARCH=l4h`: those
  outside `arch/l4h/include`, the ISA's own, `abi.h` and libsel4's). Its
  `Makefile` sets `ARCH=l4h`, so `make -C /lib/modules/$(uname -r)/build
  M=$PWD` works in a guest. The image is boot module `guest-kmods`, and is
  optional.
- **Shared read-only.** The boot module's own pages are mapped read-only
  into every guest at `L4H_KMOD_VA` (bootinfo `kmod_va`, `kmod_size`): one
  copy for all guests, nothing allocated or copied at boot. Each guest's
  copies of the frame caps cost about 150 KiB with page tables for a 9 MiB
  image. Root knows the frame of each module page (`bootmod.rs`). Guests
  map the image's last page whole, so root clears what follows the image
  in it before any guest exists, and refuses an image that shares that page
  with another module. `drivers/kmod.c` exposes the image as the read-only
  block device `/dev/l4hkmod`; `mount -t erofs -o ro /dev/l4hkmod
  /lib/modules` gives modprobe and module builds what they need.
- **Kernel text and rodata are shared too.** Every guest maps the pages of
  the kernel's read-only segments from the boot module's frames, read-only,
  so a guest cannot change its own kernel's code. The linker script keeps
  whatever the kernel writes out of those segments (`__ro_after_init` data
  and the exception table, which is sorted at boot, go with the data) and
  pads text to a page and rodata to a 2 MiB block, so on x86_64 the
  11.7 MiB of text and 2.3 MiB of rodata are seven blocks, 14 MiB saved per
  guest. A block wholly of such pages holds only those copies, and memd has
  no RAM block for it; blocks only partly read-only would get private
  copies (none with this layout). Shared blocks are guest-physical space on
  top of the RAM a guest is given: a 256 MiB guest has 270 MiB of RAM in
  its boot info. Writes to shared pages fault and stop the guest, so a
  kernel change that writes text or rodata shows at boot.
- **Side channel.** Guests share the physical pages of kernel code and
  modules, so one guest can time its access to them to learn which kernel
  code another runs (Flush+Reload). These pages are never written once
  guests exist, so data stays out of reach.
- **Modules may use the l4h ABI.** A module comes from the kernel's own
  build, so it can call seL4 directly. The kernel exports its capability
  allocator (`l4h_slot_alloc`, `l4h_obj_alloc`, …), process VSpaces
  (`l4h_vspace_get`), kernel mappings of foreign frames
  (`l4h_kernel_map_frame`) and os-sel4's vCPU state. `tests/guest/abitest`
  tests the ABI and the kernel extensions below Linux this way.
- **Measured.** The kernel and the module image are part of the UEFI
  application, which PCR 4 covers. Launch digests (§10.2) also cover the
  kernel image in guest RAM.

### 5.7 BPF JIT

The guest kernel uses the upstream x86-64 and arm64 BPF JITs, on by
default. Patches 0006 and 0007 adapt them, and `arch/l4h/{x86,arm64}/bpf_jit.c`
provide what they need from the architecture:

- **Reach (x86_64).** The JIT calls kernel helpers with a rel32 `call` and
  leaves a program to the interpreter when a target is beyond ±2 GiB.
  vmalloc follows all of RAM and the I/O pool, so BPF images
  (`EXECMEM_BPF`) go in the 1 GiB below the kernel image, which nothing
  else uses. Modules keep vmalloc (they use the large code model). A
  callback's address is always emitted as `movabs`: the verifier gives the
  JIT `MODULES_VADDR` before the last pass, and a shrinking `mov` failed
  programs with callbacks. The arm64 JIT loads call targets into a
  register and keeps vmalloc; it builds addresses with `movz` instead of
  `movn`, since the guest kernel is in the lower half.
- **Code patching.** Guest-kernel memory other than the image's text and
  rodata is mapped writable and executable, so images are written in place.
  On x86, code other vCPUs may be running (direct tail calls, trampolines)
  is patched without int3, since a breakpoint in the guest kernel goes to
  the host: `stop_machine()` holds every vCPU with interrupts off, one
  writes, and each runs `cpuid` (serializing) before it returns. On arm64
  the JIT patches only branches and NOPs, which one word-sized store and
  instruction-cache maintenance through seL4 make safe. Its atomics use LSE
  when the CPU has it (`HWCAP_ATOMICS`), LL/SC otherwise.
- **No exception tables.** A guest-kernel fault stops the guest, so the
  JIT may not emit loads that rely on a fixup. Programs with
  `BPF_PROBE_MEM` loads are left to the interpreter, which checks the
  address with `l4h_kernel_range_ok()` first. Arena accesses are not
  offered.
- **What the guest kernel lacks.** There is no `%gs` or `TPIDR_EL1` per-CPU
  base and the guest kernel cannot read `SP_EL0`, so there are no per-CPU
  instructions or private stacks, and on arm64 `bpf_get_smp_processor_id()`
  and `bpf_get_current_task()` are not inlined. BPF exceptions (need an
  unwinder) and timed `may_goto` (needs x86 per-CPU assembly) are not
  offered. Mitigation flags (retpolines, return thunks, IBT, BHB clearing)
  are never set: `cpu_feature_enabled()` folds every feature l4h does not
  set to 0. arm64 skips its Spectre-BHB sequence for classic BPF, which
  relies on firmware calls.

`tests/run-bpftest.sh` runs `lib/test_bpf.c` through the JIT, and the
verifier, direct tail calls, XDP (generic) and tcx attachment through
`tests/guest/bpftest.c`, in a 2 GiB guest on x86_64.

### 5.8 Android guests

Android's userspace needs kernel features other guests do not use. The
shipped kernel has them, so an Android guest runs the same kernel as every
other guest (§5.6). What would change other guests stays off until a
guest's command line asks for it:

| Feature | Android's user | In other guests |
|---------|----------------|-----------------|
| Binder and binderfs | all IPC (servicemanager, HALs, apps) | no device until a binderfs is mounted, which has Android's `binder`, `hwbinder` and `vndbinder` |
| ashmem (patch 0010) | libcutils' shared memory: `system_server` stops without it | `/dev/ashmem`, unused |
| dm `default-key` (patch 0009) | vold's metadata encryption of `/data` | unused |
| BPF on tracepoints (patch 0011), software perf events, event tracing | bpfloader's programs, whose maps `system_server` reads | tracefs and perf, no events enabled |
| `/dev/hw_random` | `prng_seeder` | present (x86_64) |
| AF_VSOCK, loopback only | Cuttlefish HALs that listen for their host | no transport to a host |
| cgroup v1 `cpuset` | `cgroups.json` | mounted by no one else |
| SELinux, with audit | `init`, which stops without it | off without `lsm=selinux`; audit disabled until an audit daemon (logd) enables it |
| PSI | lmkd's memory pressure triggers | off without `psi=1` |
| bootconfig | `androidboot.*` settings appended to the ramdisk | ignored without `bootconfig` |
| userfaultfd, `MREMAP_DONTUNMAP`, `UFFDIO_MOVE` | ART's concurrent compacting GC | unused |
| `/dev/rtc0` with alarms | the `CLOCK_*_ALARM` clocks | present |
| dma-buf heaps, `sync_file` | gralloc buffers and fences | unused |
| DRM with virtio-gpu (dumb buffers on render nodes, patch 0012; ARGB8888 on its plane, patch 0013) or vkms, modules | the display SurfaceFlinger composes for | no display until a driver is loaded |
| evdev, uinput | input | no input devices |
| zram with LZ4 | swap | unconfigured |
| legacy iptables with netd's matches and targets, policy routing, `SOCK_DESTROY`, XFRM | netd | empty tables |
| fs-verity, fscrypt, quotas, dm-verity FEC | APKs, file-based encryption, storage accounting, verified partitions | per filesystem |

The base is mainline 6.18 LTS, not Android's `android17-6.18` branch, which
lags the stable releases; the user ABI is upstream's either way. Android's
own additions are therefore missing except the two Android 17 cannot boot
without, ashmem and dm-default-key: there is no `xt_quota2`,
incremental-fs, fuse-bpf (mainline has FUSE passthrough), dm-user, or
ashmem ioctls on memfds.

- **RTC.** `drivers/rtc_l4h.c` is `/dev/rtc0`: the host's wall clock
  (`L4H_HC_GET_TIME`) plus a guest-local offset that setting it changes,
  lasting until the guest stops. Alarms are hrtimers. The device may wake
  the system, which alarm timers require. The system clock still comes from
  the host at boot, so `RTC_HCTOSYS` and `RTC_SYSTOHC` are off.
- **bootconfig.** `start_kernel()` looks for a bootconfig at the end of the
  initramfs right after `setup_arch()`, which records the initramfs.
- **Display.** A guest has no device memory, only pages it shares with the
  host, so `ioremap()` returns NULL (as on UML) but `NO_IOMEM` is off: DRM
  builds, and a driver that maps device memory fails its probe. vkms
  composes planes in software, raises vblanks from an hrtimer and has only
  a writeback connector; screen capture over adb shows it. The display the
  host can show is l4h-vmm's virtio-gpu (§9.6), with the `virtio_gpu`
  module. DRM, vkms and virtio-gpu are modules.
- **ashmem.** Android 17's libcutils allocates from `/dev/ashmem` unless
  `sys.use_memfd` is set and the kernel takes ashmem ioctls on memfds,
  which mainline does not. Patch 0010 is the C driver of the Android
  kernels' `android15-6.6` branch, updated for 6.18
  (`mm_get_unmapped_area()`, an allocated shrinker).
- **Metadata encryption.** A `keydirectory` in `/data`'s fstab makes vold
  map it through `default-key`, whose table is dm-crypt's. Patch 0009
  registers dm-crypt again under that name, at version 2. Android's target
  passes through bios of file contents fscrypt already encrypted; this one
  encrypts them a second time.
- **mmap layout.** mmap goes top-down below the stack, at a random offset
  of 28 to 32 bits of pages, as on x86_64 and arm64
  (`ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT`, `vm.mmap_rnd_bits`, which
  Android's `init` requires).
- **BPF on tracepoints.** `BPF_EVENTS` normally needs kprobe or uprobe
  events; l4h has software perf events (no PMU: `asm/perf_event.h` hides
  the host architecture's) and event tracing but no kprobes or uprobes, and
  patch 0011 lets event tracing suffice.
- **Not supported.** Suspend (`PM_SLEEP`, so no wakeup sources), a vsock
  transport to a host, and 32-bit compat, so Android runs as a 64-bit-only
  build. Each guest has 64 process VSpaces (§5.3), which Android's hundred
  and more processes cycle through.

#### Booting Android

Android runs in a VM that dom0 creates, never as dom0.
`tests/run-android.sh` boots Android 17 from the images of Cuttlefish's
64-bit-only x86_64 build (`aosp_cf_x86_64_only_phone`, ci.android.com),
which `tools/mkandroid.sh` turns into an initramfs and a disk. dom0
(`tests/guest/init-android`) creates the VM with the disk, a 720x1200
virtio-gpu display and a 256 MiB I/O pool, waits on its console for
`sys.boot_completed=1`, and takes a screenshot (`l4hctl screenshot`), which
must not be blank. Cuttlefish is used rather than the emulator's images,
which render only through the emulator's host (goldfish pipes,
gfxstream); Cuttlefish has a software renderer in the guest. Nothing of
Cuttlefish changes beyond what a bootloader and its launcher would give it:

- **The initramfs** is the vendor ramdisk and the generic one, then an
  archive of l4h's and a bootconfig. Both ramdisks are legacy LZ4, which
  ends only with the data or a zero frame length, so four zero bytes end it
  before l4h's archive. That archive replaces the first-stage fstab (the
  same partitions, without AVB: the device is unlocked) and the modules
  first-stage init loads with l4h's `virtio_gpu` and its dependencies.
- **The disk** is one GPT, whose partitions first-stage init finds by name
  on the platform device all virtio-l4h disks hang off
  (`androidboot.boot_devices=virtio-l4h`): misc, frp, metadata, odm, super
  and userdata. vold encrypts `/data` in place on the first boot.
- **odm** is Cuttlefish's ODM partition, relabelled with the platform's
  `/odm` policy labels, with an l4h init script: a logcat of errors and boot
  progress on the console (Cuttlefish's own goes to `/dev/hvc2`, which l4h
  lacks), and an empty sensors list mounted over the vendor's.
- **Boot properties** are those of Cuttlefish's `guest_swiftshader` mode:
  ANGLE on SwiftShader, minigbm buffers, the ranchu composer on the
  virtio-gpu with BGRA framebuffers, KeyMint and Gatekeeper in the guest, a
  vsock port above 1024 for the lights HAL. HALs that talk to Cuttlefish's
  host (OemLock, UWB, NFC, Bluetooth, radio, Thread) are left out by naming
  each APEX in `androidboot.vendor.apex.<name>` with no such file; sensors
  are none for the same reason.
- **The display.** minigbm allocates dumb buffers through the render node
  (the composer is DRM master on the primary node), which patch 0012
  allows, as the Android kernels do. The composer commits ARGB8888
  framebuffers, which patch 0013 lets the virtio-gpu plane accept. The
  Android kernels offer all eight 32-bit formats, but without blob
  scanouts l4h-vmm shows a resource in the format it was created with, and
  dumb buffers are always B8G8R8X8, so the others would show with their
  bytes in the wrong order. Every buffer is mapped through the VM's I/O
  pool, hence its size.

Android completes its boot about 150 s after the VM starts, on four vCPUs
and 3 GiB, and shows its lock screen (`build/android/screen.png`).

`tests/run-androidtest.sh` boots `tests/guest/androidtest.c` with
Android's command line and a bootconfig: Binder transactions of up to four
pages with a file descriptor passed back, userfaultfd faults from user code
and kernel copies, signals during such a fault, `MREMAP_DONTUNMAP` filled
back through userfaultfd, `UFFDIO_MOVE`, RTC alarms and setting, the alarm
clocks, code written through one memfd mapping and run through another, a
dma-buf heap, vkms (a mode, page flips, vblanks, and written-back frames
matching the buffer shown), a PSI trigger, zram swap, SELinux, bootconfig
and uinput. A second boot without those parameters checks that SELinux,
PSI, bootconfig and a display stay off.

### 5.9 AArch64 userspace on x86_64 with kemu

The x86_64 guest kernel includes [kemu](https://github.com/losfair/kemu)
to run AArch64 Linux userspace directly. `tools/build-linux.sh` imports its
patches and source overlay, then applies l4h's kernel patches. `CONFIG_KEMU=y`
and `CONFIG_RUST=y` are enabled by default on x86_64. AArch64 guest kernels
run AArch64 programs natively. `tests/run-kemutest.sh` checks the emulated
ABI, tagged addresses, vector state across threads and signals, and FP
exception flags in signal contexts (requires `gcc-aarch64-linux-gnu` and
cross libc headers); `KEMU_CMDLINE=kemu.jit=0` checks the interpreter.

---

## 6. SMP guests

- vCPU *v* consists of `kTCB_v`, `SC_K,v`, `SC_U,v`, `EP_v` and `N_v`. The
  boot vCPU starts at the ELF entry, and secondaries start at
  `l4h_secondary_entry`: the guest starts each by writing its kTCB's
  registers and resuming it (`l4h_start_vcpu()`).
  CPU hotplug is not supported (`HOTPLUG_CPU` is off).
- **IPIs.** The sender sets a reason bit in the target's IPI word and
  signals `N_target` with the IPI badge. seL4 delivers the signal across
  cores with a hardware IPI when needed.
- **TLB shootdown for guest mms** is seL4's job (§5.3), so
  `flush_tlb_range`/`flush_tlb_mm` only update the mirror and never IPI
  other vCPUs.
- **Moved threads.** When Linux moves a thread to another vCPU, the mm is
  marked `moved` (by `prepare_user()` when the thread's fault endpoint
  changes vCPU), and its next TLB sync or unmap flushes its VSpace first
  (`mm_flush_moved()`). That drops the old core from the VSpace's x86 TLB
  bitmap unless another thread runs there, so later unmaps do not send it
  shootdown IPIs. A process that moves and does not unmap pays nothing. A
  rights-lowering flush or emptying the VSpace clears the mark too.
  Measured in a 4-vCPU dom0 on 4 cores, a loop mapping, touching and
  unmapping 8 pages, moved to the next vCPU every 10 ms: 66 µs a cycle
  (380 µs without the flush; 60 µs without moves).
- **Lock-holder preemption.** The guest uses native qspinlocks and
  qrwlocks; a waiter spins if the holder is descheduled. There is no
  paravirtual spinlock slow path. The balancer keeps a guest's vCPUs on
  distinct physical cores where possible (§7), which reduces the cost.
- **Steal time** is published by the balancer in the event page (§7.4).

---

## 7. Host scheduling

### 7.1 Priorities

Global on each core, with `P_K` = `PRIO_KERNEL` = 100:

| Priority | Components |
|----------|------------|
| root task | l4h-root |
| `P_K + 2` | l4h-netd (switches and NIC drivers), l4h-blkd (disk drivers), l4h-memd and l4h-vmmgr (both on core 0) |
| `P_K + 1` | l4h-vmm instances; l4h-trustd (last core, at most 5 ms per 20 ms) |
| `P_K` | guest kernel TCBs (`SC_K`) |
| `P_U` = 99 | guest user TCBs (`SC_U`) |

Host services run with full budgets; guests' vCPUs are bounded by their
SCs. Because `P_K > P_U` for every guest, one guest's kernel work can
briefly preempt another guest's user work, bounded by `SC_K` budgets.

### 7.2 Budgets and CPU caps

- `SC_K` and `SC_U` of each vCPU have a period of 5 ms. Uncapped, each has
  the full period as budget; sums across a core may exceed 100%
  (overcommit), and threads with budget left are scheduled round-robin
  within the guest band. CPU weights are not implemented.
- **CPU caps** (`vm_set_sched`, `l4hctl sched`) give a vCPU one budget, a
  percentage of the period, split between its SC_K and SC_U so that the
  vCPU as a whole stays within the cap.
  - Each SC needs at least 200 µs, so caps below 8% get a longer period:
    1% is 400 µs every 40 ms. AArch64 capped vCPUs use at least a 40 ms
    period to amortize emulated GIC timer delivery.
  - The split adapts: when, in a balancer period, either SC used at least
    90% of its part, the budget is split in proportion to what each used
    (each keeps at least 200 µs). A vCPU alternates between its kernel and
    user threads, so when one SC runs out the other stalls too; the usage
    ratio survives that throttling, where splitting by "what the other
    used" oscillated every period.
  - Splitting one budget between two strictly alternating SCs still loses
    capacity: whichever runs out first stalls the vCPU while the other's
    budget goes unused. In `tests/run-capperf.sh` (release seL4, nested
    KVM), 200 fork+exec at a 50% cap take 3.9 s, against 0.4–0.7 s
    uncapped, and 1.8 s with both SCs given the whole budget (which breaks
    the cap). About 2× is the split; the other 2× is not yet explained.
  - seL4 keeps the sliding-window limit of a reconfigured SC whose thread is
    runnable; an idle or unbound SC starts afresh with its new budget.
    Since the split changes at most once per balancer period, that is at
    most one period's budget extra per change. Samples covering more CPU
    time than elapsed (consumption reported late) do not move the split.
  - seL4 refuses to bind an exhausted SC to a blocked thread, so the guest
    waits for the refill on 100 µs timers when it moves a capped SC_U to
    another process, not with `seL4_Yield`, which would charge SC_K its
    whole remaining budget. A timer deadline that passes during those
    waits is kept as a pending event for after the bind.
  - Capped SCs hold 16 refills (512-byte objects): with seL4's minimum of
    two, a budget used in many short pieces keeps being merged into later
    refills.
  - `tests/run-captest.sh` runs self-tests and fork loops in a guest capped
    from boot.

### 7.3 Placement and balancing

seL4 does no load balancing, so `l4h-vmmgr` runs a balancer every 100 ms.

- **Topology.** At boot, root visits each seL4 CPU on its own SC and reads
  CPUID topology (x86 leaves 1F/0B, or AMD topology extensions on Zen and
  later), mapping actual CPU IDs, gaps and sockets included, without
  assuming seL4 numbering describes siblings. Missing or inconsistent
  topology falls back to independent CPUs; AArch64 uses that flat
  topology.
- **Initial placement** is round-robin, visiting one logical CPU per
  physical core before its other SMT threads.
- **Balancing.** Each period vmmgr reads `SchedContext_Consumed` for both
  SCs of every vCPU, over the measured interval (root work can delay a
  period).
  - A vCPU is *busy* if it got at least half of its fair share among the
    vCPUs active on its core, which still counts a starved vCPU on a
    crowded core.
  - The balancer evens out busy-vCPU counts per physical core first, then
    per logical CPU. It moves at most one vCPU per period, reducing the sum
    of squared counts at the first level that improves. A difference of one
    on logical CPUs also permits a move from a CPU with at least two busy
    vCPUs to a target below 50% utilization, if physical contention does not
    worsen. Equal-load siblings stay put.
  - Equivalent moves prefer guests with no other vCPU on the target
    physical core, then logical CPU. A moved vCPU stays put for 1 s, and
    vCPUs in cooldown still count towards contention.
  - A move re-runs `SchedControl_Configure` on the target core's
    SchedControl; `SC_K` and `SC_U` always move together.
- **TLB bitmaps.** On x86_64 every CPU a VSpace has run on stays in its TLB
  bitmap until a flush of its whole PCID clears the CPUs not running it, so
  every page unmap in it sends each of those CPUs a shootdown IPI and waits
  for all, holding the kernel lock. On a loaded host that turns cheap unmaps
  into tens of milliseconds. Hence:
  - root flushes its own VSpace (`seL4_X64_PML4_Flush`) once it is back on
    its boot CPU after the topology visit (`vspace::flush_tlb_bitmap`);
    without it, loading a guest image took 13 to 48 s on a loaded host;
  - after moving a vCPU, vmmgr flushes the guest kernel's VSpace and all
    its process VSpaces (`Guest::flush_tlb_bitmaps`), so their bitmaps hold
    only the cores the guest's vCPUs are on. An unused or emptied VSpace
    costs only the call; one with other cores in its bitmap costs one IPI
    round. Measured (QEMU/KVM, 4 cores, a 1-vCPU dom0 moved every 100 ms, a
    process mapping, touching and unmapping 8 pages in a loop):

    | | idle host | loaded host |
    |---|---|---|
    | no migration | 39 µs | 157 µs |
    | migrations, no flush | 290 µs | 80 ms |
    | migrations, flush | 42 µs | 609 µs |

    A migration's flushes (65 VSpaces) take a median 157 µs idle and
    415 µs loaded.
  - moves between a guest's own vCPUs are the guest's to flush (§6).

### 7.4 Steal time

The guest accumulates its idle time in the event page (`idle_ticks`). Each
balancer period vmmgr computes, per vCPU, `steal = wall − consumed − idle`
from the vCPU's first run and publishes it monotonically as `steal_ns`.
The guest returns it as Linux's paravirt steal clock
(`CONFIG_PARAVIRT_TIME_ACCOUNTING`), so it shows as `st` in /proc/stat and
top: a guest capped at 25% sees about 75% steal (`tests/run-m6test.sh`).
`l4hctl top` shows each VM's CPU use over the last period.

### 7.5 Limits and memory sizing

- A guest costs its RAM, its I/O pool (4 MiB by default) and about 6 MiB of
  host objects, so a 256 MiB guest costs about 266 MiB (§8). Boot RAM is
  reserved in full at creation; hotplugged memory comes and goes (§8.5).
- vmmgr checks a request's memory, ASIDs and CNode slots before starting it
  and refuses with ENOMEM instead of exhausting itself; root does the same
  for what it makes for the guest (§10.3). Every size and address in a
  control request is range-checked before any arithmetic on it, and a
  request that fails half way gives back what it took.
- x86_64 seL4 has 4096 ASIDs, and a guest holds 66: its kernel VSpace, 64
  process VSpaces and its VMM. That allows about 61 guests;
  `MAX_GUESTS` is 64.
- Free root CNode slots are kept in a bitmap, so the slot ranges of vNIC
  ports and disk DMA buffers can be allocated again as ranges after
  destroy.
- Interrupt vectors are split: NICs 0–3, the serial monitor 8, disks 16–79.
- `tests/run-limits.sh` fills the host and checks that it recovers.
- **Density.** `tests/run-density.sh` runs 30 guests of 256 MiB on 4 cores
  (16 GiB QEMU) with 15 of them spinning. All 30 boot in about 45 s, every
  guest answers on its console within 0.5 s worst case, and destroying them
  returns all memory.

### 7.6 Serial monitor

`l4h-root` reads COM1 (I/O ports and IOAPIC IRQ 4, or the configured
`serial_port`/`serial_irq`; PL011 on aarch64) and runs `help`, `list`,
`info`, `destroy <vm>`, `restart-dom0` and `reboot`. vmmgr runs `destroy`
and `restart-dom0`, which root passes through the events page (§10.3);
`reboot` resets the host as `host_reboot` does, the way out when neither
dom0 nor vmmgr answers. The kernel keeps using the port for output. An
absent UART (line status reads `0xff`) disables the monitor. Input uses
interrupts, including a remapped I/O APIC entry under Intel VT-d
(`tests/run-monitor.sh`).

### 7.7 Dashboard

With a linear framebuffer from the boot loader (GRUB, which seL4 patch 0011
asks for one), `l4h-root` draws a read-only status screen every second:
host, VMs (from vmmgr's status page), disks, switches. It redraws changed
character cells only, in an 8x8 public-domain font. With `fb_console` it
keeps to the upper half.

---

## 8. Memory

A guest's paging structures and other kernel objects come from its own
RAM, so its host overhead is a small fixed amount instead of growing with
its RAM. The precondition is that no device and no host component ever
touches memory the guest can retype: devices see only a host-owned I/O
pool, and host components map only host-owned pages.

### 8.1 Host-owned I/O pool and restricted DMA

- **The pool.** At create time `l4h-root` allocates the guest's I/O pool as
  one physically contiguous Untyped of `io_pool` bytes (default 4 MiB; a
  power of two from 1 to 256 MiB; `l4hctl create --io-pool`, for dom0
  `dom0_io_pool_mb`, see "Receive buffers" below) and retypes it into
  frames. They are mapped into the guest kernel's VSpace at
  `ram_base_va + io_pool_gpa`, where `io_pool_gpa` is RAM rounded up to
  2 MiB (boot info `io_pool_gpa`, `io_pool_size`), and into the guest's
  `l4h-vmm`. The guest gets these mappings only, no capability to the
  pool. Devices reach the pool through the IOMMU domains of the disks the
  guest is given (§9.5).
- **Guest kernel.** `arch/l4h` has dma-direct (device addresses are GPAs)
  with `SWIOTLB` and `DMA_RESTRICTED_POOL`. The pool is added to memblock
  and reserved, so it has struct pages but never enters the page allocator.
  Patch 0002 adds `swiotlb_dev_init_pool(dev, base, size)` and lets
  `DMA_RESTRICTED_POOL` build without OF. The pool gets one swiotlb area
  per possible CPU, as far as areas of whole 128-slot segments allow, and a
  full pool does not warn: it is normal back-pressure. The slot array is
  `kvcalloc`ed (3 MiB for a 256 MiB pool).
  - The transport registers one platform device, `virtio-l4h`, binds it to
    the pool and makes it the DMA parent of every virtio device. Vrings are
    coherent allocations from the pool; buffers bounce.
  - It requires `VIRTIO_F_ACCESS_PLATFORM`, and fails a queue the host
    refuses.
- **VMM.** `GuestMem` is a window on the pool only (`IO_POOL_VA`); it checks
  every guest address against `[io_pool_gpa, +io_pool_size)` with
  overflow-safe arithmetic. A driver that does not accept `ACCESS_PLATFORM`
  fails `FEATURES_OK`; a queue outside the pool is refused, and
  `DRIVER_OK` then fails (`DEVICE_NEEDS_RESET`) until reset. Chains with any
  buffer or indirect table outside the pool are returned unused, and so are
  chains longer than the queue size, indirect descriptors included (virtio
  1.x §2.7.5.3.1): a chain is collected into a fixed array of that size.
- **Request size.** A block request bounces entirely through the pool, and
  one that cannot fit even in an empty pool would be requeued forever. The
  VMM therefore offers `VIRTIO_BLK_F_SIZE_MAX` with `seg_max * size_max` at
  most a quarter of the pool (72 KiB segments, about 1 MiB per request,
  with 4 MiB; 16 KiB with 1 MiB).
- **Receive buffers.** A virtio-net driver keeps its receive ring full, so
  its buffers hold pool memory all the time. The VMM offers `GUEST_TSO4/6`
  without `MRG_RXBUF` or indirect descriptors, so Linux posts "big" buffers
  of 18 pages in 19 descriptors: a 256-entry ring holds 13, 936 KiB. Left
  unbounded, three vNICs held most of a 4 MiB pool in page-sized pieces and
  a disk request found no room and was requeued forever. So the VMM sizes
  each receive queue (`host::iopool::rx_queue_size`): the largest power of
  two from 32 to 256 whose full rings, for all the guest's NICs together,
  hold at most half the pool, leaving a quarter beyond the largest request.
  A 4 MiB pool keeps 256-entry rings for one NIC and 128 for three. dom0's
  default pool (`dom0_io_pool_mb=0`) is the smallest power of two, at least
  4 MiB, with full rings for its vNICs (`host::iopool::for_nics`): 8 MiB
  for three.
- **blkd.** A client's data region is its pool: every segment must lie in
  it and is translated with one offset (`host::blk::Pool`).
- **Hypercalls.** Device register pages and console rings are host pages.
  The control API's `VM_LOAD` source is an offset in the control device's
  data area, 1 MiB of host frames mapped into dom0 (`l4h_dev_desc.data_va`),
  so no host component reads guest RAM. `L4H_CTL_LOAD_MAX` is 1 MiB.
- **Disk detach.** Destroy drains the guest's disk requests before any
  memory is reused (§10.1). Only the pool and blkd's DMA memory can be
  device targets, so a controller that fails to drain pins those, not the
  guest's RAM; with a supported IOMMU the pool is unmapped from the device
  instead, and only blkd's DMA memory stays pinned (§9.5).
- **Tests.** `tests/guest/abitest` plays a hostile driver against a
  virtio-blk disk (no `ACCESS_PLATFORM`, rings in RAM or across the pool's
  end, header, data or status in RAM, a buffer past the end; a read through
  the pool still works). `tests/fuzz-virtq` places the pool at random GPAs
  (including 0 and the top of the address space), aims descriptors and
  rings inside, at the edges of and outside it, checks queue setup both
  ways and blkd's pool check, and that no chain outside the pool reaches
  blkd. `run-blktest.sh` adds 8 parallel direct writers and readers (more
  than the pool holds), and also passes with `L4H_DOM0_IO_POOL_MB=1`.

### 8.2 Guest RAM as 2 MiB Untypeds

- **seL4 semantics** (checked by `tests/guest/abitest`, `untyped_copy_test`
  and `ram_blocks_test`). An Untyped can be copied only while it has no
  children; the copy is a revocable child of the original, and copying sets
  the original's free index to "full", so the two can never hand out the
  same memory. The guest retypes and revokes through its copy; a retype
  from a copy without children starts at its base and zeroes the memory; a
  copy with children cannot be copied again; revoking the original deletes
  the copy and everything retyped from it. So memd keeps the original of
  every block and the guest gets a copy.
- **Blocks.** Guest RAM is `ram / 2 MiB` blocks (RAM is rounded up to
  2 MiB), each a 2 MiB Untyped from anywhere in free memory: guest RAM is
  not physically contiguous. memd holds the originals (§8.4). The kernel
  image's shared blocks (§5.6) are added to these and have no Untyped.
- **Boot blocks.** vmmgr turns a block into host frames (a level-2 RAM
  CNode of 512 frames, mapped in the direct map) when it loads an image
  into it (the kernel, or an initramfs); memd gives it a copy of that
  block's Untyped for this. Shared blocks get their level-2 CNode at
  create, holding read-only copies of the kernel's frames; `VM_LOAD` into
  them fails. At `VM_START` the boot blocks are the prefix of RAM up to the
  end of the kernel, the initrd (if not empty) and anything loaded, plus one
  slack block (`BOOT_SLACK`) of frames for early `memblock` allocations; at
  least one block must be left for the guest.
  - dom0 chooses the initrd's address, so the prefix can be nearly all of
    the guest's RAM, and each boot block costs the host up to 32 KiB (its
    level-2 CNode and a page table) and three slots. Before filling any,
    `VM_START` checks that the host can afford the blocks not yet filled
    (`Guest::boot_cost`) and reserves room for them and the VMM's remaining
    objects in the guest's arena (`Arena::reserve`), failing with `ENOMEM`
    otherwise. `VM_LOAD` checks and reserves likewise. The VMM's three large
    CNodes are made at create, before loads can fragment the arena.
- **Capabilities.** Guest root slot `L4H_SLOT_BLOCKS` is the block CNode:
  slot `b` holds the Untyped copy of every non-boot block. Frames are named
  through two levels: root slot `L4H_SLOT_RAM_L1_BASE + n` is a level-1
  CNode (radix 9) for GiB `n`, whose slot `j` holds the level-2 CNode
  (radix 9) of block `512 n + j`, so `L4H_FRAME_CPTR(gpa)` names any frame.
  The host installs the level-2 CNodes of boot blocks; the guest retypes
  its own for the others. Boot info carries `nr_blocks` and `boot_blocks`.
- **Guest early boot** (`kernel/caps.c`, `l4h_caps_init`). memblock knows
  only the boot blocks. The guest marks the non-boot blocks that onlining
  needs as object blocks, creates its first capability CNode and the user
  CSpace from them, then for every other block retypes its level-2 RAM
  CNode (into its level-1 slot), one 2 MiB frame and its 512 subframe
  aliases (patch 0029), and maps the aliases at `ram_base_va + GPA`
  (read-write, execute-never), adding page tables from object blocks. Each
  block is added to memblock once mapped; object blocks are added and
  reserved, so they have struct pages.
- **Host accounting.** A host-object arena starts with an estimate of what
  its owner needs and grows from free blocks, by at least 1 MiB
  and preferably an eighth of the arena (`Arena::retype`, `Arena::reserve`).
  The VMM's estimate is what it maps (image and 1 MiB stack; it has no
  heap).
- **Buddy merging.** Guest RAM comes back in 2 MiB blocks, so free memory
  would end up in 2 MiB pieces and an I/O pool could no longer be found.
  The allocators keep the Untyped of every block they split and merge two
  free halves again by deleting them, lazily, only when no free block is
  large enough: the next retype of a merged parent makes seL4 clear
  everything its children used, so merging eagerly to GiB blocks would make
  every create clear a GiB.
- AArch64 uses the same host and guest paths; only its paging-object
  operations differ.

### 8.3 Object memory: converting blocks between frames and objects

- **At boot** the guest makes object blocks only of what onlining needs (a
  16 KiB RAM CNode and a 4 KiB page table per frame block, and a slot
  CNode), plus the reserve; everything else starts as frames. A 4-vCPU
  256 MiB dom0 boots with 6 object blocks (12 MiB), of which 2.6 MiB is
  used.
- **Chunks and classes.** `l4h_obj_alloc` takes objects from Untyped
  *chunks* of 16, 64 or 128 KiB (by object size) carved out of object
  blocks. seL4 reuses an Untyped's memory only when all its children are
  gone, so with whole blocks as the unit a few long-lived objects would pin
  each block. A chunk resets as soon as its own objects are gone. Chunks
  come from four classes, each with its own open block: small objects,
  4 KiB objects (TCBs), page tables, and CNodes. Page tables have their own
  class because they die together when a process exits or loses its
  VSpace; mixed with TCBs, they would pin their chunks. Whole-block
  Untypeds and large frames use a separate 2 MiB class. Slot CNodes
  (128 KiB) come straight from a block, since a chunk needs a slot; an empty
  one is deleted once a CNode's worth of slots is free in the others. All
  allocations take one lock.
- **Free blocks** have no live objects in any chunk and forget their
  chunks. They are either in the **reserve** or **spare**. Allocations (in
  atomic context, under page-table and capability locks) take a spare
  block, else a reserve block, and never wait. A worker (`objmem_balance`,
  on the unbound workqueue, also run synchronously by `l4h_objmem_wait`)
  keeps the reserve at its target and returns spare blocks beyond the
  watermark to frame mode. Both default to one block per vCPU, at most 1/32
  of RAM.
- **Frame → object** (`frames_to_objects`): an order-9 allocation from the
  page allocator (`GFP_KERNEL | __GFP_RETRY_MAYFAIL`, which reclaims and
  compacts; `ARCH_FORCE_MAX_ORDER` is 9, so an order-9 page is a whole
  aligned block), retrying past boot and hotplug blocks, which have no
  Untyped in this pool. If that fails, the guest scans frame blocks with
  `alloc_contig_range`, isolating a range and migrating its pages
  synchronously: direct compaction uses only `MIGRATE_SYNC_LIGHT` and can
  skip busy and dirty pages, so an order-9 failure alone does not establish
  OOM. The migration runs with `PF_MEMALLOC`, skipping locked folios rather
  than waiting under `objmem_mutex` for a folio a kernel mapping holds
  locked while it waits for object memory (EROFS decompresses into locked
  page cache via `vm_map_ram`). Revoking the block's Untyped copy then
  deletes its 512 frames with every mapping and copy; the pages stay
  allocated, out of the page allocator.
- **Object → frame** (`objects_to_frames`): the highest spare block is
  revoked, gets its 512 frames back in its (kept) RAM CNode, is mapped
  again, and its pages go back to the page allocator (`__free_pages`,
  `free_contig_range` for isolated ranges, which hold one reference per
  page, or `free_reserved_page` for blocks that were object blocks since
  boot).
- **Kernel mappings** (vmap, vmalloc, percpu) cannot be left to fault again,
  since a guest-kernel fault stops the guest. A kernel TLB sync that finds
  no memory leaves those PTEs unsynced and marks the range again, and
  `flush_cache_vmap` retries until it succeeds, sleeping between tries,
  waiting for object memory and allocating a page so that reclaim or the
  OOM killer runs.
- **No memory for objects.** Atomic callers get `-ENOMEM`: a TLB sync that
  cannot map a page leaves it unmapped and the page faults again. The fault
  path and the creation of a user context, which may sleep, call
  `l4h_objmem_wait()`; if no block could be converted, `l4h_objmem_oom()`
  calls the OOM killer, as a failed page-table allocation would on native
  Linux. Each mapping takes a slot, so its mappings and seL4 page tables
  count in a process's page-table bytes, which the OOM killer ranks by.
- **Accounting.** `/proc/meminfo` has `L4hObjects` (RAM in object blocks)
  and `L4hObjectsUsed` (in chunks with live objects); `/proc/l4h_objmem`
  shows block counts, targets and conversions, with `contig_attempts` and
  `contig_successes` for the migration fallback.
- **Test** (`tests/run-objtest.sh`). A fragmentation regression fills most
  free RAM, keeps one movable page per 2 MiB block and discards the rest,
  then (with compaction thresholds raised) touches a page every 2 MiB of a
  16 GiB mapping, which must grow object memory through migration and keep
  the retained pages intact. Stress phases run 8 processes each touching a
  page every 2 MiB of 1 GiB (4096 page tables), alone and alongside
  `selftest`'s `smp_mm_stress`, `smp_unmap_vis` and `smp_fork_storm`;
  object blocks grow and go back when they exit. Finally a process maps
  sparse memory until RAM is exhausted: the OOM killer kills it, the guest
  carries on, and conversions work afterwards. Passes with 1 and 4 vCPUs.
- **Fragmentation.** Long-lived objects can still pin partly empty chunks,
  and unmovable Linux pages can prevent a frame block from being isolated.
  There is no compaction of object memory (rebuilding VSpace mirrors into
  fresh blocks).

### 8.4 l4h-memd: the owner of memory

One component owns all free RAM and all guest RAM, so that guest memory can
grow and shrink without going through `l4h-root`.

- **Boot.** Root starts with every boot Untyped and allocates from them
  until memd runs: its own first objects, the module copies and memd itself
  (`memd::spawn`). It then moves every free block of 2 MiB or more to memd
  (`Alloc::hand_over`), keeping the parents of blocks it had split, which
  memd therefore cannot merge with their buddies. Device Untypeds stay with
  root.
- **Table.** memd has no heap (`component!(main, no_heap)`). What it knows
  of memory is a table with a 24-byte entry per 2 MiB unit of physical
  address space, up to the end of the last block it gets, which root sizes,
  zeroes and maps when it spawns memd (`TABLE_VA`; 12 KiB for a 1 GiB host,
  12 MiB for 1 TiB). memd never handles less than 2 MiB. A block of
  2^(21+k) bytes ("order k") is described by the entry of its first unit,
  and the free blocks of each order are on lists linked through their
  entries: those not reported to the hypervisor in the order they were
  freed, and those reported. Taking, freeing and finding a buddy are O(1),
  taking a block of order k is O(orders), and nothing scans the free blocks
  except a merge and the report timer.
- **CSpace.** One CNode (`SpawnArgs::cnode_bits`) with a slot for every
  block of every order that fits in the table, at a fixed place
  (`l4h_host::memd::block_slots`): two slots per 2 MiB unit, to the next
  power of two (64 KiB of CNode for a 1 GiB host). The halves of a split
  block are always in consecutive slots, as a retype needs, and no request
  can fill the CNode.
- **Clients.** memd calls no one. Root holds memd's CNode and passes
  Untypeds by moving them into memd's exchange slots. vmmgr, with a badge of
  its own (`BADGE_VMMGR`), gets memory for itself and guests' RAM; memd is
  more trusted than vmmgr, so they share a small mailbox CNode instead, memd
  keeps the original of every block it grants vmmgr and gives a copy, and
  freeing a grant revokes the original, so a mislabelled capability in the
  mailbox cannot confuse memd's table. memd empties a mailbox slot before
  writing one. VMMs call it, badged `BADGE_VMM | guest`, for their guest's
  hotplug operations only (§8.5); root mints those endpoints, since vmmgr's
  own badged one cannot be minted again.
- **Grants.** When a client's free blocks cannot meet a request, it takes an
  untouched Untyped of 16 MiB, or the request if larger (if memd has none
  that large, exactly the request, at least 2 MiB), from memd (`MEMD_ALLOC`) and splits it.
  Grants are never merged with each other. When a destroy or failed create
  leaves a client (root or vmmgr) with 48 MiB or more of free blocks, it
  merges them and returns
  whole grants beyond 32 MiB (`MEMD_FREE`, `Alloc::trim`); merging after
  every destroy would make creates a fifth slower (§8.2). Host objects,
  arenas, I/O pools and ASID pools come from these blocks.
- **Merging** in memd is lazy for the same reason: free buddies merge only
  when no block is large enough, in one pass over the smaller orders. A
  pass that finds nothing is not repeated until a block is freed or a
  report returns.
- **Guest RAM** (`MEMD_GUEST_*`). At create, memd takes the guest's 2 MiB
  blocks and the block CNode capability vmmgr passes it. For a boot block,
  memd gives vmmgr a copy of its Untyped, which vmmgr fills with frames.
  At start, memd copies the Untypeds of the other blocks into the block
  CNode, past the kernel's shared blocks (§5.6), which memd has no block
  for. At destroy, once vmmgr has reclaimed its arena, memd revokes every
  original: that deletes the guest's copies, everything the guest made of
  them, and the host's copies of boot blocks with their frames. With the
  VSpace roots gone first, deleting the frames unmaps nothing; the other
  way round, each frame was unmapped with a TLB shootdown (585 ms instead of
  about 120 for a stopped 128 MiB guest).
- **Free memory.** memd publishes its free blocks in a status page
  (`l4h_host::memd::Status`). `host_info` reports root's, vmmgr's and
  memd's free blocks; the monitor and dashboard show root's and memd's.
- **Trust.** memd is in the host TCB. It cannot read memory: every Untyped
  it has handed out has a child, so it cannot retype it, and revoking it
  first makes seL4 clear the memory before reuse. It can revoke what it
  handed out, and if it faults, a keeper thread answers its callers with
  an error, so memory requests (grants, guest creation, hotplug) fail from
  then on.
- **Scheduling.** memd runs on core 0 at `PRIO_KERNEL + 2`, above every
  guest, with a full budget: root waits for it.
- **Limits.** Only the table: its size follows the host's memory, and no
  request makes memd use more of anything. A 1 TiB host needs 12 MiB of
  table and 64 MiB of CNode.

### 8.5 Memory hotplug

dom0 can add memory to a running VM and take it back, 128 MiB at a time.
dom0 gets the mechanism only: it sets a VM's target and reads how much is
plugged; deciding sizes is left to it. Memory that is not plugged costs
nothing: no frames, seL4 objects or struct pages, only guest address space.
The properties of this section hold: a guest's host overhead is fixed
(16 KiB more), no host component reads guest RAM, and revoking a guest's
Untypeds reclaims everything it made. Plugging does not involve
`l4h-root`.

- **Region and units.** Every guest has a hotplug region, from its I/O
  pool's end rounded up to 128 MiB to the 64 GiB guest-physical limit
  (`L4H_GPA_END`), in *hotplug blocks* of 128 MiB (`L4H_HP_SIZE`, 64 RAM
  blocks, one Linux memory block). Boot info: `hp_gpa`, `hp_count` (at most
  512).
- **Capabilities.** Guest root slot `L4H_SLOT_HP` holds a level-1 hotplug
  CNode (radix 9, guard 3) that the host makes, the only host memory the
  region costs. Before plugging hotplug block m, the guest retypes a
  level-2 CNode (radix 6, 2 KiB) into its slot m from its own object
  memory; memd copies the Untypeds of the block's 64 RAM blocks into it
  (`L4H_HP_BLOCK_CPTR(m, i)`). Frames of hotplugged memory are named by
  `L4H_FRAME_CPTR` like the rest of RAM: the guest makes the level-1 RAM
  CNodes of the region's GiBs (16 KiB each) when it first plugs there.
- **Control.** `VM_SET_MEM` (vm, bytes): vmmgr rounds the part above boot
  RAM up to whole hotplug blocks, clamps it to the region, sets memd's
  target (`MEMD_SET_TARGET`), signals the VMM (`VMM_BADGE_MEM`) and
  returns. `VM_MEM_INFO`: boot, region, target and plugged bytes, from
  memd's status page; `VM_LIST` counts plugged memory. CLI: `l4hctl mem VM
  [MB] [--wait[=SECS]]`. Lowering a target revokes nothing: the guest gives
  back what it can, and `plugged > target` tells dom0 it cannot give back
  more (it may wait or destroy the VM). Targets and plugged state live in
  memd, so a dom0 restart changes no VM. A reboot (destroy and create)
  starts with an empty region.
- **memd.** Per guest: the region's size, the target, a bitmap of plugged
  hotplug blocks, and for each the head of a list of its 64 units through
  the table (`HP_HEADS`, 128 KiB of BSS for all guests). VMMs call
  `MEMD_HP_PLUG`, `MEMD_HP_UNPLUG` and `MEMD_HP_STATE` for their own guest.
  A plug checks the range, the bitmap and the target, takes 64 free blocks
  and copies them into the guest's level-2 CNode; a copy that fails (no
  CNode, or the slot occupied) undoes the plug. It takes only blocks that
  need no free page report to come back, so a guest never holds memd
  waiting: short of 128 MiB of them it answers `EBUSY`. An unplug revokes
  and frees the 64 originals; destroy revokes every plugged block with the
  rest. A token bucket per guest allows 8 plugs or unplugs a second after a
  burst of 16 (`EBUSY` beyond), bounding the time one guest can take from
  memd, which runs on core 0 above every guest.
- **VMM.** The memory device (`L4H_DEV_MEM`, `struct l4h_mem_page`) is one
  more device page: target, plugged count and bitmap, which the VMM
  refreshes from memd (`MEMD_HP_STATE`) at start, after each request and
  when signalled with a new target, raising the device's event then. A
  guest request (op, m), written in the page with a kick, becomes one memd
  call; memd does every check, and the VMM answers in the page and raises
  the event.
- **Guest kernel.** `arch/l4h` uses `SPARSEMEM_VMEMMAP` with 128 MiB
  sections and `ARCH_FORCE_MAX_ORDER` 9: Linux puts a memory block's memmap
  in the block (`memmap_on_memory`) only if it is whole pageblocks, and a
  128 MiB block's memmap is 2 MiB. The vmemmap is 2 GiB of VA below the
  last PGD slot, mirrored into seL4 by the kernel TLB sync like vmalloc;
  the boot memmap is mapped directly at boot (`l4h_map_kernel_early`),
  before the sync can work (its mappings need slab memory), and its PTEs
  are left up to date so later syncs skip them. `end_iomem`, and so
  `VMALLOC_START`, is above the region. `arch_add_memory` and
  `arch_remove_memory` only add and remove the memmap: the driver maps the
  frames first. Nothing allocates more than 2 MiB at once.
- **A plugged hotplug block** (`drivers/memhp.c`, `l4h_hp_map`):

  | Blocks | Use |
  |---|---|
  | 0 | its memmap (`MHP_MEMMAP_ON_MEMORY`) |
  | 1–62 | RAM |
  | 63 | the level-2 RAM CNodes of blocks 0–62 and the page tables mapping them in the direct map (about 1.23 MiB), retyped straight from its Untyped; its pages stay `PageOffline` |

  The guest sees 124 MiB of each block. A plug takes from its other memory
  only the 2 KiB level-2 hotplug CNode, a level-1 RAM CNode per new GiB, two
  small tables (about 1 KiB together) of page-table and large-frame slots, and the vmemmap's page tables (a Linux
  and an seL4 page table per hotplug block, kept for the next plug there).
  - Plug: those CNodes, a plug request, map, `add_memory_driver_managed`.
    Block 63's pages are skipped by an online page callback, and a memory
    notifier drops and restores their reference around offlining, as
    virtio-mem does for unplugged ranges.
  - Unplug: `offline_and_remove_memory`; revoking the copy of block 63
    deletes the page tables and RAM CNodes (and with them every frame); then
    the other copies; then an unplug request. A guest that skips this only
    harms itself. When memd answers `EBUSY`, the block stays pending and the
    driver retries every second, whether or not the target changes again.
    If a failed plug's rollback finds Linux will not let go of the block, it
    stays plugged and in use.
- **Zones.** The guest boots with `memory_hotplug.memmap_on_memory=1` and
  memory is added offline (`MHP_DEFAULT_ONLINE_TYPE_OFFLINE`); the driver
  onlines every hotplug block to `ZONE_MOVABLE`, which can always be
  offlined. A block that Linux onlined itself in another zone
  (`auto_online_blocks`, `memhp_default_state=`, a udev rule) is offlined
  and onlined again to `ZONE_MOVABLE`, or left if it cannot be offlined.
  `ZONE_NORMAL` in hotplugged memory collects unmovable kernel pages and
  then cannot be offlined, leaving VMs stuck above target; and in l4h the
  kernel memory that grows most with a VM's processes, their seL4 page
  tables and slots, comes from boot RAM anyway, since hotplug blocks are
  never object blocks. Unplug tries the highest block first.
- **Headroom.** Offlining moves what it can elsewhere, and memory that
  cannot be reclaimed (tmpfs without swap) then fills the rest; a guest
  shrunk to just above its tmpfs deadlocks. The driver therefore unplugs a
  block only if available memory stays above a sixteenth of RAM (at least
  64 MiB) without it; otherwise the guest stays above its target and
  retries every 10 s.
- **Tests.** `tests/run-hotplugtest.sh`: a 256 MiB VM grows to 2 GiB
  (MemTotal follows, object memory does not grow, host free memory falls by
  the plugged amount), fills 1200 MiB of tmpfs, shrinks short of 512 MiB
  without losing data, empties tmpfs and reaches 512 MiB (the host gets the
  memory back), grows to 1 GiB and is destroyed, after which all host memory
  is back. `tests/run-hotplugstress.sh [rounds]`: three 2-vCPU VMs under
  memory load (`tests/guest/hpstress.c`, which checks anonymous memory that
  unplugging migrates; `smp_mm_stress`; tmpfs files) get random targets
  from 256 MiB to 1.5 GiB every few seconds, 4.5 GiB in all on a host with
  3.7 GiB free, and one is destroyed mid-resize every 15 rounds. Then every
  VM must return to 256 MiB, with no bad data, no kernel BUG or WARNING, and
  all host memory back after destroy. `HPSTRESS_THP=1` runs it with THP
  enabled in the workload guests.

### 8.6 Free page reporting to the hypervisor

When l4h runs in a VM, memory it has not given to a guest should not
occupy the hypervisor's RAM.

- **Device.** `l4h-memd` drives a virtio-balloon PCI device that offers
  free page reporting (`VIRTIO_BALLOON_F_REPORTING`; QEMU
  `-device virtio-balloon-pci,free-page-reporting=on`, which
  `tools/run-qemu.sh`, `run-uefi.sh` and `run-image-aarch64.sh` add unless
  `L4H_BALLOON=0`). Only the reporting queue is used: no inflation,
  deflation or statistics. QEMU numbers its queues by the features it
  offers, so the reporting queue is 2, plus one each for statistics and free
  page hinting if offered. Root finds the device, enables it and maps its
  BARs (or gives I/O ports, for a legacy one) and three DMA pages into memd.
  It has no interrupt: memd's 100 ms timer polls it
  (`l4h-memd/src/balloon.rs`). A balloon that translates through an IOMMU
  (QEMU `iommu_platform=on`) cannot report, since reports name memory the
  device is never given.
- **What is reported.** memd's free blocks of 2 MiB or more, once free for
  2 s (as Linux does), so memory freed and reused soon is not reported.
  A report is one chain of device-writable buffers, one per block or per
  2 GiB of one, at most 32; one report is in flight at a time. Each free
  block is *free* (since a time), *reporting* or *reported*. Splitting
  passes the state to the halves, and merging two reported halves gives a
  reported parent. Clients' cached free blocks (up to about 48 MiB per
  client: 32 MiB kept after a trim, plus up to one grant before one) are not
  reported.
- **Reuse.** A block being reported is not used until the device returns
  it: allocation skips such blocks, and waits (up to 2 s) when nothing else
  fits. Reported blocks are used like others: their contents read as zero,
  as seL4 would make them anyway, and touching them backs them again.
- **Zeroing.** Patch 0019 clears free RAM at boot without touching zero
  pages, so first use of boot memory, including as guest RAM blocks, keeps
  unbacked pages unbacked. Every runtime Untyped reset clears
  unconditionally, so reusing a previously allocated block backs it again,
  even if the hypervisor had dropped it; reporting releases it again once
  it is free.
- **Measured** (`tests/run-balloontest.sh`: QEMU with 4 GiB and KVM, a
  256 MiB dom0, a 1 GiB guest that fills 768 MiB of tmpfs and is destroyed,
  twice; QEMU's resident memory): 259 MiB idle, 1091 MiB with the first
  guest, 264 MiB after destroying it; 1289 MiB with the second guest (which
  pays for unconditional resets) and 265 MiB after. Without reporting, a
  destroyed guest's memory stays backed in QEMU.
- **Not covered.** Memory a guest holds but does not use stays backed once
  written: guests have no balloon, and their free pages are not reported. A
  guest `page_reporting` device passing GPAs through the VMM to memd, which
  can translate them, is the natural extension.

---

## 9. Devices

### 9.1 Transport: `virtio-l4h` (guest side)

Linux virtio allows custom transports (`virtio_mmio`, `virtio_ccw` and
`vdpa` are examples). `virtio-l4h` provides `virtio_config_ops` for each
device, with no trapped accesses:

- **Device page.** A shared 4 KiB frame laid out like the virtio-mmio
  register file plus the device config space. Reads are plain loads.
- **Writes with side effects** (status including reset, driver features,
  queue setup and ready, config writes, IRQ routes) are written to the page
  and committed with an `L4H_HC_DEV_WRITE` hypercall, a `seL4_Call` to the
  VMM. They are rare.
- **Queue kick.** The guest atomically sets the queue's bit in the device
  page's `kick` word and calls `seL4_Signal` on the device's kick
  notification only if the bit was clear, so kicks issued before the VMM
  collects the bits cost no further signal. The VMM offers no event-idx or
  used-ring notification suppression.
- **Device interrupt.** The VMM sets an event bit in the target vCPU's
  event page, then signals `N_v`. The `l4h-irq` irqchip maps event bits to
  Linux IRQs. Virtio event owners implement `irq_set_affinity`, so standard
  Linux IRQ affinity writes update the VMM's route and the effective CPU
  mask.
- **Queue interrupts.** Block queues have separate events and CPU targets,
  which the transport reports to Linux's block queue mapper; other devices
  use their device event and target. Queue events occupy
  `80 + 4 * device_index` through that value plus three, so the 64 device
  slots use at most event 335 of 512. The device page's reserved fields
  hold the queue event base and four CPU targets; a queue target of
  `UINT32_MAX` falls back to the device event.
- **Discovery** uses the boot-info device table, not PCI or DT probing. A
  guest has at most 64 devices (`L4H_MAX_DEVICES`): console, memory,
  attestation, disks, vNICs, display and, in dom0, control. Vrings and every
  buffer live in the guest's I/O pool and are addressed by GPA (§8.1);
  `VIRTIO_F_ACCESS_PLATFORM` is required.

`tests/run-devicelimit.sh` fills dom0 and normal guests to 64 devices,
checks block I/O and networking at high device indices alongside a GPU,
rejects a 65th device, and restarts dom0 while a full guest survives.

### 9.2 Block: shared controllers and LBA windows

Each physical virtio-blk, virtio-scsi or NVMe PCI controller has one
persistent `l4h-blkd`. `BLK_ATTACH` attaches a finite, 4 KiB aligned LBA
window of a disk to a guest before it starts. A writable window overlaps no
other window of its disk; read-only windows may overlap each other, so one
seeded image can back many guests. Every window is a separate virtio-blk
volume starting at sector zero. There is no image format, host filesystem,
thin provisioning or copy-on-write.

- **Path.** Guest `virtio_blk` → l4h-vmm → per-client shared queue → blkd →
  device.
- **Guest queues.** Volumes offer four request queues through
  `VIRTIO_BLK_F_MQ`; Linux may select fewer for fewer CPUs. Requests carry
  the queue, chain head and generation, and completions return only to that
  queue. The VMM visits queues round-robin and signals only queues whose used
  ring changed; completion retries visit blocked queues without reading
  every idle queue's available ring.
- **Flush and reset.** A flush waits for accepted requests from every queue,
  and later requests wait until it completes. Device reset drains all
  accepted work before buffers can be reused. Reset of one queue returns
  completions to the others and drops only its own.
- **Clients.** Each client has its own immutable pool/window/permission
  configuration, channel and completion notification. A controller supports
  512 clients; blkd's submit loop visits only attached ones. Submission is
  round-robin, with bounded work per client and reserved completion capacity
  for outstanding requests. Hardware request tags are allocated by blkd, so
  identical IDs from different clients cannot collide.
- **Validation.** Descriptor buffers must lie in the client's I/O pool; blkd
  translates pool GPAs to physical addresses, and the device never sees
  guest RAM. Root and blkd both enforce the overlap rule
  (`DiskWindow::conflicts`). Requests are checked with checked arithmetic
  for block alignment, direction, permissions, operation and pool bounds.
- **Volatile attachments.** `BLK_ATTACH` takes flags: `BLK_RO`, and
  `BLK_VOLATILE` for a disk whose contents need not survive a power failure,
  such as the scratch disk of a VM discarded with it. Its VMM does not offer
  `VIRTIO_BLK_F_FLUSH`, so the guest treats the disk as write-through and
  turns `fsync`, journal commits and barriers into no-ops; blkd completes any
  flush from that client at once. Writes the device has cached may be lost.
  A flush on a consumer SSD or a virtualized disk can take tens of
  milliseconds, and per-commit `fsync` dominates package installs and builds
  there. Other attachments of the disk, and dom0's provisioning flush, still
  flush the device.
- **Destroy** stops the client's VMM, drains that client's submitted work,
  then releases its mapping and pool, without resetting the shared
  controller. On a five-second timeout, root suspends the driver and
  quarantines the controller: its DMA memory stays allocated, every affected
  guest pool is pinned when destroyed, and no new attachment or provisioning
  write is accepted until host reboot.
- **Provisioning.** dom0 can seed or explicitly zero *unattached* ranges
  with `BLK_WRITE` and its ioctl staging buffer (up to 1 MiB per call); a
  zero-length call flushes the controller. Provisioning uses a private 1 MiB
  DMA scratch area and never writes over a client, read-only clients
  included.
- **Legacy devices.** Every virtio device the host drives (virtio-blk,
  virtio-scsi, virtio-net and the balloon) may also be a legacy (0.9.5) one:
  transitional device ID, registers in I/O BAR 0, no virtio capabilities, as
  on GCE N2. Root gives the driver an IOPort capability for the BAR; the
  driver programs a legacy queue (the device's size, at a 32-bit page
  number) and notifies through `QUEUE_NOTIFY`. A transitional device with
  virtio capabilities is driven as a modern one. Disk and NIC drivers need
  MSI-X; the balloon is polled.
- **virtio-scsi** (modern or legacy) has a host disk per direct-access
  logical unit (up to 16): blkd lists each target's LUNs with REPORT LUNS
  (LUN 0 alone if that fails) and skips other device types. Requests become
  READ/WRITE(10 or 16) and SYNCHRONIZE CACHE, split at the device's
  `seg_max` or `max_sectors`. Write protection and the write cache come from
  MODE SENSE; unit attentions and busy statuses are retried. The driver uses
  up to four request queues, with one bounded slot table and MSI-X vector;
  submission batches rotate between queues with one notification per batch,
  and each command keeps its queue for completion and retry. Provisioning
  uses queue zero. Indirect descriptors are used when offered; otherwise
  each command slot owns a fixed run of ring descriptors.
- **Boot.** Host disks are numbered by controller in PCI order, then target
  and LUN. Before anything enables a disk controller, root resets it
  through a mapping of its registers, with bus mastering off, since
  firmware may leave one running: NVMe clears CC.EN and waits up to CAP.TO
  for CSTS.RDY to clear, which aborts every command and deletes the queues;
  virtio writes 0 to `device_status` and waits until it reads back 0. It
  then starts every
  controller's blkd at boot and learns the virtio-scsi units there. Each
  needs 4 MiB of physically contiguous DMA memory, and the host fails to boot
  without it, so a disk never lacks its driver later. A controller whose
  reset failed is not started and stays disabled: its disks fail with `EIO`,
  and the host boots without them. Clients and quarantine are per
  controller.
- **Queries.** `DISK_INFO` returns the PCI address, kind, failed flag,
  capacity and attachment count (the owner field names the first
  attachment, or -1); `BLK_INFO` enumerates `(vm, start, sectors,
  read-only)` with a cursor.

`tests/run-sharedblk.sh` checks concurrent clients, overlap and bounds
rejection, provisioning exclusion, destroy during I/O, read-only windows
shared by several guests, more than 64 attachments of one disk,
flush/readback and repeated reuse, on virtio-blk, virtio-scsi (also with
both disks as LUNs of one controller) and NVMe (512 and 4096 byte blocks).
`tests/blk-windows.rs` exercises the production validator on malformed
requests and window/pool boundaries.

### 9.3 Network: L2 virtual switches only

The hypervisor implements Ethernet switching. Routing, NAT, DHCP and
firewalling belong in a VM.

- **Path.** Guest `virtio_net` → `l4h-vmm` → shared net port rings →
  `l4h-netd` → destination port or uplink NIC. netd runs all switches and
  the uplink NIC drivers in one component: modern and legacy virtio-net,
  gVNIC, Amazon ENA and the Intel X550.
- **vNICs.** Each vNIC is on one switch and appears as a separate `ethN`.
  There are 48 guest ports in all. Guest vNICs have one RX/TX queue pair.
- **Switches and uplinks.** The API creates switches dynamically, up to 52
  (one per guest port and NIC); switches are not deleted. Each is an L2
  broadcast domain with its own learned MAC table. A physical NIC can be
  the uplink of one switch; a switch without one is internal. VLAN tags pass
  through untouched. VLAN-aware switching, jumbo MTUs on guest ports, static
  MAC entries and port rate limits are not implemented.
- **Ports and copies.** A vNIC has TX and RX rings of 24 frame slots of
  68 KiB each, so a slot holds a whole 64 KiB TSO frame, shared by its VMM and netd, in memory of the guest's root arena; root adds
  and removes ports with `NETD_ADD_PORT`/`NETD_REMOVE_PORT`. The guest
  bounces buffers through its I/O pool, the VMM copies between pool and
  port slots, and netd copies slot to slot or slot to NIC DMA buffer.
- **Offloads.** Checksum and TSO metadata pass through in the virtio-net
  header. netd validates flags, checksum offsets and GSO type, including
  that a GSO frame is TCP over IPv4/IPv6, and drops incoherent headers. A
  frame for a port that cannot take its offload is segmented and checksummed
  in software.
- **Receive offloads.** netd's virtio-net driver negotiates `GUEST_CSUM`
  and, with mergeable RX buffers (`MRG_RXBUF`, 256 × 4 KiB), `GUEST_TSO4/6`,
  so a device with large frames delivers them whole. Frames from the uplink
  then pass GRO (`offload::Gro`): consecutive full-size segments of one TCP
  flow, merged only where Linux's GRO would merge them, become one GSO frame
  with a partial checksum. Segments without a checksum verdict from the
  device are verified first. A guest thus takes one frame per up to 44
  segments.
- **Full rings hold, not drop.** A guest's RX ring has 24 slots, fewer than
  one TCP burst. Frames for a full ring wait in a per-port backlog (at most
  512 frames and 2 MiB) and are delivered in order: netd sets `rx_wanted`
  in the port and the VMM kicks netd when it frees RX slots. Frames for an
  uplink without a free TX buffer wait in a per-NIC backlog (512 frames,
  4 MiB). All backlogs share one pool of 2 KiB chunks, 16 MiB, fixed in
  netd's image. Only beyond those bounds is a frame dropped, so a guest that
  stops reading costs nobody else. Dropping instead costs a TCP
  retransmission timeout per burst.
- **NIC interrupts and notifications.** netd turns RX interrupts off while
  it drains a NIC's queue (re-checking after turning them on) and takes TX
  interrupts only while frames wait for a TX buffer. It notifies the device
  once per batch, and not while the device says it is busy with the queue
  (`VIRTQ_USED_F_NO_NOTIFY`). Each interrupt and notification is a VM exit
  in a cloud VM.
- **Learning and security.** MAC entries age after 300 s, with at most 1024
  per switch and 8192 in all. A full table drops expired entries and then
  stops learning; unknown unicast, broadcast and multicast are flooded
  within the switch. netd handles at most one ring's worth of frames per
  kick and ignores rings whose indices claim more. MAC lock is on by
  default. Isolated ports exchange no frames with each other but reach
  normal ports and the uplink (`--nic ...,isolated`).
- **Router VMs.** dom0's first vNIC takes the uplink NIC's MAC by default,
  since a cloud VPC delivers frames only for it. A router VM's other vNICs
  join internal switches and Linux provides NAT or routing. QEMU guests can
  also sit directly on the uplink switch.

**gVNIC.** `l4h-netd/src/gvnic.rs` follows Linux `gve` with the DQO queue
format and raw DMA addressing (DQO RDA), which C3 and later offer; a device
without it (GQI only) makes netd panic. It configures the device through a
big-endian admin queue in BAR 0 and rings little-endian doorbells in BAR 2.
One TX queue with its completion queue, one RX buffer queue (2 KiB buffers)
with its completion queue. As Linux, it configures a notification block per
MSI-X entry but the last; the TX and RX blocks share netd's vector and the
management vector stays masked. A DQO block masks itself when it fires;
netd re-arms RX after draining and TX only while frames wait. Transmit:
checksum offload and TSO through a context descriptor (the TCP checksum
field loses the length, as in `gve_prep_tso`), for MSS 88–9728 and headers
up to 255 bytes, else netd segments. Buffers are freed by packet
completions, or by reinjection completions after a miss completion.
Receive: the device's checksum verdict (with its packet type map) becomes
`DATA_VALID`, then GRO; the device's own coalescing (RSC) is off. On the
revision 0 device of C3, releasing an admin queue that is not registered
makes the device reset itself, so netd releases only a registered one.

**ENA.** `l4h-netd/src/ena.rs` follows Linux `ena` for the Elastic Network
Adapter of Nitro EC2 instances (1d0f:ec20 and the other IDs Linux takes).
- It resets the device, reads registers readless (the device writes them to
  DMA memory) unless the PCI revision says otherwise, and configures it
  through a polled admin queue of 64-byte commands. Host information names
  the userspace OS class, l4h's strings, spec 2.0 and driver version 2.0.0
  (Nitro accepts 1.0.0's host info but rejects CQ creation).
- One TX and one RX queue, each a submission queue with its completion
  queue, on MSI-X entry 1; entry 0 is the management vector (admin
  completions and AENQ events: netd logs link changes and errors and
  acknowledges keep-alives). Both carry netd's one vector. The device masks
  the I/O vector when it fires; netd unmasks it through the TX CQ's register
  (with 20 µs RX and 64 µs TX coalescing) after draining RX, and while frames
  wait. An RSS table sends every frame to the RX queue.
- Transmit uses the low-latency queue (LLQ) in BAR 2, which root maps
  write-combining when it fits netd's 16 MiB window: one 128-byte entry per
  frame with the metadata and buffer descriptors and the frame's first 96
  bytes, written in 64-bit stores, `sfence`, then the doorbell, at most the
  device's burst between doorbells. Without the BAR or Linux's LLQ layout,
  descriptors go to a ring in host memory. Every frame has a metadata
  descriptor; partial L4 checksums over IPv4/IPv6 are left to the device
  when offered. ENA does no TSO here: netd segments. TX buffers hold frames
  up to the device's MTU, which netd sets to its maximum.
- Receive: 2 KiB buffers, with a frame spanning several; a good L4 checksum
  on an unfragmented frame without an IPv4 header error becomes
  `DATA_VALID`.
- Not implemented: the keep-alive watchdog and device reset on errors
  (netd has no timer), and ENA Express.
- Tested on a c6i.large's secondary ENI through Linux/VFIO (`tests/ena-vfio`,
  compiling the production driver unchanged) and in full UEFI/seL4 boots on
  c6i.xlarge (`tests/ec2-test.py`): LLQ and host-memory TX pass
  packet/checksum/GSO tests, 65,600 checked UDP echoes across the 16-bit
  index wrap, and fresh MSI-X delivery. See `tests/ec2.md`.

**Intel X550.** `l4h-netd/src/ixgbe.rs` follows Linux `ixgbe` for the X550
(8086:1563, 15d1), as on Latitude.sh m4.metal servers. It resets the MAC
under the SW/FW PHY semaphore but not the PHY, which renegotiates the link
with the firmware's settings (about 7 s on 10GBASE-T), then sets up one RX
and one TX queue of advanced descriptors: 512 RX buffers of 2 KiB (larger
frames span buffers), CRC stripping, no RSC or RSS, promiscuous like the
other uplinks. RX raises MSI-X entry 0 and TX entry 1, both programmed with
netd's vector, so EIMS/EIMC mask them separately; causes auto-clear (EIAC)
and are moderated to about 20,000 per second. Receive: an L4 checksum the
device verified (L4CS without TCPE, and no IPv4 header error) becomes
`DATA_VALID`. Transmit: a context descriptor carries checksum offload for
TCP and UDP over IPv4/IPv6 and TSO (MSS 64–9216); as Linux, the TCP checksum
field loses the length and the IPv4 length and checksum are left to the
device; data descriptors take at most 16 KiB each. `tests/ixgbe-vfio`
compiles the driver unchanged into a Linux program that drives a real port
through VFIO (ARP, ICMP, DNS, UDP checksum offload, 4 KB and 60 KB TSO, both
interrupt causes).

**Tests.** `tests/fuzz-virtq` checks that GRO output segments back into
exactly the frames that went in, and that corrupted or other-flow segments
do not merge. `tests/run-nettest.sh` covers DHCP and ping over the QEMU
uplink, internal switches, multiple vNICs, isolation and MAC lock
(`NETTEST_LEGACY=1`: a legacy virtio-net uplink). `tests/run-router.sh`
uses a Debian router with nftables masquerade to connect an internal guest
to the outside.

### 9.4 Console and other devices

- **Console output.** Each vCPU writes its console output, as records
  numbered from one counter of the guest, into a ring in its event page,
  and kicks the VMM. The VMM prints the records of all rings in sequence
  order into a host-owned per-guest ring, which vmmgr reads for
  `console_read`, and, in verbose builds, to the serial port with a `[vmN]`
  prefix.
  - Head and tail wrap at twice the ring size, so their distance
    distinguishes full from empty.
  - The VMM drains at most one ring's worth before polling for other work,
    and carries any remainder forward even when the guest does not kick
    again. It tracks the next sequence, so a ring sampled empty cannot let a
    later record from another vCPU overtake it.
  - A missing sequence gets 100 ms from the first observed gap to appear
    (further kicks do not extend it), on a one-shot timer while the VMM
    serves other work. On expiry the VMM reports the missing records and
    skips to the oldest published sequence, discarding skipped records that
    arrive later, so a stalled writer cannot hold up other vCPUs' output
    indefinitely. Poweroff flushing skips gaps immediately, within its byte
    budget.
  - The VMM polls its endpoint with its notification temporarily unbound, so
    a stream of console kicks cannot take precedence over queued hypercalls.
    After rebinding it re-arms any gap deadline, since seL4 drops timer
    expiries while no notification is bound.
  - Writers never wait: output that does not fit is counted and the VMM
    reports the count, except tty output, which hvc holds until the VMM
    raises the console event for room.
- **Console input** is a ring in the guest's console device page, which hvc
  polls; power requests use the same page.
- **Control.** `l4hctl`, dom0 only (§10.1).
- **Attestation.** `L4H_DEV_ATTEST`, every guest (§10.2).
- **Memory hotplug.** `L4H_DEV_MEM`, every guest (§8.5).
- **RTC.** `/dev/rtc0`, with alarms, on the host's wall clock (§5.8).
- **Display.** virtio-gpu, 2D (§9.6).
- **Random numbers.** `/dev/hw_random` uses RDRAND (`drivers/rng_l4h.c`);
  there is no virtio-rng.
- **Not implemented:** virtio-vsock and a guest virtio-balloon.

### 9.5 IOMMU (AMD-Vi and Intel VT-d)

On an AMD or Intel host, `l4h-root` confines devices with the IOMMU, which
it drives itself (`l4h-root/src/amdvi.rs` and `vtd.rs`, selected by
`iommu.rs`). seL4 keeps `KernelIOMMU` off: its VT-d code was tested on two
chipsets, has no AMD support, and would only let root delegate I/O
mappings, which nothing in l4h needs, since root alone gives devices
memory.

Common behaviour:

- **What devices get.** Each requester group root enables gets a domain and
  an I/O page table that maps the memory its devices were given, at its
  physical address, so drivers are unchanged. The virtio drivers accept
  `VIRTIO_F_ACCESS_PLATFORM`.
  - A NIC (netd) gets its 4 MiB of DMA memory.
  - A disk controller (blkd) gets blkd's 4 MiB, and each client's I/O pool
    while it is attached. The pool is unmapped after the drain, or after a
    quarantine. Shared pools are reference-counted per domain and
    allocation, so only the final release removes their translations.
  - The balloon (memd) gets its DMA pages.
- **Requester groups.** Root walks PCI bridge headers (VT-d) or uses the
  IVHD aliases (AMD) to resolve requester aliases. Devices behind one alias
  share a domain; attaching another member adds its buffers without
  replacing existing mappings. Members of a group can reach each other's
  mapped buffers and permitted interrupts, since the IOMMU cannot tell them
  apart; root logs each device's shared requester at attach. Other groups
  stay isolated.
- **Interrupt remapping** (`iommu_intremap`, on by default). Each entry
  permits exactly one vector, delivered to APIC ID 0: AMD-Vi gives each
  group its own table, and VT-d has one table per remapping unit whose
  entries each also name one requester ID. The common `Iommu::msi` interface returns the MSI address and
  data: VT-d puts the table index in the remappable MSI address, AMD-Vi in
  the MSI data. Root programs blkd's and netd's MSI-X with them, so drivers
  write the MSI-X table unchanged, and a device can raise only its group's
  vectors.
- **Requester spoofing.** Root does not enable ACS source validation, so
  requester validation relies on the PCI fabric.
- **Tables** come from 2 MiB chunks of root memory (`layout::IOMMU_TABLES`)
  and are kept until reboot. Unmapping clears leaf entries and keeps the
  tables, so a pool slot attached again reuses them. Root stops if an IOMMU
  does not complete a command within a second, since it could then no
  longer confine anything.
- **Faults.** Root reads the event logs or fault records every 100 ms and
  prints up to 8 events per tick, with requester, address and reason.
- **Status.** `l4hctl iommu` (`CTL_IOMMU_INFO`) shows whether the IOMMU is
  on, off (`iommu=0`), absent or unusable; whether interrupts are remapped;
  the devices confined and those behind no IOMMU; and the events logged
  since boot. `l4hctl info` shows the first two in one line.
- **Off.** With no DMAR or IVRS, or `iommu=0` in `l4h.conf`, every
  operation is a no-op and devices reach all memory. `iommu_intremap=0`
  keeps DMA confined but passes interrupts unremapped. Hosts without a
  supported IOMMU include cloud VMs without a vIOMMU and aarch64. A device
  no firmware scope covers is reported at enable and left untranslated.
  Root blocks requesters with no attached devices, so an integrated GPU that
  scans out of system RAM loses its picture: use `iommu=0` there.

**AMD-Vi.**

- **Boot.** Before it enables or resets any PCI device, root reads the IVRS
  table and takes over every IOMMU on segment 0: it maps the registers and
  builds one device table for all of them, in which every device ID is
  blocked (V and TV set, no page table, no IR/IW), sets a command buffer and
  event log per IOMMU, enables them, and invalidates whatever firmware left
  cached. The IVHDs give each device ID's interrupt pass-through and SysMgt
  bits and its alias behind a PCI bridge.
- **Domains.** Each attached device's entry and its alias point to the
  group's 4-level page table; attaching a sibling preserves the alias's
  existing DMA and interrupt tables. Installing a mapping or removing its
  final owner ends with INVALIDATE_IOMMU_PAGES for the domain and a
  COMPLETION_WAIT; a new map does this too, since an IOMMU may cache missing
  entries (NpCache).
- **Interrupts.** A group gets a table of 256 entries (32-bit format), named
  in its device table entries with IntCtl "remapped". `AmdVi::msi_data`
  fills one entry per vector and returns its index. Devices root does not
  drive get IV set and no table, so their MSIs are dropped. The I/O APICs
  and HPETs (IVHD special devices) keep IV 0, since seL4 programs them in
  the compatibility format; a device that spoofs their requester ID can
  still inject any vector. Destinations are APIC IDs below 256 (no XTEn or
  GA mode). Updates invalidate the interrupt-table cache for every group
  member and the alias.
- **Unity ranges.** IVMD ranges stay mapped for the devices they name: ranges
  for all devices in one shared domain, others in a domain per range,
  aliased requests using the alias's entry at boot too. A driven group gets
  the ranges of all its members, including devices without a driver, in a
  new domain separate from boot-only domains. Recyclable DMA allocations
  cannot overlap these ranges; overlapping ranges keep the union of their
  permissions.

**Intel VT-d.**

- **Discovery.** DMAR DRHDs describe segment 0's remapping units. Explicit
  endpoint and bridge scopes take precedence over INCLUDE_PCI_ALL; paths are
  resolved through the bridges' secondary/subordinate buses. Invalid
  lengths, checksums, overlapping scopes and unsupported scope types fail
  discovery before any unit is changed. Other segments are not driven.
- **DMA.** Each unit has a legacy root table and per-bus context tables.
  Missing entries block DMA; each attached group gets a private 39- or
  48-bit second-level page table and domain ID. Contexts reject translated
  requests and ATS. RMRR ranges are identity mapped for their devices before
  translation is enabled, stay mapped across attach/unmap, and are reserved
  for the whole group. Mapping beyond the unit's address width is rejected.
  A conventional bridge aliases to its own BDF, a PCIe-to-PCI bridge to
  secondary-bus:00.0, and PCIe ports preserve IDs; the outermost alias wins
  across nested bridges. Phantom functions and device-specific requester
  quirks are not supported.
- **Invalidation.** Units with queued invalidation get a page of 128-bit
  descriptors and a completion word; older units use register invalidation
  if they support draining. Maps invalidate cached misses; unmaps invalidate
  the domain's IOTLB and wait for DMA reads and writes to drain.
  Noncoherent table walkers get CLFLUSH and barriers. Command errors or a
  one-second timeout stop root.
- **Interrupts.** When firmware and every unit support it, root enables
  remapping with a 256-entry table per unit; each IRTE permits exactly one
  requester ID and vector (SHV=0 in the MSI address). Bridge aliases apply
  even when virtio bypasses DMA translation (`iommu_platform=off`).
  Compatibility interrupts are blocked globally, so they cannot bypass
  source validation. Root matches DMAR's I/O APIC scopes to MADT IDs and
  allocates an IRTE for the UART's vector, which patch 0025 programs into
  the pin; if firmware lacks the UART's I/O APIC scope, root disables the
  monitor with a diagnostic rather than allow compatibility interrupts.
  Local APIC timers and IPIs are unaffected. Extended interrupt mode is not
  supported. Without interrupt remapping, DMA stays confined and the status
  says interrupts are not remapped.
- **Faults.** Root polls the primary fault records and counts every record
  and overflow; it masks the unit's fault and invalidation-completion
  interrupts.

**Tests.**

- `L4H_QEMU_IOMMU=intel` adds QEMU's `intel-iommu` with interrupt remapping
  and caching mode (so cached missing translations must be invalidated).
  `tests/run-vtdtest.sh` checks firmware parsing, address bounds, interrupt
  source validation and command encodings on the host; `--qemu` also runs
  virtio-blk, NVMe, VM lifecycle/unmapping, NIC and serial-monitor tests,
  including boot with remapping or the whole IOMMU disabled. An unattached
  QEMU EDU device attempts DMA and forged MSIs, which must all fault, and
  the UART's redirection entry must be remappable with commands arriving by
  interrupt. QEMU 10 passes compatibility-format interrupts through
  regardless of CFIS, so compatibility blocking is checked (CFIS clear) but
  cannot be exercised there.
- `L4H_QEMU_IOMMU=amd` adds QEMU's `amd-iommu` (`intremap=on`, with
  `kernel-irqchip=split`) on q35 and sets `iommu_platform=on` for virtio.
  `run-blktest.sh`, `run-nettest.sh` and `run-ctltest.sh` pass with it;
  with a pool left unmapped, the controller's DMA fails and the guest's
  mount fails; given an invalid index, the controller's interrupts are
  aborted while the I/O APIC's pass unremapped. QEMU logs no page fault
  events, so the event log reader is untested there.
- `tests/vtd-net-qemu.py [--iommu amd]` runs two NICs and two disk
  controllers on the root bus, behind conventional and PCIe-to-PCI bridges
  and behind nested bridges, with both `iommu_platform` settings, repeatedly
  creating and destroying a second guest that uses both disks. `--bridge
  pci|pcie-pci` also checks that an EDU sharing the disk's requester cannot
  DMA outside the group's buffers; `--no-intremap` checks DMA-only
  confinement, `--controllers 17` a shared interrupt table, and `--tap TAP0
  TAP1` uses vhost-net. The AMD-Vi PCIe-to-PCI case needs QEMU 10.2 or
  later (10.0 caches the secondary bus number before firmware assigns it);
  CI uses conventional bridges with Debian 13's QEMU 10.0.
- `python3 tests/amdvi-qemu.py` inspects the devices' and alias's shared
  tables, checks every vector, and uses EDU devices to verify that neither
  an unrelated requester nor an aliased sibling can write outside its mapped
  memory, or use the group's or an unallocated interrupt index.

### 9.6 Display: virtio-gpu

`l4h-vmm` serves a virtio-gpu device (2D, one scanout; `gpu.rs`), which dom0
gives a VM before it starts (`gpu_attach`, `l4hctl create --gpu WxH`), with
that size as the preferred mode. The guest uses Linux's `virtio_gpu`
module.

- **Buffers stay in the I/O pool.** As every virtio-l4h device, it requires
  `VIRTIO_F_ACCESS_PLATFORM`, so a resource's backing is the pool pages the
  guest's DMA layer bounced the buffer into, and the driver syncs the whole
  buffer there before every `TRANSFER_TO_HOST_2D`. The VMM keeps no copy of
  any resource: a transfer only checks its bounds. The pool must hold four
  images of the scanout (`GPU_POOL_IMAGES`); `l4hctl` sizes it so by
  default.
- **The display area.** `RESOURCE_FLUSH` of the resource on the scanout
  copies the flushed rectangle into the display area: a header (frame
  counter, size, format) and the image, host frames that the VMM and vmmgr
  both map. The VMM writes it under a seqlock (the counter is odd during an
  update), so the reader (`gpu_read`, 1 MiB per call into dom0's control
  data area) can tell a torn copy and reports it as `-EAGAIN`; `l4hctl
  screenshot` reads again and writes a PPM. The reader takes the image size
  from its own record, not the VMM's header.
- **The VMM's tables** of resources and backing (1024 resources, 65536
  pieces of backing, merged where contiguous) live in host frames mapped
  only in that VMM, so VMMs without a GPU pay nothing. Commands complete at
  once and in order, so a fence is done with its command. There is no cursor
  plane (cursor commands are dropped), no EDID, no 3D and no blob resources.
- **Memory.** The display area and tables come from the guest's arena, which
  destroy returns. A 1920 x 1200 display is about 10 MiB.
- **Not implemented:** a live view of the display (a VNC server in dom0 on
  `gpu_read`, or the host's framebuffer), input, and a cursor.

`tests/run-gputest.sh` has a VM draw with DRM dumb buffers, flip, and turn
its display off, checks every pixel of dom0's screenshots (`gpucheck`),
checks that the host refuses a display or I/O pool too small, and that
destroy returns the memory.

---

## 10. Host components

All host components are Rust: no_std, on the rust-sel4 crates `sel4` and
`sel4-root-task`. Device drivers are also Rust, following sDDF's design
(shared queues, block requests that add no host data copy, a
virtualiser/switch per device class) rather than linking sDDF's C drivers,
whose components assume a static, Microkit-shaped system.

| Component | Instances | Role |
|-----------|-----------|------|
| `l4h-root` | 1 | Boots the host and spawns the other components. Owns PCI, the IOMMU, interrupts, disks, reset and the RTC. Makes guests' I/O pools, disk channels and netd ports when vmmgr asks, and authorizes disk and NIC attachments. Serves the control ops on the host's disks, switches and NICs; runs the serial monitor and the dashboard. |
| `l4h-vmmgr` | 1 | Builds guest CSpaces, kernel VSpaces, vCPUs and boot info from memory it gets from memd; loads the guest kernel and images; measures launches; spawns guests' VMMs. Runs lifecycle, the control API and the balancer (§10.3). |
| `l4h-vmm` | 1 per guest | Serves virtio backends, console, display and hypercalls using the guest's I/O pool and host-owned pages. Never maps guest RAM. |
| `l4h-blkd` | 1 per disk controller | Validates pool addresses and LBA windows and drives a virtio-blk, virtio-scsi or NVMe PCI controller for all its clients. |
| `l4h-netd` | 1 | Runs all L2 switches, guest ports and the virtio-net, gVNIC, ENA and X550 uplink drivers. |
| `l4h-trustd` | 1 | Maintains taint/seal flags; with a TPM, quotes its signing key and signs guests' reports (§10.2). |
| `l4h-memd` | 1 | Owns free memory and every guest's RAM blocks; gives root and vmmgr memory for host objects; serves memory hotplug; reports free memory to the hypervisor (§8.4). |

**No dynamic allocation.** Nothing a guest, dom0 or a device does may
exhaust a host component's memory: a component that runs out cannot
recover, and with it go every guest it serves (root, vmmgr or memd: the
whole host). Their state is sized at start, from constants (`MAX_GUESTS`,
queue sizes) or from the host (memd's table), and lives in fixed arrays and
tables. Where allocation is truly needed, it is bounded by a stated limit
checked before the allocation, fails as an error rather than a panic, and is
never made per request on a path whose size a guest or client controls. A
component without a heap says so (`component!(main, no_heap)`, or for root
a `#[root_task]` without `heap_size`) and does not link `alloc`: root, vmmgr, memd, netd, blkd and the VMM have none, and keep
state too large for a stack in statics (`l4h_host::fixed::{StaticCell,
Scratch}`). The one heap is trustd's, for the third-party AML interpreter of
the TPM start method; its size (`aml::HEAP`) is bounded by the firmware's
tables, which trustd checks first.

**Stacks.** Every stack has an unmapped page below it, so an overflow faults
rather than writing over statics: root maps each component's stacks (its
main thread's and its keeper's) in a region of their own
(`l4h_host::STACK_TOP`), and unmaps the lowest page of its own stack, which
seL4 places in its `.bss`. Stack probes touch every page of a large frame
in order, so one guard page catches any overflow. Root's and vmmgr's main
stacks are 1 MiB.

**Crates.** `l4h-abi` mirrors the guest ABI and `l4h-virtio` implements the
virtio PCI transport for host drivers. Host infrastructure is divided by
responsibility:

| Crate | Responsibility | Boundary |
|-------|----------------|----------|
| `l4h-host` | Component protocols, address-space and CSpace layouts, shared data structures, bounded containers, pure validation helpers. | Independent of seL4 calls, runtime initialization and task ownership. |
| `l4h-rt` | Component entry, TLS and IPC-buffer setup, panic handling, keeper threads, optional heap, runtime conveniences. | Runs a component on resources its parent provisioned. |
| `l4h-task` | Kernel-object and CSpace allocation, memd grant client (`memd::MemdLink`), ELF loading, component spawning, CPU topology, VSpace/scratch mappings. | Callers supply capabilities, storage, mappings and ASID assignment; boot setup, authorization and placement policy stay in the executables. |

`l4h-rt` and `l4h-task` both depend on `l4h-host` and are independent of
each other. Shared code lives in a library imported through Cargo;
executables never import another executable's sources. Root and vmmgr use
`l4h-task` to allocate objects, build address spaces and spawn components,
each with its own CNode, allocator storage, scratch VSpace, memd endpoint
and exchange slots; ASID-pool ownership and assignment stay local. blkd,
netd, trustd and the VMM use capabilities and mappings installed by their
parent and need only `l4h-rt`. memd's allocator, which tracks physical
blocks, ownership, retained originals and reporting, is memd's own.

**Serial output** uses seL4's printing syscall; root drives COM1 input for
the monitor. A kernel print is a synchronous serial write with interrupts
off, which stalls its core for the whole message, so prints are rare:

- informational messages (device discovery, guest lifecycle, balancer
  moves) use `info!`, which prints only when `host::VERBOSE`, not in
  `L4H_RELEASE=1` builds. Release builds print critical errors only, and
  repeated ones (failed I/O) only the first few times (`l4h_rt::ErrorLimit`);
- guest consoles, dom0's included, are copied to the serial port only when
  verbose; they always go to the console rings `console_read` serves;
- the serial monitor's replies and the opt-in watchdog dumps always print.

**Host log.** Diagnostics from root, vmmgr, VMMs and device services also go
to a shared, bounded log ring (`l4h_host::log`), including `info!` in
release builds, Rust panics and keeper fault reports. `l4hctl logs` reads a
snapshot and `--follow` polls for new records (`CTL_LOG_READ`, dom0 only,
with independent sequence cursors and an explicit count of unavailable
records). Guest kernel faults include the VM id, vCPU and fault registers;
guest power requests distinguish power off, reboot and kernel panic.
- The ring keeps 256 records in 132 KiB, each with elapsed host time and
  component id, at most 480 bytes with an explicit truncation marker. Root
  owns the page-aligned storage and shares only those frames; destroying a
  VM neither revokes them nor clears its diagnostics. Logs do not survive a
  host reboot.
- Writers format on their own stack and publish with atomic memory
  operations, without allocating, making an IPC or touching message
  registers, and never wait on a lock: a writer preempted or faulting in a
  slot leaves the others the remaining slots. Readers validate the slot
  generation around atomic payload reads and report overwritten, dropped
  and incomplete records as unavailable; no reader consumes another's
  history or blocks the host.
- Querying needs a working dom0 and vmmgr; this does not capture seL4's own
  debug stream or make a crashed host queryable.
- `tests/run-logtest.sh` checks kernel faults, panics and shutdowns retained
  after VM destruction and read with `l4hctl` (also with `L4H_RELEASE=1`).

**Guest boot protocol.** The guest boots without firmware or a bootloader.
vmmgr loads the guest kernel's segments and the initramfs dom0 uploaded
into the guest's boot blocks, builds the kernel VSpace and
`struct l4h_bootinfo`, then starts vCPU0 at the entry point with `rdi`
(`x0` on aarch64) pointing at boot info. It holds:

- a magic number and the guest ABI version (`L4H_ABI_VERSION`, currently 6);
- the guest id;
- RAM size, direct-map base (`ram_base_va`), block and boot-block counts;
- the kernel's end and the initramfs's GPA and size;
- the I/O pool's and the hotplug region's GPA and size;
- the vCPU count and pre-assigned VSpace count;
- the time-counter frequency (`tsc_hz`);
- boot flags (`L4H_BOOT_DOM0`);
- the device table;
- the kernel module image's address and size (`kmod_va`, `kmod_size`);
- the command line;
- on aarch64, the CPU feature ID registers.

Capability slots and special mappings, including event-page addresses, are
defined by `include/l4h/abi.h`, the single source of truth, which the guest
includes directly. `host/l4h-abi/src/lib.rs` is a handwritten Rust mirror
with layout assertions.

### 10.1 Control plane: dom0 and the runtime API

**Boot modules.** `tools/build-host.sh` builds the services and root, and
`host/l4h-root/build.rs` embeds the services' ELFs (vmmgr's embeds
l4h-vmm's). The guest kernel and its module tree (§5.6), dom0's initramfs
and the host settings are named modules (`guest-kernel`, `guest-kmods`,
`dom0-initrd`, `l4h-config`); root has none built in. They come from:

- **the boot loader** (deployment). l4h ships as one UEFI application per
  seL4 variant (§11), the same for every host. GRUB passes the guest kernel
  and its module tree from its memdisk, and `/l4h/dom0/initrd` and
  `/l4h/l4h.conf` from the EFI partition, as boot modules; on BIOS, GRUB
  passes the same files from a directory on a filesystem. seL4 keeps them
  intact (patch 0021), and root keeps them mapped, since restarting dom0
  loads them again. QEMU's multiboot `-initrd` can pass the same modules;
- **root's own ELF** (x86_64 and aarch64, which has no boot loader that
  passes modules). `tools/add-modules.py` appends the files to a built
  `l4h-root.elf` as one more `PT_LOAD` segment, right after root's last,
  reusing the program header of `PT_GNU_STACK` (which seL4 ignores), and
  writes the segment's address and size into an anchor static in root
  (`bootmod.rs`). The kernel or loader maps them with the rest of root; no
  Rust is rebuilt. The QEMU scripts do this from `L4H_GUEST_KERNEL`,
  `L4H_GUEST_KMODS`, `L4H_DOM0_INITRD` and `L4H_CONFIG`
  (`tools/dom0-modules.sh`).

Boot loader modules win over appended ones of the same name. Without a
`guest-kernel`, root starts no vmmgr and no guests and serves only the
serial monitor. Root maps the guest kernel, its module tree and dom0's
initramfs read-only into vmmgr, which loads dom0 from them.

**Settings.** dom0's memory, vCPUs, I/O pool, disks and its window of disk
0, NICs, internal switches and command line; the uplink NICs, the boot
disk, the serial port and IRQ, the framebuffer console, the IOMMU and the
watchdog default to the `L4H_*` variables root was built with. `l4h.conf`
overrides them: one `key=value` per line, lowercase without the prefix
(`dom0_mem_mb=1024`, `uplink_nic=01:00.1`). GRUB sources the same file for
`serial_port` and `fb_console`, so it is written as GRUB script: no spaces
around `=`, values with spaces in double quotes. Root reports unknown keys
and bad scalar values and keeps the defaults. The user manual lists the
settings.

**dom0's disks.**

- `dom0_disk0_windows=start:count,...` exposes each selected partition of
  an existing GPT installation as a separate filesystem device. Values are
  in 512-byte sectors, multiples of eight, counts positive. The list replaces
  disk 0 and requires `dom0_disks` > 0 and `dom0_disk0_mb=0`. Invalid,
  overlapping, excessive or out-of-bounds ranges stop boot; they never grant
  access to the whole disk. Other host disks keep their order after these
  devices.
- dom0's whole device plan must fit in 64 slots, including console, control,
  memory and attestation devices, all disk windows and NICs; oversized plans
  stop boot, and neither list is truncated.
- Root reserves every boot disk range before attaching it and keeps those
  reservations across dom0 restarts. If an attachment fails, dom0 gets a
  zero-capacity, read-only virtio-blk device in that position, which fails
  all I/O without a driver channel or DMA mappings, so other disks keep their
  names and dom0 can still boot. The range stays reserved against
  provisioning and conflicting attachments. When a failed disk cannot report
  its capacity, root checks the configured ranges for alignment, overflow
  and overlap and reserves them; a whole-disk reservation covers all aligned
  sectors. The same applies to an automatically selected whole disk whose
  capacity is not a multiple of eight sectors.
- dom0 sees filesystem devices, not the physical partition table: GRUB reads
  the physical GPT before l4h starts, and both GPT headers stay intact.
  Mounts must use filesystem UUIDs or labels. Partition changes and boot
  loader installation need native Linux. A storage allocator must use an
  explicit data range that excludes system partitions, boot loader sectors
  and GPT metadata.
- dom0 can rewrite the EFI partition when it holds the boot disk, so a
  compromised dom0 persists across reboots. That is within dom0's trust (it
  decides what runs), and Secure Boot is off, but GRUB measures the files
  into the TPM, so a host's attestation shows what dom0 booted (§10.2).

**The control device.** dom0 is guest #0 and receives a host-owned
`l4hctl` device page whose kick notification is vmmgr's; other guests have
none. dom0 runs no host hardware drivers.

- dom0 writes a fixed-layout request (`struct l4h_ctl_req`) into the page,
  bumps its `seq` and signals the kick. vmmgr executes the request, writes
  the response into the same page, sets `done` and raises the device's
  event; the calling task sleeps meanwhile, and the vCPU runs others.
- `/dev/l4hctl` (mode 0600, and `CAP_SYS_ADMIN`) takes one ioctl that
  carries a request, its response and, for `VM_LOAD`, a user buffer. The
  driver stages the buffer in the control device's data area, 1 MiB of
  host-owned frames mapped into dom0, so vmmgr never reads dom0's RAM. The
  data area is root's memory, made once and mapped into every dom0 and into
  vmmgr (read-write, for `VM_LOAD` and `GPU_READ`) and root (read-only, for
  `BLK_WRITE`).
- Requests and responses are synchronous, fixed-layout, little-endian
  structs defined in `abi.h` and mirrored in `l4h-abi`. The control version
  (`L4H_CTL_VERSION`) is 3; it changes only for incompatible changes, not for
  new operations.

| Area | Operations |
|------|------------|
| Host | `host_version` (the build version; the tag for a release); `host_info` (cores, free/total bytes, disk, VM and NIC counts); `host_reboot`; `rtc_set`; `iommu_info` (§9.5); `log_read` (§10) |
| Guests | `vm_create`, `vm_load`, `vm_start`, `vm_shutdown`, `vm_destroy`, `vm_list`, `vm_info` (cores of the first six vCPUs), `vm_stats` (CPU use and cap), `vm_set_sched`, `vm_set_mem`, `vm_mem_info` (§8.5), `vm_trust` (flags, §10.2) |
| Block | `blk_attach` (disk, read-only and volatile flags, LBA window), `blk_write` (provisioning), `blk_info`, `disk_info` |
| Network | `switch_create`, `switch_attach_uplink`, `nic_create` (MAC, MAC lock, isolation), `switch_info` (ports with VM and MAC, counters), `nic_info` (PCI address, switch, MAC) |
| Console | `console_read` (offset, bytes and lost-byte count), `console_write` |
| Display | `gpu_attach` (scanout size), `gpu_read` (the image, 1 MiB at a time, with size, format and frame; §9.6) |

A Rust userspace library and CLI live in `tools/l4hctl`; external
orchestration runs in dom0. Devices are attached before start and removed
on destroy. Pause/resume, device hotplug, switch deletion, I/O limits and
asynchronous event queues are not implemented; `vm_pause` would need more
than suspending the vCPU kernel thread, which does not stop a user thread
holding SC_U.

**Lifecycle.**

- `vm_create` → (`blk_attach` / `nic_create` / `gpu_attach` / `vm_load`)\*
  → `vm_start` → `vm_destroy`. `l4hctl` loads the initramfs with raw
  `VM_LOAD(vm, gpa, bytes)` writes from the GPA `vm_create` returns; vmmgr
  copies page by page from the data area into the guest's boot blocks and
  never parses what guests load. `vm_start` loads the kernel, measures the
  launch, writes the boot info and spawns the guest's VMM.
- `vm_shutdown` (`l4hctl shutdown [--reboot]`) is the ACPI power button:
  vmmgr sets `power_request` in the guest's console page and raises the
  console event on vCPU 0, and the guest runs `orderly_poweroff()` or
  `orderly_reboot()`. The guest also reads `power_request` once its handler
  is installed, since an event raised during boot finds none.
- `host_reboot` (`l4hctl host-reboot`) resets the machine, so dom0 can boot
  a new l4h or dom0 it wrote to the EFI partition. Root resets as Linux
  does: the FADT's reset register (system I/O, memory or PCI config space),
  the PCI reset control register at 0xcf9, then the keyboard controller. It
  returns `EIO` only if the machine did not reset; aarch64 has no reset
  (`ENOSYS`). Every guest stops without notice, so dom0 shuts down guests
  that matter first. Root flushes nothing: every guest flush reaches the disk
  before it completes (except on a volatile attachment), so dom0 syncs what
  it wrote first.
- **Reclaim.** Each guest holds RAM blocks (in memd) and a host-object arena
  in vmmgr, and in root its I/O pool and an arena for its disk channels and
  netd ports. CNode slots allocated on its behalf are tracked: vmmgr and root
  each keep a bitmap of free slots and an owner byte per slot (`mem::Slots`,
  288 KiB for vmmgr's 2^18 slots, 576 KiB for root's 2^19), and destroy
  deletes the guest's by a scan of owner bytes. Destroy order is in §10.3.
  ASIDs are released by the kernel when VSpaces die. Repeated
  create/destroy leaves free memory unchanged (`tests/run-ctltest.sh`).
- **Disk detach.** A disk window is detached only when its guest is
  destroyed, and the shared controller keeps running. Root asks blkd to
  drain the client (`BLKD_REMOVE`): every request it submitted completes
  before the pool can be reused, then root unmaps the pool from the
  controller's IOMMU domain. Clearing bus mastering alone would not be a
  drain, since a device can complete a command it already started. If blkd
  has failed or the drain times out (five seconds), root quarantines the
  controller: it suspends blkd and disables the PCI function, marks the
  controller failed until host reboot (`blk_attach` returns EIO, `l4hctl
  disks` says so), and keeps the guest's pool and blkd's DMA memory out of
  the free pool, unless an IOMMU has cut the device off from the pool
  (§9.5). `tests/run-ctltest.sh` destroys guests in the middle of throttled
  reads on virtio-blk and NVMe, and checks that the next guest, which reuses
  the memory, sees no disk data appear in it.

**Policy and safety.**

- vmmgr enforces resource accounting for guests (memory, cores) and root
  for what it makes for them and for disk ownership (a writable window is
  attached to at most one VM). Both reject invalid requests. dom0 cannot
  breach host isolation, but it is fully trusted to decide *what* runs; in
  particular it can attach any disk to itself.
- If dom0 reboots or crashes, the other guests keep running. vmmgr destroys
  it and boots it again from the same images and settings, and the new dom0
  recovers state with `vm_list` and `switch_info`; authoritative state lives
  in vmmgr (guests), memd (memory targets) and root (disks, switches)
  (`tests/run-m6test.sh`).
- The serial monitor (§7.6) stays available on COM1, which is the GCE serial
  console.

### 10.2 Attestation

A guest can prove to a remote verifier what it booted, and on which host.
The chain has four links.

1. **Measured boot.** The firmware measures the UEFI application into PCR 4.
   The application holds seL4, `l4h-root` and every host component (§11),
   so one digest covers the whole host. GRUB's `tpm` module measures dom0's
   kernel, initramfs and `l4h.conf` into PCR 9, and its commands into PCR 8.
   Secure Boot is not needed: nothing is checked at boot; the verifier
   checks afterwards. A BIOS boot measures none of this (BIOS GRUB has no
   `tpm` module), so such a host's quotes say nothing about what it booted.
2. **The host key.** `l4h-trustd` is the only component that maps the TPM,
   which root finds in the ACPI `TPM2` table (see **TPM interfaces**).
   trustd polls it at locality 0, sleeping on its E3 timer between polls
   (20 µs up to 2 ms). It runs on the last core at `P_K + 1` with at most
   5 ms of every 20 ms, so neither a slow TPM nor the firmware's AML can
   take a core from guests. At start, trustd:
   - generates a P-256 key K in software, from TPM randomness;
   - creates the attestation key (AK), a restricted ECDSA P-256 signing
     primary key of the endorsement hierarchy, so the same template gives
     the same key every boot. It has an empty password and `noDA`: trustd
     never shuts the TPM down orderly, which the TPM counts as a failed
     authorization, so a protected key would lock out after a few boots;
   - quotes PCRs 0–15 with the AK, with `SHA-256("l4h-trustd-key-v1" ‖ K)`
     as qualifying data;
   - extends PCR 15 with that same value.

   The quote shows PCR 15 as zero, which only a quote taken before the
   extension can, so K is the only key trustd issued since the TPM was last
   reset. After start, the TPM is used only for ActivateCredential. With
   swtpm, start takes 0.4 to 0.6 s; earlier guest requests are answered
   once it is done.
3. **Reports on guests.** vmmgr measures each guest as it boots it, dom0
   included. The launch digest is `SHA-256("l4h-launch-v1" ‖ ram_base_va ‖
   entry ‖ kernel_end ‖ RAM[0, kernel_end) ‖ initrd size ‖ initrd ‖ cmdline
   length ‖ cmdline)`, with u64 little-endian integers.
   - vmmgr reads the image back from guest RAM before the guest starts, and
     `vm_start` fails if dom0 loaded anything outside the initramfs. vmmgr is
     in the host TCB for this: whoever builds a guest can make it run
     anything.
   - vmmgr passes the digest to root (`TRUST_REGISTER`), which writes
     {instance, RAM, vCPUs, dom0, digest} into a registry page that trustd
     maps read-only. Root never waits for trustd's main thread, whose TPM
     commands can take seconds.
   - Each guest has an attestation device (`L4H_DEV_ATTEST`). Requests are
     asynchronous, so a vCPU never waits for trustd: the guest writes its
     request into the device page, then a new sequence number, and signals
     the kick, whose badge is the guest's id, so trustd answers a guest only
     about itself. trustd answers in the page, sets `done`, and asks root
     (`ROOT_CALL_ATTEST_DONE`) to have the device's event raised on vCPU 0
     (root tells vmmgr through its events page). Linux sleeps the caller
     meanwhile.
   - trustd owns the 64 request pages, one per guest id, and root lends one
     to each guest, so a page stays mapped in trustd while it answers a
     guest being destroyed. trustd drops an answer whose guest's instance
     changed while it worked.
   - `L4H_ATTEST_REPORT`, with 64 bytes of the guest's data, returns a
     COSE_Sign1 (ES256) signed by K, carrying a CBOR map `v` (1), `ram`,
     `data`, `dom0`, `host` (SHA-256 of K), `seal`, `guest`, `taint`,
     `vcpus`, `launch` and `instance` (unique per guest created since boot),
     in deterministic key order. The two bitmaps are 32-byte strings, bit n
     in bit n % 8 of byte n / 8. A report is at most 512 bytes and fits in
     one answer.
   - `L4H_ATTEST_EVIDENCE` returns the host evidence, a CBOR map: K as a
     COSE_Key, the AK's `TPMT_PUBLIC`, the quote (`TPMS_ATTEST`) and its
     signature, the quoted PCR values, and the EK certificate if the TPM has
     one in NV. It is fixed at startup and comes in pieces: each request
     gives the offset its answer starts at.
   - Linux exposes both as configfs-tsm reports (provider `l4h`: `inblob`,
     `outblob`, and the evidence as `auxblob`) and through
     `/dev/l4h-attest` (`l4hctl attest`).
4. **Verification.** `tools/l4h-attest.py verify` checks that:
   - the AK is a fixedTPM restricted signing key, and the quote verifies
     under it;
   - the quote's qualifying data is K's hash;
   - the PCR values match the quote's digest, and PCR 15 is zero;
   - the PCRs have the expected values (`--pcr`);
   - the EK certificate is issued directly by the CA certificate given with
     `--ek-ca` (no chain building);
   - the report verifies under K and carries the verifier's nonce and the
     expected launch digest. `measure` computes the digest from the kernel
     (`vmlinux` in a release's debug archive), initramfs and command line.

   **AK enrollment.** A quote only proves something if the AK is in a real
   TPM. `make-credential` encrypts a secret to the EK (from its certificate)
   bound to the AK's name (TPM2_MakeCredential). A guest decrypts it with
   `l4hctl attest activate`, which runs TPM2_ActivateCredential with a
   PolicySecret(endorsement) session for the EK; only the TPM holding both
   keys can. The verifier then pins the AK's name (`--ak-name`), which is
   stable across boots.

   **Rate limit.** ActivateCredential is the only request that uses the TPM
   (about 80 ms on a discrete Infineon TPM), and trustd answers one request
   at a time. Each guest instance may make 5 at once, then one a second
   (GCRA, one timestamp per guest id, reset when a new guest takes the id);
   beyond that trustd answers `-EAGAIN` without using the TPM. Reports,
   evidence, ACT and SEAL cost no TPM time and are not limited.

**Taint and seal.** Each guest instance has two set-only 256-bit bitmaps.
Taint bit b records that action b happened; seal bit b prevents it from
happening. `ACT(bits)` atomically refuses with `-EPERM` if any requested bit
is sealed, otherwise taints all of them. `SEAL(bits)` sets seals. Neither
dom0 nor the guest can clear either bitmap. A verifier's check
`taint & mask == 0 && seal & mask == mask` covers the past and the future;
checking taint alone leaves a session key exposed after its report.

| Bits | Who acts | Who seals | Meaning and trust |
|------|----------|-----------|-------------------|
| 0–31 | Host actor (vmmgr) | Guest userspace | Host TCB enforces the refusal; 0 is `CONSOLE_IN`, 1 is `CONSOLE_OUT`, 2–31 reserved |
| 32–63 | Reserved for host actors | Nobody | Reserved |
| 64–127 | Guest kernel | Nobody | Bit 64 + Linux's taint flag; trusted as far as the measured kernel |
| 128–255 | Guest userspace | Guest userspace | Workload-defined actions; the workload must honour refusal |

- `CONSOLE_WRITE` takes `CONSOLE_IN` before injecting bytes, including input
  queued before start. `CONSOLE_READ` and `GPU_READ` take `CONSOLE_OUT`
  before disclosing text or pixels. Empty operations do not taint; a write
  that finds its ring full does. Every call checks seals, empty ones
  included. An image copied into dom0's data area taints even if it changed
  and the read returns `-EAGAIN`. dom0's own console is exempt. The serial
  monitor never injects guest input. Debug builds also copy guest output to
  the physical serial port; that is trusted debug output, not a dom0
  control op.
- **Rule for new control ops:** reading or changing a running guest's state
  outside the devices attached before start needs an action bit, recorded
  before the effect and refused after sealing. Register access, memory
  dumps, snapshots and migration must follow this rule. An op without a bit
  stays available on a sealed guest, so adding one is an
  attestation-visible decision. Scheduling, shutdown, destruction and
  cooperative memory hotplug are dom0's availability decisions; host
  metadata queries disclose no guest state. Disk and network choices are
  outside the launch measurement.
- **The flags service.** A passive thread in trustd is the sole writer of
  an 8 KiB flags area: 64 entries of 128 bytes, each with a seqlock,
  instance and the two bitmaps. Readers (the host actor and trustd's main
  thread) map it read-only and retry an odd or changed sequence. Root assigns
  monotonically increasing instances at `VM_CREATE` and publishes them in
  the registry at start. An entry for another instance reads as empty; a
  higher-instance request replaces an entry, an older one gets `-ESRCH`.
  Destruction does not clear flags.
- **Callers.** The flags endpoint has badged callers: `FLAGS_ROOT` (used by
  the host actor) can ACT on defined host bits, and `FLAGS_TRUSTD` (guest
  requests) can ACT on guest bits and SEAL defined host or userspace bits.
  Kernel bits cannot be sealed. All arguments are validated before any
  entry changes. Requests are MR0 op, MR1 id, MR2 instance, MR3–6 bitmap,
  MR7 options; replies MR0 status, MR1 instance, MR2–5 taint, MR6–9 seal.
  The thread runs at root's priority on the caller's donated scheduling
  context, with no heap, TPM, AML or calls back; a fault in it is a host
  bug.
- **Ordering.** An actor first checks the seal in a consistent entry. If the
  taint is already set, no IPC is needed; otherwise ACT must succeed before
  the operation. This costs one IPC per action kind per instance. ACT and
  SEAL serialize in the flags thread. An operation that passed its check can
  land after sealing, but its taint was set before that seal, so a report
  showing a clean sealed bit guarantees the action has never happened and
  never will (not that an already-tainted action is no longer in flight).
- **Guest interface.** ACT (4) takes a 32-byte bitmap and an optional u32
  options word, SEAL (5) a 32-byte bitmap; each returns 32 bytes of taint
  then 32 of seal. An empty ACT reads the flags. `L4H_ACT_SEAL` on userspace
  bits taints and seals atomically, giving at-most-once actions even between
  racing processes. Failed multi-bit ACTs change nothing; invalid ranges or
  options get `-EINVAL`, and a host without these ops `-ENOSYS`. The Linux
  driver refuses userspace ACTs below bit 128 with `-EPERM`. Its `add_taint`
  hook accumulates kernel bits atomically, sends them from workqueue
  context, and flushes them under the request lock before any report; probe
  sends existing taints, failed sends are retried, and the kernel never
  seals on its own.
- **Tools.** `l4hctl attest flags`, `seal console-in|console-out|BIT...` and
  `act [--seal] BIT...` expose the gates; refused actions exit 1. Sysfs
  `/sys/kernel/l4h/attest/{taint,seal}` prints bit lists. A measured
  initramfs seals early by calling `l4hctl attest seal console-in` from init;
  input queued before it is still recorded. dom0's `VM_TRUST` (30) reports
  bits 0–63 only; `l4hctl list` shows seals. The verifier prints host names
  and Linux taint letters and accepts `--deny-taint` / `--require-seal` as
  comma-separated names, numbers and ranges; by default it denies
  `console-in` (`--deny-taint ''` opts out). Bitmaps may grow: at least 32
  bytes are required, and bits beyond their length count as clear.

**Without a TPM.** trustd always starts, on both architectures. With no TPM,
an unsupported one, or a failed initialization, it is a flags-only service:
ACT, SEAL and VM_TRUST work, while REPORT, EVIDENCE and ACTIVATE return
`-ENODEV`. `L4H_ATTEST_NO_REPORTS` (set by root when no TPM was found, or by
trustd on failure) tells Linux, which keeps `/dev/l4h-attest` and registers
configfs-tsm only when reports work; `l4hctl attest report` says `no TPM:
flags only`. Local seals still work, but have no remote proof. A later TPM
command failure returns `-EIO`.

**TPM interfaces**, following Linux's `tpm_crb` and `tpm_tis`:

- **FIFO (TIS)**, start method 6: locality 0's registers at the TPM2
  table's address, or 0xfed40000 if it gives none.
- **CRB**, start method 7: the locality registers, the control area at 0x40
  in their page, and the command and response buffers it names. Buffer
  sizes come from the CRB registers; Linux also clips them to the device's
  `_CRS`, which trustd does not.
- **CRB with the ACPI start method**, 2 or 8: AMD's firmware TPM in the PSP,
  with no locality registers or idle state and buffers in reserved RAM.
  Every command starts with the TPM device's `_DSM` (function 1 of GUID
  `6bbf6cab-…`), firmware AML. Root gives trustd the FADT, DSDT and SSDTs;
  trustd loads them into the `acpi` crate's interpreter, finds the
  `MSFT0101` device whose `_DSM` offers that function, runs only its and its
  parents' `_INI`, and calls the `_DSM` after setting the start bit.
  - Accesses outside trustd's own TPM ranges go to root (`ROOT_CALL_HW`),
    which refuses RAM, device memory in use, I/O ports already handed out,
    and config writes to the PCI functions the host drives; refused reads
    return all ones.
  - The interpreter runs in trustd, not root, because it can panic on some
    AML. If trustd's main thread faults, root suspends only it, revokes the
    guests' kick capabilities, marks every attestation page failed and
    answers pending requests with -EIO; no new guest gets attestation. The
    flags thread stays alive, so seals stay enforced.
  - The crate is pinned to an upstream commit past 6.1.1, whose buffer
    comparison, needed by every `_DSM`'s UUID check, panics.
- **CRB with Pluton**, start method 13: the start and reply doorbells named
  in the TPM2 table, rung after each request. Untested: QEMU has no Pluton.

**Trust.** A report is worth what the host TCB is worth: seL4, root, vmmgr,
memd, trustd, blkd, netd and the guest's VMM (§3), all identified by PCR 4.
dom0 decides what runs but cannot forge a report, because vmmgr computes the
launch digests and trustd answers each guest only about itself. Not
covered:

- **The event log.** GRUB's multiboot2 path exits boot services without
  fetching the firmware's event log, and seL4 hands boot-services memory to
  root as RAM, so the log is lost. A verifier pins PCR values from a
  known-good boot of the same application on the same kind of machine; they
  also depend on the firmware (PCRs 0–7) and dom0's files and settings
  (PCRs 8–9). A small EFI shim in front of GRUB could save the log.
- **DMA.** Without a supported IOMMU (§9.5), a malicious device can DMA
  anywhere. With one, it reaches only memory it was given and raises only
  its own interrupts, except that a device spoofing an I/O APIC's requester
  ID can inject any vector.
- **The cloud provider.** On a cloud VM, the provider's hypervisor and vTPM
  are trusted too, and nothing is encrypted.
- **Disks and networks** are dom0's choice and not measured, as for
  confidential VMs.
- **ActivateCredential** creates the EK on first use, which takes a hardware
  TPM seconds for RSA; other guests' requests wait (their vCPUs do not). The
  rate limit bounds each guest, not the number of guests.
- **aarch64** has no TPM path; local flags and seals work.

**Tests.** `tests/run-trusttest.sh` checks badge/range validation, atomic
gates, instance reuse, concurrent snapshots and verifier policy;
`tests/run-flagstest.sh` is a flags-only boot on either architecture.
`tests/run-attesttest.sh` checks signed flags, console/display seals, kernel
taints, racing userspace gates and pre-start input, and boots under OVMF
with swtpm three times (CRB, FIFO, then CRB with the ACPI start method),
checking the whole chain each time, the credential included. For the third
boot GRUB replaces QEMU's TPM2 table with one for start method 2 and adds
an SSDT (`tests/ftpm`) with an `MSFT0101` device whose `_DSM` does what the
PSP firmware would: take the locality, start the command, wait for it, and
count on QEMU's debug port. QEMU ignores the start bit without a locality,
so a command only runs if trustd ran the `_DSM`. `tools/mkefi.sh` swaps the
tables with `L4H_ACPI_TABLES` and `L4H_ACPI_EXCLUDE`, which can also work
around broken firmware tables.

### 10.3 Guest manager: l4h-vmmgr

Root holds every capability on the host: device memory, interrupts, I/O
ports, PCI configuration, the IOMMU and the components' CSpaces.
`l4h-vmmgr` builds and runs the guests, so a bug on the path from a guest,
its VMM or dom0 does not run with all of that. Only vmmgr and trustd call
root.

- **vmmgr holds** memd grants for guest objects, the guests' CNodes,
  VSpaces, vCPUs and VMMs, copies of every core's SchedControl, and the ASID
  pools (root makes all eight at boot and hands them over, keeping
  ASIDControl). It runs guest creation, image loading and the launch digest,
  start, shutdown and destroy, dom0's boot and restart, the balancer and
  steal time (§7), memory targets (§8.5) and the control API. Guests' VMMs
  call it, and guest kernels and VMMs fault to it.
- **Root holds** what devices reach. A guest's I/O pool is root's: root maps
  it into the IOMMU domains of the guest's disks by physical address. If
  vmmgr named addresses, a compromised vmmgr could have root give a device
  any memory, so vmmgr names guest ids, disk numbers, LBA windows and sizes,
  root checks them against its own table (`vmmgr::RootGuest`), and every
  address root gives the IOMMU, blkd or netd comes from that table. Disk
  channels and netd ports are root's too, in a per-guest arena root revokes
  when vmmgr is done with the guest. Root also numbers guest instances, so
  they stay unique since boot whatever vmmgr does.
- **The interface** (`l4h_host::vmmgr`) is a handful of calls from vmmgr to
  root, with integers in message registers: `GUEST_NEW` (the pool and the
  attestation device), `GUEST_DEL`, `DISK_ATTACH`, `NIC_ADD`,
  `TRUST_REGISTER` (the launch digest), and `HOST_OP`, which carries the
  control ops on the host's disks, switches and NICs, reset and RTC as their
  `CTL_*` number and six arguments, with data returned in a result page.
  Capabilities cross in vmmgr's exchange slots, which root reaches through
  vmmgr's CNode. Root empties a slot before filling it, so a slot vmmgr left
  full cannot make root fail, and takes no capability from vmmgr: even the
  notification blkd and netd signal for a guest's VMM is made by root at
  `GUEST_NEW`, so it cannot be an endpoint that would block them.
- **Root never calls vmmgr**, so calls cannot deadlock. It signals vmmgr's
  notification instead, with news in an events page: trustd answered a
  guest (vmmgr raises its attestation event), or the serial monitor asked
  for `destroy` or `restart-dom0`. vmmgr publishes its guests in a status
  page for the monitor's `list` and the dashboard.
- **Destroy.** vmmgr stops the guest and revokes its own arena (VSpaces
  first, so nothing is unmapped page by page), then `GUEST_DEL` has root
  forget it in trustd, remove its ports, quiesce its disks and only then
  revoke the pool (kept out of use if a disk did not stop), and finally memd
  revokes the guest's RAM blocks (§8.4). The call to root is synchronous, so
  a disk reset holds up vmmgr for its timeout.
- **Boot modules.** Root maps the guest kernel, its module tree and dom0's
  initramfs read-only into vmmgr, with a CNode of their frames, so guests
  can share the kernel's read-only blocks and the module tree (§5.6).
- **dom0's devices.** Root makes the switches at boot, attaches the uplinks,
  and chooses dom0's disks and vNICs (`Dom0Plan`); vmmgr creates every dom0
  with them.
- **Trust.** vmmgr is in every guest's TCB: whoever builds a guest's CSpace
  can copy its frames. The console seals (§10.2) are vmmgr's to keep: it
  reads the VMM-written console rings and display areas and acts on
  trustd's flags. A bug in vmmgr reaches guests' memory but not the
  hardware, the IOMMU, the TPM or root.
- **If vmmgr fails**, guests keep running: their vCPUs, disks, networks and
  memory hotplug need nothing of vmmgr. Like blkd, netd and memd it has a
  keeper thread (`l4h_rt`), which reports the fault and answers every later
  call with a failure, the call vmmgr was serving first (its reply object is
  in `SLOT_REPLY`), so a VMM's call or a guest's power request returns
  instead of blocking. For dom0's control requests, the failure service
  writes EIO, publishes the completion and raises the device event, for an
  outstanding request and later ones, using pages and a notification
  registered before dom0 starts and none of vmmgr's mutable state. A keeper
  takes over the main thread's bound notification; a panicking main thread
  serves it itself. Faults of guest kernels and VMMs stay unanswered, so
  those vCPUs stop. Nothing can then create, change or destroy guests,
  attestation answers no longer reach guests, and the balancer stops; the
  serial monitor's `reboot` resets the host (`tests/control-failure.rs`).
- **Scheduling.** vmmgr runs on core 0 at `PRIO_KERNEL + 2`, above every
  guest and VMM, with a full budget and its own deadline timer for the
  balancer.

---

## 11. Boot and deployment

- **UEFI.** UEFI → GRUB (EFI) → multiboot2. `tools/mkefi.sh` builds l4h as
  one UEFI application: a standalone GRUB whose memdisk holds the seL4
  kernel, `l4h-root` (with the service ELFs), the guest kernel and its
  module tree (§5.6). GRUB loads dom0's initramfs and `l4h.conf` from the
  EFI partition it was loaded from or, since `$cmdpath` is empty under OVMF,
  the first partition with `/l4h/dom0/initrd` (or else `/l4h/l4h.conf`)
  (§10.1). It passes
  `console_port`/`debug_port` (0x3f8 or `serial_port`) explicitly, because
  UEFI firmware need not fill in the BIOS data area seL4 otherwise reads.
  Initramfs images for other guests come through the dom0 API. QEMU can also
  use plain `-kernel` multiboot for development.
- **BIOS.** BIOS → GRUB (i386-pc) → multiboot2, for clouds whose VMs boot
  only with SeaBIOS, such as DigitalOcean. BIOS GRUB's core image is read
  into conventional memory and must stay within a few hundred KiB, so it
  cannot hold l4h as a memdisk. `tools/mkbios.sh` builds l4h's files
  instead: the seL4 kernel, `l4h-root`, the guest kernel, its module tree
  and a `grub.cfg` that boots them like the UEFI script. They live in
  `bios/` of a directory `$l4h` that also holds `dom0/initrd` and
  `l4h.conf`. Two GRUBs can run that `grub.cfg`:
  - the disk image's own (`tools/mkimage.sh`): its boot sector in the MBR
    and its core image, with every module `grub.cfg` needs, in a BIOS boot
    partition; it finds the ESP by its volume serial and uses its `/l4h`.
    mkimage.sh writes the boot sector and the core image's block list
    itself, as `grub-bios-setup` would, so it needs no loop device;
  - the distribution's, through a `custom.cfg` entry that the installer
    writes, with `$l4h` at `/boot/l4h` (§11.3).

  `grub.cfg` loads `vbe`, so multiboot2 sets up the framebuffer for the
  dashboard and `fb_console`. seL4 finds the ACPI tables in GRUB's
  multiboot2 tags. Nothing else differs: the kernel, root and the components
  do not depend on the firmware. There is no measured boot (§10.2).
- **Disk image.** `tools/mkimage.sh` builds a GPT disk that boots under UEFI
  and BIOS: the ESP from 1 MiB, then a 1 MiB BIOS boot partition. The ESP
  holds `EFI/BOOT/BOOTX64.EFI` (the l4h application), `/l4h/bios` (l4h's BIOS
  files) and optionally `/l4h/dom0/initrd` and `/l4h/l4h.conf` (`-i`, `-c`).
- **Variants.** The application is the same for every host except for seL4
  options fixed at build time. `tools/build-efi.sh` builds them into
  `build/efi/`: `l4h-generic.efi` (x2APIC, PCID: QEMU, GCE, EC2),
  `l4h-xapic-nopcid.efi` (Latitude.sh, below) and `l4h-skim-xapic-nopcid.efi`
  (Meltdown isolation, xAPIC, no PCID). All variants share one `l4h-root`.
- **Platform discovery.** seL4 reads ACPI (MADT, cores, IOAPIC). `l4h-root`
  enumerates PCI over MCFG/ECAM or port I/O config and allocates MSI/MSI-X
  through `seL4_IRQControl_GetMSI`.
- **Releases.** CI (`.github/workflows/release.yml`) builds, for x86_64, and
  attaches to the GitHub release of each pushed `v*` tag, with
  `SHA256SUMS`:
  - all three applications, in release mode, with the components packed
    without debug information;
  - `l4h-bios-x86_64.tar.xz`: l4h's BIOS files, with each variant's kernel as
    `kernel-VARIANT.elf`, for the installer;
  - `l4h-dom0-x86_64.tar.xz` (`tools/build-dom0.sh`): the dom0 userspace
    package, a static `l4hctl`, an example `l4h.conf` and the installer
    (`install.py` and its static initramfs), for a dom0 of any distribution;
    the kernel is in the UEFI application;
  - `l4h-debug-x86_64.tar.xz`: the unstripped build (root, components, each
    variant's kernel and the guest kernel `vmlinux`), for `addr2line` on
    fault addresses;
  - `l4h-attest.py`, the attestation verifier (§10.2);
  - `l4h-manual.pdf`, the user manual.

  No aarch64 binaries are published.
- **Version.** Host builds use `L4H_VERSION` when set, otherwise `git
  describe --tags --match 'v*' --always --dirty`, or `unknown` without Git
  metadata; release builds set it to the tag. `l4hctl version` reports it.

### 11.1 Targets

1. **QEMU (development and CI).** `-cpu host,-vmx` with KVM used only as a
   fast CPU. Devices: virtio-net-pci, virtio-blk-pci, virtio-scsi-pci, nvme,
   a 16550 UART, optionally virtio-balloon and an IOMMU. `tests/run-uefitest.sh`
   boots the disk image as GCE would, under OVMF on q35 with an NVMe boot
   disk and virtio-net NIC, with dom0's initramfs and `l4h.conf` from the
   ESP, and dom0 gets DHCP through the uplink. `tests/run-biostest.sh` boots
   the same image as a DigitalOcean droplet would: SeaBIOS on i440fx, a
   transitional virtio-blk boot disk and virtio-net NIC, checking the VBE
   framebuffer too.
2. **GCP.**
   - N2 uses virtio-net and NVMe local SSDs. GCE's virtio-net is a legacy
     (0.9.5) device, and N2 attaches the boot disk and SCSI persistent disks
     to one legacy virtio-scsi controller without indirect descriptors, as
     targets 1, 2, ... (LUN 0), each a host disk.
   - C3, C3D, N4, C4 and later need gVNIC (DQO) and attach every disk, the
     boot disk included, as NVMe. C3's gVNIC is revision 0 (admin queue by
     page frame number) with DQO RDA, 1024-entry rings, MTU 1460 and 9 MSI-X
     entries.
   - A custom image with GRUB EFI; Secure Boot off (Shielded VM vTPM and
     integrity monitoring optional); the serial console carries seL4 and
     monitor output. `tools/gce-image.sh` packages the image as
     `disk.raw.tar.gz` and prints the `gcloud` import and instance commands
     (`nic-type=VIRTIO_NET` on N2, `GVNIC` on C3 and later; image features
     `UEFI_COMPATIBLE,GVNIC`).
   - E3 shares seL4's LAPIC timer (APIC countdown on N2, which has no TSC
     deadline), so there is no HPET dependency; patch 0014 stabilizes
     calibration there.
   - dom0's first vNIC takes the uplink NIC's MAC, since the VPC delivers
     frames only for it.
   - `tests/gce-test.sh` (n2-standard-4 with virtio-net;
     c3-standard-4-lssd with `BOOT_DISK_INTERFACE=NVME NIC_TYPE=GVNIC`)
     checks UEFI boot, DHCP and internet access, a 10 MB download (about
     96 MB/s on N2, 44 MB/s on C3), a 4-vCPU guest self-test, a local NVMe
     SSD (4 KiB blocks) passed through, and 12 small guests;
     `SCSI_DISK_GB=10` also reads the boot disk and writes an extra blank
     one.
3. **AWS EC2.** c6i.xlarge boots the generic UEFI image with ENA and NVMe
   EBS. `tools/ec2-image.py` imports a raw disk through the EBS direct API
   and registers a private UEFI/ENA AMI. `tests/build-ec2.sh` and
   `tests/ec2-test.py` cover DHCP, IMDSv2, internet HTTP, jumbo frames, a
   checked 32 MiB TCP download, a four-vCPU self-test, 64 MiB of EBS
   write/readback and four concurrent guests; the runner terminates the
   instance and volumes and keeps AMIs and snapshots. See `tests/ec2.md`.
4. **Bare metal: Latitude.sh m4.metal.small** (Supermicro H13SRE-F, AMD
   EPYC 4244P, Intel X550, Micron 7500 NVMe; UEFI), deployed with
   the separate l4h-sandbox repository (its `deployments/latitude-sh-l4es`). It needs the
   `xapic-nopcid` variant and these settings (`l4h.conf` keys, §10.1):
   - The variant: the firmware leaves x2APIC off (`L4H_LAPIC_MODE=XAPIC`),
     and the CPU has no PCID (`L4H_PCID=OFF`; seL4 otherwise stops in its
     first boot check). There is no TSC-deadline timer; APIC countdown
     serves.
   - `serial_port`/`serial_irq`: serial-over-LAN is COM2 (0x2f8, IRQ 3), per
     the ACPI SPCR table.
   - `uplink_nic=bus:dev.fn` (here the X550's second port) and `boot_disk`,
     the controller that becomes host disk 0, so dom0 gets it.
   - `uplink2_nic=bus:dev.fn`: a second uplink on switch 1 (dom0's internal
     switches follow it), where dom0 gets one more vNIC with that NIC's MAC.
     dom0 tells its vNICs apart by MAC (`CTL_SWITCH_INFO` lists each port's
     VM and MAC), not by order. The first port carries the private storage
     network on a tagged VLAN, which l4h passes through.
   - `fb_console=1`: GRUB and the seL4 console (patch 0020) on the screen,
     which the BMC's web console shows; the dashboard keeps to the upper
     half.

Azure (MANA and NVMe) is not supported.

### 11.2 Partitioning large machines with Xen

seL4's big kernel lock limits how far one l4h scales across cores, so a
machine with many cores runs several l4h instances side by side as Xen HVM
guests. l4h needs no VT-x of its own, so an ordinary HVM guest suffices.
Each instance gets a slice of the cores and memory and its own NIC, passed
through whole (no SR-IOV).

- **Xen and dom0.** `tools/build-xen-dom0.sh` builds, from Debian 13
  packages, the Xen 4.20 hypervisor and a minimal dom0: Debian's kernel plus
  a 22 MiB initramfs with busybox, `xl`, QEMU as the device model and the Xen
  driver modules. Its init (`tools/xen/dom0-init`) starts xenstored,
  xenconsoled and a QEMU that serves the guests' disks (`backendtype=qdisk`),
  hands each device named in `xen-pciback.hide=(BB:DD.F)...` to pciback
  (built-in drivers such as virtio-pci have already bound them by then), and
  starts the `xl` configurations in `/etc/l4h-xen`. dom0 serves no guest
  traffic.
- **Firmware.** The partitions boot the usual l4h image under OvmfXen
  (`tools/build-ovmf-xen.sh`, from edk2-stable202502), referenced with
  `bios_path_override`. Debian's OVMF no longer supports Xen: it finds none
  of the ACPI tables hvmloader builds, so GRUB has no RSDP to give seL4.
  OvmfXen changes GRUB's heap use enough to trip a GRUB 2.12 bug (it grows
  its heap through boot services after multiboot2 has exited them), which
  `tools/mkefi.sh` works around.
- **Passthrough.** Each partition's `pci = [...]` names its NIC; Xen maps
  its DMA through the IOMMU and its MSI-X through interrupt remapping, and
  netd drives it as on bare metal. libxl warns that it cannot reset a device
  without function-level reset, which applies to QEMU's virtio-net, not to
  NICs such as the X550.
- **Test.** `tests/run-xentest.sh` nests the setup in QEMU/KVM: q35 with an
  emulated VT-d (interrupt remapping, caching mode) and two virtio-net NICs
  on one hub, with `iommu_platform` so their DMA is translated. Xen starts
  two l4h partitions, each with one NIC and a disk image, and each
  partition's dom0 pings the other's.

### 11.3 Installing under an existing Linux

On a supported x86_64 machine booted with 64-bit UEFI or BIOS GRUB, the
installer boots the existing Linux userspace as dom0 with l4h's
paravirtual kernel:

```sh
curl -fsSL https://raw.githubusercontent.com/losfair/l4h/main/tools/install.sh | bash
```

- **Release.** It uses `sudo` when needed, installs missing dependencies
  with apt, dnf or yum, and downloads a tagged GitHub release with SHA-256
  verification. No source build or hardware virtualization is needed.
- **Variant.** Preflight selects `skim-xapic-nopcid` for Meltdown-affected
  CPUs or when immunity cannot be established, and `generic` (x2APIC, PCID,
  INVPCID) or `xapic-nopcid` otherwise. All variants require FSGSBASE,
  XSAVEOPT, AVX and 1 GiB pages. Updates keep the installed variant, and
  switching away from SKIM needs native Linux, so the installer can check
  the CPU.
- **Preflight** checks CPU features, Meltdown status, Secure Boot (must be
  off), EFI variables and the ESP (UEFI) or GRUB (BIOS), storage, network
  and userspace. `--check` runs it read-only. Some cloud VMs omit the
  `constant_tsc` flag; `--assume-stable-tsc` waives that check, assuming
  rather than verifying a stable TSC, which l4h uses directly.
- **Supported layouts.** Headless systemd installations with a plain
  ext4/XFS root on NVMe namespace 1 or a supported virtio disk, exposed to
  dom0 as partition windows (§10.1), and one or two physical virtio-net,
  gVNIC, ENA or X550 NICs. Each NIC becomes the uplink of its own switch
  (switch 0, then 1, in PCI address order), and dom0 gets one interface on
  each with the original name and MAC, so existing address, route and DNS
  settings apply. Software interfaces (WireGuard, PPP, GRE, TUN/TAP and the
  like) are not counted as uplinks, and existing userspace recreates them;
  the guest kernel includes WireGuard, PPP, GRE/IP tunnels, L2TP, VXLAN,
  GENEVE and MAC/IP VLANs, plus nftables FIB lookups and redirects. Profiles
  tied to a PCI path or native driver may need adaptation. Rejected: NICs
  enslaved to a bond or bridge, LVM, encryption, RAID, Btrfs, a separate
  `/usr`, SATA/USB storage, active AppArmor profiles and DKMS modules.
- **Memory.** At least 768 MiB usable RAM. dom0 gets half the usable RAM
  (512 MiB to 8 GiB); `--memory MiB` overrides it, up to 60 GiB, keeping at
  least 256 MiB for l4h. Swap does not count. `--vcpus` sets dom0's vCPUs.
- **UEFI boot selection.** The default installation sets BootNext for one
  l4h boot, preserves BootOrder and native loaders, and does not reboot.
  After testing dom0, `sudo sync; sudo l4hctl host-reboot` returns to native
  Linux, and rerunning with `--make-default` puts l4h first. A UEFI dom0
  cannot change firmware boot selection, so `--make-default` requires native
  Linux. Recovery: choose native Linux in the firmware menu; from native
  Linux, `efibootmgr --delete-bootnext` cancels a trial and
  `--bootnum XXXX --delete-bootnum` removes the entry.
- **BIOS boot selection.** The installer writes l4h's files to `/boot/l4h`
  and an `L4H` entry to the distribution's GRUB `custom.cfg`, and selects it
  once with `next_entry` (`grub-editenv`), without running `grub-install` or
  `update-grub`; GRUB clears `next_entry` before booting l4h, so the next
  reset returns to native Linux. `--make-default` makes it the default.
  `sudo grub-reboot 0` then `sudo l4hctl host-reboot` boots native Linux
  once; deleting `custom.cfg` removes the entry. It needs `/boot` on
  ext2/3/4 or XFS and a `grub.cfg` from `grub-mkconfig`.
- **Inside dom0**, an ordinary `reboot` restarts only dom0.
- **Updates.** Rerunning the installer from native Linux or a running dom0
  replaces the boot payload, initramfs and `l4hctl`, preserving `l4h.conf`,
  the variant and GRUB customizations; `--memory`, `--vcpus` or `--variant`
  change them explicitly. The installer's record is
  `/var/lib/l4h/install.json`; replaced files are backed up under
  `/var/lib/l4h/backups`, and a failed installation restores files and EFI
  settings. Native updates recreate missing EFI entries (matched by ESP and
  loader, not number or label) or generated GRUB entries, and restore
  missing payloads. An existing one-time boot selection for another OS is
  preserved. From dom0, the update takes effect at the next
  `l4hctl host-reboot`; BIOS dom0 updates check the installed root UUID,
  boot filesystem UUID and managed GRUB entry rather than a physical MBR.
- `python3 tests/test_installer.py` tests preflight, verified downloads, EFI
  changes, updates and rollback without touching the host;
  `tests/run-install-vm.sh` installs into a disposable UEFI or BIOS KVM VM
  with one or two uplinks and returns to native Linux. The user manual
  documents installation in full.

---

## 12. Portability to aarch64

| Concern | x86_64 | aarch64 |
|---------|--------|---------|
| seL4 support | MCS, SMP | MCS, SMP, and the best proof coverage |
| syscall trap (E1) | `syscall`, number in `rdx` | `svc`, number in `x7`; the fault carries Linux's x8 (patch 0007) |
| FaultIP | advance by 2 | advance by 4 |
| FPU access (E2) | XSAVE area | V-regs + FPSR/FPCR |
| Guest VA | 47-bit | 48-bit TTBR0, user space limited to 47 bits |
| TLS | `fs_base` | `TPIDR_EL0`, in the saved user registers |
| Timer (E3) | LAPIC TSC-deadline or countdown | ARM generic timer |
| vDSO clock | `rdtsc` | none yet (syscall) |
| Drivers | Rust virtio-net/blk/scsi PCI, NVMe, gVNIC, ENA, X550 | the same drivers; ECAM, BAR assignment and GICv2m MSI-X |
| Boot | multiboot2 / UEFI or BIOS GRUB | rust-sel4 loader, entry at EL1 or EL2 |
| IOMMU, TPM, reset | supported | not supported (flags-only trustd) |

Rules that keep the port cheap:

1. ISA code lives only in `arch/l4h/<isa>/` and `host/*/src/arch/<isa>.rs`.
2. Nothing in the protocols depends on the ISA: boot info, event pages,
   virtio-l4h, host block and net queues. Fields are fixed-width and
   little-endian.
3. No x86-only seL4 features (I/O ports outside drivers, EPT,
   `GetStatusBits`).
4. Guest RAM has 4 KiB aliases and optional 2 MiB process mappings on both
   ISAs.
5. CI builds both ISAs.

**Kernel.** seL4 aarch64 (QEMU `virt`, MCS, SMP, EL1, no hypervisor
support) builds with all l4h patches from `kernel/configs/l4h-aarch64.cmake`
via `tools/build-kernel-aarch64.sh`. E1–E3 and patches 0005 and 0006 are
ISA-neutral; 0007, 0015, 0016 and 0018 are aarch64-specific (§4.5).
The HWCAPs come from the boot core's ID registers alone, so l4h requires
cores with the same features; heterogeneous CPUs would need the fields
intersected across the cores guests run on.

**Boot.** `third_party/patches/rust-sel4/0001` adds an EL1 path to
rust-sel4's kernel loader, which only entered EL2 kernels: it drops from EL2
with the EL1 translation regime set up and no traps. At EL2 the loader
clears `HCR_EL2.E2H` before setting up its own translation (firmware may
leave VHE on; CPUs where E2H is RES1 are refused), and the drop to EL1 sets
`VTTBR_EL2` (VMID 0), `MDCR_EL2` (no debug or PMU traps, all counters to
EL1), `VPIDR_EL2`, `VMPIDR_EL2` and, with a GICv3, `ICC_SRE_EL2`, all of
which reset to UNKNOWN. FEAT_FGT trap registers and `HCRX_EL2` are left to
the firmware, as TF-A initializes them for a lower EL. Patch 0002 supports
direct EL1 entry, initializes the EL1 regime and selects QEMU's HVC PSCI
conduit when EL2 is unavailable. Both EL1 paths set `TCR_EL1.AS` when
`ID_AA64MMFR0_EL1.ASIDBits` reports 16-bit ASIDs, and invalidate EL1's TLB
before turning its MMU on. `tools/build-loader-aarch64.sh` applies the
patches and builds the loader. The run script disables virtualization by
default; `L4H_QEMU_VIRTUALIZATION=on` tests the EL2 path.

**Host.** All components build for AArch64. QEMU `virt` uses GICv2,
`highmem-ecam=off,highmem-mmio=off`, a 16 MiB ECAM at 0x3f000000 and the
32-bit PCI memory aperture. Root assigns memory BARs before starting
devices. GICv2m supplies 64 MSI interrupts (SPIs 80–143), divided between
NICs and up to 48 disks; MSI address/data are passed explicitly to the
common drivers. The PL031 supplies wall time and the PL011 serial monitor
input.

**Linux.** The native AArch64 ABI, signals and FPSIMD context records,
ptrace register sets, TLS, SMP, atomics, setjmp/longjmp, syscall restart,
instruction-cache maintenance and module relocations are implemented.
Modules use the large code model, like the guest kernel.

**Tests.** `run-abitest.sh` covers the ABI with an attached PCI disk.
`L4H_ARCH=aarch64` selects the Linux integration tests, including 1/4-vCPU
self-tests, modules, virtio-blk/NVMe, VM lifecycle, networking and the
serial monitor; CI has a QEMU/TCG job for these. The assembled image also
runs on Apple Silicon macOS under QEMU/HVF with `kernel-irqchip=off`
(`tools/run-image-aarch64.sh` selects HVF on macOS); 1/4-vCPU self-tests
pass on an Apple M4.

**Scope.** This targets QEMU `virt` with GICv2m. Other ARM boards need their
own platform description and interrupt routing.

---

## 13. Performance

The design prioritizes I/O and idle density, the cloud workload, over
syscall-heavy microbenchmarks.

**Where the time goes.**

| Operation | Cost on l4h | Why |
|-----------|-------------|-----|
| null syscall | ~1.2 µs (nested KVM) | Fault IPC slowpath plus ReplyRecv: of a ~3,200-cycle seL4 round trip, most is two thread switches (an address-space switch and an eager FPU swap each, ~640 cycles) and four kernel entries and exits; Linux itself takes ~440 cycles. A fastpath for the trapped syscall and its reply saved only ~6 %. |
| page fault (anon) | 5–6.5 µs | Fault IPC, `handle_mm_fault` and `Page_Map`. |
| context switch | | Two `SetSchedParams` and a reply; no FPU copying. |
| `clock_gettime` | ~40 ns | vDSO on x86_64; a syscall on aarch64. |
| fork | | Lazy refault of the child; the parent's write-protect remaps batched with one ASID flush (patch 0017). |
| disk I/O | | One bounce copy by the guest through its I/O pool, plus two host queue hops. |
| network | | The guest bounces through its I/O pool; the VMM and netd copy between pool, port and NIC buffers (§9.3). |

**Measurements.** Unless stated otherwise these were taken with
`tests/run-bench.sh` on a development box that is itself a Hyper-V VM, so
QEMU/KVM runs *nested*. Every VM exit of seL4 (timer MSR writes, IPIs, EOIs,
HLT wakeups) costs tens of microseconds there, against roughly one on a
single-level cloud hypervisor, so figures dominated by exits are
pessimistic.

| Operation | l4h, nested KVM | Notes |
|-----------|-----------------|-------|
| getpid | 1.2–1.3 µs | 20 µs without kernel patch 0006. |
| `clock_gettime` | ~40 ns | vDSO. |
| page fault (first touch) | 5–6.5 µs | |
| pipe round trip | 10 µs (same vCPU) | 37 µs between 2 vCPUs (cross-core IPIs). |
| fork+exit+wait | 340–450 µs | |
| disk, 1 MiB direct, 1 vCPU | 430–510 MB/s write, 450–600 MB/s read | Measured on a heavily loaded host (load ~10 on 8 CPUs, up to 3× run-to-run variation); includes the swiotlb bounce. A quieter run gave 974 MB/s write and 750 MB/s read. |
| disk, 4 KiB read latency | 350–375 µs | Two cross-core wakeups each way (guest → VMM → blkd), plus the bounce; higher than the copy alone explains, not yet investigated. |
| guest↔guest ping | 1.4 ms | Four component hops per direction, with cross-core wakeups. |
| guest↔guest TCP | 670–710 MB/s | 1 vCPU each, sender ~70 % busy (`netbench`, 256 KiB writes, 1 MiB reads); checksum offload and TSO pass through the switch. |
| dom0 ↔ host over a tap NIC (vhost) | 380–620 MB/s down, 410–490 MB/s up | 256 MiB with wget / a 256 KiB-write sender. A plain Linux VM on the same QEMU: 0.5–1.3 GB/s. |
| dom0 ↔ host over QEMU user net | ~165 MB/s down, ~37 MB/s up | QEMU's user networking caps a plain Linux VM at ~440 / ~84 MB/s; it takes no TSO, so netd segments uploads. |

**Guest cost** (`tests/run-vmbench.sh`, nested QEMU/KVM, debug builds; host
memory beyond a booted guest's RAM, median latencies): 10 MiB of overhead
whatever the RAM (the 4 MiB I/O pool and about 6 MiB of host objects);
create returns in 128 ms for 128 MiB and 143 ms for 512 MiB; init is ready
258 ms after create for 128 MiB (the guest retypes its own RAM at boot,
about 130 ms of that); destroying a stopped guest takes 119 ms.

**Transparent huge pages** (`tests/run-thpbench.sh 1` and `4`, measured
2026-10-30). `MADV_NOHUGEPAGE` against `MADV_HUGEPAGE` on the same kernel,
each trial in a fresh process with alternating order; medians of five
trials after one warmup pair. A 512 MiB guest; QEMU 10.0.13 with KVM, four
vCPUs and 4 GiB, on an i7-13700H exposed through an eight-vCPU Hyper-V VM,
with other jobs stopped. The benchmark enables `madvise` policy and defrag,
disables background underused splitting and delays `khugepaged`. Each dense
THP trial verifies 32 native large leaves, and base-page trials zero.

| Operation | 1 vCPU, base | 1 vCPU, THP | 4 vCPUs, base | 4 vCPUs, THP |
|-----------|--------------|-------------|---------------|--------------|
| Dense 64 MiB first-touch, ms | 70.462 | 5.620 | 75.183 | 6.420 |
| Minor faults during first-touch | 16,387 | 35 | 16,387 | 35 |
| Random page-stride read, ns/access | 17.29 | 14.07 | 19.03 | 16.15 |
| Fork + exit + wait, ms | 4.658 | 0.421 | 4.982 | 1.038 |
| Fork + COW-write 64 MiB + wait, ms | 102.358 | 132.368 | 110.642 | 136.517 |
| Partial protection changes in 32 PMDs, ms | 0.208 | 15.703 | 0.309 | 16.160 |
| Unmap after protection changes, ms | 12.679 | 11.401 | 14.584 | 10.887 |
| Sparse 64 MiB first-touch, ms | 0.164 | 6.241 | 3.309 | 8.831 |
| Sparse RSS, KiB | 128 | 65,536 | 128 | 65,536 |
| Dense `VmPTE`, KiB | 1,110 | 216 | 1,094 | 200 |
| Native seL4 2 MiB leaves in dense mapping | 0 | 32 | 0 | 32 |

Dense first-touch writes one byte per 4 KiB; sparse first-touch one per
2 MiB. Protection changes make one 4 KiB page in each PMD read-only, then
writable. Each fork measurement averages eight forks of the populated
mapping; the COW child writes and verifies every base page and the parent
checks its data. The fault counts include three faults outside the mapping.

Dense first-touch is 11.7–12.5 times faster with THP and fork 4.8–11.1
times. `VmPTE` drops by about 81%: a PMD uses one mapped frame cap instead
of 512 and needs no seL4 leaf page table (Linux still keeps its deposited
PTE table). COW is 23–29% slower,
since Linux splits a shared PMD for base-page COW and the backend installs
the small mappings, and partial protection changes pay for splitting.
Sparse RSS is 64 MiB instead of 128 KiB, the usual THP tradeoff. These
costs are why the default is `madvise`. Full ranges, raw trials and
validation are in
[`tests/results/thp-native-backing-nested-kvm-2026-10-30.txt`](tests/results/thp-native-backing-nested-kvm-2026-10-30.txt).

**Workloads.** `tests/run-debian.sh` boots Debian 13 with systemd as dom0
from a passed-through virtio-blk disk on 2 vCPUs: systemd reaches "running"
with no failed units, DHCP and DNS work, `apt-get update` and `install`
succeed, and `ping` works (image from `tests/mkdebian.sh`).
`tests/run-workload.sh` on that image, with 4 vCPUs: fio random writes with
crc32c verification, direct I/O, libaio, queue depth 16 (13.4k IOPS, all
verified); busybox built with `make -j4` in 124 s; a clean `e2fsck -f` on
the host; a checksum intact after a second boot.

**Next steps for I/O latency:** place each guest's VMM, blkd and netd work on
the guest's core, or use passive servers on the caller's scheduling context;
poll briefly before blocking; measure on single-level cloud hypervisors,
where exits are about 20× cheaper; remove the VMM's network copy by making
the I/O pool itself a netd port region.

---

## 14. Repository, building and testing

```
l4h/
  DESIGN.md          this document
  docs/manual/       user manual (LaTeX; make -C docs/manual renders the PDF)
  include/l4h/abi.h  guest <-> host ABI (single source of truth)
  kernel/            seL4 (git submodule, pinned) + patches/ + configs/
  guest/linux/       arch/l4h sources, patches/ for anything outside arch/, defconfig (Linux 6.18 LTS)
  host/              Rust workspace: l4h-abi, l4h-host, l4h-rt, l4h-task, l4h-root, l4h-vmmgr, l4h-vmm,
                     l4h-memd, l4h-blkd, l4h-netd, l4h-trustd, l4h-virtio
  tools/l4hctl/      dom0 userspace CLI and library for the control API
  third_party/rust-sel4/  Rust bindings and runtime (submodule)
  third_party/sddf/  submodule (design reference; no linked C drivers)
  third_party/kemu/  AArch64 userspace emulation in x86_64 guests (submodule)
  third_party/patches/  patches for rust-sel4
  tools/             build-kernel.sh, build-linux.sh, build-kmods.sh, build-host.sh, mkefi.sh, build-efi.sh,
                     add-modules.py, mkbios.sh, mkimage.sh, run-qemu.sh, run-uefi.sh, run-bios.sh,
                     mkinitramfs.sh, install.sh, l4h-attest.py, swtpm.sh, and image builders for clouds
  tests/             integration tests driven by QEMU and console scripting, host-side unit tests, fuzzing
```

### 14.1 License

Unless otherwise noted, l4h is licensed under the GNU General Public License
version 2 only (`GPL-2.0-only`); see [LICENSE](LICENSE). The CLI and Rust
client library in `tools/l4hctl` and the attestation verifier
`tools/l4h-attest.py` are licensed under BSD-2-Clause; see
[tools/l4hctl/LICENSE](tools/l4hctl/LICENSE) (the standalone verifier
carries the full text). Third-party components, including the submodules
in `kernel/seL4` and `third_party`, retain their own licenses and copyright
notices.

### 14.2 Building and running

The build machine needs:

- QEMU with KVM, used only as a fast CPU (VMX is hidden from the guest);
- gcc, Rust (stable, plus the nightly pinned by rust-sel4), cmake, ninja and
  the Python modules seL4 needs, in `.venv`;
- for kemu in the x86_64 guest kernel: Rust's `rust-src`, Clang/libclang and
  `bindgen-cli` 0.71.1 (`rustup component add rust-src`,
  `cargo install --locked bindgen-cli --version 0.71.1`);
- busybox, e2fsprogs and erofs-utils;
- for disk images: GRUB EFI and BIOS (`grub-efi-amd64-bin`, `grub-pc-bin`),
  mtools, sfdisk and OVMF;
- for aarch64: `gcc-aarch64-linux-gnu`, cross libc headers,
  `qemu-system-arm` and a static AArch64 BusyBox (`L4H_BUSYBOX` can name
  another). `tools/ci-setup.sh aarch64` prepares these on Debian 13 (as
  root).

```sh
git submodule update --init
tools/build-kernel.sh                 # patched seL4 -> build/sel4
tests/run-selftest.sh 4               # build Linux + host, boot a 4-vCPU guest self-test
```

For AArch64, build the kernel and loader once, then select the guest ISA
with `L4H_ARCH`. Linux outputs go to `build/linux-l4h-aarch64` and the
kernel to `build/sel4-aarch64`.

```sh
tools/build-kernel-aarch64.sh
tools/build-loader-aarch64.sh
L4H_ARCH=aarch64 tests/run-selftest.sh 4
L4H_ARCH=aarch64 tests/run-blktest.sh
L4H_ARCH=aarch64 tests/run-nettest.sh
```

The same selection works with `tools/build-linux.sh`, `tools/run-dom0.sh`,
`tools/mkinitramfs.sh` and the control, memory and scheduler tests. QEMU
starts at EL1; `L4H_QEMU_VIRTUALIZATION=on` exercises entry from EL2. The
UEFI and cloud image scripts are x86_64 only. `L4H_MEM` accepts MiB, `M` or
`G`; `run-dom0.sh` rebuilds the seL4 RAM map and loader when it changes.
An assembled `build/l4h-aarch64.img` boots on Apple Silicon macOS with QEMU
installed (`brew install qemu`): `tools/run-image-aarch64.sh
build/l4h-aarch64.img` selects HVF with an emulated GICv2.

To run your own dom0 initramfs:

```sh
tools/mkinitramfs.sh build/my.cpio.gz my-init-script
tools/run-dom0.sh build/my.cpio.gz "console=hvc0" 600   # output in build/qemu.log
```

Inside dom0, `l4hctl` with no arguments prints the control commands, for
example:

```sh
l4hctl version                       # running host's version, e.g. v2026.10.1
l4hctl logs --follow                 # retained host diagnostics and VM stop reasons
l4hctl create web --initrd /web.cpio.gz --mem 512 --vcpus 2 \
    --disk 0 --nic 0
l4hctl console 1 --follow
```

When building `l4h-root` directly with Cargo, set `L4H_VERSION` explicitly;
without it the host reports `unknown`.

**Test environment.** The development machine has KVM, which QEMU uses
only as a fast CPU to mimic a cloud VM: `-cpu host,-vmx -smp 4`, with
`virtio-blk-pci`, `nvme` and `virtio-net-pci`, and UEFI via OVMF or plain
multiboot. seL4 never uses VT-x. The 30-guest test uses a 16 GiB QEMU
machine and guests of 256–512 MiB.

### 14.3 Test command index

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
| `tests/run-thptest.sh`, `tests/run-thpbench.sh [vcpus]` | transparent huge pages: correctness (§5.3) and the paired benchmark (§13) |
| `tests/run-reclaimtest.sh [secs]` | 128 MiB checking workload in a 64 MiB memcg, with 32 MiB read-only hot data and swap; `RECLAIM_SWAP_DIR=/dev/shm` puts swap in host RAM |
| `tests/run-objtest.sh [vcpus]` | object memory growth under fragmentation, block conversion, SMP memory stress, OOM recovery |
| `tests/run-cryptotest.sh [vcpus] [secs] [MiB]` | dm-crypt with AES-NI (x86_64) or the ARMv8 Crypto Extensions (aarch64) vs generic C (cross-check, throughput), user SIMD state under concurrent kernel crypto |
| `tests/run-futexbench.sh [vcpus] [rounds]` | process-shared futex handoff latency |
| `tests/run-nodetest.sh /path/to/node [vcpus]` | Node startup/JIT, string internalization, worker threads and concurrent GC |
| `tests/run-modtest.sh` | external kernel module relocation, load and unload |
| `tests/run-bpftest.sh [vcpus]` | BPF JIT: the kernel's BPF test vectors, verified XDP and tc programs, direct tail calls patched in and out, XDP (generic) and tcx on lo |
| `tests/run-android.sh`, `tests/run-androidtest.sh` | Android 17 boot to the lock screen; Android's kernel features (§5.8) |
| `tests/run-blktest.sh` (`BLKTEST_DEV=nvme`, `scsi`, `scsi-legacy`, `scsi-luns`, `virtio-legacy`) | disk pass-through, data integrity |
| `tests/run-sharedblk.sh` | shared controllers: concurrent clients, windows, provisioning, destroy during I/O |
| `tests/run-ctltest.sh` | VM lifecycle, console, clean shutdown, disk re-attach, windows, reclaim |
| `tests/run-devicelimit.sh` | 64 devices per guest |
| `tests/run-gputest.sh` | virtio-gpu drawing, screenshots, size checks and reclaim |
| `tests/run-nettest.sh`, `tests/run-router.sh` | switches, uplink, multi-NIC, isolation, MAC lock, NAT router VM (`NETTEST_LEGACY=1`: legacy virtio-net uplink) |
| `tests/run-density.sh 30 256` | 30 guests on 4 cores stay responsive |
| `tests/run-m6test.sh` | dom0 restart, CPU caps, steal time |
| `tests/run-vtdtest.sh [--qemu]` | VT-d DMAR parsing, table/interrupt formats and address bounds; with QEMU, DMA, lifecycle, NIC and serial tests |
| `python3 tests/vtd-net-qemu.py [--iommu amd]` | bridge aliases with two NICs and disk controllers; `--no-intremap` checks DMA-only confinement, `--controllers 17` checks shared interrupt capacity |
| `python3 tests/amdvi-qemu.py` | AMD-Vi shared tables, DMA bounds and interrupt isolation using QEMU EDU devices |
| `tests/run-schedtest.sh` | host-side SMT topology, initial placement and migration policy tests |
| `tests/run-rtctest.sh [--qemu]` | RTC calendar, BCD/binary and 12/24-hour modes, bounds and error recovery; with `--qemu`, dom0 writes verified against the emulated hardware |
| `tests/run-smttest.sh` | QEMU boot with SMT: CPU discovery, initial placement and busy-vCPU migration |
| `tests/run-captest.sh [cap%] [rounds]` | self-test and fork loops in a guest capped from boot |
| `tests/run-capperf.sh [caps]` | fork/exec and CPU-bound timings, uncapped and under each cap (use a release seL4) |
| `tests/run-limits.sh` | the host refuses what it cannot afford and recovers |
| `tests/run-balloontest.sh` | free memory reported to QEMU (virtio-balloon; `BALLOONTEST_LEGACY=1`: a legacy one) is dropped: QEMU's memory use idle, with a guest and after destroying it |
| `tests/run-hotplugtest.sh` | memory hotplug: a VM grows from 256 MiB to 2 GiB and shrinks again under `l4hctl mem`, falling short while its data needs the memory; host memory comes back |
| `tests/run-hotplugstress.sh [rounds]` | memory hotplug under stress: three VMs under memory load resized at random, oversubscribing the host, destroyed mid-resize; data checked, all memory back |
| `tests/run-monitor.sh` | serial monitor (`list`, `restart-dom0`), continued operation with an absent UART |
| `tests/run-uefitest.sh` | UEFI/GRUB boot image with NVMe and virtio-net, as on GCE |
| `tests/run-biostest.sh` | the same image under SeaBIOS with virtio-blk, virtio-net and a VBE framebuffer, as on DigitalOcean |
| `tests/run-xentest.sh` | two l4h partitions as Xen HVM guests, nested in KVM, each with a passed-through NIC, ping each other (§11.2) |
| `tests/run-attesttest.sh` | attestation with swtpm over CRB, FIFO and the AMD fTPM ACPI start method: reports on dom0 and a guest, host evidence, AK credential |
| `tests/run-debian.sh`, `tests/run-workload.sh` | Debian + systemd, fio verify, parallel build, fsck (`tests/mkdebian.sh` first) |
| `tests/run-bench.sh`, `tests/run-vmbench.sh`, `tests/run-startbench.sh` | micro-benchmarks, guest cost, start latency |
| `tests/run-fuzz.sh` | hostile-guest virtqueue fuzzing of l4h-vmm |
| `tests/run-skimtest.sh` | the skim-xapic-nopcid variant on a Meltdown-affected CPU without PCID/x2APIC: SKIM mappings and syscall state at the user/kernel boundary (`tests/skim-qemu.py`, GDB) |
| `python3 tests/blkmq-qemu.py` | block multiqueue and fsync suites under local QEMU (`--suite blkmq\|fsync`, `--guest-queues`, `--scsi-queues`); run by hand |
