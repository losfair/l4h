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
| R3 | virtio-blk and virtio-net. Block devices are passed through. Network is multiplexed by virtual switches. | The guest runs stock Linux `virtio_blk`/`virtio_net` drivers over a paravirtual transport, `virtio-l4h`, with no trapped MMIO (§9). All device buffers live in a host-owned I/O pool (§8.1). The hypervisor provides **only L2 virtual switches**; a physical NIC is an uplink port on a switch, and routing and NAT are done by a VM. The one exception is stateless steering (§9.3): dom0 may have netd pick a port by IP address, protocol and port, rewriting only MAC addresses. |
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
   Cloud VM or bare-metal hardware; VT-x or AMD-V only for guests' KVM (§5.10)
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

l4h supports only 64-bit platforms, x86_64 and aarch64. Its patches assume
a 64-bit kernel (for example, `VMEnter` takes its three call MRs from
registers even without an IPC buffer, and the frame and EPT invocations
they add exist only with 64-bit page tables), and none is built or tested
for ia32, aarch32 or riscv32, which may not build or may misbehave. The
guest's `arch/l4h` likewise builds only 64-bit kernels. Upstream seL4's own
32-bit code is left in place, to keep the patch set small against upstream.

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
- `KernelVTX=ON`, `KernelX86_64VTX64BitGuests=ON`: seL4's VCPU and EPT
  objects, for guests that run KVM (§5.10,
  [#84](https://github.com/losfair/l4h/issues/84)). Every guest may create
  them from its own RAM; there is no per-VM grant, and patches 0039 and
  0040 limit the VMX controls and SVM intercepts a guest can turn on or off.
  On an AMD CPU the same objects use AMD-V (SVM, patch 0040), chosen at
  boot by the CPU's vendor. On a CPU without usable VT-x or AMD-V (no VMX
  or SVM, as under QEMU's `-cpu host,-vmx,-svm`, either locked off by the
  firmware, or no EPT or nested paging) the kernel boots without them
  (patches 0038 and 0040), so the same image serves all of these. The SKIM
  variant leaves both off at runtime: Meltdown-affected CPUs are
  also L1TF-affected, and seL4 does not flush the L1D on VM entry. It still
  builds with `KernelVTX`, as every x86_64 variant must: the option inserts
  invocation labels (`X86PageMapEPT` after `X86PageGetAddress`, and VCPU
  register labels), renumbering the ones after them, and all variants
  share one root task and guest kernel.
  Tested by `tests/run-vtxtest.sh` (§14.3).
- `KernelSkimWindow=OFF` in the default variants, which require a CPU
  unaffected by Meltdown. The `skim-xapic-nopcid` variant sets it `ON`,
  uses xAPIC and disables PCID. Builds without SKIM refuse to boot when
  `IA32_ARCH_CAPABILITIES.RDCL_NO` is clear, or on Intel CPUs that do not
  enumerate that MSR (patch 0024). The PCID variant requires INVPCID too.
  The installer picks the variant (§11.3).
- Development builds keep `KernelDebugBuild` on. `L4H_RELEASE=1
  tools/build-kernel.sh` turns the debug build off but keeps kernel
  printing for boot messages and fatal errors. Host output goes through
  l4h-logd (§10.4).
- `L4H_RELEASE=1` also builds the host components with Cargo's release
  profile (optimised; overflow checks off: §10, "Integer arithmetic"), into
  `host/target/<target>/release` rather than `debug`
  (`tools/host-profile.sh`, the one definition: every script that
  builds, packages or boots them sources it, the Python tests through
  `tests/host_profile.py`). Host informational messages and guest consoles
  are printed in either profile.

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
| 0000 | Unmodified squashed backport of [seL4 PR #1849](https://github.com/seL4/seL4/pull/1849), all eight commits through `59c2595a24cc64f1c291634ed7c4e3e912173d1b`, including its GenMC lock/IPI models. Applied before the local patches. Blocking remote calls run in the kernel-lock wait path; a stall racing a syscall or fault makes its caller retry. IRQ-path stalls save live x86 FS/GS before switching to idle, preserving user TLS. The new completion counter and pending-call ordering replace patches 0005 and 0010. |
| 0004 | x86_64 `syscall` entry never saved the user RSP and `sysretq` cleared it (libsel4 keeps RSP in RBX, which hid this). RSP is now saved through a per-node scratch slot and restored on both the slow path and the fastpath. 0027 does the same with SKIM: RSP is saved before loading the kernel CR3 and carried through the per-CPU SKIM scratch word, cleared after each read, with no user-stack access and no extra SKIM mappings. |
| 0012 | (x86, MCS) The LAPIC latches a timer interrupt that fires while a core waits for the kernel lock; it was then handled as a new event after the next deadline was armed, meaning another lock wait. Under host load every core looped on stale interrupts and user threads never ran. A timer interrupt that finds the timer still armed is now acknowledged and dropped before the lock (checking 0006's `ksArmedDeadline` first). The native fast return records explicitly that it does not hold the lock; VM returns use the locked path for VCPU preparation. The patch is x86-only. |
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
| 0020 | (x86) `fb_console`: kernel output (host output is logd's, §10.4) is also drawn on the lower half of a 32-bpp direct-RGB multiboot2 framebuffer below 4 GiB, 8x8 glyphs doubled vertically, wrapping rather than scrolling so the framebuffer is never read. Refused if it overlaps usable RAM or starts below 1 MiB. For machines whose screen is reachable but not their serial port. |
| 0021 | (x86) Multiboot modules after the root task (up to 8) are copied to page-aligned memory above the root task's image and below 4 GiB, kept out of managed RAM so they reach root as device Untypeds (frames without clearing), and listed with their loader strings in a bootinfo chunk (`SEL4_BOOTINFO_HEADER_X86_BOOT_MODULES`). This is how dom0's files are loaded (§10.1). |
| 0022 | (x86) Intel CPUs that enumerate the TSC rate in CPUID 0x15 (or 0x16) take it from there, rounded to the nearest MHz; with TSC-deadline the PIT is then unused. Alder Lake and later may gate the 8254, so the PIT wait never ended. VMs (leaf 0x15 zero) still measure with the PIT. |
| 0023, 0029 | `Page_TestAndClearAccessed` (x86_64, and AArch64 without hypervisor support) atomically clears and returns the A/AF bit of a frame cap's mapping, for 4 KiB frames (0023) and 2 MiB frames (0029), after verifying the mapped ASID, address, size and physical frame. It does not invalidate TLBs, as with native x86 aging. On AArch64 without hardware AF updates (and without hypervisor support), seL4 repairs EL0 access-flag faults itself (setting AF and restarting) without fault IPC; `TCR_EL1.HA` stays off. 0029 also adds `Page_DeriveSubframe` (x86_64 and AArch64), which derives up to 512 consecutive unmapped 4 KiB capabilities from a RAM-backed 2 MiB frame into a validated window of CNode slots, with intersected rights, allocating nothing. Aliases are smaller regions in the derivation tree: deleting the large cap leaves them valid, and revoking the backing Untyped removes all of them and their mappings. |
| 0024 | (x86) No boot without SKIM unless the CPU reports RDCL_NO (above). |
| 0025 | (x86) `GetIOAPICRemapped` adds a 16-bit interrupt-remapping table index to the I/O APIC handler arguments and writes the remappable RTE format. Root publishes the matching VT-d IRTE first; seL4 keeps pin masking, acknowledgement and capability lifecycle and does not manage the IOMMU. |
| 0038 | (x86, `KernelVTX`) A kernel built with VT-x boots on a CPU without usable VT-x (no VMX, VMX locked off by firmware, or no EPT write-back or 2 MiB support) instead of halting. The boot core records the result in `x86KSVTXEnabled`; secondary cores skip VT-x when it is off and must match the boot core when it is on. Without VT-x, `Untyped_Retype` refuses VCPU and EPT objects (`seL4_InvalidArgument`), which is also how userspace probes for it. With the SKIM window VT-x stays off (§4.1). EPT checks run before `vmxon`, and a failed `vmxon` clears `CR4.VMXE`, so no core is left in VMX operation, where INIT is blocked. This lets one `KernelVTX` image (§4.1) serve hosts with and without VT-x. |
| 0039 | (x86_64, `KernelVTX`) The VCPU interface KVM in a guest needs (§5.10), and VM exits and entries with only the VMCS and MSR accesses they need (each one is an exit when seL4 runs nested without VMCS shadowing): the syscall MSRs switch through the MSR-load lists, an exit reads only the fields its reason defines, VMEnter writes only what changed, and EPT maps do no `invept`, as they only fill not-present entries. Userspace can turn on only listed VM-execution, exit and entry controls: the others use VMCS address fields nothing sets (virtual APIC, PML, posted interrupts, VMCS shadowing, #VE), which would point at host physical page 0. MOV-DR, RDPMC, MWAIT and MONITOR always exit, and so do #AC, #DB and #MC whatever the exception bitmap says: a guest could make delivering #AC or #DB raise it again, a loop no host interrupt ends (CVE-2015-5307, CVE-2015-8104). With the hardware debug API, DR0-3 are cleared before a VM entry, as a guest DR7 could enable another thread's breakpoints. `VMEnter` returns one MR layout for faults and notifications, adding CR2 and the exit and IDT-vectoring information; when the VCPU did not run, the exit fields read 0 and `INTERRUPT_INFO_MR` keeps the undelivered event. The guest's CR2 survives exits (other threads' page faults overwrite it) and `WriteMSR(SEL4_VCPU_MSR_CR2)` sets it. Unmapping an EPT page or table invalidates every core that may hold the root's translations, so no core keeps translations of an unmapped frame (upstream unmapped pages without any `invept`); so does deleting an EPT root, as nothing below it can then be found to unmap and maps no longer invalidate a root reused at the same address; so does deleting an ASID pool, for the EPT roots in it; and `invept` passes the whole EPTP, which nested KVM matches in full, and reaches the cores that looked the root up to enter a VM since it was last invalidated, which each root keeps in the upper halves of its last two entries (they map nothing, as guest-physical addresses end at 2^47, and stay not present): interrupting every core that had entered a VM instead let any guest take them all out of guest mode, to queue for the kernel lock, as often as it could map and unmap a page of its own. A core records that it enters VMs, and looks up the EPT root to enter with, before releasing the kernel lock to enter one (looked up after, the root could come from an ASID pool another core had just deleted and freed, and be one that has no ASID any more, whose tables can still map freed frames); `VCPU_FlushTLB`, for what the guest's own paging produced, flushes only the VCPU's VPID before it next runs, which needs no IPI, as a core the VCPU arrives on flushes it then (an `invept` interrupted every core that had run a VM on each guest TLB flush). each VCPU has its own XCR0, checked as XSETBV would (AVX-512, MPX and AMX state only whole, whatever `KernelXSaveFeatureSet` enables) and loaded only around VM entries; a VCPU new to a core, or given a VPID, has it invalidated there; a thread about to enter guest mode makes its VCPU its core's current one before releasing the kernel lock (`vcpu_make_current()`), so an invocation on another core always finds it there and takes it out of guest mode first, and takes its VPID there too, as every core shares the VPID table and two cores could give two VCPUs the same one (revoking an I/O port cap then left the ports to the other); `WriteRegisters` takes the VCPU out of guest mode first too; a thread that loses its VCPU in guest mode (`SetTCB`, the VCPU's deletion) has its `VMEnter` end as a notification ends it, or with the exit it has still to report, rather than entering guest mode again with none, and its core is stalled first, as for an invocation of the thread (it may be waiting there for the kernel lock after an exit, where a later stall IPI took the now running thread for one in a system call and made it start its `VMEnter` again, in place of the result it had been given), and a deleted thread is unbound from its VCPU, which kept pointing at the freed TCB. Rebinding stalls both affected TCBs, and final VCPU deletion stalls its bound TCB; if either stall refuses, the operation retries before changing bindings; an exit for userspace is the VCPU's until userspace has it: a thread that a stall IPI took off its core while it waited for the kernel lock with one (another core invoking the thread) entered guest mode again when it next ran and the exit was dropped, which repeated a fault but lost a trap (the #DB of a single step, which always exits), so the thread now returns the exit when it next runs, a notification signalled meanwhile stays for its next `VMEnter`, and a thread that loses its VCPU meanwhile returns the exit then; with MCS, `TCB_SetPriority` and `TCB_SetSchedParams` requeue a thread in guest mode as they do a running one (it stayed in the ready queue of its old priority, when preempted or when its core was stalled for the invocation, and was later dequeued from the queue of the new one, where a NULL neighbour was a kernel fault that any guest could cause with its own TCB and VCPU); an exit reads its interrupt information and qualification, and a failed entry restores the kernel's XCR0, before taking the lock, as an invocation there can take the VMCS meanwhile; a notification interrupts another core only for a thread running there, and otherwise ends the `VMEnter` itself, as the IPI handler would take the VCPU back inside the signaller's remote call; an exit userspace does not see (an external interrupt) that came while the CPU delivered an event has that event injected again, from the IDT-vectoring information, unless userspace injected one since; an exit for a failed VM entry leaves the launch state and the entry event as they were; a failed VM entry of a 64-bit-guest kernel swaps GS back and moves to the kernel stack, as an exit does (upstream left the thread's GS base in `GS_BASE` and ran on the VCPU object); VM-return preparation and bound-notification checks run with the kernel lock held; the stale-timer fast return handles native threads only; `EnableIOPort` refuses a range whose low port is above its high one, which reached ports outside the cap, and gives a VCPU without a VPID one, as revoking the cap finds the VCPU by VPID; `WriteVMCS` takes only the active and HLT activity states, as no host interrupt ends guest mode in shutdown or wait-for-SIPI; WBINVD always exits where the CPU can make it, as a guest's would flush the caches the core shares with seL4 and other guests; an exit forgets the guest's RIP, so a thread resumed after a suspend in guest mode enters with the RIP it brings; `WriteVMCS` takes the TSC offset and entry instruction length, `Read`/`WriteMSR` `KERNEL_GS_BASE`, canonical in 57 bits on a CPU with 5-level paging. A VM exit leaves GDTR and IDTR with the limit 0xffff, so the exit path loads the limits the tables have (upstream loaded them only at boot, and after a core's first exit selectors past the end of its GDT named the kernel data after it); `WriteVMCS` turns on "load IA32_PERF_GLOBAL_CTRL" for entries only on a CPU whose exits load the host's value again; `ReadVMCS` of a field the CPU lacks returns 0, not what the register last held, as the failed VMREAD writes nothing; and an NMI injected again after an exit userspace did not see has its blocking cleared first, as an entry that injects one with it set fails its checks; a spurious interrupt that ends guest mode (vector 255, acknowledged on the exit) is dropped as `c_handle_interrupt()` drops it, where upstream handled it as IRQ 223, reported it as above `maxIRQ` and sent an EOI; VPIDs are used only on a CPU with an INVVPID that flushes one VPID, or all of them, which every core must have (an INVVPID of a type the CPU lacks fails without a fault, and nothing then flushed a VPID that changed hands or cores); and an exit for an INVPCID, or for a failed VM entry, reports its qualification (the operand, and which check or MSR failed), the latter without IDT-vectoring information or an instruction length, which the CPU leaves from the exit before it. The host SYSENTER fields of the VMCS are 0 in a kernel entered with SYSCALL, as every VM exit loads the SYSENTER MSRs from them: upstream put the entry point of a SYSENTER kernel there, so after a core's first VM exit any thread on it entered the kernel with SYSENTER, at an entry the kernel is not built for (with the user's TF, which stops the machine, and a return address that nothing checked before SYSRET used it), where it must be a #GP. `ReadMSR` of `KERNEL_GS_BASE` takes the VCPU out of guest mode on another core first, as `ReadVMCS` does. The guest runs on the TCB's FPU state, without the two swaps per exit seL4 made into state userspace could not read. |
| 0040 | (x86_64, `KernelVTX`) AMD-V (SVM) behind the same VCPU interface (§5.10), chosen by `vtx_init()` on AMD CPUs: the VCPU holds a VMCB, the EPT objects hold nested page tables (`nptFromEPT()` converts what `ept.c` builds, the memory type into an index into the host's PAT, write-combining included; what it reads back is in the same place), and `VMEnter` keeps VT-x's MR layout with SVM's fields (`vmenter.h`). A core needs SVM not disabled in `VM_CR`, nested paging, next-RIP saving and ASIDs, or the kernel boots without VMs as with 0038; SKIM leaves SVM off too, and so does a build without `KernelX86_64VTX64BitGuests`, as `restore_svm()` switches r8-r15, which the VCPU then does not hold. `ReadVMCB` reads up to 64 words, `WriteVMCB` writes one word, by byte offset; userspace writes only the fields and bits `svm_field()` lists, and seL4 keeps on the intercepts the host needs (INTR, NMI, SMI, INIT, shutdown, INVD, which would discard other guests' and seL4's dirty cache lines, WBINVD, which would flush the caches they share, I/O and MSR maps, VMRUN, VMLOAD, VMSAVE, CLGI, STGI, SKINIT, INVLPGA, XSETBV, RDPMC, RDPRU, MONITOR, MWAIT, all debug registers, #DB, #AC and #MC) and the fields that hold host addresses or would make the CPU use one (map bases, nCR3, ASID, AVIC, SEV, virtual VMLOAD/GIF), which read as 0; addresses are canonical in 57 bits on a CPU with 5-level paging, as on VT-x. CR4 writes always exit, and CR4 takes only the bits in `VCPU_GUEST_CR4_ALLOWED` (`vcpu.h`, shared with VT-x in 0042), as 0042 describes. VMRUN runs inside CLGI with IF set, so host interrupts end guest mode (`V_INTR_MASKING` is always on); the STI comes right after CLGI, as AMD CPUs leave the STI shadow of an STI just before VMRUN in the guest's interrupt state when VMRUN exits during event injection; the host's FS, GS, TR, LDTR and syscall MSRs come back with VMLOAD from a copy each core saves once, so the exit then reloads the thread's FS and GS bases and resets seL4's cache of them (a `KernelFSGSBase=msr` kernel otherwise skips a WRMSR it thinks is done), and STGI comes only on the kernel stack, where an NMI held since the exit is ignored (only between `restore_svm()` and the exit's handler: elsewhere a kernel NMI still halts, as it may have come in another trap's frame or with the user's GS; a kernel exception's frame goes below the red zone of the code it interrupts, as this one returns to it). The exit finds the host save area's address in the VCPU's SVM state, not its register array, which `WriteRegisters` and `WriteVMCB` write. An invocation on a VCPU whose thread is in guest mode on another core first takes it out of guest mode there, as `switchVCPU()` does on VT-x (`vcpu_make_current()`, 0039, records it as the core's before the lock is released, so none is missed, and sets the nested page table root there, as the EPT root on VT-x), since the CPU owns the VMCB during VMRUN and the exit writes the VCPU before taking the kernel lock; a deleted VCPU is forgotten on every core it ran on. `VMEnter` takes only EVENTINJ's defined bits, as `WriteVMCB` does, and its MRs from a thread without an IPC buffer too; an exit for userspace is recorded in the VCPU before the lock and reported as 0039 does on VT-x (by its thread with the lock, or when it next runs after a stall IPI, or by whoever takes its VCPU meanwhile), and the save area is reset after a shutdown before that; an INTR, NMI, SMI or INIT exit that came while the CPU delivered a hardware event has it injected again from EXITINTINFO, as 0039 does on VT-x (a software interrupt, INT3 or INTO runs again from its instruction). ASIDs are per core: an invalidation (nested page table unmap) moves the cores that may hold the root's translations (0039) to a new generation, and every VCPU takes a fresh ASID before running there again, while a new root or `FlushTLB` gives only its VCPU one; when they run out, entries flush all ASIDs until a VMRUN passes its checks. VMCB clean bits are cleared for each group a write changes, and all of them when the VCPU moved or another ran on the core; a VMRUN that fails its checks leaves them cleared, and reports no EXITINTINFO, which is the exit's before it. The VCPU's XCR0 (0039) is loaded around VMRUN as around VM entry, and `Read`/`WriteMSR` take it (both only with `KernelX86_64VTX64BitGuests`, as on VT-x). |
| 0041 | (x86, `KernelVTX`) VT-x keeps CR0.CD, CR0.NW and the reserved CR0 bits (28:19, 17, 15:6) in the CR0 guest/host mask, whatever userspace writes to `VMX_CONTROL_CR0_MASK`: VM entries and exits do not load these bits, so a guest MOV to CR0 that set CD or NW would leave the core's caches off for seL4 and every thread after it. A guest write to them now always exits. l4h's KVM already owns all of CR0 (`CR0_GUEST_HOST_MASK` is `~0` in `kvm/vmx.c`), so nothing changes for it. AMD-V needs no counterpart, as #VMEXIT reloads the host's whole CR0 from the host save area. Cherry-picked from upstream seL4 PR #1847 (open), without its CHANGES.md entry. |
| 0042 | (x86, `KernelVTX`) VT-x guests set only the CR4 bits on an allowlist, `VCPU_GUEST_CR4_ALLOWED`, as they turn on only the VM-execution controls on 0039's lists. 0040 defines the list and applies it on AMD-V. The list holds the bits whose effects stay in guest mode, on state that VM entry and exit or seL4 switch: VME, PVI, TSD, DE, PSE, PAE, MCE, PGE, PCE, OSFXSR, OSXMMEXCPT, UMIP, LA57, FSGSBASE, PCIDE, OSXSAVE, SMEP and SMAP. Every other bit stays clear, including any a later CPU defines, because some enable state that nothing switches and that the next guest on the core would run with. PKE is one: PKRU is outside the XSAVE features seL4 enables (`KernelXSaveFeatureSet` 7), and the host runs with CR4.PKE clear. KL is another: LOADIWKEY sets the core's Key Locker wrapping key. PKS, CET, UINTR and FRED are left out for the same reason. On VT-x, the bits outside the list are always in `VMX_CONTROL_CR4_MASK`, so a guest changing one exits, and `GUEST_CR4` takes only listed bits and the fixed ones (VMXE). On AMD-V (0040), which has no CR4 mask, CR4 writes always exit and `WriteVMCB` keeps the bits outside the list clear. l4h's KVM already owns all of CR4 and hides PKU, CET, LAM and FRED, and Linux's KVM does not offer Key Locker, PKS or UINTR, so nothing changes for it. |
| 0043 | (x86, `KernelVTX`) VT-x keeps CR8-load and CR8-store exiting on, as 0039 keeps MOV-DR exiting on. CR8 is the core's local APIC TPR: 0039 does not allow the TPR shadow, so with these exits off a guest MOV to or from CR8 reaches the TPR, which neither VM entry and exit nor seL4 switch. The next guest on the core would read the value, and a guest that raised it would mask the host's timer and IPIs on that core, in guest mode and after it. A guest's CR8 access is now a control-register exit to userspace, which emulates CR8 per VCPU. l4h's KVM already sets both exits (`kvm/vmx.c`), so nothing changes for it. AMD-V needs no counterpart, as `V_INTR_MASKING` is always on (0040) and a guest's CR8 is its VMCB's `V_TPR`. |
| 0044 | (MCS) `SchedContext_Consumed` appends a `runnable` word: a bound thread is runnable and the SC has available budget. The existing consumed-time prefix and invocation labels stay unchanged, so older clients can ignore the new result. The snapshot is taken after synchronizing a remotely running context and needs only the SC capability. Vmmgr uses it to distinguish idle capacity from a guest waiting to run, without another syscall or trusting a guest's idle counter. Host builds need the matching kernel headers and kernel. |

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
hooks (§10.2), the Android features of §5.8 and x86's
`load_unaligned_zeropad()` (§5.2).

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
  still between its check and its access. For the same reason the x86_64
  `load_unaligned_zeropad()` (checksum tails, dcache name hashing,
  `strscpy`, siphash) cannot rely on x86's `EX_TYPE_ZEROPAD` fixup: a word
  that crosses into the next page reads it only when that page passes the
  same check, and otherwise loads the aligned word ending its own page and
  shifts in zeroes.

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
- **Kernel lockdown.** Guests can enable Linux lockdown with
  `lockdown=integrity` or `lockdown=confidentiality` on their command line.
  The lockdown LSM initializes early, even with an explicit `lsm=` list,
  and exposes its state at `/sys/kernel/security/lockdown` when securityfs
  is mounted. Lockdown is off by default. `modules_install` signs the
  shipped modules with the build's key, whose certificate is built into
  the kernel; the private key is not included in the module image.
  Guests that enable lockdown reject unsigned external modules.
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

### 5.10 KVM inside guests

Where the CPU has VT-x or AMD-V, the x86_64 guest kernel provides
`/dev/kvm` for unmodified QEMU, Firecracker and cloud-hypervisor.
The guest runs in ring 3, so it cannot run VMX or SVM instructions: it
builds `arch/x86/kvm`'s common code (`x86.c`, the TDP MMU, lapic/ioapic/PIT,
the emulator, `virt/kvm`) with a vendor backend in `arch/l4h/kvm` that
implements `kvm_x86_ops` on seL4 VCPU objects: `vmx.c` on VT-x (patch
0039), `svm.c` on AMD-V (patch 0040), and `common.c` for what they share
(VCPU objects and their binding, the stubs, and the choice, by CPUID's
vendor, as seL4 makes it).

- **Enabling.** l4h-root retypes a VCPU at boot; patches 0038 and 0040
  refuse it without usable VT-x or AMD-V. Where it works, vmmgr gives every guest
  `L4H_MAX_EPT_ROOTS` (8) EPT PML4s with ASIDs at `L4H_SLOT_EPT_POOL`, as
  it gives VSpace roots, and `bootinfo.nr_ept_roots` says how many. With
  none the guest registers no `/dev/kvm`. Each KVM VM takes a root, so a
  guest runs at most 8 VMs at a time.
- **Running a vCPU.** `KVM_RUN` calls `seL4_VMEnter` on the kTCB of the
  L4H vCPU it runs on; `vcpu_load` binds the VCPU and the VM's EPT root to
  that kTCB when they are not already. The exit is the call returning,
  with the guest's GPRs, RIP, RFLAGS, CR2, interruptibility and the exit
  and IDT-vectoring information in message registers; RSP and CR3 are
  read when KVM needs them. A notification
  on N_v (timer, IPI, device event) ends the call too, and counts as an
  external-interrupt exit: the vCPU's events are delivered when KVM
  re-enables interrupts. Other VMCS reads are system calls, cached until
  the next entry; GPRs are written back only when they differ from what
  seL4 holds.
- **On AMD-V** the same calls carry SVM's fields (patch 0040): the exit
  code, EXITINFO1 and 2, NEXT_RIP's instruction length, the interrupt
  state, CR3 and EXITINTINFO, and the misc1 intercepts (the IRQ and NMI
  windows' VINTR and IRET) go in with each entry. The VMCB is memory to
  seL4, so `ReadVMCB` returns 32 words at a time into a copy that lives
  until the next entry, and `WriteVMCB` writes through. `svm.c` follows
  Linux's `svm/svm.c`: CR0 and CR4 writes and CR8 always exit, CR0 reads
  only when the CPU's CR0 differs from the guest's, CR3 never; NMI masking
  is tracked to the IRET (no vNMI), and an NMI blocked by an interrupt
  shadow is single-stepped to, except on an entry that injects an event,
  whose frame would keep the TF (the window is looked at again at the next
  exit, as VMEnter has no immediate exit); IRQ windows are a V_IRQ at the
  highest priority. Nested KVM gives L1 no decode assists, so CR, DR and string I/O
  exits go through KVM's emulator. seL4 keeps #DB, #AC and #MC
  intercepted; the debug registers always exit, as on VT-x, and so does
  XSETBV, whose XCR0 reaches seL4 as on VT-x (FPU below).
- **Nested guest memory.** KVM keeps its TDP page table in software, and
  the CPU walks a seL4 EPT (or, on AMD, a nested page table) that mirrors
  its leaves (`kvm/ept.c`, the same for both: KVM's SPTEs use the EPT
  masks on both, as no CPU walks them), as
  process VSpaces mirror Linux page tables (§5.3): one frame-capability
  copy per mapping, 4 KiB or, for a RAM block with a large frame, 2 MiB.
  A hook in the TDP MMU (patch `guest/linux/patches/0016`) syncs a leaf to
  its SPTE's current value after each change, under a per-VM lock, so
  concurrent changes cannot leave a mapping behind; a fault KVM finds
  spurious syncs it again, which repairs anything the EPT lacks. Fast page
  faults are off (they change SPTEs without the hook); there are no
  accessed or dirty bits, so aging and dirty logging use write protection
  and access tracking. Revoking a block takes our capability copies, and
  the nested guest refaults. seL4 invalidates the EPT on every core that
  has entered a VM on it since it was last invalidated, whenever it
  removes a leaf or table, and adding one
  needs no invalidation (no TLB holds a not-present entry), so KVM's
  remote TLB flushes have nothing to do. `kvmtest.c` checks that a
  replaced memslot and a dirty-log write-protect take effect at once.
- **FPU.** seL4 runs the guest on the kTCB's FPU registers. The guest's
  XSAVE state stays loaded across exits and is saved when kernel-mode SIMD
  needs the registers, when the task leaves `KVM_RUN`, and in `vcpu_put`,
  when it is scheduled out of its vCPU in between and may migrate. `KVM_SET_XSAVE`
  refuses a state XRSTOR would fault on. The guest's XCR0 (a subset
  of seL4's x87, SSE and AVX) is loaded by seL4 around its VM entries
  while CR4.OSXSAVE is set, so XGETBV, CPUID leaf 0xD and XSAVE agree
  with what the guest set.
- **What the common code would do in ring 0** (MSRs, debug registers,
  XSETBV, WBINVD, IBPB) is a no-op through `arch/l4h/kvm/compat.h`. Optional
  static calls left NULL return 0 (the guest has no `HAVE_STATIC_CALL`).
- **Not available**, as seL4's VCPU interface cannot provide them: APICv,
  AVIC and posted interrupts, PML, nested VMX or SVM, vNMI, the PMU, PKU, XSAVES, AVX-512,
  RDTSCP/RDPID (seL4 does not switch `TSC_AUX`), hardware breakpoints in
  the guest, and the speculation-control MSRs (hidden from guests, which
  get no IBPB between nested VMs either). SMM is not built.
- **Huge pages.** A new memslot asks for THP behind it (`MADV_HUGEPAGE`,
  unless the VMM said `MADV_NOHUGEPAGE`), for 2 MiB EPT leaves: the guest
  kernel's THP mode is `madvise`, and Firecracker, unlike QEMU, does not
  ask. Its guests booted 2.5 times as slowly without.
- **Cost.** Every exit is an seL4 call and its return; the VMCS reads KVM
  needs beyond what the exit returns are calls too, cached until the next
  entry. On a host without VMCS shadowing, which is the case for nested
  KVM on this development machine, each VMREAD and VMWRITE seL4 does is
  itself an exit to L0, so patch 0039 keeps them to what each exit needs,
  switches the syscall MSRs through the VMCS MSR-load lists, and maps into
  the EPT without `invept`. `tests/run-kvmbench.sh` compares l4h's dom0
  as L1 with the same Linux kernel as L1, both with two vCPUs, under
  nested KVM on an i7-13700H (best of 3; boots are QEMU 10.0, Firecracker
  1.17 and cloud-hypervisor 54 booting Debian's 6.12 kernel on 2 vCPUs):

  | | Linux L1 | l4h dom0 |
  |---|---|---|
  | guest compute (10⁹ loop iterations) | 267 ms | 263 ms |
  | CPUID exit (handled by KVM) | 54 µs | 50 µs |
  | port I/O exit to the VMM | 72 µs | 64 µs |
  | MMIO exit to the VMM (emulated) | 92 µs | 84 µs |
  | first touch of a 4 KiB page (EPT fault) | 49 µs | 64 µs |
  | boot under QEMU | 1.96 s | 2.64 s |
  | boot under Firecracker | 1.51 s | 2.29 s |
  | boot under cloud-hypervisor | 1.57 s | 2.17 s |

  Before these changes an exit took about 155 µs and a Firecracker boot
  13 s. An EPT fault costs a capability copy and a map on top of the exit,
  and each unmap an `invept` on every core that has run a VM (about 0.3 s
  of each boot; batching them is left to do).
  About 85% of an exit is the `seL4_VMEnter` call, almost all of it L0's
  emulation of the nested entry and exit.
- **Cost on AMD-V.** There is no VMREAD or VMWRITE to trap: an exit costs
  L0's emulation of VMRUN and the three VMLOAD/VMSAVE around it (`vls=0`
  on L0 here, so each is an L0 exit, as it is for Linux as L1). On a
  Ryzen 7 7700 (Zen 4) under nested KVM, Linux 6.12 as L0, same benchmark
  and VMMs as above, best of 3:

  | | Linux L1 | l4h dom0 |
  |---|---|---|
  | guest compute (10⁹ loop iterations) | 188 ms | 189 ms |
  | CPUID exit (handled by KVM) | 6.2 µs | 6.4 µs |
  | port I/O exit to the VMM | 9.4 µs | 8.2 µs |
  | MMIO exit to the VMM (emulated) | 10.4 µs | 9.3 µs |
  | first touch of a 4 KiB page (nested page fault) | 23.6 µs | 25.3 µs |
  | boot under QEMU | 1.36 s | 1.48 s |
  | boot under Firecracker | 1.24 s | 1.36 s |
  | boot under cloud-hypervisor | 1.24 s | 1.34 s |
- **Test.** `tests/run-kvmtest.sh`, `tests/run-kvmbench.sh`,
  `tests/run-vtxtest.sh`, `tests/run-vcpustress.sh` (§14.3).

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
- **Lock-holder preemption.** A vCPU that holds a spinlock, or waits in
  a queued spinlock's line, can lose its core to another thread or run out
  of budget under a CPU cap (§7.2), for milliseconds; a waiter that spins
  meanwhile burns its core, and under a cap its own budget. The balancer
  keeps a guest's vCPUs on distinct physical cores where possible (§7),
  and guests with more than one vCPU use Linux's **paravirtual queued
  spinlocks** (`CONFIG_PARAVIRT_SPINLOCKS`, `asm/qspinlock.h`); qrwlocks
  queue their writers on one.
  - The waiter at the head of a lock's queue, and those queued behind
    it, spin for `SPIN_THRESHOLD` = 2¹¹ `cpu_relax()` iterations, an
    estimated 100 µs with interrupts on and less with them off or on
    AArch64, then block their kTCB in `seL4_Wait(N_v)` while the word they
    watch is unchanged (`l4h_pv_wait()`). The vCPU that changes the word
    signals the waiter's `N_v` afterwards, at once or when it unlocks
    (`l4h_pv_kick()`), with the IPI badge and no reason bit: a vCPU that
    no longer waits runs no handler for it, though it ends one user run,
    VM entry or idle wait like any event. Signals are sticky: one sent
    between the check and the wait ends the wait at once. Neither the
    host nor seL4 takes part beyond the IPI path.
  - With interrupts on, a waiter delivers pending events instead of
    blocking, and those that end its wait, as its `cpu_relax()` did while
    it spun; like it, not inside an event's own delivery, softirqs
    included, where it blocks with events pending until the handler
    returns. With interrupts off, events already collected do not keep it
    from blocking, and one that ends the wait stays pending for the next
    polling point (§5.4); the lock code re-checks the lock after any
    wake-up.
  - Unlocking is a compare-and-exchange instead of a store. There is
    no code patching in `arch/l4h`, so a static key read by every lock
    slow path and unlock selects the native operations for guests given
    one vCPU, and with `nopvspin` on the kernel command line. It is
    switched in `smp_prepare_cpus()`, while one vCPU runs. The unlock is
    inlined at some 5000 places, which adds about 230 KiB (1.4%) to the
    x86_64 kernel's `.text`; the image, padded to 2 MiB, is no larger.
  - Modules inline the unlock too, so one built for the other kind must
    not load: the version magic says `pvspinlocks` (`asm/vermagic.h`).
  - Time blocked for a lock counts as idle, not steal (§7.4).
    `/proc/interrupts` has a `PVW` row: each vCPU's waits in seL4 for a
    lock.
  - Not covered:
    - A waiter that arrives when the head of the queue has blocked spins
      on, trying to steal the lock, until the lock is free or the head
      wakes and spins again (`pv_hybrid_queued_unfair_trylock()`): with
      interrupts on that is the head's next tick, with them off not
      before it is kicked. So during one long preemption the first
      waiter blocks, with those that queued behind it while it still
      spun, and later ones burn their time as before.
    - Readers of a qrwlock waiting for a writer, and a writer waiting
      for readers, spin.
    - `vcpu_is_preempted()` is always false, as before, so mutexes and
      rwsems still spin optimistically on an owner whose vCPU is not
      running. The guest cannot tell; seL4 would have to publish it.
  - The threshold is not yet tuned by measurement.
  - **Test.** `tests/run-pvlocktest.sh`: a module contends four locks on
    every vCPU, holding them for 5 ms at times, and calls a function on
    the other vCPUs from under one. No update is lost, waiters block
    (counted apart with interrupts off and in timers) and take the IPI,
    in a 4-vCPU dom0 and a 4-vCPU guest capped at 25%, and none blocks in
    guests with `nopvspin` or one vCPU. It does not measure how long
    waiters spin, nor the accounting.
- **Memory barriers.** On x86_64 the barriers between CPUs are those of
  `arch/x86` (`x86/asm/barrier.h`): a vCPU is a thread on an x86 CPU, which
  reorders only a store with a later load.
  - `smp_mb()` is a locked add. `smp_rmb()`, `smp_wmb()`,
    `smp_store_release()`, `smp_load_acquire()` and the barriers around
    atomic operations emit nothing. `dma_*` and `virt_*` follow them: the
    host's components share guest memory from other cores of the same
    machine. `mb()`, `rmb()` and `wmb()` stay fences.
  - UML's header, written for one CPU, left all of these to asm-generic,
    which builds them from the fences: an `mfence` in every
    `spin_unlock()` and `set_current_state()`, an `lfence` in every
    seqlock read. The kernel image had 9477 `mfence`, 2179 `lfence` and
    691 `sfence`; it has 10, 9 and 12, and 502 locked adds.
  - AArch64 guests keep asm-generic's barriers, built from `dmb`.
- **Steal time** is published by the balancer in the event page (§7.4).

---

## 7. Host scheduling

### 7.1 Priorities

Global on each core, with `P_K` = `PRIO_KERNEL` = 100:

| Priority | Components |
|----------|------------|
| root task | l4h-root |
| `P_K + 4` | l4h-netd (switches and NIC drivers), l4h-blkd (disk drivers), l4h-memd and l4h-vmmgr (both on core 0) |
| `P_K + 3` | boosted l4h-vmm instances; l4h-trustd (last core, at most 5 ms per 20 ms) |
| `P_K + 2` | l4h-logd (core 0, at most 1 ms per 5 ms), strictly above throttled VMMs |
| `P_K + 1` | VMMs whose boost was withdrawn; their budgets are limited only while a guest on their core can run |
| `P_K` | guest kernel TCBs (`SC_K`) |
| `P_U` = 99 | guest user TCBs (`SC_U`) |

Boosted, uncapped VMMs have full round-robin scheduling contexts. At each
100 ms sample, vmmgr withdraws the boost only if VMMs consumed at least
80% of wall time on their core and another guest or VMM needs CPU (or
logd shares core 0). Only the largest consumer, including ties, loses
its boost. Idle VMMs do not change that selection, so a spinner using
60% does not demote an I/O neighbour using 40% merely because six other
VMMs are idle.

Throttled VMMs stay above guest kernels at `P_K + 1`, so a kernel spinning
for a device reply cannot starve the VMM servicing it. While a guest on
their core can run, these VMMs divide a combined half-core budget,
leaving time for guest users. The kernel's `SchedContext_Consumed`
runnable snapshot (0044) supplies that demand; a guest's reported idle
counter does not. When no guest there can run, the extra limit is removed
even during boost backoff: a busy VMM can use spare CPU rather than stay
hard-capped on an idle core. Explicit guest caps still apply. Limited
periods grow if necessary to keep every SC above 200 µs. Other VMMs,
including idle ones, do not divide this allowance.

Before demotion vmmgr lowers the VMM's MCP to `P_K + 1`, so its own TCB
cannot restore priority `P_K + 3`. Recovery requires continuous use below
half its allowance for 1 second after the first demotion, then 2, 4, 8
and at most 16 seconds after repeated demotions. Busy samples reset the
quiet streak. Other VMMs' use does not block recovery, and the MCP stays
low when the manager restores priority. This prevents 100 ms quiet/spin
cycles regaining a full boost every other sample. A VMM spinning before
READY is protected and its CPU use appears
in management statistics. `tests/run-vmmfairtest.sh` checks progress with
continuously runnable guest kernel, user and logd-priority threads in the
real kernel, the runnable-state snapshots, and the authority ceiling.
`tests/run-vmmguardtest.sh` has an actual VMM spin before READY, try to
undo demotion, and go quiet for a restored boost; a CPU-bound guest on
the same core must boot and keep making progress throughout.

VMMs stay on the core where vCPU 0 started; moving that vCPU does not move
the VMM. A CPU cap charges the VMM's hypercalls, virtio queues, display
and console work against vCPU 0's budget (§7.2).
Other host services run with full budgets unless listed above.
memd charges hotplug to the guest's token bucket (§8.5). Because
`P_K > P_U` for every guest, one guest's kernel work can briefly preempt
another guest's user work, bounded by `SC_K` budgets.

### 7.2 Budgets and CPU caps

- `SC_K` and `SC_U` of each vCPU have a period of 5 ms. Uncapped, each has
  the full period as budget; sums across a core may exceed 100%
  (overcommit), and threads with budget left are scheduled round-robin
  within the guest band. CPU weights are not implemented.
- **CPU caps** (`vm_set_sched`, `l4hctl sched`) give each vCPU one budget,
  a percentage of the period, split between SC_K and SC_U. vCPU 0 shares
  its budget with the guest's VMM. Thus the guest and its VMM together stay within the
  cap times the number of vCPUs.
  - Each SC needs at least 200 µs. Below 12%, vCPU 0's three SCs need a
    longer period (600 µs every 60 ms at 1%); other vCPUs' two SCs need
    one below 8% (400 µs every 40 ms at 1%). AArch64 capped vCPUs use
    at least a 40 ms period to amortize emulated GIC timer delivery.
  - The split adapts: when, in a balancer period, any SC used at least
    90% of its part, the budget is split in proportion to what each used
    (each keeps at least 200 µs). A vCPU alternates between its kernel and
    user threads, so when one SC runs out the other stalls too; the usage
    ratio survives that throttling, where splitting by "what the other
    used" oscillated every period. For vCPU 0 the VMM's fraction adapts
    too, starting at one quarter of the cap; its minimum remains 200 µs.
  - Splitting one budget between two strictly alternating SCs still loses
    capacity: whichever runs out first stalls the vCPU while the other's
    budget goes unused. In `tests/run-capperf.sh` (release seL4, nested
    KVM), 200 fork+exec at a 50% cap take 3.9 s, against 0.4–0.7 s
    uncapped, and 1.8 s with both SCs given the whole budget (which breaks
    the cap). About 2× is the split; the other 2× is not yet explained.
  - seL4 keeps the sliding-window limit of a reconfigured SC whose thread is
    runnable; an idle or unbound SC starts afresh with its new budget.
    That allows at most one period's budget extra per change. The split
    changes at most once per balancer period; cap changes and the VMM's
    start can also reconfigure its SCs. Guard transitions and changes in
    the number of throttled VMMs can change their VMM allowances; ordinary
    boosted VMMs starting or stopping do not change a neighbour's limits.
    Unchanged limits are never
    reconfigured on ordinary IPC turns. Samples covering more CPU time
    than elapsed (consumption reported late) do not move the split.
    A failed SC or priority update stops only that guest, including a
    partial update. Adapted shares and cached plans are committed only
    after configuration succeeds; the rest of the balancing pass continues.
  - seL4 refuses to bind an exhausted SC to a blocked thread, so the guest
    waits for the refill on 100 µs timers when it moves a capped SC_U to
    another process, not with `seL4_Yield`, which would charge SC_K its
    whole remaining budget. A timer deadline that passes during those
    waits is kept as a pending event for after the bind.
  - Guest and VMM SCs hold 16 refills (512-byte objects): with seL4's minimum of
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

The guest accumulates its idle time in the event page (`idle_ticks`),
including the time its vCPUs block waiting for a spinlock (§6). Each
balancer period vmmgr computes, per vCPU, `steal = wall − consumed − idle`
from the vCPU's first run and publishes it monotonically as `steal_ns`.
The guest returns it as Linux's paravirt steal clock
(`CONFIG_PARAVIRT_TIME_ACCOUNTING`), so it shows as `st` in /proc/stat and
top: a guest capped at 25% sees about 75% steal (`tests/run-m6test.sh`).
`l4hctl top` and the host dashboard show each VM's CPU use over the last
period, including its VMM's consumption.

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
and `restart-dom0`, which root posts in vmmgr's mailbox (§10.3);
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
keeps to the upper half, and logd draws host output on the lower (§10.4).

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
  The guest is held to both: a chain with a longer data
  segment, or with more data segments than `seg_max` (14, or fewer if the
  disk's device takes fewer; data sharing the header's or the status byte's
  buffer counts), is returned with an I/O error and never reaches blkd.
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
  memory a device can still reach is reused (§10.1). Only the pool and blkd's DMA memory can be
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
    objects, its mappings of the backends included (`Guest::start_bytes`),
    in the guest's arena (`Arena::reserve`), failing with `ENOMEM`
    otherwise, before the kernel is written. `VM_LOAD` checks and reserves
    likewise. The VMM's three large
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
- **Clients.** memd calls no one. Its calls, and which caller may make
  each, are declared in `l4h_host::memd::call` (§10, "Wiring declarations").
  Each call's capabilities cross in the caller's exchange area, at the
  slots the call declares (`call::caps`). Root holds memd's CNode, and its
  area is slots of memd's (`SLOT_XCHG`), into which it moves Untypeds. vmmgr,
  with a badge of its own (`Sender::Vmmgr`), gets memory for itself and
  guests' RAM; memd is more trusted than vmmgr, so vmmgr's area is a small
  CNode the two share (`SLOT_XCHG_CNODE`) instead, memd keeps the original
  of every block it grants vmmgr and gives a copy, and freeing a grant
  revokes the original, so a mislabelled capability in the area cannot
  confuse memd's table. memd takes no capability from vmmgr to invoke: it
  makes the guests' CNodes itself (below), since invoking an endpoint
  vmmgr put there as a CNode would be a call, blocking memd or passing
  vmmgr memd's own CNode. memd empties a slot of vmmgr's area before
  writing one, and a write that fails all the same (vmmgr filled the slot
  again from another thread, or root left its own slot full) fails the
  call, taking back what it gave. VMMs call it, badged as `Sender::Vmm(guest)`, for their guest's
  hotplug operations only (§8.5); root mints those endpoints, since vmmgr's
  own badged one cannot be minted again.
- **Grants.** When a client's free blocks cannot meet a request, it takes an
  untouched Untyped of 16 MiB, or the request if larger (if memd has none
  that large, exactly the request, at least 2 MiB), from memd (`alloc`) and splits it.
  Grants are never merged with each other. When a destroy or failed create
  leaves a client (root or vmmgr) with 48 MiB or more of free blocks, it
  merges them and returns
  whole grants beyond 32 MiB (`free`, `Alloc::trim`); merging after
  every destroy would make creates a fifth slower (§8.2). Host objects,
  arenas, I/O pools and ASID pools come from these blocks.
- **Merging** in memd is lazy for the same reason: free buddies merge only
  when no block is large enough, in one pass over the smaller orders. A
  pass that finds nothing is not repeated until a block is freed or a
  report returns.
- **Guest RAM** (`guest_create`, `guest_copy`, `guest_give`, `guest_destroy`). At create, memd takes the guest's 2 MiB
  blocks and makes its block CNode and hotplug CNode (§8.5) of 2 MiB
  blocks it keeps for guests' CNodes, each free again once no guest has
  one there; vmmgr gets copies, to give the guest. For a boot block,
  memd gives vmmgr a copy of its Untyped, which vmmgr fills with frames.
  At start, memd copies the Untypeds of the other blocks into the block
  CNode, past the kernel's shared blocks (§5.6), which memd has no block
  for. At destroy, once vmmgr has reclaimed its arena, memd revokes every
  original: that deletes the guest's copies, everything the guest made of
  them, and the host's copies of boot blocks with their frames; then the
  guest's CNodes, with every copy. With the
  VSpace roots gone first, deleting the frames unmaps nothing; the other
  way round, each frame was unmapped with a TLB shootdown (585 ms instead of
  about 120 for a stopped 128 MiB guest).
- **Free memory.** memd publishes its free blocks in a status page
  (`l4h_host::memd::Status`), under a sequence count that is odd while
  memd writes it: root and vmmgr take a copy only if the count did not
  change (`Status::read_at`, 16 tries) and otherwise count no memory in
  memd, so `can_afford` refuses. `host_info` reports root's, vmmgr's and
  memd's free blocks; the monitor and dashboard show root's and memd's.
- **Trust.** memd is in the host TCB. It cannot read memory: every Untyped
  it has handed out has a child, so it cannot retype it, and revoking it
  first makes seL4 clear the memory before reuse. It can revoke what it
  handed out, and if it faults, a keeper thread answers its callers with
  an error, so memory requests (grants, guest creation, hotplug) fail from
  then on: blocks a `free` does not take go back to the client's slots
  and stay in use there (`MemdLink::free`, which also empties an exchange
  slot before it puts a block in it), and a boot block it
  cannot copy fails the guest's load.
- **Scheduling.** memd runs on core 0 at `PRIO_KERNEL + 3`, above every
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
  CNode (radix 9, guard 3) that memd makes (§8.4), the only host memory the
  region costs. Before plugging hotplug block m, the guest retypes a
  level-2 CNode (radix 6, 2 KiB) into its slot m from its own object
  memory; memd copies the Untypeds of the block's 64 RAM blocks into it
  (`L4H_HP_BLOCK_CPTR(m, i)`). Frames of hotplugged memory are named by
  `L4H_FRAME_CPTR` like the rest of RAM: the guest makes the level-1 RAM
  CNodes of the region's GiBs (16 KiB each) when it first plugs there.
- **Control.** `VM_SET_MEM` (vm, bytes): vmmgr rounds the part above boot
  RAM up to whole hotplug blocks, clamps it to the region, sets memd's
  target (`set_target`), signals the VMM (`badges::vmm::MEM`) and
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
  `hp_plug`, `hp_unplug` and `hp_state` for their own guest.
  A plug checks the range, the bitmap and the target, takes 64 free blocks
  and copies them into the guest's level-2 CNode; a copy that fails (no
  CNode, or the slot occupied) undoes the plug. It takes only blocks that
  need no free page report to come back, so a guest never holds memd
  waiting, and it leaves the hosts' reserve (`memd::HOST_RESERVE`, the
  32 MiB that root's and vmmgr's `can_afford` keep back): short of
  128 MiB of them beyond the reserve it answers `EBUSY`. An unplug revokes
  and frees the 64 originals; destroy revokes every plugged block with the
  rest. A token bucket per guest bounds the time one guest can take from
  memd, which runs on core 0 above every guest: it holds microseconds of
  memd's time, refilled at 8 ms a second up to 16 ms, and each call is
  charged what it took, at least 1 ms, so a guest makes 8 plugs or unplugs
  a second after a burst of 16 (`EBUSY` beyond). The bucket also counts
  the VMM's calls, whatever they ask and however memd answers them
  (`hp_state` and refused calls take no time from it otherwise): 64 at
  once and 32 a second, where a guest's driver makes at most 18. A call
  beyond is answered `EBUSY` before memd decodes it or writes its status
  page, so it costs memd a receive and a reply. How long a revocation
  takes is the guest's to choose (it can make many capabilities of a
  block), so an unplug revokes only while the guest has time left, looked
  at after each block, and otherwise answers `EBUSY` with the rest still
  plugged, for its retry. A call overruns by at most one block's
  revocation, which the guest pays back before its next.
  That one
  revocation is not bounded by a block's size: a guest can hold about 33
  million capabilities per GiB of its RAM (a CNode slot is 32 bytes), all
  derived from one block, and memd deletes each. One unplug, and likewise
  a destroy, can therefore keep memd, and root and vmmgr waiting on it,
  for a time that grows with the guest's RAM (seconds per GiB by
  estimate; not measured).
- **VMM.** The memory device (`L4H_DEV_MEM`, `struct l4h_mem_page`) is one
  more device page: target, plugged count and bitmap, which the VMM
  refreshes from memd (`hp_state`) at start, after each request and
  when signalled with a new target, raising the device's event then. If
  memd does not answer `hp_state` (`EBUSY`, or it has failed), the page
  stays as the guest last saw it. `EBUSY` schedules a retry after one call
  credit can refill (31.25 ms), even if the guest is idle at its old
  target; publication of a changed target raises the event. The VMM's
  one-shot timer serves the earliest console or retry deadline. Other
  errors wait for the device's next kick or target signal, so a failed
  memd causes no retry loop. A
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
  BARs (or gives I/O ports, for a legacy one) and three DMA pages into memd;
  a device whose common configuration structure is shorter than the 0x38
  bytes the driver touches is left off.
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
  fits. A device that does not return a report in that time is given up
  on: it gets no more reports and is not waited for again, and the blocks
  of that report stay out of use, and out of memd's free count, until it
  returns them. Reported blocks are used like others: their contents read as zero,
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

### 9.2 Block: shared controllers, LBA windows and extent volumes

Each physical virtio-blk, virtio-scsi or NVMe PCI controller has one
persistent `l4h-blkd`. `BLK_ATTACH` attaches a finite, 4 KiB aligned LBA
window of a disk to a guest before it starts. A writable window overlaps no
other window of its disk; read-only windows may overlap each other, so one
seeded image can back many guests. Every window is a separate virtio-blk
volume starting at sector zero. There is no image format, host filesystem,
thin provisioning or copy-on-write.

**Extent volumes (LVM-compatible).** `BLK_ATTACH_EXTENTS` attaches instead
a list of up to 4096 4 KiB aligned extents of one disk, joined in order
into one guest disk: an LVM2 linear logical volume, among others. It takes
the same flags as `BLK_ATTACH`. The host never reads LVM metadata. dom0
runs stock LVM2, and `l4hctl lv-extents` / `--lv` turn a linear LV on one
PV into extents from `lvm`'s own reports (segments in LV order, physical
extents to host sectors, adjacent runs joined); thin, snapshot, origin,
mirror, RAID and cache volumes are refused. The bytes the guest sees are
those dm-linear maps from the same metadata, so the disk stays an ordinary
LVM2 PV. With several extents each is at least 4 MiB (LVM's default extent
size): a request is at most 3.5
MiB (14 segments of 256 KiB; blkd refuses a larger one from any client), so it
crosses
at most one boundary, and blkd splits such a request into two device
requests. If the device has no room for the second when the first starts,
it waits ("carry") and starts before any new request; the guest gets one
completion, with the first error. The overlap rule applies extent by
extent: dom0 can only reattach the physical extents of a removed LV once no
guest holds them, and provisioning (`BLK_WRITE`) refuses every attached
extent.

- **Where the list goes.** dom0 writes the list into its control data area.
  Root bounds its count and offset and copies the bytes, unread, into
  blkd's staging buffer, as it does for `BLK_WRITE`. `blk::call::check` builds and
  checks the disk there; `add` builds it again into the client's
  extent table: frames root allocates per attachment (two pages for a
  window, 27 for 4096 extents) and maps into blkd alone, at
  `extent_va(client)`. The table holds the extents sorted by start, for
  linear-time overlap checks, and their guest order, for a binary search per
  request. blkd checks the sorted order, disjointness and that the guest
  order chains from offset 0 before it uses a table. A window is a table of
  one extent, so windows and volumes share one path.
- **dom0's view of a PV.** dom0 never holds a PV's data area: its boot plan
  gives it only the PV's head (label and metadata, up to `pe_start`). To
  edit the VG, dom0 builds a device-mapper device of the PV's size from that
  window and an `error` target for the rest, and runs LVM with activation
  off and `lvcreate -Zn -Wn`; data written by mistake fails loudly.
  `l4hctl disk-zero` and `disk-write` zero or seed an LV's extents while
  it is unattached.
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
  completions to the others and drops only its own. A VMM waits at most
  five seconds for the
  drain, whether or not responses keep coming, and takes no more of them than
  blkd can owe it (one per request, and a ring's worth): a blkd that root
  quarantined is suspended and never answers, and one that runs an attacker's
  code may answer for ever. If the drain fails, the VMM faults and vmmgr
  stops the guest (or replaces dom0). The reset call stays unanswered, and
  no synthetic error completion returns another queue's pending buffers:
  blkd or its device may still DMA into them. Root cuts devices off before
  reusing the I/O pool at teardown, as for any other stopped guest.
- **Clients.** Each client has its own immutable pool/window/permission
  configuration, channel and completion notification. A controller supports
  512 clients; blkd's submit loop visits only attached ones. Submission is
  round-robin, with bounded work per client and reserved completion capacity
  for outstanding requests: blkd takes a request only while its response has
  room in the completion ring, and a VMM that takes responses while requests
  wait in its submission ring kicks blkd, which learns of the room no other
  way. Hardware request tags are allocated by blkd, so
  identical IDs from different clients cannot collide.
- **Validation.** Descriptor buffers must lie in the client's I/O pool; blkd
  translates pool GPAs to physical addresses, and the device never sees
  guest RAM. Requests are checked with checked arithmetic for block
  alignment,
  direction, permissions, operation, pool bounds and size: at most 3.5 MiB,
  whatever the client's VMM let through, so what a client can have in flight
  is bounded. A virtio-blk device that takes fewer than 14 data segments is
  given no more: blkd tells its clients (`Channel::seg_max`), whose VMMs offer
  their guests that many, and refuses a request with more. Operations other
  than read, write and flush (GET_ID among them) are answered unsupported by
  the VMM.
- **Who may use which sectors.** blkd alone decides: the overlap rule
  (`DiskWindow::conflicts`), dom0's boot reservations and provisioning
  exclusion (`blk::Reservations`). Root only asks: `check` gives the
  errno or the slot to attach in before root allocates anything, and
  `add` repeats the check for that slot (`Reservations::admits`): a
  removal root posts in between may free a lower slot, which leaves the
  checked one right. Root asks
  for a claim of a boot range only for dom0's windows, and takes a reserved
  slot only for dom0's window of the disk and range it reserved: any other
  answer naming one quarantines the controller. Root parses no ranges of
  dom0's and keeps
  its attachment records only for teardown and reports. blkd sends the
  commands, so a second check in root could not stop a faulty one.
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
- **Destroy** stops the client's VMM and takes its pool out of the
  device's IOMMU domain; blkd then drains that client's submitted work and
  releases it, without resetting the shared controller, and root reclaims
  its channel once blkd has answered (§10, "Root never waits on a driver").
  blkd serves its
  other clients meanwhile. A slow device is waited for: only if it finishes
  none of the requests it had when the drain began for five seconds does blkd
  say so (`EBUSY`). A drain that takes more than a second is answered
  `EAGAIN` and asked for again, so root's other requests for that blkd
  (attachments, provisioning, other removals) have their turn in between;
  the client's channel is no longer read from the first request on. Once
  blkd has said that the device stopped, root suspends
  the driver and quarantines the controller: its DMA memory stays
  allocated, without an IOMMU every affected guest pool is pinned, and no
  new attachment or provisioning write is accepted until host reboot.
- **Provisioning.** dom0 can seed or explicitly zero *unattached* ranges
  with `BLK_WRITE` and its ioctl staging buffer (up to 1 MiB per call); a
  zero-length call flushes the controller. Provisioning uses a private 1 MiB
  DMA scratch area and never writes over a client, read-only clients
  included.
  It waits for a busy device as long as that completes requests; one that
  completes nothing for five seconds fails the write, and root quarantines the
  controller.
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
- **NVMe** uses namespace 1 and one I/O queue pair of up to 1024 entries.
  A request becomes commands cut at the device's transfer limit (MDTS) and
  wherever its pieces cannot share one PRP list; it starts only once there
  is a command id for each, so none fails part way. The ids (and PRP lists,
  sized by the limit) suffice for a 4 MiB request at an 8 KiB limit, unless
  the device's queue is shallower.
- **Boot.** Host disks are numbered by controller in PCI order, then target
  and LUN. Before anything enables a disk controller, root resets it
  through a mapping of its registers, with bus mastering off, since
  firmware may leave one running: NVMe clears CC.EN and waits up to CAP.TO
  for CSTS.RDY to clear, which aborts every command and deletes the queues;
  virtio writes 0 to `device_status` and waits until it reads back 0. It
  then starts every
  controller's blkd at boot and learns the virtio-scsi units there. A blkd
  that has not reported its units 180 seconds after the drivers were started
  is quarantined as one that faulted, and the host boots without its disks;
  after 30 seconds root says which drivers it still waits for. The bound is
  for a driver that hangs: one whose device is only slow, or does not come
  up, gives it up itself long before and is failed at once (an NVMe
  controller that does not become ready, a NIC command without an answer,
  a virtio device whose status does not read 0 within a second of its
  reset). Each
  needs 4 MiB of physically contiguous DMA memory, and the host fails to boot
  without it, so a disk never lacks its driver later. A controller whose
  reset failed, or whose BARs are not free device memory (below), is not
  started and stays disabled: its disks fail with `EIO`, and the host boots
  without them. Clients and quarantine are per
  controller.
- **Queries.** `DISK_INFO` returns the PCI address, kind, failed flag,
  capacity and attachment count (volumes, not extents; the owner field
  names the first attachment, or -1); `BLK_INFO` enumerates `(vm, start,
  sectors, read-only, extent)` with a cursor: a row per window, or per
  extent of a volume in guest order, which root asks blkd for
  (`blk::call::extent`; unknown once the controller is quarantined).

`tests/run-sharedblk.sh` checks concurrent clients, overlap and bounds
rejection, provisioning exclusion, destroy during I/O, read-only windows
shared by several guests, more than 64 attachments of one disk,
flush/readback and repeated reuse, on virtio-blk, virtio-scsi (also with
both disks as LUNs of one controller) and NVMe (512 and 4096 byte blocks).
`tests/blk-windows.rs` exercises the production validator on malformed
requests and window/pool boundaries, extent tables (building, tampering,
splitting and a randomized byte-coverage check) and blkd's range decisions
against a per-block model. `tests/run-lvmblk.sh` attaches an LV whose guest
order differs from its disk order, as `l4hctl lv-extents` reads it from
LVM2 on the build host, writes and reads it across extent boundaries in a
guest, checks overlap and provisioning refusal, and then has the build
host's dm-linear read back the same bytes.

### 9.3 Network: L2 virtual switches only

The hypervisor implements Ethernet switching. Routing, NAT, DHCP and
firewalling belong in a VM.

- **Path.** Guest `virtio_net` → `l4h-vmm` → shared net port rings →
  `l4h-netd` → destination port, or an uplink channel → the NIC's driver
  (a nicd, §9.8). netd runs all switches and has no device code; each NIC
  is driven by its own nicd: modern and legacy virtio-net, gVNIC, Amazon
  ENA, Intel X550 and ConnectX-5.
- **vNICs.** Each vNIC is on one switch and appears as a separate `ethN`.
  There are 48 guest ports in all. Guest vNICs have one RX/TX queue pair.
  A VMM processes at most 32 chains per RX or TX batch, counting malformed
  or empty chains too. Remaining work gets another IPC turn without a new
  kick, so a producer on another vCPU cannot keep a handler from returning.
- **Switches and uplinks.** The API creates switches dynamically, up to 64
  (one per guest port and uplink, of which there are 16); switches are not deleted. Each is an L2
  broadcast domain with its own learned MAC table. A physical NIC can be
  the uplink of one switch; a switch without one is internal. VLAN tags pass
  through untouched. VLAN-aware switching, jumbo MTUs on guest ports, static
  MAC entries and port rate limits are not implemented.
- **Ports and copies.** A vNIC has TX and RX rings of 24 frame slots of
  68 KiB
  each, so a slot holds a whole 64 KiB TSO frame, shared by its VMM and netd,
  in memory of the guest's root arena, whose frame capabilities stay root's
  (vmmgr gets copies, which revoke nothing); root adds
  and removes ports with `net::call::add_port`/`remove_port`. The guest
  bounces buffers through its I/O pool, the VMM copies between pool and
  port slots, and netd copies slot to slot or between slots and uplink
  channels (the nicd copies between its channel and its DMA buffers).
  The shared counts wrap as `u32`; each producer and consumer also keeps
  its slot privately (`l4h_host::spsc`), advancing modulo the ring size.
  A counter wrap therefore preserves unread entries in the 24-slot rings.
- **Offloads.** Checksum and TSO metadata pass through in the virtio-net
  header. netd validates flags, checksum offsets and GSO type, including
  that a GSO frame is TCP over IPv4/IPv6, and drops incoherent headers. A
  frame for a port that cannot take its offload is segmented and checksummed
  in software.
  A guest port takes a GSO frame whole only if its driver accepted
  both large frames and partial checksums.
- **Receive offloads.** The virtio-net driver negotiates `GUEST_CSUM`
  and, with mergeable RX buffers (`MRG_RXBUF`, 256 × 4 KiB), `GUEST_TSO4/6`,
  so a device with large frames delivers them whole. Frames from the device
  then pass GRO (`offload::Gro`, in the nicd, on its own CPU time): consecutive full-size segments of one TCP
  flow, merged only where Linux's GRO would merge them, become one GSO frame
  with a partial checksum. Segments without a checksum verdict from the
  device are verified first. A guest thus takes one frame per up to 44
  segments.
- **Full rings hold, not drop.** A guest's RX ring has 24 slots, fewer than
  one TCP burst. Frames for a full ring wait in a per-port backlog (at most
  512 frames and 2 MiB) and are delivered in order: netd sets `rx_wanted`
  in the port and the VMM kicks netd when it frees RX slots. Each drain
  counts failed puts as well as delivered frames against a bounded turn.
  If the wakeup recheck sees room after that budget runs out, netd defers
  the port and polls on its next turn, so it need not wait for a lost kick.
  Frames for an
  uplink without a free TX buffer wait in a per-NIC backlog (512 frames,
  4 MiB). All backlogs share one pool of 2 KiB chunks, 16 MiB, fixed in
  netd's image. The pool keeps 136 KiB for each backlog (two frames of any
  size), and a backlog takes more of the rest only while it holds no more
  of it than is left (`pool::Pool::push`): however many ports stall, each
  other backlog keeps its reserve and a share of what remains. Only beyond
  those bounds is a frame dropped, so a guest that stops reading costs
  nobody else more than that share. Dropping instead costs a TCP
  retransmission timeout per burst.
- **NIC interrupts and notifications.** netd turns RX interrupts off while
  it drains a NIC's queue (re-checking after turning them on) and takes TX
  interrupts only while frames wait for a TX buffer. A turn takes at most 256
  frames from a NIC: with more left, netd serves its ports, links and root's
  commands and comes back, without waiting for an interrupt. It notifies the
  device
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
- **Dom0 bonding.** Each dom0 uplink keeps its physical MAC. Root permits
  either member's permanent MAC on the two designated dom0 uplink ports.
  Other source MACs remain locked. Linux bonding runs in dom0,
  with one separate switch per physical member. Slow Protocol frames
  (`01:80:c2:00:00:02`, EtherType `8809`) pass only between that member
  and its designated dom0 port, before FDB learning or steering. Ordinary
  guest ports cannot send or receive them. ConnectX-5 port events update
  dom0's carrier, speed and duplex through virtio configuration interrupts,
  including when no data arrives. Other guest ports keep virtual carrier.
- **Router VMs.** dom0's first vNIC takes the uplink NIC's MAC by default,
  since a cloud VPC delivers frames only for it. A router VM's other vNICs
  join internal switches and Linux provides NAT or routing. QEMU guests can
  also sit directly on the uplink switch.

**Steering.** The one exception to "nothing above L2": dom0 can hand part
of one address's traffic to a port on any switch, without a router VM in
the path. For example, a web VM on an internal switch serves TCP 80/443 of
dom0's external IP, or owns a cloud alias IP outright.
- **Endpoints and rules.** An endpoint (`L4H_CTL_EP_SET`) is a switch, a MAC
  on it and a peer MAC. The MAC must belong, when the endpoint is set, to a
  port on the switch or to its uplink NIC: never to a host behind the
  uplink. The peer is the gateway its steered traffic comes from. A rule
  (`L4H_CTL_STEER_SET`) matches (IP, proto, port), where proto and port may
  be wildcards and a port needs TCP or UDP, and names one target port. The
  most specific rule wins: (IP, proto, port), then (IP, proto, \*), then
  (IP, \*, \*). Up to 16 endpoints and 128 rules.
- **Inbound.** A frame on the endpoint's switch, from the peer to the
  endpoint MAC, that matches (dst IP, proto, dst port) and does not come
  from the target, goes to the target with the target's MAC as destination.
- **Return.** A frame from the target matching the mirrored tuple (src IP,
  proto, src port) leaves on the endpoint's switch as endpoint MAC → peer.
  It is never sent back to the endpoint's owner, nothing is learned from
  it, and isolation does not apply. With an IP-wide rule the target owns
  the address, outbound connections included.
- **The invariant.** Both directions pass between the endpoint MAC and the
  peer, and only the MAC fields change. So there is no state, no NAT, no
  checksum fixup, offload metadata stays valid and the target sees the
  client's address. Only the targets can send as the endpoint. A target
  takes an address from one endpoint only (`-EEXIST`), so a reply always
  leaves through the endpoint whose rule steered the request.
- **What is classified.** Untagged IPv4 and IPv6 only; up to two IPv6
  hop-by-hop, routing or destination-options headers are skipped. Ports
  only from a first fragment: later fragments match proto and IP rules
  when the protocol is known. A later IPv6 fragment whose Next Header
  requires further parsing matches only IP rules; its payload is never
  parsed as headers. An ICMP error (ICMPv4 3, 11, 12; ICMPv6 1–4) is
  classified as the packet it quotes, mirrored, when that packet is the
  classified address's own, so path-MTU discovery works for the target in
  both directions.
- **Not steered.** IPv6 Neighbor Discovery (ICMPv6 133–137) stays on its
  link in both directions, including unicast reachability probes, so the
  endpoint owner keeps answering ND for the address. Guests on the
  endpoint's switch send from their own MACs, not the peer's, so they
  reach the owner as before; their replies would otherwise go to the
  gateway. Port numbers are reused, so a removed port
  leaves every rule, and a rule left without a target is deleted. An
  endpoint outlives its owner: a VM recreated with the same MAC is steered
  again.
- **Cost.** A frame on a switch without endpoints, from a port that is no
  target, pays a bit test; on an endpoint's switch, a compare of its MACs;
  a candidate, the parse and up to three probes of a 256-slot table. GRO
  runs first, so a merged TCP run is classified once.
- **Guest setup.** The target holds the steered address on `lo` (or with
  `arp_ignore`) and needs a next hop through its vNIC, whose MAC netd
  replaces: a permanent neighbour entry for any address will do. The owner
  keeps the address for ARP/ND and must not use a steered port as a local
  source port.
- `l4hctl ep set SWITCH MAC|VM:NIC|uplink [--peer MAC|gw]`, `l4hctl steer
  set EP IP[/PROTO[:PORT]] --to VM:NIC|PORT`, and `del`/`list`.
  `tests/fuzz-steer` checks the classifier and tables against a model.

**gVNIC.** `l4h-nicd-gvnic/src/gvnic.rs` follows Linux `gve` with the DQO queue
format and raw DMA addressing (DQO RDA), which C3 and later offer; a device
without it (GQI only) makes its nicd refuse it. It configures the device through a
big-endian admin queue in BAR 0 and rings little-endian doorbells in BAR 2.
One TX queue with its completion queue, one RX buffer queue (2 KiB buffers)
with its completion queue. As Linux, it configures a notification block per
MSI-X entry but the last; the TX and RX blocks share the driver's vector and the
management vector stays masked. A DQO block masks itself when it fires;
the driver re-arms RX after draining and TX only while frames wait. Transmit:
checksum offload and TSO through a context descriptor (the TCP checksum
field loses the length, as in `gve_prep_tso`), for MSS 88–9728 and headers
up to 255 bytes (its offer), else netd segments. Buffers are freed by packet
completions, or by reinjection completions after a miss completion.
Receive: the device's checksum verdict (with its packet type map) becomes
`DATA_VALID`, then GRO; the device's own coalescing (RSC) is off. On the
revision 0 device of C3, releasing an admin queue that is not registered
makes the device reset itself, so the driver releases only a registered one.

**ENA.** `l4h-nicd-ena/src/ena.rs` follows Linux `ena` for the Elastic Network
Adapter of Nitro EC2 instances (1d0f:ec20 and the other IDs Linux takes).
- It resets the device, reads registers readless (the device writes them to
  DMA memory) unless the PCI revision says otherwise, and configures it
  through a polled admin queue of 64-byte commands. Host information names
  the userspace OS class, l4h's strings, spec 2.0 and driver version 2.0.0
  (Nitro accepts 1.0.0's host info but rejects CQ creation).
- One TX and one RX queue, each a submission queue with its completion
  queue, on MSI-X entry 1; entry 0 is the management vector (admin
  completions and AENQ events: the driver logs link changes and errors and
  acknowledges keep-alives). Both carry the driver's one vector. The device masks
  the I/O vector when it fires; the driver unmasks it through the TX CQ's register
  (with 20 µs RX and 64 µs TX coalescing) after draining RX, and while frames
  wait. An RSS table sends every frame to the RX queue.
- Transmit uses the low-latency queue (LLQ) in BAR 2, which root maps
  write-combining when it fits the manifest's 16 MiB window: one 128-byte entry per
  frame with the metadata and buffer descriptors and the frame's first 96
  bytes, written in 64-bit stores, `sfence`, then the doorbell, at most the
  device's burst between doorbells. Without the BAR or Linux's LLQ layout,
  descriptors go to a ring in host memory. Every frame has a metadata
  descriptor; partial L4 checksums over IPv4/IPv6 are left to the device
  when offered. ENA does no TSO here: netd segments. TX buffers hold frames
  up to the device's MTU, which the driver sets to its maximum.
- Receive: 2 KiB buffers, with a frame spanning several; a good L4 checksum
  on an unfragmented frame without an IPv4 header error becomes
  `DATA_VALID`.
- Not implemented: the keep-alive watchdog and device reset on errors
  (a nicd may ask root for a timer, `F_TIMER`, which ENA does not use
  yet), and ENA Express.
- Tested on a c6i.large's secondary ENI through Linux/VFIO (`tests/ena-vfio`,
  compiling the production driver unchanged) and in full UEFI/seL4 boots on
  c6i.xlarge (`tests/ec2-test.py`): LLQ and host-memory TX pass
  packet/checksum/GSO tests, 65,600 checked UDP echoes across the 16-bit
  index wrap, and fresh MSI-X delivery. See `tests/ec2.md`.

**Intel X550.** `l4h-nicd-ixgbe/src/ixgbe.rs` follows Linux `ixgbe` for the X550
(8086:1563, 15d1), as on Latitude.sh m4.metal servers. It resets the MAC
under the SW/FW PHY semaphore but not the PHY, which renegotiates the link
with the firmware's settings (about 7 s on 10GBASE-T), then sets up one RX
and one TX queue of advanced descriptors: 512 RX buffers of 2 KiB (larger
frames span buffers), CRC stripping, no RSC or RSS, promiscuous like the
other uplinks. RX raises MSI-X entry 0 and TX entry 1, both programmed with
the driver's vector, so EIMS/EIMC mask them separately; causes auto-clear (EIAC)
and are moderated to about 20,000 per second. Receive: an L4 checksum the
device verified (L4CS without TCPE, and no IPv4 header error) becomes
`DATA_VALID`. Transmit: a context descriptor carries checksum offload for
TCP and UDP over IPv4/IPv6 and TSO (MSS 64–9216); as Linux, the TCP checksum
field loses the length and the IPv4 length and checksum are left to the
device; data descriptors take at most 16 KiB each. `tests/ixgbe-vfio`
compiles the driver unchanged into a Linux program that drives a real port
through VFIO (ARP, ICMP, DNS, UDP checksum offload, 4 KB and 60 KB TSO, both
interrupt causes).

**Intel 82574L.** `l4h-nicd-e1000e/src/e1000e.rs` follows Linux `e1000e` for the
82574L and 82583V (8086:10d3, 150c), the parts of that family with MSI-X;
QEMU emulates the 82574L as `e1000e`. (The older 8254x, QEMU's `e1000`, have
INTx only, which a nicd does not take.) It resets the MAC under the software
flag but not the PHY, which keeps its link, then sets up one RX and one TX
queue of legacy descriptors: 512 RX buffers of 2 KiB (no long packets, so a
frame fits one buffer), CRC stripping, promiscuous like the other uplinks.
RX raises MSI-X entry 0 and TX entry 1, both the driver's vector, masked
separately (IMS/IMC RXQ0 and TXQ0); causes auto-clear (EIAC) and auto-mask
(IAM), moderated to about 20,000 per second. Root's tick (`F_TIMER`) reads
the link. Receive: a TCP/UDP checksum the device verified, without an IPv4
header error, becomes `DATA_VALID`. Transmit: a context descriptor carries
checksum offload and TSO over IPv4/IPv6, as Linux `e1000_tso`; data
descriptors take at most 8 KiB each. `tests/run-e1000etest.sh` makes it dom0's
uplink in QEMU: DHCP, ping and 8 MiB TCP transfers each way checked against
a host peer (`tests/nic-peer.py`), before and after a restart (QEMU's device
has no FLR); with `L4H_QEMU_IOMMU=intel|amd` it is the QEMU test of a
confined driver (virtio drivers never are), and must cause no IOMMU fault.

**Tests.** `tests/fuzz-virtq` checks that GRO output segments back into
exactly the frames that went in, and that corrupted or other-flow segments
do not merge. `tests/run-nettest.sh` covers DHCP and ping over the QEMU
uplink, internal switches, multiple vNICs, isolation and MAC lock
(`NETTEST_LEGACY=1`: a legacy virtio-net uplink). `tests/run-router.sh`
uses a Debian router with nftables masquerade to connect an internal guest
to the outside.

**ConnectX-5.** `l4h-nicd-mlx5/src/mlx5.rs` supports PCI device 15b3:1017.
Each PF uses one RX queue, one TX queue and one MSI-X event queue.
The command transport follows the NVIDIA Ethernet PRM and Linux mlx5.
The official libmlx5 VFIO provider requires Linux VFIO and libibverbs.
A nicd has neither Linux syscalls nor a heap, so this driver uses firmware
commands directly. The adapter stays in `mlx5.rs`. `tests/mlx5-vfio` runs
that same command and queue code against a VFIO-bound PF on Linux.
The PF has a 32 MiB DMA budget. A fixed 24 MiB pool supplies firmware
pages and reuses returned pages without a heap. Firmware can return fewer
pages than requested, including zero. The driver checks returned addresses
against its outstanding pool pages before reuse. The lower 16 MiB of BAR 0
contains the init segment, MSI-X table and allocated UAR. The driver rejects
a UAR outside that aperture. netd completes checksums and segments TCP in
software (the driver offers neither). The TX path accepts Ethernet frames up to 1518 bytes, including a VLAN tag.
RDMA, SR-IOV, RSS and hardware TSO are outside this driver.
The installer accepts `--uplink IFNAME` once or twice to select physical
interfaces on machines with more ports. Other interfaces stay outside the
migration plan. Selected ports retain the existing PCI order and MAC rules.
`--uplink-bond IFNAME` accepts an existing 802.3ad bond with exactly two
ConnectX-5 members. It reads each member's saved permanent MAC and preserves
the distribution's bond configuration. The bond MAC must be one of those
permanent MACs. Other master devices remain unsupported.

### 9.8 NIC drivers outside netd

Every NIC is driven by a nicd of its own: a component built from a driver
of the bundle, outside netd and, with an IOMMU, outside the TCB. A driver
that faults, hangs or misbehaves takes down only its own uplink, which
root restarts. Root and netd know no device kind. The design is issue
#134; this is its phase 1 (Wi-Fi is phase 2).

- **Uplink channel** (`l4h_host::uplink`). One region of root's frames,
  mapped by netd and the nicd (copies: neither can revoke the other's): a
  header page with the driver's offer, its link state, ring indices and
  waiting flags, then TX and RX rings of 1024 descriptors and two circular
  data areas (4 MiB each by default). A descriptor holds a length and a
  virtio-net header, never an offset: the consumer computes where a frame
  is from its own cursor, so the only value it checks is the length. A
  frame never wraps (a zero-length descriptor pads to the end). The
  producer reckons free bytes from its own record of what it wrote and the
  ring's tail, which it checks. `tests/fuzz-uplink` runs honest peers on
  two threads against a model, a producer that scribbles over the
  descriptors and data while the consumer reads, and a consumer that writes
  any tail.
- **What netd checks.** It copies each frame before it looks at it,
  checks headers with `MIN_MSS` (as a partition link's: it cuts no frame
  into more segments than a guest could make it), gives a nicd at most
  256 looks per turn, refuses an offer of another ABI, and stops reading a
  channel whose producer broke the protocol. It sends a driver only frames
  inside its offer (checksum and GSO types, MSS and header bounds, frame
  lengths) and segments and checksums the rest.
- **The SDK** (`l4h-nicdrv`): the `NicDriver` trait (what netd's drivers
  had: `start`, `offer`, `receive`, `transmit` and their interrupt
  handshakes), `Hw` (BARs, DMA region, MSI-X, legacy ports, the
  configuration snapshot and filtered configuration requests), and the
  loop: device RX straight into GRO and the channel, channel TX into the
  device while it takes frames (a refused frame stays in the channel, so
  the channel is the backlog), notifications only when the other side
  sleeps, root's mailbox. `driver!` puts the driver's manifest in the ELF
  section `.l4h.driver`. A driver's device code (`driver.rs`'s view) also
  compiles into the VFIO harnesses unchanged (`tests/nicdrv-vfio/sdk.rs`).
- **Manifests and the bundle.** A manifest says which PCI IDs a driver
  takes and what it needs: memory BARs required and optional, write-
  combining BARs, a window per BAR, MSI-X entries, DMA region size, channel
  size, firmware blob names, configuration-space write windows, image
  size. Drivers ship in a bundle (`tools/mkdrivers.py`): the boot module
  `l4h-drivers`, or the copy built into root. Root reads each manifest
  with bounds checks, checks the device against it (BARs present and
  mappable, MSI-X table inside a mapped BAR, virtio regions) and binds
  (`nic_auto`, default on; `nic_bind = BDF DRIVER|none`).
- **What a nicd gets.** Its BARs, windowed; a DMA region in its device's
  IOMMU domain only; one interrupt vector from root's pool (§9.5),
  remapped for its device; a snapshot of its configuration space; its
  channel; a control page; read-only copies of its firmware blobs; a
  mailbox. No PCI configuration capability, IRQControl, Untyped or
  endpoint to netd. Configuration writes go through root
  (`Published::cfg_req`), inside the manifest's windows, past the header,
  and by an allow-list: vendor-specific capabilities (not virtio's, one of
  which reaches a whole BAR), AER's status registers, LTR, L1 PM substates,
  and in the PCI Express capability Device Control's relaxed ordering and
  no-snoop bits and Link Control's ASPM bits; root merges the write into
  the register's other bits.
- **Confinement.** A nicd is outside the TCB (`confined` in `l4hctl nic
  list`) when the IOMMU is on with interrupt remapping and its device's
  isolation group holds only functions the host does not use or NICs of
  the same driver. The group follows Linux's: the functions below every
  bridge on the path that does not isolate with ACS (§9.5), those of its
  multi-function siblings, and the other functions of a multi-function
  device without ACS: every function root found in the slot, as only
  function 0 need set the multi-function bit, and what is below those
  that are bridges; a bridge without ACS adds its slot's other functions
  the same way. The walk covers the whole inventory, so no bridge or peer
  is left out. The group also takes every function the IOMMU translates
  as a member's requester (behind a PCI bridge, or an IVHD alias), which
  shares its domain whatever ACS does, and is closed under both: every
  member's reach and aliases are in it. Binding refuses a driver that would share a confined
  NIC's group, and every start checks again. A virtio NIC's driver is never
  confined: the device takes the IOMMU path only if the driver negotiates
  `ACCESS_PLATFORM`, which the driver, the untrusted party, decides.
  Root tells a virtio device by the device (a virtio PCI id, or virtio 1.x
  structures under any vendor's), not by the driver's manifest, which a
  driver dom0 loaded writes itself. A multikernel partition sees
  neither the bridges nor the other partitions' functions, so none of its
  NICs is confined. Elsewhere a driver is
  TCB code, and only the measured boot bundle's may run (Wi-Fi drivers
  never): a driver dom0 loads runs only confined, and is refused at load
  on a host without an IOMMU and interrupt remapping.
- **Faults and restarts.** A nicd that faults, refuses its device, breaks
  its channel, has its offer refused or leaves a liveness ping unanswered
  for 5 s is stopped without waiting on it: suspended, bus mastering off
  and read back, an FLR if the function has one (its header restored
  after, from root's record of it at boot), netd told to let go of the
  channel (RemoveUplink). Once both are done, its memory is reclaimed and a
  new instance started after a backoff
  (1 s doubling to 60 s), at most `nic_max_restarts` (5) an hour. The
  channel, the DMA region (in the device's IOMMU domain for good: a device
  no reset stopped reaches only it) and the uplink's switch stay; a later instance must offer the
  same MAC, which root checks (unicast, unique) before dom0's uplink port
  takes it.
- **Control API.** `l4hctl nic list|bind|unbind|restart|ctl` and `l4hctl
  driver list|load`. A driver dom0 loads (CTL_DRIVER_LOAD) is copied into
  root's memory and checked as the bundle's; it is refused unless drivers
  are confined.
- **Tests.** `tests/run-nictest.sh` runs two NICs and makes NIC 1's driver
  panic and hang: dom0's uplink on NIC 0 keeps working while root restarts
  it, and NIC 1 is unbound, bound again and NIC 0's driver restarted.
- **Not yet.** Zero-copy TX (the channel's TX area in the device's IOMMU
  domain), multiqueue, measuring dom0-loaded drivers into the attestation
  event log, and isolation groups and confinement on aarch64 (which has no
  IOMMU support).

### 9.4 Console and other devices

- **Console output.** Each vCPU writes its console output, as records
  numbered from one counter of the guest, into a ring in its event page,
  and kicks the VMM. The VMM prints the records of all rings in sequence
  order into a host-owned per-guest ring, which vmmgr reads for
  `console_read`, and, in every build, to the serial port with a `[vmN]`
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
    while it is attached. The pool is unmapped when its guest is destroyed,
    and freed only once blkd has drained the client (§10.1, Disk detach), or
    after a quarantine. Shared pools are reference-counted per domain and
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
- **Peer-to-peer and requester spoofing** (`pcie_acs`, on by default; `acs.rs`).
  Without PCIe Access Control Services a switch routes a request from one
  downstream port to a sibling's BARs directly, and a root port may route
  one to another root port inside the root complex: such a request never
  reaches the IOMMU, so a device could write another device's registers
  whatever its domain maps. Nor does a port check that a request's
  requester ID is one behind it, so a device could take another's ID, and
  with it the other's domain and interrupt entries. So with the IOMMU on,
  before it enables any device, root turns on in every PCIe function with
  the ACS capability each of Source Validation, Translation Blocking (root
  enables ATS nowhere), P2P Request and Completion Redirect and Upstream
  Forwarding that the function implements, as Linux does, and reads the
  control back. ACS is in extended configuration space, which the
  configuration ports do not reach, so root maps every segment-0 ECAM
  window of the MCFG whole into `layout::ECAM_X86`, where a function's page
  is at its BDF's: a few carves of 2 MiB frames (`acs::blocks`), as one
  carve per function would split the device memory table into hundreds of
  pieces on a large server and leave no room for the BARs carved next.
  Other accesses still use the ports. A window with a base that is not
  1 MiB aligned, that overlaps another, or that is not free device memory
  is not used, and a function whose ECAM vendor and device ID differ from
  the ports' is left alone, so a wrong MCFG gets no writes.
  - **Partitions** (§11.4) use the ECAM pages they have. The shim gives
    every bridge to partition 0, which so sets ACS in all root and switch
    ports; it tells the other partitions the IOMMU is ready (`Iommu::publish`)
    only after that, so none enables a device below a port that does not
    yet isolate it. A secondary partition reads ACS in the bridges above
    its functions, which it maps read-only, and reports any that do not
    isolate.
  - A root port or switch downstream port with devices below it that
    still does not isolate them (no ACS, a bit that does not stick, or an
    extended space root cannot reach) is logged at boot: those devices can
    reach each other's BARs without the IOMMU. QEMU's `xio3130-downstream`
    ports have no ACS; its `pcie-root-port` has it. Functions of one
    multi-function device without ACS can reach each other too, which is
    not reported. Root has none of Linux's ACS quirks: root ports of Intel
    PCHs that keep ACS in vendor registers, or that Linux knows to
    isolate without the capability, are reported as not isolating.
  - ACS is set once, at boot: root has no PCI hotplug, and a port reset
    by a link going down and up again (which clears its ACS control) is
    not set again or reported.
  - Without an MCFG (e.g. GCE, whose VMs have no IOMMU anyway) root says
    ACS is off. Without the IOMMU root leaves ACS alone: a device reaches
    all memory then.
  - The ECAM windows root maps are no longer free device memory, so
    trustd's AML reaches them through root's mapping
    (`pci::Pci::ecam_memory`), under the same rules as before (§10.2).
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
  `tests/run-acstest.sh` checks the ACS setup against a model of
  configuration space: only the bits a function implements are set,
  firmware's other bits are kept, a bit that does not stick is reported,
  looping or out-of-range capability lists end, and an ECAM window is
  mapped in few aligned blocks that cover it exactly.
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
  CI uses conventional bridges with Debian 13's QEMU 10.0. The
  `pcie-switch` topology puts each device on its own downstream port of a
  switch behind a root port, and checks that root turns ACS on in the root
  port and reports the switch's ports, which have none in QEMU. With AMD-Vi
  on QEMU 10.0 its first NIC gets no traffic, with `pcie_acs=0` too.
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
  once and in order, so a fence is done with its command. A kick handles at
  most eight commands (a flush copies up to a whole frame); the VMM takes
  the rest on its next turns, after the hypercalls and the other devices'
  work that waits. There is no cursor
  plane (cursor commands are dropped), no EDID, no 3D and no blob resources.
- **Memory.** The display area and tables come from the guest's arena, which
  destroy returns. A 1920 x 1200 display is about 10 MiB.
- **Not implemented:** a live view of the display (a VNC server in dom0 on
  `gpu_read`, or the host's framebuffer), input, and a cursor.

`tests/run-gputest.sh` has a VM draw with DRM dumb buffers, flip, and turn
its display off, checks every pixel of dom0's screenshots (`gpucheck`),
checks that the host refuses a display or I/O pool too small, and that
destroy returns the memory.

### 9.7 USB: whole xHCI controllers, safe without an IOMMU

A guest (dom0 included) can be given whole xHCI controllers (one PCI
function each), with all their root ports and everything behind them. This
is device assignment, not PCI passthrough (§1): an xHCI fetches DMA
addresses from memory its driver writes, asynchronously, and without an
IOMMU uses them as host physical addresses, so a guest running `xhci-hcd`
on the hardware could reach any host page. Instead `l4h-usbd` drives the
controller, one per claimed controller, and the guest forwards Linux's
`hc_driver` operations and URBs to it.

- **Discovery and claim.** At boot root only lists functions of class
  `0c/03/30` (up to `MAX_USB_CTRLS`, 16) and leaves them to the firmware:
  legacy keyboard emulation and BMC virtual devices keep working, and a
  host that assigns no USB spends nothing (`l4hctl usb`: `firmware`). The
  first `CTL_USB_ATTACH` (or dom0's `dom0_usb=`) claims one: root reads its
  capability registers through a temporary uncached mapping (a controller the
  firmware is still resetting gets 5 ms to become ready; the attach is then
  refused with `EBUSY`, the controller stays the firmware's and the attach can
  be tried again, which vmmgr does for dom0's boot, on its timer, for a
  second before dom0 starts without the controller), allocates
  usbd's DMA region (one contiguous Untyped, `host::usb::dma_bytes`: the
  scratchpad, DCBAA and contexts, command and event rings and a pool of 256
  transfer rings of 512 TRBs; 4 MiB for QEMU's), maps BAR 0 uncached into a new usbd,
  binds the interrupt (MSI-X entry 0, or plain MSI, which Intel PCH
  controllers have instead) to its notification, and posts `usb::call::claim` in
  usbd's mailbox (`l4h_host::mailbox`, §10, "Root never waits on a
  driver").
  usbd walks the extended capabilities (bounded: 256 entries inside BAR 0,
  `host::usb::xcaps`), takes the controller from the firmware (OS Owned,
  then up to 1 s for BIOS Owned to clear, else it clears it, as Linux
  does; legacy SMIs off), halts and resets it. Root routes Intel PCH ports
  to the xHCI once usbd has answered. Root never calls usbd: a guest that
  has the controller can keep usbd busy, and even the claim's handoff and
  reset take up to seconds, which would hold up every guest's control
  requests. Claim, attach and release are requests in the mailbox: usbd
  answers them in order when it gets to them, and root finishes each from
  its serve loop (`usb::poll`). The attachment that claimed the controller
  does not wait for the claim: the guest gets its queue area at once, its
  attach is posted when the claim is answered, and if the claim fails the
  controller is quarantined and the guest's driver finds no magic. usbd
  publishes its refused requests and resets in the mailbox's second page
  (`usb::Published`, for `l4hctl usb`). A controller once claimed stays
  with its usbd until reboot,
  `idle` (halted, bus mastering off, its DMA region kept) when no guest has
  it, and `failed` if a claim, attachment, reset or drain fails. An
  asynchronous attachment error quarantines the controller and becomes
  visible through `CTL_USB_INFO` (`l4hctl usb`); its queue area stays with
  the guest until destruction. Renesas uPD72020x without a
  firmware ROM and controllers without MSI are `unsupported`.
- **Attach.** `root::call::usb_attach (guest, device, controller)`: vmmgr names
  both by number; root claims the controller if needed, makes the queue
  area (101 host frames in an arena of root's own: usbd maps the frames' own
  capabilities and the guest's are copies of those, which root can revoke
  without touching usbd's mapping), usbd's kick, mints the guest's VMM
  notification (root's, from `guest_new`) for usbd with bit n of
  `badges::vmm::USB` (`wiring::USBD_VMM`), maps the pool into the controller's IOMMU domain,
  turns bus mastering on and posts `usb::call::attach` with the pool's addresses
  from its own table. usbd keeps two areas (`AREAS`): while the previous
  guest's release still runs, the next guest gets the other, and its
  attach (bus mastering with it) waits for the release (or the claim)
  to be answered; the guest's
  driver waits for usbd to write the area's magic. vmmgr maps the area into the guest at
  `L4H_USB_AREA_VA(n)` (the pages usbd writes read-only) and adds an
  `L4H_DEV_USB` device (ABI 7). A guest has at most four
  (`L4H_MAX_GUEST_USB`); `l4hctl create --usb BDF` raises the default I/O
  pool by 4 MiB each.
- **The queue area** (`include/l4h/abi.h`): usbd's info page (ports and
  their USB revision, slots, streams, the largest transfer, its indices),
  the guest's index page, a control SQ (32 records of 256 bytes: port
  get/set/clear, enable/disable slot, address, endpoint configuration, hub,
  ep0 max packet, device and endpoint reset, streams, URB cancel), a
  transfer SQ (128 records of 2 KiB: one URB each, with up to 64 pool
  segments, a 256 KiB request of 4 KiB pages, and 48 isoch packets), a 256-entry completion queue shared by
  both, and a 64-entry event queue (port changes, controller resets).
  Indices are free-running and each in its own cache line; the guest
  signals usbd's kick only when usbd said it is about to wait.
  Completions go back through the VMM, which raises the device's event on
  the vCPU the guest routed it to (`L4H_HC_DEV_WRITE`, as virtio's): the
  VMM sees no request, maps nothing of the controller and needs no
  capability from vmmgr.
- **usbd** is a Rust xHCI driver in the shape of blkd's: one command ring,
  one event ring of 4096 TRBs (interrupter 0, IMOD 40 us, which the guest
  cannot change; in one 64 KiB-aligned segment), a ring per endpoint or
  stream from the fixed pool, TDs laid out as Linux's `xhci-ring.c` does
  (64 KiB splits, TD Size, TBC and TLBPC for isoch, ISP on IN data, a bulk
  zero-length packet as a TD of its own). usbd schedules isoch URBs, as
  Linux's HCD does: right after the endpoint's previous URB, or past MFINDEX
  plus the scheduling threshold for an idle one, reporting the start frame
  in the CQE; with CFC, TDs carry Frame IDs from it, the device speed and
  the service interval (SIA when it is out of the valid window, or ASAP).
  usbd publishes MFINDEX with the host counter (TSC, CNTVCT) at which it
  read it, under a sequence count, each time it runs; the guest's frame
  number goes on from that sample at 8000 microframes a second, so it
  advances while usbd sleeps. A cancelled isoch URB reports its packets as
  done, failed or cancelled (the one the controller stopped in with its
  bytes), and its length as their sum.
  An isoch TD that fails before its last TRB stays on the ring until an
  event shows the controller past it; an event on a later isoch URB retires
  the ones before it, their unreported TDs missed (a Missed Service event
  may carry no TRB pointer). A TD crosses the Link TRB only where its data
  before it ends on a packet boundary (xHCI §4.11.7.1); otherwise its URB
  goes at the start of the ring after no-ops, which even an empty ring has
  room for, and which stay reserved until the URB completes. Commands run one at a time, polling the
  event ring (5 s timeout). An endpoint halted by an error is recovered
  with Reset Endpoint and Set TR Dequeue past the failed URB, as Linux
  does (one
  pending recovery an endpoint, on the ring it has by then); a cancelled URB
  is skipped (dequeue moved, or its TRBs made
  no-ops, unchained, which stay reserved with the URB after them until the
  controller is past them, or wound back off a stopped ring after its last
  posted URB) and completed only once the endpoint has stopped, and every
  stream of the endpoint restarted. One whose record usbd has not taken
  (it waits behind a full CQ) is marked to be skipped and never completes
  (`ST_DROPPED`; the guest gives it back). A URB that
  does not fit its ring waits in usbd, so one full ring does not hold up
  other endpoints. Recovery requires successful Reset Endpoint and Set TR
  Dequeue completions; a rejection resets the controller before any old
  ring can restart or its software dequeue advance. A command timeout, HSE or HCE resets the controller and
  posts `HC_RESET`; only its owner is affected. A reset that cannot halt
  the controller faults usbd before returning any URB or freeing a ring,
  so root quarantines the device while the buffers are still owned.
  Disable Slot likewise releases endpoints and buffers only after the
  command succeeds; a refused disable leaves them owned.
- **Validation** (`host::usb`, the code tests/fuzz-usbreq runs): every
  record is copied before it is checked, every index against usbd's own
  copy and the ring size; every segment must lie in the pool
  (`blk::Pool::translate`) and the total within the advertised maximum;
  slots must be the client's and endpoints configured, with the type and
  direction of the transfer; endpoint fields must be in the xHCI range for
  their speed and type, the interval
  included; route strings at most five tiers; a device behind no transaction
  translator names no TT port; a stream count is a power of two from 4 (a
  stream array has no fewer entries); the context dwords the controller gets
  are made from the checked fields, and slot context dwords copied back from
  an output context are masked, so a guest sets no reserved bit and no
  Interrupter Target (every event goes to interrupter 0, the only one usbd
  sets up); isoch packets
  inside the data; port writes only the bits the feature names. A request
  is accepted only while the CQ has room for it, so it never overflows and
  a guest that does not consume completions stalls only itself; transfers
  leave one entry for control requests, so an `URB_CANCEL` always gets in.
  usbd's turns are bounded (one SQ's worth of each, the
  transfer records an `URB_CANCEL` takes in on the way included, and one event
  ring's worth of events), so neither a guest refilling its queues from
  another vCPU nor a controller that keeps producing events keeps usbd from
  its events and the mailbox. They are bounded in records, not time: a
  control record may wait for a controller command (5 s, then a reset), so
  usbd stops taking them once root has posted a request
  (`l4h_rt::mailbox::pending`), and the next turn serves the mailbox first.
  A going guest's REMOVE, and the next guest's ATTACH behind it, waits for
  at most the record usbd is in, not a queue of them.
- **DMA without an IOMMU.** Every DMA pointer the controller reads is
  written by usbd into its own region, which no guest maps: registers,
  DCBAA, scratchpad, contexts, stream arrays, rings and Link TRBs. Every
  data pointer is a translated pool segment; setup packets travel as
  immediate data; only data buffers are shared, and the controller does
  not interpret them. USB devices cannot DMA. With an IOMMU the
  controller's domain holds only usbd's region and the attached pool, and
  interrupt remapping confines its MSI. What remains without one is, as for
  blkd and netd, a bug in usbd or a controller erratum.
- **Release.** `GUEST_DEL` cuts the controller off without waiting for
  usbd: root revokes the guest's copies of the queue frames, turns bus
  mastering off and reads the command register back (the controller can
  issue no more DMA, and that read's completion cannot pass the writes it
  already posted, so they are in memory: the pool can be reused at once,
  with or without an IOMMU), unmaps the pool from the
  domain, deletes usbd's copy of the VMM notification (usbd signals it with
  NBSend, which an empty slot ignores) and posts `usb::call::remove`, after the
  attach if usbd has not answered that yet. usbd then halts and resets the
  controller and forgets every URB; when it answers root frees the area, and the controller is `idle` for the next
  guest, which enumerates its devices again. Bus mastering stays off until
  then: the next guest's attach turns it on only after the reset, so the
  controller never finishes a transfer it had started into the reused pool
  (a disk controller, which other guests share, cannot be cut off this way,
  §10.3). If the reset fails root
  quarantines the controller (decoding, bus
  mastering and MSI off); its guest's pool is then reused like any other's, as
  the controller has no bus mastering. A
  reset does not reset USB devices' firmware: a controller carries its
  devices with it.
- **Guest.** `usb-l4h` (`arch/l4h/drivers/usb_l4h.c`) registers a USB 2 and
  a shared USB 3 HCD whose root hubs have the controller's ports; the
  stock USB core does enumeration, hubs, descriptors and class drivers, so
  usbd never parses device data. Buffers bounce through the pool
  (swiotlb), like virtio-l4h's. The HCD, HID and the common class
  drivers (storage, UAS, serial, audio, network) are built into the guest
  kernel, not modules: every guest maps the kernel's text and rodata from
  the same host frames, while a module would be copied into the RAM of each
  guest that loads it (§5.6). Built in, they add 1.45 MiB of shared text
  and rodata, and about 200 KiB to a guest's RAM whether it uses USB or not
  (60 KiB of data, the rest slab from their initialization), against 0.6 to
  1.6 MiB per guest that loads them as modules.
- **Not in v1:** sharing a controller among guests or assigning single
  ports (the protocol is meant to allow it: an owner per root port and
  slot), hot attach and detach, EHCI and older, USB4, LPM and runtime PM,
  the Debug Capability (usbd never enables DbC), giving a controller back to
  the firmware.

`tests/run-usbstress.sh` benchmarks each disk (against the same devices
under a plain Linux VM with `USBSTRESS_NATIVE=1`, §13), runs writers,
readers and verifiers on all of them for `STRESS_SECS` while one is
deauthorized and authorized again every few seconds (its URBs cancelled
under load), destroys `STRESS_CYCLES` guests while every disk is busy,
and checks that the stress run's data survived.
`tests/run-usbtest.sh` (QEMU's xHCI with MSI-X, `USBTEST_HC=nec` an NEC
one with MSI only; `L4H_QEMU_IOMMU=intel|amd`) checks that the controller
is the firmware's until a guest gets it; that a guest enumerates a
keyboard, a tablet, a BOT disk on the root hub and one behind a hub and a
UAS disk, reads both disks' digests and writes one; that a driver reload
resets the controller and enumerates again; and that a guest destroyed
during I/O leaves it idle for the next. `tests/usb.rs` and
`tests/fuzz-usbreq` (`tests/run-fuzz.sh`) check the capability walk on
malformed lists, endpoint ranges, TRB layout and index arithmetic, and
that whatever usbd accepts from random records points only into the pool.

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
| `l4h-netd` | 1 | Runs all L2 switches, guest ports and the virtio-net, gVNIC, ENA, X550 and ConnectX-5 uplink drivers. |
| `l4h-trustd` | 1 | Maintains taint/seal flags; with a TPM, quotes its signing key and signs guests' reports (§10.2). |
| `l4h-memd` | 1 | Owns free memory and every guest's RAM blocks; gives root and vmmgr memory for host objects; serves memory hotplug; reports free memory to the hypervisor (§8.4). |
| `l4h-usbd` | 1 per claimed xHCI controller | Drives a whole USB controller for the guest it is assigned to; validates its requests and pool segments (§9.7). |
| `l4h-logd` | 1 | The only host writer to the serial port: prints every partition's serial ring and the other kernels' console rings, whole lines in one order (§10.4). |

**No dynamic allocation.** Nothing a guest, dom0 or a device does may
exhaust a host component's memory: a component that runs out cannot
recover, and with it go every guest it serves (root, vmmgr or memd: the
whole host). Their state is sized at start, from constants (`MAX_GUESTS`,
queue sizes) or from the host (memd's table), and lives in fixed arrays and
tables. Where allocation is truly needed, it is bounded by a stated limit
checked before the allocation, fails as an error rather than a panic, and is
never made per request on a path whose size a guest or client controls. A
component without a heap says so (`component!(main, no_heap)`, or for root
a `#[root_task]` without `heap_size`) and does not link `alloc`: root, vmmgr, memd, netd, blkd, usbd, logd and the VMM have none, and keep
state too large for a stack in statics (`l4h_host::fixed::{StaticCell,
Scratch}`). The one heap is trustd's, for the third-party AML interpreter of
the TPM start method; its size (`aml::HEAP`) is bounded by the firmware's
tables, which trustd checks first.

**Root never waits on a driver.** blkd, netd and usbd handle guests' rings
and device memory, so root assumes any may run an attacker's code, and an
attacker's driver could leave a request unanswered forever. Root does not
call them, nor wait for them with a deadline: it posts requests in a ring
in a page it shares with the driver (`l4h_host::mailbox`), signals the
driver's notification and goes back to its loop. The driver answers in
order and signals root, which then finishes what the request was for
(`blkd::poll`, `Netd::poll`, `usb::poll`). A request a driver never answers stays
pending, and so does whatever waits for it, nothing else:

- **netd's commands** need no answer: root validates them and keeps their
  state (ports, uplinks, steering), and netd publishes its counters and
  MACs in the mailbox's second page, as blkd publishes its disks. Root's
  boot,
  which needs both, finishes from the serve loop once they are there, or 30
  seconds after the drivers were started: a driver that has not published by
  then is failed as one that faulted (a disk controller is quarantined, netd's
  networking stops), and the host boots without it.
- **blkd's** checks and attachments, provisioning writes and extent queries
  are answered later through vmmgr (`root::Later::Token`, §10.3), and through
  dom0's control device, whose caller may give up and make the next
  request (§10.1). One staging user at a time per controller: another is
  `EBUSY`. A controller holds at most two of vmmgr's 256 tokens for
  requests its blkd has not answered, so drivers that never answer leave
  tokens for the other controllers.
- **usbd's** claim, attach and release need no answer before root replies
  to vmmgr: a guest's driver waits for the queue area's magic instead
  (§9.7). A usbd that never answers keeps its controller's queue areas,
  and no later guest of that controller gets a working one.
- **Teardown waits for no one.** A destroyed guest's I/O pool leaves the
  devices' IOMMU domains at once; what drivers map (disk channels, extent
  tables, port memory) is kept until they say they have let go, and the
  pool until blkd has drained the guest's disks, IOMMU or not, since the
  device may still run their commands (a `Zombie`; §10.1, Disk detach;
  the pool does not wait for netd). Revoking
  the memory would also unmap it from the driver, but an honest driver
  would fault. A driver that never answers keeps that memory (a blkd, the
  pool too), and the
  client and port slots, for good, and each such guest keeps a guest's
  place: root admits a guest other than dom0 only while live guests and
  zombies are fewer than
  64, and a dom0 only while no other lives (`EEXIST`), so every deletion finds
  a zombie, and a
  guest whose drivers answer gets all its memory back.
- A full ring (64 requests) refuses new ones with `EBUSY`; removals queue
  in root until there is room.
- **A driver that faults** fails in root, not in itself. Drivers have no
  keeper thread (`host::has_keeper`): no one calls them, so no caller
  needs answering, and a fault goes to root's endpoint like any other
  component's. Root suspends the driver and quarantines what it drove
  (`blkd::fault`, `Netd::fault`, `usb::fault`), and its pending requests
  finish at once as `wire::FAILED` answers would (`Mailbox::abandon`), as
  do later ones: a quarantined controller takes none, and a failed netd's
  commands are dropped and its ports let go. Root acts on the kernel's
  fault message, which the driver cannot forge or withhold. A driver's
  answer can also say that a request failed (an errno, or `wire::FAILED`,
  which `l4h_rt::mailbox::serve` writes for a request the driver could not
  carry out), and root quarantines the controller on a `Check` answered
  `FAILED`, with a slot in use or with a
  boot range's slot for anything but dom0's claim of it, a refused `Add`,
  `Remove` or `Reserve`,
  a device failure in `Write`, and a failed USB `Claim` or `Remove`, as
  it would on a fault. That gives a driver nothing it lacks, since it
  could fault or stop answering instead, and a quarantine only takes
  memory out of use, never frees it early. A Rust panic in a driver traps
  after `l4h_rt::abort_trap` logs it, and faults so too.

Root still calls memd, which handles no one's data, and trustd's flags
server only in its start-up handshake, before any guest exists; everything else root shares
with a component is a notification or shared memory. `tests/run-hangtest.sh`
has a blkd stop answering (`inject blkd-hang`): dom0 gives up a write that
waits for it, its next is `EBUSY`, and a guest with another disk boots and
is destroyed; then netd stops too, and root still serves the monitor.

Signals cannot keep queued calls waiting indefinitely either. Root,
vmmgr and the VMM declare their bound notification to the common serve
loop: after each signal it briefly unbinds it and polls the endpoint,
then rebinds it, preserving the received words across both the bind and
the timer rearm. A peer partition that keeps ringing its doorbell cannot
take that endpoint turn. Each server rearms its original timer deadline,
including one that expired while unbound, rather than postponing its next
tick after every signal. memd has no untrusted signal source (only its own
timer) and root calls it with badge 0, so it uses the ordinary receive.
The failed-server loop uses the same `Bound::poll_endpoint` arbitration:
continuous control kicks cannot keep calls waiting for `wire::FAILED`.
Notification takeover accepts an already-unbound main TCB, since it may
have faulted during that poll, and repairs a binding already held by the
keeper if its panic recovery retries. Other kernel errors still fail.

**Integer arithmetic.** Shipped host components build without overflow
checks (Cargo's release profile, §4.1), so an overflow wraps rather than
panics, and a wrapped bound check passes. The code is correct by
construction instead: arithmetic on a value a less-trusted party chose (a
guest's descriptors, registers and requests, a device's DMA writes and
registers, a driver's or a peer partition's shared pages and answers, dom0's
control requests, the config file, firmware tables) never overflows. Such a
value is validated where it comes in, so that the arithmetic after it is in
range (`checked_add` and the like at that point), or is computed with the
`wrapping_*` or `saturating_*` operation that is its meaning (sequence
numbers wrap). Shifts by such a value are bounded first, and a divisor is
checked for zero. Development builds check overflow as well, which catches
what is missed in tests and in `tests/run-fuzz.sh`, whose parsers are the
host's own.

**Shared rings.** A ring in memory shared with a less-trusted party (blkd's
channels, netd's ports, usbd's queues) has one index per side, and each
side keeps its own privately and only publishes it (`l4h_host::spsc`): the
peer can write over the shared copy, which changes nothing this side does.
The peer's index is read once per look and checked against ours; one
further from it than the ring holds gives nothing to read and no room to
write. A driver signals a client through a slot root fills and empties
with NBSend (`l4h_rt::mailbox::notify`), which an empty slot ignores where
Signal would fault the driver, whatever order root's request to stop and
its emptying of the slot arrive in.

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
| `l4h-ipc` | The one seL4 IPC path of the protocols `l4h-host` declares: calling an endpoint (`Endpoint`), serving one (`serve`), keeping a received message across invocations (`preserving`). | Moves words between the message registers and arrays; knows no protocol. |
| `l4h-rt` | Component entry, TLS and IPC-buffer setup, panic handling, keeper threads, optional heap, runtime conveniences. | Runs a component on resources its parent provisioned. |
| `l4h-task` | Kernel-object and CSpace allocation, memd grant client (`memd::MemdLink`), ELF loading, component spawning, CPU topology, VSpace/scratch mappings. | Callers supply capabilities, storage, mappings and ASID assignment; boot setup, authorization and placement policy stay in the executables. |

`l4h-rt` and `l4h-task` both depend on `l4h-host` and `l4h-ipc` (which
`l4h-rt` re-exports as `l4h_rt::ipc`) and are independent of each other. Shared code lives in a library imported through Cargo;
executables never import another executable's sources. Root and vmmgr use
`l4h-task` to allocate objects, build address spaces and spawn components,
each with its own CNode, allocator storage, scratch VSpace, memd endpoint
and exchange slots; ASID-pool ownership and assignment stay local. blkd,
netd, trustd and the VMM use capabilities and mappings installed by their
parent and need only `l4h-rt`. memd's allocator, which tracks physical
blocks, ownership, retained originals and reporting, is memd's own.

**Wiring declarations.** How components reach each other is declared in
`l4h-host` as data the compiler checks (`l4h_host::wire`), and there is
one way to do each part of it:

- **Badges.** Every receiver's badge bits are a badge space
  (`badge_space!`), all in `l4h_host::badges`: root's, vmmgr's, memd's,
  the VMM's, trustd's two notifications and its flags endpoint's, logd's,
  and the drivers', which include `driver` (root's `CALL`). A range is a
  `field` (a value: `ID.get(b)`, `ID.put(v)`), a `flag` (a call's bit), a
  `signal` or a range of `signals` (`LINK.nth(l)`). A space can include one
  other (root's and vmmgr's include `parent`, the badges `l4h_task`'s
  `component_badge` mints for a spawned component's calls and faults) and
  fails to compile if two ranges overlap. Its `SIGNALS` is every
  notification bit, which a serve loop tests and a `FailureHandler`'s
  `notification_badges` is. Whoever mints and whoever tests a badge name
  the space's constant; there are no other names for them. The guest
  vCPUs' badges are the guest ABI's (`L4H_BADGE_*`). memd's timer moved
  from bit 0 to bit 40 when its space was declared (bit 0 lay in the VMMs'
  guest field), and trustd's kick shares guest 63's bit with the relay
  (`trust::RELAY_BADGE`) by design, as one range.
- **Protocols.** Every request one component makes of another is a call
  of a protocol (`protocol!`): its label, typed arguments and reply
  (`wire::Wire`: integers that reject a word too wide instead of
  truncating it, booleans that must be 0 or 1, arrays, pairs, bounded
  lists, `Tail`s, structs declared with `wire_struct!`, `root::Later`),
  and the senders that may make it. Each protocol is `<module>::call` and
  its callers `<module>::Sender`, made from the badge: memd's endpoint
  (`memd`), root's (`root`: trustd's and vmmgr's calls), vmmgr's (`vmmgr`:
  the VMMs'), trustd's flags endpoint (`trust`), the VMM's (`hypercall`:
  the guest's, whose side is `abi.h`), and the drivers' mailboxes (`blk`,
  `net`, `usb`, whose `Sender` is root alone, `Root: mailbox`). A protocol generates the decoded
  `Request`, a `Server` trait with a method per call, `serve` (decode,
  refuse what the declaration does not allow with `EINVAL`, run, encode),
  a `Client` trait with a method per call, and `reply::<Call>` for a
  reply taken later. Labels must be distinct and calls must fit the IPC
  buffer (a mailbox's `ARGS` and `ANSWER`), at compile time. A reply's
  first word is 0 or an errno and its value follows; a failed server
  answers `wire::FAILED` (memd's and vmmgr's keeper; root itself for a
  faulted driver's mailbox, `Mailbox::abandon`), and a
  method that must leave its caller blocked returns `wire::NO_REPLY`.
  Both transports reject replies longer than their envelope: an endpoint
  preserves the actual received length for its client to check, and a
  mailbox refuses a length beyond its entry. Neither accepts a success
  prefix obtained by truncating an oversized reply.
- **Transports.** An endpoint's calls go through `l4h-ipc`: clients call
  an `l4h_ipc::Endpoint<P>`, which serves protocol P and is made from a
  call edge whose protocol is P (`Endpoint::of`, or `chosen` for one in a
  slot of the holder's choosing), so only P's `Client` methods can be
  called on it (`MemdLink` is one with exchange slots). Every server's
  thread runs `l4h_ipc::run`, the one serve loop: the server
  (`l4h_ipc::Server`) names its badge space's signals, the FAULT bit if
  faults come to it, and its `Sender`; `run` tells signals, faults and
  calls apart by the badge, decodes the sender (`wire::Badged`) and
  refuses with `EINVAL` any badge that is no sender, answers no fault,
  and replaces a reply object left bound to an unanswered caller
  (`l4h_task::reply::ReplySlot`, where the server can). It records,
  before the server's code runs, whether its reply object holds a call
  (`l4h_ipc::holds_call`), for the failure service. `l4h_ipc::serve`
  takes a call's arguments out of the message registers before its
  handler runs and puts the reply there after it returns, and `run` keeps
  a message, and a reply not yet sent, there across the server's other
  work, so no invocation can overwrite either; both copy only the
  message's own words, and `serve` at most its protocol's longest call
  and reply. A reply's first word is 0 or an errno, at most
  `errno::MAX_ERRNO`: a client takes anything above as a failed server
  (`wire::reply`), so no answer of a less trusted server (a driver's, to
  root) passes for a value the host gives a meaning of its own
  (`wire::NO_REPLY`, a deferred request) or overflows a guest status. A
  thread that is not called (trustd's main thread, logd, the drivers)
  waits on its notification instead. Only l4h-ipc calls, serves and
  receives on endpoints (and l4h-rt's keeper's initial fault receive), and
  nothing sends on one without calling: a send gives a server no reply to
  make, and would leave a passive one without a scheduling context to come
  back on (the host has no passive server: the flags server keeps a scheduling
  context of its own, §10.2). clippy's `disallowed-methods`
  (`host/clippy.toml`, `tests/check-ipc.sh`) refuses those seL4 calls anywhere
  else; the one send left is `l4h_rt::mailbox::notify`'s, to a notification. A
  driver's mailbox carries the same protocols without IPC: root posts a
  typed `Request` through `Mailbox<P>`, made from its `Rights::Post`
  notification edge of protocol P, and decodes each answer by its
  call's reply type. `wire::Message::Proto` ties the request to P, as an
  endpoint's client is tied to its protocol. The private counts and
  encoding live in `l4h_host::mailbox::Client<P>`; root adds the signal.
  The driver answers with `l4h_rt::mailbox::serve`, which reads and writes
  the ring and never the registers. Every entry carries the actual
  argument and reply lengths: neither side decodes padding as fields or
  tail items, oversized lengths are refused, and short replies stay short
  for `wire::reply` to reject. The two ring pages and published page still
  take three pages per mailbox. Capabilities
  still cross in exchange slots, which each call's declaration names,
  with their direction and kind: both ends find a slot with
  `Caps::passed_in` or `passed_out`, which refuse, at compile time, the
  other direction and another kind than the type of the capability that
  end's own code puts or takes (`l4h_ipc::Kind`). Nothing checks what the
  other end left in the slot: a release seL4 cannot tell a capability's
  type. So a receiver never invokes what a less trusted sender passed: it
  only moves or deletes it (memd's `free` deletes vmmgr's and revokes its
  own originals), and a capability the more trusted side must invoke is
  one it made and passes out (memd's GuestCreate CNodes). Nor does
  the more trusted side keep a mapping under a capability the other can
  revoke: root reads dom0's control data area, so it keeps the frames' own
  capabilities and gives vmmgr a CNode of copies, as for a USB queue area and
  a netd port's frames. vmmgr invokes
  only what root and memd pass it, and root only memd's Untypeds, which
  are memd's to give.
- **Wiring.** Every capability by which one party calls, signals or
  faults to another is an edge of `l4h_host::wiring`: its holder and
  where it holds it (fixed slots, a slot its minter chooses, an IRQ
  handler, a fault endpoint), its target and which of its objects, its
  rights, its badge (one value, a field per instance, or a bit per
  instance), its minter and what it is for. Each edge is typed
  `E<Holder, Target, Object, Protocol>`, whose descriptor is private:
  `edge()` and its shared `Deref` expose it read-only, so it cannot be
  replaced in safe code. `E::new` checks at compile
  time that the type names the edge's holder, target and object and,
  for a call or mailbox post, the protocol the target's object serves. A capability is
  minted from its edge and nothing else (`l4h_task::edge::mint`,
  `Component::give_edge`, the guest's `give_edge` in vmmgr), so slot,
  rights and badge cannot drift from the declaration, and only from an
  `Obj<Target, Object>`: what an edge is minted from has the edge's
  target and object as its type. An `Obj` is claimed where the object
  is made or received, naming its party and object (`Obj::claim(party,
  object, cap)`; `Component::obj`, which checks the component's kind;
  `MemdLink::obj`, the guest's `vcpu_obj` and `vmm_ntfn_obj`), so
  passing another party's notification to a mint does not compile. Only
  an edge's minter mints it: root and vmmgr say which they are
  (`edge::minter`), and a mint of another's edge stops. A capability
  that reaches its holder through another (vmmgr's copy of root's flags
  capability, a VMM's capability to memd and its backends' kicks, a
  guest's attestation kick) is passed on from its edge as well
  (`Component::pass_edge`, `edge::pass`), which gives the slot and caps
  the rights. The only other mint is of a CNode with its guard
  (`edge::mint_cnode`, `give_cnode`), and clippy refuses `mint`, and
  `mutate`, which can badge what it moves, anywhere
  else, for both architectures. A component gets a capability to its parent's endpoint only if
  it calls its parent (`wiring::parent_call`: trustd, vmmgr, the VMMs),
  and its faults go to its parent by its fault edge (`parent_fault`, or
  `keeper_fault` for a component with a keeper); `create` checks that
  both are to the parent it is given. In debug builds the running system
  is held to the declarations too (`host::AUDIT`: debug host builds,
  which boot debug kernels): each component, as it starts
  (`l4h_rt::init`), looks at every slot of its CSpace's layout with
  seL4's `DebugCapIdentify` and stops if an endpoint or notification is
  in a slot that no edge it holds, and none of its own objects
  (`wiring::OWN`), gives it, or is of another type than the edge's
  object (`wiring::audit`); each later `give_edge` and `pass_edge`
  checks the type of what it put there. A VMM's parent also checks ordinary
  copies, the dynamically minted parent-call endpoint and live installs.
  Live installs check the stable source capability before copying or
  minting, since a running VMM can replace its destination slot immediately.
  At compile time no two edges share
  a slot or a notification bit unless both are declared shared, every
  call's badge decodes as a sender its protocol accepts, every signal is
  in its receiver's badge space, root calls no driver, vmmgr or VMM (it
  posts in their mailboxes), every fault carries the FAULT bit, and a
  component has a keeper exactly when another component calls it
  (`host::has_keeper`): memd, vmmgr and trustd's flags server, which
  trustd's main thread and vmmgr call. No two call capabilities on an
  endpoint have the same badge unless the wiring declares one a copy of
  the other (`VMM_MEMD`, passed on from vmmgr's `VMMGR_VMM_MEMD`), so each
  holder is the sender its badge says. Capabilities that pass resources (CNodes, frames, IRQ
  handlers, I/O ports, TCBs) are not edges, nor are a guest's own
  vCPUs' (the guest ABI). The edges themselves are listed only in
  `wiring.rs`.

**Serial output** goes through shared memory to l4h-logd (§10.4), and root
drives COM1 input for the monitor. The port takes about 11 KB/s; writers
enqueue output without waiting for it:

- informational messages (device discovery, guest lifecycle, balancer
  moves) use `info!`, and critical diagnostics use `log!`. Both print in
  every build; repeated errors (failed I/O) print only the first few times
  (`l4h_rt::ErrorLimit`);
- guest consoles, dom0's included, are copied to the serial port in every
  build; they also go to the console rings `console_read` serves;
- the serial monitor's replies and the opt-in watchdog dumps always print.

`tests/check-debug-print.sh` keeps host code from printing through the
kernel, a synchronous serial write for every byte.

**Host log.** Diagnostics from root, vmmgr, VMMs and device services also go
to a bounded log (`l4h_host::log`), including `info!` in release builds,
Rust panics and keeper fault reports. `l4hctl logs` reads a snapshot and
`--follow` polls for new records (`CTL_LOG_READ`, dom0 only, with
independent time cursors and an explicit count of unavailable records).
Guest kernel faults include the VM id, vCPU and fault registers; guest power
requests distinguish power off, reboot and kernel panic.
- **One lane per writer.** Every writer there can be (`log::Writer`: root,
  logd, memd, trustd, the flags server, vmmgr, netd, a blkd per disk
  controller, a usbd per xHCI controller, a VMM per guest) has a lane of its
  own, in pages of its own, fixed at start in a static of root's (780 KiB):
  255 records for root, 63 for vmmgr, 15 for each other service and 7 for
  each driver and VMM, each record at most 480 bytes with an explicit
  truncation marker. A component maps only its own lane, writable; root
  gives vmmgr the VMMs' lanes, for it to give each VMM its own, and maps
  all of them read-only into vmmgr for `CTL_LOG_READ`. A record holds its
  text and time; the reader adds the time since boot, from a clock only
  root writes, and the writer's
  id, from the lane the record is in (the component id; `0x1000 + g` for guest
  g's VMM, whose component id is its guest's and would be root's 0 for guest
  0): a
  component can neither write a line another's id is printed on nor
  overwrite or erase another's records, and fills only its own lane. A
  guest id's VMM lane is the next VMM's of that id; destroying a VM
  neither revokes
  the lanes nor clears vmmgr's diagnostics about it. A component takes its
  lane over when it starts (`ring::View::adopt`): one left as no honest writer
  leaves it (a head near the end of the sequences, a slot claimed by a
  sequence that is not there yet, a record of a time still to come) is reset,
  so the last VMM of a guest id can neither make the next one's records drop
  nor leave one to come up later as the next one's; readers count what a reset
  took as lost. A serial lane is taken over the same way, but for the
  records' times: a secondary partition's ring is written by its other
  tasks meanwhile, and logd prints a record when it is the oldest waiting,
  not when its time comes. Logs
  do not survive a host reboot.
- The reader merges the lanes by time: a read returns the records of
  [cursor, end), oldest first, ending a moment (100 ms) before now, so that
  a record still being committed falls in the next read rather than
  between two; the records of one time are never split between two reads.
  A cursor a read gave can be later than that moment (the read was full),
  and the read from it is then empty, at the cursor: only a cursor in the
  future, or past the caller's end, is refused, so no writer can make
  another's reads fail by leaving a slot claimed. A read that stops short
  of the end its caller gave still reports that end, so a snapshot's
  reader goes on reading to it rather than taking it as done; an end still
  to come counts as none, so a snapshot's end is fixed by its first read
  and reached within a moment, whatever writers leave claimed.
  A record's time is its writer's to choose: one in the future waits, one in
  the past is missed by a follower, and either is only its writer's loss.
  Lost counts the slots a read finds unavailable between a lane's records,
  and, from boot, what was
  overwritten (2^32 at most for a lane, whose head is its writer's word, so no
  lane's number can bring the count to its end and hide the others'); a lane
  that a follower's read finds
  overwritten since its last record counts as at least one. Each read scans
  every lane's slots once per record it takes,
  returned (at most 1984 bytes of them) or unavailable, and takes no more
  records of a lane than it has slots: a writer that keeps committing records
  as the reader goes is left out of the rest of that read, which ends after at
  most as many scans as the lanes have slots and moves a follower past it.
- Writers format on their own stack and publish with atomic memory
  operations, without allocating, making an IPC or touching message
  registers, and never wait on a lock: a writer preempted or faulting in a
  slot leaves the others the remaining slots. Readers validate the slot
  generation around atomic payload reads, and a checksum of the record
  against the one store a writer that lost its slot can still make, read
  each lane's head once and bound every scan by the lane's capacity, and
  report overwritten, dropped, torn and incomplete records as unavailable;
  no reader consumes another's history or blocks the host. What a record's
  text holds is made printable (`log::printable`) before it is handed out.
- **Rate limit.** A record that a less trusted party can make vmmgr write
  (a guest's faults and power requests, its VMM's calls) goes through
  `log::RateLimit`: per guest, 8 at once and then one a second, fixed
  state; the next record let through says how many were not.
  Root limits the same way
  what trustd can make it write (refused `hw` accesses) and what a peer
  partition can (channel.rs), and logs only the first 8 writes it refuses to
  another partition's PCI function.
- Querying needs a working dom0 and vmmgr; this does not capture seL4's own
  debug stream or make a crashed host queryable.
- `tests/run-logtest.sh` checks kernel faults, panics and shutdowns retained
  after VM destruction and read with `l4hctl` (also with `L4H_RELEASE=1`).

**Guest boot protocol.** The guest boots without firmware or a bootloader.
vmmgr loads the guest kernel's segments and the initramfs dom0 uploaded
into the guest's boot blocks, builds the kernel VSpace and
`struct l4h_bootinfo`, then starts vCPU0 at the entry point with `rdi`
(`x0` on aarch64) pointing at boot info. It holds:

- a magic number and the guest ABI version (`L4H_ABI_VERSION`, currently 8);
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
  in 512-byte sectors, decimal digits only. Starts and fixed counts must
  be multiples of eight, with positive counts. `start:end` extends to the
  disk's last complete block; `start:end-N` leaves at least N sectors there, e.g.
  `2097152:end-2048` leaves room for the backup GPT. Root resolves these
  against the capacity reported by blkd on each host boot, with checked
  subtraction and rounds the end down to a 4 KiB boundary, excluding at
  most seven additional sectors. At most one end-relative window is
  allowed, and every fixed range must end at or before its start,
  regardless of list order. This rule prevents unresolved windows from
  overlapping fixed ranges when geometry is lost. A disk enlarged between
  boots needs no config rewrite (and no change to the config's PCR 9
  measurement). The list replaces
  disk 0 and requires `dom0_disks` > 0 and `dom0_disk0_mb=0`. Invalid,
  overlapping or excessive ranges stop boot. A range beyond the disk's
  capacity, which is its driver's word, does not: it is logged and stays
  reserved, and dom0 gets a zero-capacity placeholder for it. None ever grants
  access to the whole disk. Other host disks keep their order after these
  devices.
- dom0's whole device plan must fit in 64 slots, including console, control,
  memory and attestation devices, all disk windows and NICs; oversized plans
  stop boot, and neither list is truncated.
- Root has blkd reserve every boot disk range before attaching it
  (`blk::call::reserve`); blkd keeps those reservations across dom0 restarts. A controller root answers
  `EBUSY` for (another attachment or a provisioning write under way, or
  the last dom0's disks being let go) is tried again for up to 10 s. If an attachment fails, dom0 gets a
  zero-capacity, read-only virtio-blk device in that position, which fails
  all I/O without a driver channel or DMA mappings, so other disks keep their
  names and dom0 can still boot. The range stays reserved against
  provisioning and conflicting attachments. When a failed disk cannot report
  its capacity, root checks the configured ranges for alignment, overflow
  and overlap and lists them as dom0's (its controller serves nothing); a
  whole-disk reservation covers all aligned sectors. The same applies to an automatically selected whole disk whose
  capacity is not a multiple of eight sectors.
  An end-relative range that cannot resolve against the reported capacity
  is likewise a placeholder: its data area is conservatively reserved
  against the largest aligned capacity, never attached with that size.
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
  event; the calling task sleeps meanwhile, and the vCPU runs others. A
  request that waits for a driver (`blk_attach`, `blk_write`, an extent's
  `blk_info`) is answered when the driver has answered, or never: vmmgr
  writes its seq at `L4H_CTL_TAKEN_OFF` once it has read the request and
  the data area, and the caller can be killed. The next request then takes
  its place, and the old one's answer, if it ever comes, is dropped (its
  effect, such as an attached disk, stays).
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
| Host | `host_version` (the build version; the tag for a release); `host_info` (cores, free/total bytes, disk, VM and NIC counts); `pci_list` (boot inventory, IDs, class and service owner); `host_reboot`; `rtc_set`; `iommu_info` (§9.5); `log_read` (§10) |
| Guests | `vm_create`, `vm_load`, `vm_start`, `vm_shutdown`, `vm_destroy`, `vm_list`, `vm_info` (cores of the first six vCPUs), `vm_stats` (CPU use and cap), `vm_set_sched`, `vm_set_mem`, `vm_mem_info` (§8.5), `vm_trust` (flags, §10.2) |
| Block | `blk_attach` (disk, read-only and volatile flags, LBA window), `blk_write` (provisioning), `blk_info`, `disk_info` |
| Network | `switch_create`, `switch_attach_uplink`, `nic_create` (MAC, MAC lock, isolation), `switch_info` (ports with VM and MAC, counters), `nic_info` (PCI address, switch, MAC) |
| Console | `console_read` (offset, bytes and lost-byte count), `console_write` |
| Display | `gpu_attach` (scanout size), `gpu_read` (the image, 1 MiB at a time, with size, format and frame; §9.6) |

`CTL_PCI_LIST` takes an inclusive first BDF and returns up to 124
`CtlPci` records in BDF order; the next page starts at the last BDF plus
one, and a zero count ends the list. Root records every enumerated
function at boot, including unhandled devices, with vendor/device,
subsystem IDs, class/subclass/programming interface and revision. The
16-byte records occupy a fixed table in root's .bss: 1 MiB for x86's whole
BDF space, or 64 KiB for aarch64's 16 buses. Queries touch no PCI
configuration registers or BARs and use a binary search to locate a page.
The service owner is `none`, `blkd`, `netd`, `memd`, `firmware` (unclaimed
xHCI), `usbd`, or `root` for disabled NICs that were not handed to netd
and failed or quarantined disk/USB controllers, including disk reset
failures during boot. Disk and USB ownership is resolved from the current
controller state on each query. Guest assignment remains in the
disk/NIC/USB queries.
Subsystem IDs come from an endpoint or CardBus header, or a bridge's
optional subsystem-ID capability; absent IDs are zero. On a multikernel
machine each dom0 sees its root's inventory. `l4hctl pci` prints the list;
`l4hctl pci --json` supplies numeric IDs and class fields for boot-time
platform selection.

A Rust userspace library and CLI live in `tools/l4hctl`; external
orchestration runs in dom0. Devices are attached before start and removed
on
destroy. A `nic_create` that root refuses, or a `gpu_attach` that runs out of
host memory, leaves what it had made (a CNode; the GPU's CNodes and frames)
with the guest for the next attempt, since an arena gives nothing back:
refused attempts take no more than one attach does. Pause/resume, device
hotplug, switch deletion, I/O limits and
asynchronous event queues are not implemented. A stopped guest (powered
off, or its kernel or VMM faulted) stays stopped until it is destroyed:
the guest needs its kTCBs and SC_Us with every right (it starts its
other vCPUs, arms their timers and binds SC_U to its tasks), and seL4 TCB
capabilities have none to take away, so vmmgr revokes its own kTCB and
SC_U capabilities, which deletes every copy the guest made of them, then
suspends the kTCBs and unbinds every SC, which a user thread or call
chain may hold (`Guest::stop`). `vm_pause` would need to give them back.

**Lifecycle.**

- `vm_create` → (`blk_attach` / `nic_create` / `gpu_attach` / `vm_load`)\*
  → `vm_start` → `vm_destroy`. `l4hctl` loads the initramfs with raw
  `VM_LOAD(vm, gpa, bytes)` writes from the GPA `vm_create` returns; vmmgr
  copies page by page from the data area into the guest's boot blocks and
  never parses what guests load. `vm_start` loads the kernel, measures the
  launch, writes the boot info and spawns the guest's VMM.
  It checks the
  guest's state (`EBUSY` once it has a VMM, or while a disk is being
  attached), its parameters and the host's memory for the boot blocks and
  the VMM before it writes anything, so a start that is refused leaves the
  guest as it was and can be made again; nothing after the boot info is
  written can be refused. The kernel `vm_start` writes is not among what
  was loaded into the guest.
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
  destroyed, and the shared controller keeps running. Root first unmaps the
  pool from the controller's IOMMU domain, which waits for the device's
  DMA to it to drain (§9.5): the device can no longer reach the pool,
  whatever blkd does. Then root asks blkd to drain the client
  (`blk::call::remove`), and the pool is reused once blkd has drained every
  disk of the guest (`vmmgr::zombie_disk_done`): until then the device may
  still run commands the guest had started and it had not begun, and the
  controller's domain may meanwhile map another client's pool at the same
  addresses (the allocator gives the next pool of that size the same
  block), which those commands would reach. Without an IOMMU the pool
  waits for that drain too, until every request the client submitted has
  completed.
  Root cannot cut one client off by clearing bus mastering, as it cuts off
  a USB controller's one guest (§9.7): that would stop the controller's
  other clients, and once bus mastering was back on the device would finish
  commands it had started, into the reused pool. A USB controller is reset
  before bus mastering comes back. If blkd has failed or the device
  finishes nothing of what it had for five seconds, root quarantines the
  controller: it suspends blkd
  and disables the PCI function, marks the controller failed until host
  reboot (`blk_attach` returns EIO, `l4hctl disks` says so), and keeps the
  guest's pool and blkd's DMA memory out of the free pool, unless an IOMMU
  has cut the device off from the pool (§9.5). Root does not count on the
  disabled function there: a controller that did not drain is already not
  doing what it was told. `tests/run-ctltest.sh` destroys guests in the middle of throttled
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
   so one digest covers the whole host. Loading its child GRUB image
   extends PCR 4 again. GRUB's `tpm` module measures dom0's
   kernel, initramfs and `l4h.conf` into PCR 9, and its commands into PCR 8.
   Secure Boot is not needed: nothing is checked at boot; the verifier
   checks afterwards. A BIOS boot measures none of this (BIOS GRUB has no
   `tpm` module), so such a host's quotes say nothing about what it booted.
2. **The host key.** `l4h-trustd` is the only component that maps the TPM,
   which root finds in the ACPI `TPM2` table (see **TPM interfaces**).
   trustd polls it at locality 0, sleeping on its E3 timer between polls
   (20 µs up to 2 ms). It runs on the last core at `P_K + 3` with at most
   5 ms of every 20 ms, so neither a slow TPM nor the firmware's AML can
   take a core from
   guests; the flags server takes at most a tenth of that core besides. At
   start, trustd:
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
     maps read-only, once per guest (a second registration is `EEXIST`): a
     running guest's record never changes, and its instance, written last,
     never reads as 0 before the guest is destroyed. Root writes a record
     with `trust::write_record` (its fields, then its instance) and clears
     it with `clear_record`; trustd reads it with `trust::read_record`: the
     instance, then the record, then the instance again. The
     fields between two equal readings are that instance's, since instances
     are never given twice and a record is written only while its instance
     is 0. One read of the whole record would not do, whose loads come in
     any order: a guest started on a destroyed one's id could be given that
     one's digest and dom0 bit. Whether a guest is dom0
     is root's to say, and there is one at a time. Root never waits for
     trustd's main thread, whose TPM
     commands can take seconds.
   - Each guest has an attestation device (`L4H_DEV_ATTEST`). Requests are
     asynchronous, so a vCPU never waits for trustd: the guest writes its
     request into the device page, then a new sequence number, and signals
     the kick, whose badge is the guest's id, so trustd answers a guest only
     about itself. trustd answers in the page, sets `done`, and asks root
     (`root::call::attest_done`) to have the device's event raised on vCPU 0
     (root posts it in vmmgr's mailbox: one notice a guest at a time, the next
     once vmmgr has taken it, and at most 32 a guest between two ticks of
     root's 100 ms timer, so trustd cannot flood vmmgr or a guest with events;
     an event can come that much later, and none is lost). Linux sleeps the
     caller meanwhile.
   - trustd owns the request pages, two per guest id, and root lends one
     to each guest, so a page stays mapped in trustd while it answers a
     guest being destroyed. trustd drops an answer whose guest's instance
     changed while it worked: it says in a status page which page it is
     about to write, then looks at the registry a last time. Root
     unregisters a guest before it gives the id to another, and gives the
     new guest the id's other page while the status names the old one's,
     so no answer lands in a page given to another guest since.
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
   beyond
   that trustd answers `-EAGAIN` without using the TPM. A primary gives each
   other partition's relayed requests the same allowance. Reports,
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
  outside the launch measurement; guests treat the network as untrusted,
  so steering rules (§9.3) take no bit, also on a sealed guest's MAC or
  port.
- **The flags service.** The flags server, the trustd image started by
  root a second time as a component of its own (`host::KIND_FLAGS`, with
  its own CSpace and VSpace), is the sole writer of an 8 KiB flags area:
  64 entries of 128 bytes, each with a seqlock, instance and the two
  bitmaps. Only it maps the area writable; readers (the host actor, root
  and trustd's main thread) map it read-only and retry an odd or changed
  sequence, 128 times at most:
  the server can be stopped in the middle of a write until its next budget,
  and no reader spins for that long. A reader that still finds the entry
  being written asks the server (`sync`, a call that does nothing and is
  answered in its turn, so after that write), up to three times: it waits
  less than the server's period, and a caller that floods the server to
  stop it in a write gains nothing. An entry that stays unreadable after
  that, as a failed server leaves it, reads as all
  tainted and sealed (`Flags::UNAVAILABLE`): the host actor refuses the
  operation with `-EAGAIN`, and a report fails with `-EAGAIN` rather than say
  what trustd did not see. trustd's main thread, which parses guests' pages
  and runs the
  firmware's AML, reaches the flags only through its calls. Root assigns
  monotonically increasing instances at `VM_CREATE` and publishes them in
  the registry at start, which the flags server maps read-only too. An
  entry for another instance reads as empty; a higher-instance request
  replaces an entry, an older one gets `-ESRCH`. Destruction does not
  clear flags.
- **Callers.** The flags endpoint has badged callers, each with a badge
  of its own: `trust::Sender::Vmmgr` (the host actor) can ACT on defined
  host bits, `trust::Sender::Trustd` (guest requests) can ACT on guest
  bits and SEAL defined host or userspace bits, and `trust::Sender::Root`
  only makes the start-up handshake. Kernel bits cannot be sealed. All
  arguments are validated before any entry changes, the instance too:
  trustd's must be the one the registry has for the guest, and vmmgr's
  too once the guest has started (before, vmmgr records console input
  queued for the instance root gave it), so neither can replace a running
  guest's entry with another instance's. The operation is the message
  label (`trust::FLAGS_ACT`, `FLAGS_SEAL`); requests are MR0 id, MR1
  instance, MR2–5 bitmap, MR6 options; replies MR0 status, MR1 instance,
  MR2–5 taint, MR6–9 seal. The server runs
  at root's priority on a scheduling context of its own, 1 ms of every 10 ms
  (`trust::FLAGS_BUDGET_US`), with no heap, TPM, AML or calls back. It never
  runs on a caller's: a message sent without a call donates none, and a server
  waiting for one would stop for good, and vmmgr's next call with it. A
  request takes microseconds; a caller that floods the server takes at most
  that tenth of the last core and delays another caller's request by less than
  10 ms. If it faults, its keeper answers every call `FAILED` from then
  on: the actions they were for are refused, so seals stay enforced.
- **Ordering.** An actor first checks the seal in a consistent entry. If the
  taint is already set, no IPC is needed; otherwise ACT must succeed before
  the operation. This costs one IPC per action kind per instance. ACT and
  SEAL serialize in the flags server. An operation that passed its check can
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

**Multikernel.** On a machine split into partitions (§11.3) only
partition 0 has the TPM. Every partition's trustd still has its own key K;
a secondary's comes from RDRAND, and partition 0's trustd quotes it and
runs the secondary's ActivateCredential calls (the relay):

- **Transport.** trustd writes a request into a relay page it shares with
  root and calls root (`root::call::relay`), which sends it over the control
  channel (`MSG_TPM_REQUEST`); the other root writes it into the sender's
  inbox slot there and kicks trustd (badge bit 63, also guest 63's kick,
  which is only a hint). Answers go back as `MSG_TPM_REPLY`. Channels
  never wait and can lose messages, so a request carries an id and is sent
  again every second (key) or five seconds (ActivateCredential) until its
  answer comes, for at most two minutes or 20 s; partition 0 answers a
  repeated id from what it
  kept, without using the TPM again, and gives each partition's
  ActivateCredential requests the allowance a guest's have. A secondary
  has one request out at a time and keeps serving other guests meanwhile
  (root kicks it on its timer while it waits); only guests that need the
  answer wait. If partition 0 is dead or has no TPM, the secondary ends up
  flags only.
- **PCR 15.** The binding becomes `SHA-256("l4h-trustd-key-v2" ‖
  partition (u32 LE) ‖ K)`. Partition 0 quotes and extends its own key
  first, then each secondary's once, in the order they ask (partitions
  boot in parallel); a second, different key from a partition is refused.
  A key's quote therefore shows PCR 15 as the chain of the keys extended
  before it, and its evidence lists them (`chain`: [partition, K] pairs).
  The verifier recomputes the chain and checks that it starts with
  partition 0, has at most one key per partition and none of the
  evidence's partition, so each partition's key is the only one it got in
  this boot.
- **Format.** Reports and evidence are version 2 and carry `partition`;
  single-kernel hosts keep version 1. `l4h-attest.py` accepts both, checks
  that a report's partition is its evidence's, and prints the partition and
  the partitions whose keys came before.

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
  - Accesses outside trustd's own TPM ranges go to root (`root::call::hw`),
    which serves them only for this start method and takes them for an
    attacker's, since trustd's main thread also parses guests' pages. Root
    serves memory only if it is free device memory: not RAM, not what root
    carved for itself or a driver (the AML's pages are carved into a frame
    table
    of their own, so whatever root carved, the IOMMU's registers among
    it, is not free for them), and not a BAR of a PCI function root drives. On
    a machine split into partitions the others' RAM is device memory to this
    kernel and the descriptor does not list it, so there root serves memory
    only where none can be: the chipset's addresses from 0xfec00000 to 4 GiB,
    the ECAM window and the memory BARs of the partition's own functions. It
    serves I/O ports seL4 has not handed out, except those that
    reset the machine, put it to sleep or enter SMM (0x60, 0x64, 0x92,
    0xb2–0xb3, 0xcf9 and the FADT's SMI command and PM1/PM2 control
    blocks). PCI configuration,
    by ports or through the MCFG's ECAM windows, it serves for reading. Writes
    it refuses to every function root manages (disk controllers, uplink NICs,
    xHCI controllers, the balloon device, IOMMUs, every bridge, an ISA or LPC
    bridge included, and the function that holds the FADT's reset register),
    to functions of other segments, and in every function to the command
    register, the BARs and the expansion ROM's, so the AML neither moves a
    device root does not drive onto another's addresses nor lets one master
    the bus. Root keeps up to 16 ECAM windows; if the MCFG lists more, or
    cannot be read, it serves no memory write at all, since any could be a
    configuration write. Refused reads return all ones, and root logs refusals
    through `log::RateLimit`.
  - The interpreter runs in trustd, not root, because it can panic on some
    AML. If trustd's main thread faults, root suspends only it, revokes the
    guests' kick capabilities, marks every attestation page failed and
    answers pending requests with -EIO; no new guest gets attestation. The
    flags server, which the main thread can reach only by its calls, stays
    alive, so seals stay enforced.
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
so a command only runs if trustd ran the `_DSM`. `MK_ATTEST=1
tests/run-mktest.sh` boots two partitions with swtpm, verifies dom0's and
a VM's reports in each against its partition's evidence, and activates a
credential in each on a second boot. `tools/mkefi.sh` swaps the
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
  call it, and guest kernels and VMMs fault to it: a guest whose kernel or
  VMM faults is stopped as one that powers off is (`Guest::stop`, §10.1),
  and dom0 is restarted.
- **Root holds** what devices reach. A guest's I/O pool is root's: root maps
  it into the IOMMU domains of the guest's disks by physical address. If
  vmmgr named addresses, a compromised vmmgr could have root give a device
  any memory, so vmmgr names guest ids, disk numbers, LBA windows and sizes,
  root checks them against its own tables (`vmmgr::RootGuest`; a window
  against the disk's capacity, while an extent list is blkd's to read and
  check), and every
  address root gives the IOMMU, blkd or netd comes from that table. Disk
  channels and netd ports are root's too, in a per-guest arena root revokes
  when vmmgr is done with the guest. Root also numbers guest instances, so
  they stay unique since boot whatever vmmgr does.
- **The interface** (`l4h_host::vmmgr`) is a handful of calls from vmmgr to
  root, with integers in message registers: `GUEST_NEW` (the pool and the
  attestation device), `GUEST_DEL`, `DISK_ATTACH`, `NIC_ADD`, `USB_ATTACH` (§9.7),
  `TRUST_REGISTER` (the launch digest), and `HOST_OP`, which carries the
  control ops on the host's disks, switches and NICs, reset and RTC as their
  `CTL_*` number and six arguments, with data returned in a result page.
  Root answers every call at once; one that waits for blkd answers
  `root::Later::Token` and a token, and root posts `vmmgr::call::op_done`
  in vmmgr's mailbox when it has the answer, which `root::call::result`
  then gives. vmmgr goes
  on meanwhile: a guest whose disk is pending gets no other device, and
  does not start, until it is answered; dom0's boot disks are attached one
  after another this way.
  Capabilities cross in vmmgr's exchange slots, which root reaches through
  vmmgr's CNode. Root empties a slot before filling it, so a slot vmmgr left
  full cannot make root fail, and one vmmgr fills again meanwhile (from
  another thread) fails the call (`EINVAL`). Root takes no capability from vmmgr: even the
  notification blkd and netd signal for a guest's VMM is made by root at
  `GUEST_NEW`, so it cannot be an endpoint that would block them.
- **Root never calls vmmgr**, so calls cannot deadlock. It posts notices
  in vmmgr's mailbox instead (`vmmgr::call`, from `Sender::Root`), as it
  asks the drivers: a request it answers later has its answer (`op_done`),
  trustd answered a guest (`attest_done`: vmmgr raises its attestation
  event), or the serial monitor asked for `destroy` or `restart-dom0`. A
  full ring keeps them in root until vmmgr has taken some: answers and
  guests as bits, and one monitor command (the monitor says "busy" past
  that). vmmgr publishes its guests in a status page for the monitor's
  `list` and the dashboard.
- **Destroy.** vmmgr stops the guest and revokes its own arena (VSpaces
  first, so nothing is unmapped page by page) and has memd revoke the
  guest's RAM blocks (§8.4; guest RAM is never a DMA target, so this does
  not wait for the drivers), then `GUEST_DEL` has root
  forget it in trustd, cut its disks off the pool (the IOMMU) and revoke it
  (without an IOMMU, only once its disks are quiesced, and kept out of use
  if one did
  not stop), and have netd and blkd let go of its ports and disks. Root
  answers at once: what drivers map stays with root until they have let go
  of it (§10). Its requests still waiting for a driver are answered
  `ENOENT` then, so a control request waiting on them is answered; the
  token stays taken until the driver answers too, which root then drops.
- **Boot modules.** Root maps the guest kernel, its module tree and dom0's
  initramfs read-only into vmmgr, with a CNode of their frames, so guests
  can share the kernel's read-only blocks and the module tree (§5.6).
- **dom0's devices.** Root makes the switches at boot, attaches the uplinks,
  and chooses dom0's disks and vNICs (`Dom0Plan`); vmmgr creates every dom0
  with them. A dom0 that cannot be built (memory, or a plan that does not
  fit) is logged and given back, and the monitor's `restart-dom0` tries
  again; vmmgr does not fail for it. A vNIC whose netd has failed is not
  added (`EIO`, as for a disk or USB controller whose driver failed).
- **Trust.** vmmgr is in every guest's TCB: whoever builds a guest's CSpace
  can copy its frames. The console seals (§10.2) are vmmgr's to keep: it
  reads the VMM-written console rings and display areas and acts on
  trustd's flags. A bug in vmmgr reaches guests' memory but not the
  hardware, the IOMMU, the TPM or root.
- **If vmmgr fails**, guests keep running: their vCPUs, disks, networks and
  memory hotplug need nothing of vmmgr. Like memd, the other component
  that serves calls, it has a keeper thread (`l4h_rt`), which reports the fault and answers every later
  call with a failure, the call vmmgr was serving first if it was serving
  one (its reply object is in `SLOT_REPLY`), so a VMM's call returns instead
  of blocking. A fault vmmgr was handling when it failed gets no reply,
  which would restart the faulting thread: the first receive on the reply
  object lets go of it. A guest's
  power request does not return: its VMM does not answer it, so the vCPU
  that asked stays blocked in it, as stopped as vmmgr would have left it.
  For dom0's control requests, the failure service
  writes EIO, publishes the completion and raises the device event, for an
  outstanding request and later ones, using pages and a notification
  registered before dom0 starts and none of vmmgr's mutable state. A keeper
  takes over the main thread's bound notification; a panicking main thread
  serves it itself. Panic recovery retains the executing TCB in TLS, so a
  panicking keeper keeps that ownership too. Faults of guest kernels and
  VMMs stay unanswered, so
  those vCPUs stop. Nothing can then create, change or destroy guests,
  attestation answers no longer reach guests, and the balancer stops; the
  serial monitor's `reboot` resets the host (`tests/control-failure.rs`).
- **Scheduling.** vmmgr runs on core 0 at `PRIO_KERNEL + 3`, above every
  guest and VMM, with a full budget and its own deadline timer for the
  balancer.

### 10.4 Serial output: l4h-logd

One task, l4h-logd, is the only host code that prints to the serial port. Lines cannot split, because one writer prints whole records.
The kernel still prints boot messages and fatal errors to the port itself,
so the guarantee covers host output only: a kernel message can land inside
a line.
A debug kernel also reports each invocation it refuses. Root makes the one
that every boot without VT-x has, its try at a VCPU object (`HostInfo::vtx`),
before it starts logd: that message stands on its own line, where it used to
land inside one of root's first lines, a different one each boot, and failed
whichever test looked for that line (`tests/run-selftest.sh` checks it).

```
 partition 0                         secondary partition k
 root       other writers            root       other writers
 |          | a lane each            |          | a lane each
 v          v                        v          v
 root ring  serial lanes             root ring  serial lanes
 |          | read-only              |          | read-only
 +----------+                        +----------+
       |                                   |
       |                              local l4h-logd
       |                              trusted provenance per record
       |                                   |
       |                            serial ring k (shared region)
       +--------------------+--------------+
                            v
                       l4h-logd  ------> UART, framebuffer
                            ^
              secondary kernels' console rings
```

- **Serial ring** (`l4h_host::serial`). 1023 slots of 224 bytes, 256 KiB,
  room for a dom0 boot and no deeper, since a deep ring only makes output
  later: a guest flood fills it, and everything waits behind that. Separate
  from the log so that console volume cannot push diagnostics
  out of `l4hctl logs`. The slots are the log's (`l4h_host::ring`):
  writers format on their stack, claim, never wait and make no seL4 call. A
  writer that stalls in a commit keeps its slot until the writer of a later
  lap takes it back, and then stops, at worst after one more store, which
  the record's checksum shows its reader (the record is then lost). A line
  that does not fit takes consecutive slots, flagged as going on, and a
  reader prints them next to each other.
- **Lanes.** In every partition the root ring is root's alone. Every other
  writer
  (`log::Writer`) has a lane of its own (`serial::Lanes`, 1.6 MiB in a
  static of root's, fixed at start): dom0's VMM one as deep as the ring,
  for dom0's console; each other VMM 63 records, for its guest's console;
  vmmgr 31; every other component 15. A component maps only its own lane,
  writable, at the same fixed address in every partition; root
  gives vmmgr the VMMs' lanes, for it to give each VMM its own, and maps
  every lane into logd read-only. logd prints whose a line is from the lane
  it is in, never from the record: root's lines and dom0's console have no
  prefix; a VMM's guest console `[vmN] `, with N its guest's, whatever the
  record claims; and every other writer's lines its name: `[netd] `,
  `[blkd3] `, `[vmm2] `, `[dom0 vmm] `. A component can neither print a
  line that passes for another's nor overwrite or erase another's: it fills
  only its own lane. The next VMM of a
  guest id resets a lane its last one left unusable, as in the log
  (`serial::init_lane`; a ring as deep as root's only for a wrong head or
  slot, not for a record's time), and
  logd reads a lane whose head moved back from the oldest record it holds, so
  the new writer's first lines print. A secondary runs a local logd without
  UART authority. It reads root's private ring and every lane, applying the
  same scheduling bounds, and is the only component given the shared
  transport ring from the partition descriptor. `Merge::forward` copies
  each input record with a writer index derived from its lane, plus its
  continuation and console bits; claimed writer identities are discarded.
  Partition 0 prints `[pN] ` followed by that writer's label. Every
  continuation carries its provenance, so wrapping the transport cannot
  remove a surviving record's identity. Lost records can still occur on
  this bounded shared transport; retained host logs use their separate
  lanes. Partitions themselves remain outside the security boundary (§11.4).
- **Printable text.** logd hands on a record's text, and a kernel console
  line, only as text (`log::printable`, also what `l4hctl logs` reads):
  tabs
  and line ends become spaces, and other control characters (C0, DEL and C1,
  escape sequences included), the line and paragraph separators, the controls
  of bidirectional text and bytes that are not UTF-8 become `?`. The text is
  for a terminal that reads UTF-8: one that reads single bytes takes some
  bytes of a character for C1 controls. Guest names
  that root's monitor or vmmgr prints, and a guest's console, cannot move
  the terminal's cursor over another line or pass for another writer's.
- **Writers.** `log!` and `info!` write the writer's serial ring or
  lane as well as its log lane in every build. A VMM gathers its guest's
  console by line, and sends what it has of one after 100 ms, so that
  prompts show. Panic text is gathered by line. The ring's timestamps are
  not printed.
- **logd** wakes on a 10 ms timer, since writers cannot wake it. `Merge`
  (also in `l4h_host::serial`) prints the record with the lowest timestamp
  of any ring, then lines of kernel console rings. A record claimed and not
  committed gets 100 ms; `(N lines lost)` reports what was overwritten or
  skipped. Each partition has 64 records or reports of a pass, which bounds
  what a ring claiming to hold the oldest record can do, and a pass ends
  only when nothing is left to print. Partition 0's home ring and lanes
  share theirs: its lines go out oldest first, as from the one ring it had,
  so a line printed after a guest's (vmmgr's "all guests stopped") follows
  what the guest printed before
  it. A lane's times, lines and losses are its writer's to make up, so within
  that budget a lane's record takes its turn at its time or, if later, at the
  time logd saw the lane without it (a writer reads the time once it has
  claimed its records, so an honest record's is later anyway; a lane that
  always claims the oldest time waits behind what was already there, and at
  most twice its slots of backdated records get ahead of another's line); the
  rest of a lane's open line comes first for 128 records, more than the
  longest line a guest's tools print (an attestation's evidence), and then
  takes its turn by time, so a line without an end is cut by an older line;
  and an input's loss is reported once in a pass. Honest writers' lines keep
  the order of their times through all three, which a share of the budget for
  each lane would not. It has 5 more for the rest of a line it
  has started, the length of the longest message; a longer line can split
  where a pass ends. logd waits for the rest of a line only from root's
  ring: another writer could ask for 100 ms every time, and another
  ring's `(N lines lost)` waits for the end of a line. logd turns on
  the UART's FIFO, which seL4 leaves off on a 16550, and sends 15 bytes when
  it finds the FIFO empty, leaving room for a byte of the kernel's, or one
  byte without a FIFO. It sleeps on `seL4_TCB_SetTimer` while the UART
  sends, 1.4 ms at 115200 baud, and a record only counts as printed once
  its last byte has left the shift register. Root keeps the port's receive
  side and interrupt.
- **Port.** On x86_64, logd uses the `serial_port` setting unless no UART
  answers there: then COM1, where the kernel prints unless told otherwise.
  On aarch64 it is the PL011 of QEMU's virt machine, whose registers root
  maps into logd as well as itself: MMIO needs no system call, and sending
  and receiving use different registers.
- **Secondary partitions** have no logd. Their ring is in the shared region,
  cleared by the shim and described in the partition descriptor. Partition
  0 does not trust that memory, nor any lane: slots are indexed modulo
  their number, lengths are clamped, a corrupt record is skipped and
  counted, and text is made printable, so a line cannot pass for another
  partition's. Root's first lines go to a
  private ring until the shared one is mapped.
- **Framebuffer.** `fb_console` shows host output only if something draws
  it, now that it does not go through the kernel. logd draws it on the lower
  half of the screen, in the layout and glyphs of patch 0020. The kernel
  keeps its own cursor there for what it still prints, so a kernel message
  can overwrite a line.

Root hands logd the UART and spawns it, and holds no logging logic of its
own. Root outranks logd on its core, so during root's
boot logd prints only when root waits or stops; a panic is printed, a loop
that never yields is not:

| Failure | Result |
|---|---|
| Component panics | The text is in the ring; logd prints it |
| Root panics | Its text is in the ring; logd, a task of its own, prints it |
| logd faults | Serial output stops. The host goes on, and `l4hctl logs` still works |
| Partition 0 dies | Secondaries' output stops |
| Before logd starts | Records wait in the ring. logd is the first component root starts, once it has the setting and memory for it; a root panic before that is not printed |
| Hard hang or kernel panic | Undrained records are lost; the kernel's own message still prints |

A host reset sleeps until logd has printed root's ring, for at most 2
seconds, so that what preceded it is on the wire. `tests/run-logdtest.sh`
injects these failures in a host built with `L4H_TEST_INJECT=1`;
`tests/run-mktest.sh` fails on a `[pN] ` that is not at the start of a line.

---

## 11. Boot and deployment

- **UEFI.** UEFI → EFI wrapper → GRUB (EFI) → multiboot2. `tools/mkefi.sh`
  builds l4h as one UEFI application containing a standalone GRUB whose
  memdisk holds the seL4 kernel, `l4h-root` (with the service ELFs), the
  guest kernel and its module tree (§5.6). At boot, GRUB looks for
  `/EFI/L4H/grubenv` on every device.
  Exactly one such file selects the partition containing dom0's initramfs
  and `l4h.conf` through its `l4h_esp_uuid` or `l4h_esp_label`. More than
  one selector file aborts the boot before any selector or slot is read.
  Only when no selector file exists does GRUB use the EFI partition it
  was loaded from or, since `$cmdpath` is empty under OVMF, the first
  partition with `/l4h/dom0/initrd` (or else `/l4h/l4h.conf`) (§10.1).
  From the shared GRUB environment block, only `l4h_esp_uuid` and
  `l4h_esp_label` are imported, and exactly one must name the slot
  containing `/l4h`. Missing or conflicting selector variables, an
  unreadable environment block, or a failed slot search abort this boot
  attempt before any slot's config is sourced. The application returns
  `EFI_LOAD_ERROR` to its caller,
  allowing a front loader to update the selector and try the other slot.
  GRUB 2.12's `exit` ignores arguments and returns success. A small outer
  EFI wrapper (`boot/grub-efi-wrapper.c`) loads the standalone GRUB as a
  child, preserving its device path. L4H boot never returns: any return
  from GRUB is converted to `EFI_LOAD_ERROR`, after GRUB's normal cleanup
  and unloading its image. Firmware measures both the wrapper (including
  the embedded GRUB) and the child image into PCR 4.
  A front-stage GRUB can update this block and chainload the slot's
  application even when `$cmdpath` is empty. Only the selected slot's
  config and initramfs are read; the shared environment block is also
  measured into PCR 9 by GRUB's TPM module. This applies to the slot's
  multikernel configuration and per-partition files too (§11.4).
  It passes
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
  through `seL4_IRQControl_GetMSI`. A device names its own BAR addresses,
  which may lie in RAM, in memory root already holds or over another
  device's BAR: root carves the frames of the BARs it will map of a disk
  controller, NIC or xHCI controller when it finds it (`blkd::carve_bars`)
  and drives it only if that succeeds, logging the rest; of two devices
  claiming one range, the first found takes it.
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
    variant's kernel, its multikernel slot kernels `kernel-VARIANT-sK.elf`,
    the shim and the guest kernel `vmlinux`), for `addr2line` on fault
    addresses;
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
machine with many cores runs several l4h instances side by side: directly,
one seL4 kernel per partition (§11.4), or as Xen HVM guests. l4h needs no VT-x of its own, so an ordinary HVM guest suffices.
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
  gVNIC, ENA, X550 or ConnectX-5 NICs. Each NIC becomes the uplink of its own switch
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

### 11.4 Multikernel partitions

A large x86_64 machine can also run several l4h instances ("partitions")
directly, with no hypervisor beneath them: one seL4 kernel per partition,
each statically given a set of CPUs, a set of RAM ranges and whole PCI
functions, and each partition a full l4h host with its own root, memd,
vmmgr, netd, blkd, trustd, dom0, control API and guests. There is no
machine-wide control point: an operator manages each partition as a
separate host. At most 8 partitions.

**Trust.** Every partition's kernel and host components are trusted, as
one kernel and its components are; nothing defends one partition against
another beyond correct static assignment. Partitioning is for scaling past
the big kernel lock (§11.2 is the Xen alternative) and to keep partitions
from disturbing each other by accident, not a security boundary; guest
isolation inside each partition is unchanged. The boot shim is trusted as
the boot loader and kernel images are: root takes its descriptor's values
(the clock epoch, the ECAM base, channel and ring sizes, the PCI lists) as
given, before any kernel runs, without the checks it applies to firmware
tables, devices and the shared pages another partition writes.

**Boot shim.** `boot/l4h-mkshim` (built with `tools/build-mkshim.sh`) is a
freestanding multiboot1/multiboot2 image that GRUB (or QEMU's `-kernel`)
loads at 272 MiB with these modules, each named by its last word:
`kernel-s0` … `kernel-s7`, `l4h-root`, `l4h-mk.conf`, and `guest-kernel`,
`guest-kmods`, `dom0-initrd`, `l4h-config` for every partition, where
`pN:ROLE` replaces ROLE for partition N. It runs once on the boot CPU:

1. parses the boot information and ACPI (MADT, SRAT, MCFG, FADT), scans
   and sizes every PCI function through ECAM, and checks `l4h-mk.conf`;
2. masks the 8259 PIC and measures the TSC (CPUID leaf 0x15 or the PIT)
   and, without TSC-deadline, the APIC timer, and reads the CMOS clock:
   no kernel touches the PIT or RTC afterwards;
3. per partition, loads its kernel at its slot, copies its modules into a
   low chunk of its RAM, and builds an ACPI copy, a multiboot2 information
   structure and a descriptor;
4. starts each secondary partition's first CPU with INIT-SIPI-SIPI into a
   real-mode page that enters the kernel in multiboot2 state, and enters
   partition 0's kernel on the boot CPU.

Without `l4h-mk.conf` GRUB boots one kernel as before: `tools/mkefi.sh` and
`tools/mkbios.sh` add a stanza (`tools/mkshim-grub.sh`) that boots the
shim when the boot partition has `/l4h/l4h-mk.conf`, taking each
partition's `/l4h/pN/dom0/initrd` and `/l4h/pN/l4h.conf` (or the shared
`/l4h/dom0/initrd` and `/l4h/l4h.conf`). `tools/build-efi.sh` builds the
shim into every shipped UEFI application. The installer's `--partitions
N` (UEFI only) writes a NUMA-aligned `l4h-mk.conf` that gives each other
partition an NVMe controller and a NIC of its own; their dom0s need their
own `pN/` files.

**Configuration.** `/l4h/l4h-mk.conf`, `key = value` lines:

```
partitions = 2               # 1..8
p0.cpus = node:0             # or: 4 (count), 0-15 (CPU numbers), apic:0,2,4
p0.mem  = 60G                # partition 0 takes the rest by default
p1.cpus = node:1
p1.mem  = 64G                # others: an even share by default
p1.pci  = 0000:80:04.0, 0000:80:05.0
link.p0-p1 = 1               # a virtual wire between the two netds
                             # ("uplink": on their switch 0, sharing a NIC)
```

Every PCI function no other partition lists is partition 0's, so
`partitions = 1` behaves like one l4h. The shim refuses, rather than
guesses: a BDF that does not exist or is in two partitions, a bridge, a
partition without a disk controller, functions behind a PCI(-X) bridge
(one requester ID) split between partitions, and a partition 0 without the
boot CPU. Without MCFG (GCE's i440FX machines) it scans through the ports
0xcf8/0xcfc, and the descriptor's ECAM base is 0.

**CPUs.** Each partition's MADT lists only its own LAPIC/x2APIC entries,
its first CPU first, so seL4 starts exactly those. Partition 0 keeps the
I/O APICs, interrupt source overrides and the PCAT_COMPAT flag; the others
have none and use MSI/MSI-X only. Root programs every MSI (and IRTE) for
the partition's first CPU (`partition::msi_dest`): the boot CPU in
partition 0, the one with the lowest APIC ID in the others. MSI addresses
and the IRTEs root writes have 8-bit destinations, so the shim refuses a
partition whose first CPU has an APIC ID above 255.

**Memory.** seL4 x86_64 is linked at a physical address: kernel *k* is
built for slot *k* at 16 MiB + *k* × 32 MiB (`L4H_KERNEL_SLOT`), where root's
image follows it. Each partition's RAM is its slot, a low chunk below 4 GiB
for its modules (seL4 loads root above them and copies them again), and
its share of the rest, carved from its CPUs' NUMA node where it can. Its
multiboot2 memory map lists only its own RAM as available; everyone else's
RAM, and a shared region the shim keeps (8 MiB of IOMMU state, 8 MiB of
per-partition blocks, and the channels), are reserved. RAM above 512 GiB
(seL4's kernel window) stays unused, as with one kernel. The boot loader's module copies become
partition 0's RAM.

**Kernel patches** (all inert unless their option is set):

| Patch | Option | Why |
|-------|--------|-----|
| 0031 | `KernelX86ElfPaddrBase` | one kernel ELF per slot |
| 0032 | `ap_boot_page=` | each partition starts its APs from its own page below 1 MiB (0x1000 × (k + 1)) |
| 0033 | `no_legacy_irq` | boot without I/O APICs and leave the PIC alone |
| 0034 | `tsc_mhz=`, `apic_khz=` | the shim's measurements: the PIT is global |
| 0035 | `console_ring=paddr,size` | a secondary kernel prints to memory, not the serial port |
| 0036 | `peers=`, `IRQControl_SendPeer` | a doorbell interrupt to another kernel's CPU |
| 0037 | — | APs load their GDT's whole base in real mode: a kernel linked above 16 MiB got the wrong GDT |

**Descriptor.** The boot module `l4h-partition` (`host/l4h-partition`)
gives root its index and count, role, first CPU, PCI functions with the
BARs the shim sized (root never sizes a BAR in a partition: sizing stops
decoding), ECAM base, clock rates and boot wall clock, console ring,
channels, its share of the IOMMU and, for partition 0, every partition's
CPUs, RAM and console ring and the owner of every function. Root
(`partition.rs`) then:

- reaches its own functions through ECAM (`pci.rs`), and walks the
  descriptor's list instead of all buses; it may also read, never write,
  the bridges above its functions and the IOMMUs' functions (the
  descriptor's `upstream` list, mapped read-only), which say which IOMMU
  unit's device scope covers a function and which requester ID a function
  behind a PCIe-to-PCI bridge borrows; partition 0, which builds every
  unit's context tables, reads every partition's functions. Without ECAM
  the shared 0xcf8/0xcfc pair carries the same accesses, each address and
  data under a ticket lock in the shared region's control page, and root
  refuses the rest as ECAM would (reads of other functions return all
  ones, writes are dropped);
- in partition 0 only: the RTC, reset, serial monitor, framebuffer
  dashboard, balloon and TPM (a secondary's ACPI copy has no TPM2);
- in partition 0, copies the other kernels' console rings to the serial
  port, each line prefixed `[pN]`;
- in a secondary, refuses `host-reboot` (`EPERM`): resetting the machine
  stops every partition, so only partition 0's dom0 can; and forwards
  `rtc-set` to partition 0.

Generated MACs carry the partition index (`02:4c:34:P:G:N`), and
`l4hctl info` shows the partition (`CTL_PARTITION_INFO`).

**Channels** (`channel.rs`). The shim reserves a control channel of 256 KiB
between partition 0 and each other partition, and a channel of 2 MiB for
each configured link, and lists each in both descriptors: two
single-writer message rings and a doorbell each way (user vector 96 +
sender for control, 88 + sender for a link; the kernel's `peers=` lists
each other partition once). A writer never waits: a header word counts the
bytes ever written, and a reader that falls behind by a whole ring knows it
lost messages; a crashed partition leaves a stale ring, never a blocked
writer. Roots read and write the control channels: heartbeats (secondary
to primary, every second; partition 0 logs a partition silent for 5 s),
the wall clock (primary to secondaries every 10 s and after an RTC
change), forwarded RTC settings, and trustd's requests. Root
handles at most 64 messages of a channel each time it looks and leaves the
rest for the next doorbell or timer tick, writes the RTC for a partition at
most once a second, and logs what a peer causes within a rate limit. Frames
never share
a control channel's rings, so a busy link cannot overwrite them.

**IOMMU** (`iommu/shared.rs`). Every partition's root drives the IOMMU
for its own functions; only the command queue is truly shared. The shim
reserves 8 MiB for the units' shared state: a control page, then per unit
the VT-d invalidation queue, root table and interrupt remapping table (or
AMD's command buffer and event log), then the VT-d context tables or AMD
device table. Partition 0 resets and enables the units, pre-allocates a
context table for every bus that carries a function (from its table of
owners, so no secondary ever allocates a shared table), blocks every
entry, sets ACS in every bridge (§9.5), and then sets a ready flag (on,
absent, or off with `iommu=0`); a secondary joins without writing a register, waits for the flag before
enabling any device, and then programs only its own functions' context
entries or DTEs, with I/O page tables in its own RAM. Domain IDs and VT-d
IRTEs are split statically: partition *k* uses part *k* of *n* of each
unit's. A ticket lock per unit in the control page serializes "write
commands, move the tail, wait for completion" (VT-d wait descriptors, AMD
COMPLETION_WAIT); a waiter past 1 s logs the holding partition and keeps
waiting. Invalidations are device- or domain-selective. Partition 0 alone
reads the fault and event logs and names the owning partition.

**Links** (`link.pA-pB = 1`, `l4h-netd/src/link.rs`). A link is a port of
netd's, on a switch root creates for it, with one more dom0 vNIC, so the
partitions' uplink networks are never bridged. The two netds move the
frames themselves: root maps the link's channel into netd only (by the
CPU; no device reaches it), and netd writes each frame for the link as a
message into its outgoing ring and switches each message from the incoming
ring. Plain Ethernet frames carry complete checksums and have a limit of
9216 bytes. TCP GSO frames carry their offload header in a separate record
type. The receiving netd validates this header and segments the frame when
the destination needs plain
frames. Each direction has a 1 MiB ring; root and netd refuse a link channel
of another size.
A reader that falls behind skips records that the writer can overwrite.
A count that is not a multiple of 8, or padding followed by
padding, is a broken writer's: the reader drops what it published and goes on
from the next aligned count. One read takes at most two records.

Root binds the link's receive vector to netd's notification. Netd
acknowledges the interrupt. Only root holds IRQControl, so the sending netd
signals root to make one `SendPeer` call per pending link. A reader sets the
wake flag only when its ring is empty, then checks the ring once more.
The writer checks and clears the flag during large batches and at the end
of each batch. Netd bounds each guest transmit turn on a linked switch by
bytes and polls for control requests before it processes more slots.
Netd looks at a link's ring 256
times, each look reading at most two records (a frame, or a record it drops),
then gives its other ports a turn.
`link.pA-pB = uplink` instead puts the link port on both partitions'
switch 0, with no switch or vNIC of its own: a partition without a NIC
shares the network of the one whose switch 0 has the uplink NIC (a star of
such links shares one NIC among all partitions). Every frame then crosses
the NIC owner's netd and the channel, without flow control, and the
others lose the network if that partition stops. Networks that deliver
only the instance's own MAC addresses (GCE, EC2) drop the other
partitions' frames: there, route through the owner's dom0 instead.

**Attestation.** Only partition 0 has the TPM. A secondary's trustd signs
with a key of its own (from RDRAND) and asks partition 0's trustd, over
the control channel relayed by the two roots, to quote and extend it into
PCR 15 and to run ActivateCredential; requests carry ids, are resent until
answered, and a dead or TPM-less partition 0 leaves the secondary
unattested rather than stuck (§10.2). Reports and evidence name their
partition.

**Lifecycle.** Partitions boot in parallel and run independently; a
crashed secondary stays down until the machine reboots. There is no
per-partition restart; partition 0's `l4hctl host-reboot` resets the whole
machine. If partition 0 dies, the others keep running without its
services (serial output, clock, attestation, IOMMU fault logging).

**Test.** `tests/run-mktest.sh` boots two partitions on QEMU q35 (KVM),
each with its own virtio disk and NIC: each dom0 gets an address by DHCP,
runs a VM no other dom0 sees, and a secondary's `host-reboot` is refused
and its `rtc-set` reaches partition 0, which then resets the machine.
The partitions' dom0s ping each other over a link, and partition 1's floods
it while its heartbeats and `rtc-set` must still reach partition 0.
`MK_PARTITIONS=8` covers every slot, `MK_BOOT=uefi|bios` boots through
GRUB from a `tools/mkimage.sh` disk, `L4H_QEMU_IOMMU=intel|amd` shares an
IOMMU (VMs in every partition attach and drain I/O pools at once), and
`MK_ATTEST=1` attests a VM in each partition through partition 0's swtpm,
`MK_BRIDGES=1` puts partition 1's devices behind root ports and a
PCIe-to-PCI bridge, and `MK_UPLINK=1` gives partition 1 no NIC but an
`uplink` link to partition 0's.

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
via `tools/build-kernel-aarch64.sh`. E1–E3 and patches 0000 and 0006 are
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
| USB disk through usbd (§9.7), 1 MiB direct, 2 vCPUs | UAS: 470–1280 MB/s read, 430–510 MB/s write; BOT: 115–195 / 115–140 MB/s | QEMU's xHCI (`tests/run-usbstress.sh`, several runs on a host with other load: up to 2× run-to-run). The same devices under a plain Linux VM with `xhci-pci`: UAS 560–985 / 390–440, BOT 400–1070 / 320–410 MB/s. Requests are at most 256 KiB (64 pool segments, swiotlb's largest mapping) against native 512 KiB–1 MiB. |
| USB disk, 4 KiB direct reads | UAS 1250–1740 IOPS, BOT 640–830 IOPS | Native 1590–1910 and 1580–2110. Each URB round trip (guest → usbd → controller → usbd → VMM → guest) costs a few hundred µs more, the cross-core wakeups of the disk path above; BOT takes three per command, UAS overlaps them. |
| USB Ethernet through usbd (QEMU's `usb-net`, CDC Ethernet, on QEMU's user network) | 12.5–12.9 MB/s receive, 5–10 MB/s send; ping 1.2 ms | `tests/run-usbnetbench.sh`: 256 MB each way to a peer on the build host. A plain Linux VM on the same devices: 13.8 MB/s receive, 4–9 MB/s send, ping 0.35 ms. QEMU's emulation of the device sets the throughput for both; the extra 0.8 ms of ping is two URB round trips (§9.7 disks above). |
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

- QEMU with KVM, used only as a fast CPU (VMX and SVM are hidden from the guest);
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
only as a fast CPU to mimic a cloud VM: `-cpu host,-vmx,-svm -smp 4`, with
`virtio-blk-pci`, `nvme` and `virtio-net-pci`, and UEFI via OVMF or plain
multiboot. seL4 uses VT-x or AMD-V only in `tests/run-vtxtest.sh on`,
`tests/run-vcpustress.sh`, `tests/run-kvmtest.sh` and `tests/run-kvmbench.sh`,
which expose VMX or SVM
(the host's: `-cpu host`). A CPU without PCID, such as AMD's desktop Zen 4,
needs `L4H_PCID=OFF tools/build-kernel.sh`. The 30-guest test uses a 16 GiB QEMU
machine and guests of 256–512 MiB.

### 14.3 Test command index

| Test | What it checks |
|------|----------------|
| `python3 tests/test_installer.py` | installer preflight, verified downloads, EFI changes, updates and rollback without touching the host |
| `tests/run-install-vm.sh debian-13-nocloud-amd64.qcow2 [release-directory] [1\|2]` | in a disposable UEFI/KVM VM, install from native Debian with one or two uplinks, verify each switch and network, then return to native Linux; uses prebuilt releases and `sudo -u "$L4H_QEMU_USER"` (defaults to the invoking user); `INSTALL_VM_SWAP_NAMES=1` with two NICs also tests exchanging eth0/eth1 names; `INSTALL_VM_FIRMWARE=bios INSTALL_VM_MEMORY=1G INSTALL_VM_CPUS=1` tests small-VM defaults through BIOS GRUB |
| `tests/run-versiontest.sh` | host version metadata: release tags, development builds, overrides and worktrees |
| `tests/run-flagstest.sh` | focused flags-only boot: console/display seals, kernel taints, userspace gates and instance reuse, on either architecture |
| `tests/run-acstest.sh` | PCIe ACS setup against a model of configuration space: implemented bits only, firmware bits kept, bits that do not stick, hostile capability lists, read-only checks; ECAM window block planning |
| `tests/run-trusttest.sh` | taint/seal permissions, atomic gates, instances, seqlock snapshots and verifier policy |
| `tests/run-alloctest.sh` | host allocator growth under fragmentation, reclaim, fixed-container panic safety and memd grant validation |
| `tests/run-devicetest.sh [--qemu]` | console ordering, bounded sequence gaps, cursor wrap, draining and writer wakeups; endpoint fairness and malformed replies; bounded VMM network batches; VMM CPU accounting, caps and priority protection; checked wiring cannot be replaced; memory-hotplug completion and timed retry scheduling; USB attachment failures and DMA ownership on failed halt/disable; control completions after manager failure; block replies across nested calls; host log wraparound and concurrent writers; with QEMU, hypercalls under continuous console output and VMM priority enforcement |
| `tests/run-vmmfairtest.sh` | x86 real-kernel scheduling: a throttled VMM makes progress against a continuously runnable guest kernel and leaves time for guest users; it cannot restore its MCP or boost, and its parent can restore priority |
| `tests/run-vmmguardtest.sh` | x86 production-manager priority protection against a VMM spinning before READY; a guest on its core boots and gets CPU, self-boosts fail, and restoring priority retains the lower authority |
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
| `tests/run-lvmblk.sh` | LVM linear volumes as extent disks: dm-linear agreement, split requests, overlap and provisioning refusal (needs `lvm2` on the build host) |
| `tests/run-ctltest.sh` | VM lifecycle, console, clean shutdown, disk re-attach, windows, reclaim |
| `tests/run-devicelimit.sh` | 64 devices per guest |
| `tests/run-gputest.sh` | virtio-gpu drawing, screenshots, size checks and reclaim |
| `tests/run-usbstress.sh` (`STRESS_SECS`, `STRESS_CYCLES`, `USBSTRESS_NATIVE=1`) | USB stress and benchmark: all disks busy while one is pulled and put back, guests destroyed under load, data intact; per-disk throughput and IOPS, optionally against a plain Linux VM |
| `tests/run-usbnetbench.sh` (`NETBENCH_MB`, `NETBENCH_RUNS`, `USBSTRESS_NATIVE=1`) | USB Ethernet (QEMU's `usb-net`) given whole to a guest: receive and send throughput and ping against a peer on the build host, optionally against a plain Linux VM |
| `tests/run-usbtest.sh` (`USBTEST_HC=nec`) | whole xHCI controller assignment: left to the firmware until claimed, HID, BOT and UAS disks, a hub, driver reload, destroy during I/O, a second guest (§9.7) |
| `tests/run-nictest.sh` | NIC drivers outside netd: two NICs, NIC 1's driver panics and hangs and is restarted while NIC 0's uplink keeps working, unbind and rebind, a restart of dom0's uplink driver (`L4H_QEMU_IOMMU=intel\|amd`: confined) |
| `tests/fuzz-uplink` (in `run-fuzz.sh`) | the uplink channel: honest peers against a model, a producer that scribbles over descriptors and data, a consumer that writes any tail |
| `tests/run-nettest.sh`, `tests/run-router.sh` | switches, uplink, multi-NIC, isolation, MAC lock, NAT router VM (`NETTEST_LEGACY=1`: legacy virtio-net uplink) |
| `tests/run-density.sh 30 256` | 30 guests on 4 cores stay responsive |
| `tests/run-m6test.sh` | dom0 restart, CPU caps, steal time |
| `tests/run-vtdtest.sh [--qemu]` | VT-d DMAR parsing, table/interrupt formats and address bounds; with QEMU, DMA, lifecycle, NIC and serial tests |
| `python3 tests/vtd-net-qemu.py [--iommu amd]` | bridge aliases with two NICs and disk controllers; `--no-intremap` checks DMA-only confinement, `--controllers 17` checks shared interrupt capacity |
| `python3 tests/amdvi-qemu.py` | AMD-Vi shared tables, DMA bounds and interrupt isolation using QEMU EDU devices |
| `tests/run-schedtest.sh` | host-side SMT topology, initial placement and migration policy tests |
| `tests/run-tls-stalltest.sh` | two-core seL4-only regression for remote-stall TLS preservation (0000): a worker changes FS/GS directly and yields while the other core issues 100,000 SC consumption queries; CI runs debug and release kernels |
| `tests/run-rtctest.sh [--qemu]` | RTC calendar, BCD/binary and 12/24-hour modes, bounds and error recovery; with `--qemu`, dom0 writes verified against the emulated hardware |
| `tests/run-smttest.sh` | QEMU boot with SMT: CPU discovery, initial placement and busy-vCPU migration |
| `tests/run-captest.sh [cap%] [rounds]` | self-test and fork loops in a guest capped from boot |
| `tests/run-capperf.sh [caps]` | fork/exec and CPU-bound timings, uncapped and under each cap (use a release seL4) |
| `tests/run-pvlocktest.sh` | paravirtual spinlocks: contended locks stay exclusive and waiters block, in dom0 and a capped 4-vCPU guest; plain locks with `nopvspin` or one vCPU |
| `tests/run-limits.sh` | the host refuses what it cannot afford and recovers |
| `tests/run-balloontest.sh` | free memory reported to QEMU (virtio-balloon; `BALLOONTEST_LEGACY=1`: a legacy one) is dropped: QEMU's memory use idle, with a guest and after destroying it |
| `tests/run-hotplugtest.sh` | memory hotplug: a VM grows from 256 MiB to 2 GiB and shrinks again under `l4hctl mem`, falling short while its data needs the memory; host memory comes back |
| `tests/run-hotplugstress.sh [rounds]` | memory hotplug under stress: three VMs under memory load resized at random, oversubscribing the host, destroyed mid-resize; data checked, all memory back |
| `tests/run-monitor.sh` | serial monitor (`list`, `restart-dom0`), continued operation with an absent UART |
| `tests/run-uefitest.sh` | UEFI/GRUB boot image with NVMe and virtio-net, as on GCE |
| `tests/run-biostest.sh` | the same image under SeaBIOS with virtio-blk, virtio-net and a VBE framebuffer, as on DigitalOcean |
| `tests/run-mktest.sh` | two (`MK_PARTITIONS`) multikernel partitions on q35: each dom0 boots, gets DHCP and runs a VM; a secondary's host-reboot is refused (§11.4) |
| `tests/run-xentest.sh` | two l4h partitions as Xen HVM guests, nested in KVM, each with a passed-through NIC, ping each other (§11.2) |
| `tests/run-attesttest.sh` | attestation with swtpm over CRB, FIFO and the AMD fTPM ACPI start method: reports on dom0 and a guest, host evidence, AK credential |
| `tests/run-debian.sh`, `tests/run-workload.sh` | Debian + systemd, fio verify, parallel build, fsck (`tests/mkdebian.sh` first) |
| `tests/run-bench.sh`, `tests/run-vmbench.sh`, `tests/run-startbench.sh` | micro-benchmarks, guest cost, start latency |
| `tests/run-fuzz.sh` | hostile-guest virtqueue fuzzing of l4h-vmm; usbd's record checks and TRB layout (`tests/usb.rs`, `tests/fuzz-usbreq`) |
| `tests/run-skimtest.sh` | the skim-xapic-nopcid variant on a Meltdown-affected CPU without PCID/x2APIC: SKIM mappings and syscall state at the user/kernel boundary (`tests/skim-qemu.py`, GDB); VT-x stays off (`run-vtxtest.sh skim`) |
| `tests/run-kvmbench.sh l4h\|linux` | KVM exit, EPT or nested page fault and guest compute timings (`tests/guest/kvmbench.c`) and boot times under QEMU, Firecracker and cloud-hypervisor, with L1 l4h's dom0 or the host's Linux kernel in QEMU, both on nested KVM with two vCPUs (§5.10); `KVMBENCH_CMDLINE` adds to dom0's command line |
| `tests/run-kvmtest.sh [vmm] [vcpus]` | KVM in dom0 (§5.10; needs nested VMX or SVM, `-cpu host`): `tests/guest/kvmtest.c` runs real- and long-mode VMs with port I/O, MMIO, 62 MiB of EPT faults, a run long enough to be preempted, a replaced memslot, dirty logging, vector registers across migrations inside `KVM_RUN`, XCR0 and CPUID after XSETBV and CR4 changes, SMAP set before paging, IDTR and CR4 changed between runs on one core and then two (SVM's clean bits), an RDPMC (always an exit), an exception injected while KVM single-steps to an NMI window, `KVM_EXIT_SET_TPR` when a guest without an in-kernel LAPIC lowers CR8, an IRQ window open across a shutdown's reset, two VMs at once and 20 in a row; `vmm` also boots the host's kernel (`KVMTEST_KERNEL`) with two vCPUs under the host's QEMU and the pinned Firecracker and cloud-hypervisor releases (`KVMTEST_VMMS`). CI runs it in the VT-x/AMD-V step where the runner has nested virtualization |
| `tests/run-vtxtest.sh off\|on\|skim` | VT-x or AMD-V below l4h-root (patches 0038 and 0040, by the host's CPU), with `tests/vtxprobe.c` as the root task on 4 cores: `off` (`-cpu host,-vmx,-svm`) boots without them and refuses VCPU and EPT objects; `on` (`-cpu host`, nested KVM) creates them, binds the VCPU to a TCB and checks that WriteMSR refuses a noncanonical KERNEL_GS_BASE and that FlushTLB succeeds, and on AMD runs a real-mode guest to an I/O exit, a nested page fault, an INVD exit it did not ask for and a HLT and checks that seL4 keeps its intercepts and refuses the VMCB fields it owns, and that CR4 keeps only the allowed bits, a guest's MOV setting CR4.PKE exits and its WRPKRU then raises #UD (patches 0040 and 0042; on Intel it checks the CR4 mask and `GUEST_CR4` instead, and that MOV-DR, CR8-load/store and WBINVD exiting stay on, patches 0039 and 0043); `skim` keeps VT-x off. CI runs `off` always and `on`, with the 1-vCPU self-test, where the runner has nested virtualization, and says in the job summary when it has not |
| `tests/run-vcpustress.sh [rounds]` | SMP stress of the VCPU interface below l4h-root (patches 0039 and 0040; needs nested VMX or SVM, `-cpu host`), with `tests/vcpustress.c` as the root task on 4 cores: two threads keep a long-mode guest in `seL4_VMEnter` while two others signal their notifications, read and write their VCPUs, flush them, take guest pages and the page table out of their EPT, suspend and resume them, change their priority, scheduling context, core, flags, FPU state and deadline timer, rebind and swap their VCPUs, and at the end delete everything under them; the kernel must survive and each `VMEnter` must return what the guest did (its counter never goes back, its registers keep their values, exits come where its code makes them). Three runs: `smp`; `step`, with RFLAGS.TF set in the guests, where every instruction is a #DB exit, so a dropped exit or a discarded `VMEnter` result shows as an instruction the guest passed without one; and `onecore`, every thread on core 0, preempted in guest mode. On the series before these checks, `smp` ended in a kernel fault (MCS `setPriority()`) and `step` lost traps. The AMD-V side was run on QEMU's TCG (with a kernel changed to do without next-RIP saving, which TCG lacks, so the script itself reports a skip there); the VT-x side has not been run yet. CI runs it in the VT-x/AMD-V step where the runner has nested virtualization |
| `tools/lint-shell.sh [-a]` | ShellCheck over every tracked shell script (`*.sh`, and sh/bash shebangs such as the guest init scripts): fails on error-severity findings and on SC2251, a bare `! cmd` that `set -e` ignores; `-a` also prints warnings and notes without failing. CI runs it in the installer job |
| `python3 tests/blkmq-qemu.py` | block multiqueue and fsync suites under local QEMU (`--suite blkmq\|fsync`, `--guest-queues`, `--scsi-queues`); run by hand |
