# l4h: Design and implementation

l4h is a hypervisor built on seL4 that runs Linux VMs without hardware
virtualization. It targets public-cloud instances where VT-x and SVM are
unavailable or nested virtualization is disabled. Guests are paravirtualized:
the guest Linux kernel is ported to run as an ordinary seL4 user-level program,
and guest user processes run natively in their own seL4 address spaces. l4h
never emulates an instruction.

Status: **v0.1 implemented on x86_64**, including SMP Linux guests,
block and network I/O, dom0 control, CPU caps and balancing, and GCE N2
bring-up. AArch64 runs the host and native Linux guests on QEMU `virt`,
including SMP and PCI block/network drivers, with virtualization disabled (§11). The original
review decisions are recorded in §14. Future work is identified below;
§15 records the implemented guest-owned memory design, §16 the
memory owner, `l4h-memd`, and §17 memory hotplug.

---

## 1. Requirements

| # | Requirement | How the design meets it |
|---|-------------|-------------------------|
| R1 | No hardware virtualization. Paravirtualize, as Xen PV does. Avoid instruction emulation. | The guest kernel is a new Linux architecture, `ARCH=l4h`, that runs in ring 3 as an seL4 thread and calls seL4 directly. Guest user code runs unmodified. Its `syscall` instructions and exceptions reach the guest kernel as seL4 fault IPC. |
| R2 | x86_64 first, but friendly to aarch64. | Each layer is split into ISA-independent and ISA-specific parts (§11). seL4, rust-sel4 and sDDF already support aarch64. Nothing in the design relies on an x86-only mechanism such as segmentation, rings 1/2 or Xen-style page-table validation. |
| R3 | virtio-blk and virtio-net. Block devices are passed through. Network is multiplexed by virtual switches. | The guest runs stock Linux `virtio_blk`/`virtio_net` drivers over a new paravirtual transport, `virtio-l4h`, with no trapped MMIO (§8). All device buffers use a host-owned I/O pool; the guest copies block data between its RAM and the pool, and the device DMAs into the pool (§15.1). For networking, the hypervisor provides **only L2 virtual switches**. A VM can have several vNICs, each on a switch, and a physical NIC is just an uplink port on a switch. Routing and NAT, when wanted, are done by a VM. |
| R6 | A runtime management API, available to "dom0", the first guest started at boot. | `l4h-vmmgr` exposes a control API through a `l4hctl` paravirtual device that only dom0 receives (§9.1). dom0 has no device-driver duties. |
| R7 | Targets: QEMU with virtio devices first, then GCP. | QEMU uses virtio-net-pci, virtio-blk-pci, virtio-scsi-pci and nvme. GCE N2 is tested with virtio-net and C3 with gVNIC, both with NVMe local SSDs (§10). |
| R4 | SMP guests. | Each guest vCPU is an seL4 kernel-context thread with its own scheduling context. IPIs are seL4 notifications (§6). |
| R5 | Many guests per host, e.g. 30 guests on 4 CPUs. | seL4 MCS scheduling contexts give each vCPU a budget. Idle guests consume no CPU because the guest kernel is tickless and idle means blocked in `seL4_Recv`. A host balancer moves vCPUs between cores (§7). Each guest makes its kernel objects from its own RAM (§15). |

Non-goals for v1: running unmodified guest *kernels*, live migration, memory
overcommit or ballooning, 32-bit guest userspace, PCI passthrough into guests,
Windows guests, and any L3 networking (routing, NAT, IP filtering) inside the
hypervisor.

---

## 2. Prior art and why this shape

| Approach | Verdict |
|----------|---------|
| **Xen PV ABI on seL4.** Reuse upstream `CONFIG_XEN_PV`. | Rejected. Xen PV gives the guest control of real hardware page tables, which the hypervisor validates through `mmu_update`. It also uses a hypervisor-assisted syscall bounce, `iret` hypercalls, event channels, grant tables and xenstore. Implementing this would mean writing Xen inside the seL4 kernel. Xen PV exists only on x86, which fails R2, and upstream treats it as legacy. |
| **lguest-style `pv_ops` subarch of x86.** | Rejected. It is x86-only and needs the guest kernel in a privileged ring. lguest was removed from Linux in 4.14. |
| **UML (User-Mode Linux) on seL4.** | Rejected as a base, but used as a source of ideas. UML is in-tree and gained initial SMP in 6.18. However, its host layer (`arch/um/os-Linux`) assumes a POSIX host with libc, signals and mmap of a physmem file, and it is effectively x86-only. Its separate-address-space kernel model is the same as ours, so we reuse its approaches to `uaccess` and `pt_regs`. |
| **L4Linux** (TU Dresden / Kernkonzept, Linux on Fiasco.OC). | **The closest model.** L4Linux is a maintained out-of-tree `arch/l4` with x86-64 and arm64 subarches. The guest kernel is a user-level task, and each guest process is a microkernel task whose syscalls and faults arrive as IPC. It relies on Fiasco's *vCPU mode*, which seL4 lacks. §5 shows how seL4 threads, priorities and the kernel extensions replace it. |
| **Wombat / OK Linux** (NICTA, L4/seL4 era). | A historical precedent for Linux para-virtualized on L4-family kernels. |
| **gVisor systrap.** | Different goal: it reimplements Linux rather than running it. It confirms that trapping syscalls from unmodified binaries without VT-x is practical in production. |
| **seL4 Microkit / LionsOS / sDDF / libvmm.** | **Use sDDF as a design reference.** l4h's Rust drivers and shared queues support dynamic guest attachment; they do not link sDDF's C drivers. The libvmm hardware-virtualization VMM and Microkit's static system model do not fit dynamic cloud guests, so we do not adopt them. |

The result: **a new Linux architecture (`arch/l4h`), modelled on L4Linux and
UML, running on an MCS SMP seL4 kernel with three kernel extensions. Host
components and device drivers are written in Rust on rust-sel4.**

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
 │  │ virtio_blk / virtio_net over virtio-l4h                                  │
 │  └───────┬──────────────────────┘                                          │
 │          │ shared vrings + notifications                                   │
 │  ┌───────▼──────────┐                                                       │
 │  │ l4h-vmm (A)      │ one per guest, maps its I/O pool, never guest RAM     │
 │  │ virtio backends  │                                                       │
 │  └──┬────────────┬──┘                                                       │
 │     │ blk queue  │ net port rings                                           │
 │  ┌──▼───────┐  ┌─▼─────────────┐                                            │
 │  │ l4h-blkd │  │ l4h-netd      │  switches and uplink NIC drivers           │
 │  └──┬───────┘  └──────┬────────┘                                            │
 │  ┌──▼───────────┐  ┌──▼───────────────┐                                     │
 │  │ NVMe /       │  │ virtio-net /    │                                     │
 │  │ virtio-blk   │  │ gVNIC uplinks   │                                     │
 │  └──────────────┘  └──────────────────┘                                     │
 └─────────────────────────────────────────────────────────────────────────────┘
   seL4 microkernel (MCS, SMP, x86_64), plus l4h extensions E1–E3 (§4)
   Cloud VM hardware (QEMU/KVM, GCE …) with no VT-x exposed
```

`l4h-root` (not drawn) spawns the host services and keeps the hardware:
PCI, the IOMMU, interrupts, and the memory devices reach, each guest's I/O
pool, disk channels and netd ports, which it makes when `l4h-vmmgr` asks
(§9.3). Nothing a guest, its VMM or dom0 sends reaches root.

Each `l4h-blkd` drives one attached disk. `l4h-netd` combines all switches
and uplink NIC drivers in one component. The drivers are Rust: virtio-net,
gVNIC after Linux `gve`, ENA after Linux `ena` and the X550 after Linux
`ixgbe`.

Trust: the seL4 kernel, `l4h-root`, `l4h-vmmgr`, `l4h-memd`, `l4h-blkd`,
`l4h-netd` and `l4h-trustd` form the host TCB, which a TPM can attest (§9.2). dom0 is trusted for control-plane decisions (§9.1) but cannot
read other guests' memory. Each `l4h-vmm` is trusted only by its own
guest: it maps that guest's I/O pool and host-owned device, event and
queue pages, and never its RAM (§15), so a compromised VMM can harm only
that guest. Guest kernels are untrusted. Capabilities
confine them, and the hypervisor never validates guest page tables.

---

## 4. seL4 kernel configuration and extensions

Configuration:

- `KernelIsMCS=ON`: scheduling contexts with budget and period are required for
  multi-tenant fairness (§7).
- `KernelMaxNumNodes`: up to 64 cores.
- `KernelFastpath=OFF`.
- `KernelFSGSBase=inst`.
- `KernelXSave=XSAVEOPT`, with `KernelXSaveFeatureSet=7` covering x87,
  SSE and AVX. The guest hides AVX-512, AMX and PKU, which seL4 does not
  enable.
- `KernelSkimWindow=OFF` for the default variants, which require a CPU
  unaffected by Meltdown. The `skim-xapic-nopcid` variant sets it `ON`,
  uses xAPIC and disables PCID. SKIM removes the full kernel/RAM window
  from user page tables, protecting against Meltdown on affected CPUs.
  Patch 0027 preserves the user RSP across SKIM's page-table switches,
  so Linux syscall trapping works with either configuration.
  Builds without SKIM refuse to boot when `IA32_ARCH_CAPABILITIES.RDCL_NO`
  is clear, or on Intel CPUs that do not enumerate that MSR (patch 0024).
  The installer chooses SKIM for affected/unknown CPUs, preserves the
  installed variant on updates, and requires native Linux to validate a
  switch away from SKIM. The PCID variant requires INVPCID as well as PCID.

Release builds turn the debug syscalls off but keep kernel printing on, for
the host components' serial log: `seL4_DebugPutChar` and
`seL4_DebugDumpScheduler` stay available to threads with an MCP of at least
`KernelDebugSyscallMinMCP` (below).

**Revised (security audit, v1).** Development builds keep
`KernelDebugBuild` on, and debug syscalls need no capability: one of them,
`seL4_DebugHalt`, stops the machine. Patch 0008 therefore reserves debug
syscalls to threads with an MCP of at least `KernelDebugSyscallMinMCP`
(101 for l4h). Guest threads are confined to MCP 100, so in a guest they
are unknown syscalls in every build. The same threshold silences the
kernel's messages about failed invocations (`userError`) and about threads
that fault without a fault handler: every kernel print is a synchronous
serial write with the kernel lock held, so a guest could otherwise stall
every core by failing invocations in a loop. With
`KernelInvocationReportErrorIPC` (off in l4h), error replies to such
threads carry an empty message rather than the shared buffer, which would
hold an earlier invocation's message. `L4H_RELEASE=1 tools/build-kernel.sh`
turns the debug build off. `KernelMaxNumNodes` is 64. XSAVE covers x87,
SSE and AVX; the guest hides AVX-512, AMX and PKU, which seL4 does not
enable, from its CPU feature set.

The kernel is pinned to the seL4 16.0.0 release (`6e7c3b7`, the `16.0.0`
tag). We carry a **small, upstreamable patch set**:

### E1. `seL4_TCBFlag_trapSyscalls` (required)

On x86_64, seL4 takes the syscall number in **`rdx`**, and Linux uses `rdx`
for argument 3. On aarch64, seL4 uses `x7` and Linux uses `x8`. If a guest
process issues a Linux syscall whose 3rd argument happens to equal a valid
seL4 syscall number, seL4 would execute an seL4 syscall instead of raising a
fault.

E1 adds a new bit for the existing `seL4_TCB_SetFlags` (which today only has
`fpuDisabled`). When the bit is set, *every* syscall instruction from that
thread raises `seL4_Fault_UnknownSyscall`, which already carries FaultIP,
SP, FLAGS and the argument registers (all GPRs on x86_64; X0–X7 on aarch64,
plus X8 with patch 0007). The check goes in `c_handle_syscall` and the fastpath
entry on each arch, before the `SYSCALL_MIN..MAX` range test. The patch is
roughly 30 lines per arch, and the semantics do not depend on the ISA.
On x86, seL4 also opens its spare IDT vectors (above the IRQs) to user
level and reports `int $N` on them as an unknown syscall, which a trapping
thread's handler could not tell from `syscall`: Linux would run the call
in `eax`. For a trapping thread they raise the user exception #GP instead,
with the vector in the error code, as closed gates do natively, and the
guest delivers SIGSEGV.

### E2. TCB FPU state access (required)

Linux needs the FPU and XSAVE state of a user thread for signal frames,
`sigreturn`, `ptrace`, core dumps and `fork`; a child must inherit its
parent's MXCSR/x87 control. seL4 keeps this state in the TCB and has no
invocation that reads or writes it.

E2 adds `seL4_TCB_ReadFPU(tcb, frame_cap, offset)` and
`seL4_TCB_WriteFPU(tcb, frame_cap, offset)`. They copy the arch FPU save area
(`XSAVE` format on x86, `V0–V31+FPSR/FPCR` on arm64) to or from a frame the
caller owns. The kernel validates the frame, offset and alignment, and on
write sanitises the XSAVE header, and masks MXCSR with the CPU's
MXCSR_MASK (read with `fxsave` at boot), so that loading the image cannot
fault in the kernel. A caller that targets itself gets its FPU reloaded,
since it returns to user level without passing through the scheduler; a
target running on another core is stalled off it first, as for every TCB
invocation.

Fallback if upstream objects: user-mode trampolines in the guest vDSO run
`xsave`/`xrstor` on the thread's behalf. This needs no kernel change, but it
complicates `sigreturn` and `ptrace`.

### E3. Kernel deadline timers (required; this is the primary timer)

GCE guests are not guaranteed to have an HPET, and the PIT is too coarse to
multiplex. The MCS kernel already programs the per-core LAPIC TSC-deadline
timer, or LAPIC countdown where TSC-deadline is unavailable (the generic
timer on arm64), for budget enforcement, so the cheapest,
most portable option is to let user level share it.

E3 adds a deadline timer to each TCB:

- `seL4_TCB_SetTimer(tcb, deadline, badge)` arms or re-arms it; a zero
  deadline disarms it. The absolute deadline uses the kernel timer's ticks
  (TSC on x86, generic timer counter on aarch64).
- At the deadline the kernel signals the badge on the TCB's bound
  notification, if any, and disarms the timer. It never signals before
  the deadline, and the hardware is programmed for the deadline itself,
  not one timer precision (1 µs on x86) earlier as the MCS scheduler does
  for budget and release events, whose checks are exact. (Signalling up
  to that precision early let a guest wake, see its clock still short of
  the deadline, and wait again with no timer armed.) In APIC countdown mode the count rounds up for
  the same reason.
- TCBs with armed timers sit in a per-core red-black tree ordered by
  deadline, whose first node is cached. The kernel programs the hardware
  with the minimum of the next budget event and that first node.
- Arming and disarming take O(log n) time, and at most 32 timers fire per
  kernel entry (the rest fire on the next, immediate, timer interrupt).
  Guests arm timers on TCBs they retype from their own memory, so n is
  theirs to choose: a sorted list let one guest hold the kernel lock for
  milliseconds per call.
- A timer fires on the core it was last armed on. Migrated vCPUs re-arm on
  their new core.
- Timers fire from the scheduler, so the thread a timer wakes may have
  blocked in the same kernel entry and still hold the current scheduling
  context. `sendSignal()` already skips the refill check then; its
  debug assertion that this cannot happen is removed.
- The kernel time of firing timers is charged to whatever runs on the core
  then, as for any interrupt. A guest that arms many timers for one
  deadline (each from its own memory, each a syscall it pays for) can
  make a co-located vCPU absorb about N/32 back-to-back entries. Kept, as
  each entry stays bounded; root could cap guests' TCB counts if this
  matters.

The guest clockevent invokes `seL4_TCB_SetTimer` on its vCPU's kTCB, so
there is **no user-level timer server** and no IPC hop. No separate Timer
object is allocated or retyped.

### Not required

Unlike Fiasco vCPU mode, we need no new interrupt-injection primitive (§5.4).
We need no IOMMU support in the kernel, since no device is passed into a
guest. Where there is an AMD-Vi or Intel VT-d IOMMU, root drives it itself (§8.5).

### Found during implementation

- **Patch 0006 (performance): no timer reprogram for a later deadline.**
  - `setNextInterrupt()` wrote IA32_TSC_DEADLINE on every
    scheduling-context change. Each write is a VM exit when seL4 runs
    virtualised.
  - The kernel now keeps a still-pending earlier deadline. The interrupt
    then fires early, causing at most one spurious timer interrupt and a
    reprogram.
  - Most switches only move the deadline later, so most writes
    disappear: trapped syscalls got 16× faster under nested KVM.
- **0008, debug syscalls need a minimum MCP** (see above).
- **0009, `seL4_X86_ExecuteNever`.** seL4 on x86 had no way to map a
  readable user page without execute permission. The new VM attribute sets
  XD on 4 KiB, 2 MiB and 1 GiB mappings, and boot code enables EFER.NXE when
  the CPU has it. The guest maps pages without `PROT_EXEC` with it, so
  `mmap`/`mprotect` execute permissions are enforced. As on x86 and arm64,
  the heap (`brk`), `.bss` and the stack are executable only with
  `READ_IMPLIES_EXEC` or an executable `PT_GNU_STACK`; arch/um's default,
  inherited at first, made every heap writable and executable. On a CPU
  without NX, or whose firmware hides it (`IA32_MISC_ENABLE.XD_DISABLE`,
  which seL4 leaves alone), the attribute is dropped silently and every
  readable page is executable.
- **0010, SMP remote calls.** `handleIPI()` read a remote call's operation
  and arguments before checking that the call was pending for this core.
  A late hardware IPI for a call already handled from the lock's wait loop
  could then run the previous call's operation in the next round. With
  Linux guests unmapping memory on 4 cores this skipped TLB invalidations
  (user memory corruption) or replayed an invalidation on a reused VSpace
  root (triple fault). The flag is now checked first. This is an upstream
  bug.
- **0012, stale timer interrupts (x86, MCS).** The local APIC latches a
  timer interrupt that fires while the kernel runs with interrupts off,
  for example while a core waits for the kernel lock. It is delivered on
  the way back to user level, after the kernel has armed the next
  deadline, and seL4 handled it as a new timer event, which means another
  wait for the lock.
  - When vCPUs of the machine running seL4 are descheduled, or a core
    holds the lock for long, a lock wait can outlast the 5 ms timeslice
    that the previous entry armed. The next timer interrupt is then
    latched during the wait, and so on.
  - Every core then loops through the lock on stale interrupts and user
    threads never run again, even after the host load has gone. In CI
    (4 vCPUs on a 4-vCPU runner) this stopped the whole machine during
    the 4-vCPU self-test. Locally 4 vCPUs on 2 host CPUs hit it on every
    run.
  - A timer interrupt that finds the timer still armed (the TSC-deadline
    MSR is cleared when it fires) is now acknowledged and dropped before
    the lock is taken. `ksArmedDeadline` from 0006 is checked first, so
    interrupts that are due skip the MSR read. This is an upstream bug.
    On aarch64 the timer interrupt is level-triggered, so setting a new
    deadline withdraws it.
  - seL4 still needs its vCPUs to run together: the kernel lock is a FIFO
    (CLH) lock, and remote calls wait for every target core. With 4 vCPUs
    on 2 host CPUs and no pause-loop exiting (nested virtualisation),
    guests make progress but very slowly.
- **0013, MCS reconfiguration of a remote thread.**
  `SchedControl_ConfigureFlags` on an SC whose runnable thread is on
  another core postponed the thread to the release queue when its new
  refill was not ready, then enqueued it in that core's ready queue too:
  a failed assertion in debug kernels, corrupt queues otherwise. l4h-root
  does this whenever it changes the budget of a capped vCPU that used it
  up. Only a schedulable thread is enqueued now; for a postponed one the
  remote core is still told to reprogram its timer. This is an upstream
  bug.
- **0014, x86 timer calibration (MCS).** Every core measured the TSC and
  APIC timer rates again at boot and overwrote the shared values, each
  from a single PIT wraparound. A virtualised PIT can end that wait
  early: on GCE about one boot in three had a core measure the TSC at
  1 MHz or the APIC timer at ~490 kHz.
  - A bad last core gave every core a wrong clock. A ratio of 0, which
    means TSC deadline mode, stopped the timer on N2, which has no TSC
    deadline mode: the whole machine stalled.
  - A bad boot core left the root task with an initial budget below the
    minimum, failing `refill_sufficient` in `switchToThread`.
  - The rates are now measured once, on the boot core, as the median of
    5 wraparounds each. This is an upstream bug.
  - Countdown mode converted TSC ticks to APIC ticks by their truncated
    integer ratio, so timers fired up to twice as late (a 2.99 GHz TSC
    with a 1 GHz APIC timer gave a ratio of 2). The conversion now uses
    both rates, and a delay too long for the 32-bit count fires early and
    is programmed again instead of wrapping.


- **0004, x86_64 user RSP across syscalls.** seL4's fast `syscall` entry
  never saved the user RSP, and the `sysretq` path cleared it. Only the
  libsel4 convention of keeping RSP in RBX made this work. Trapped Linux
  threads returned with RSP = 0. The patch saves RSP on entry, through a
  per-node scratch slot, and restores it on `sysretq`, on both the slow
  path and the fastpath. Patch 0027 extends this to SKIM: save RSP before
  loading the kernel CR3, and carry the return RSP through the existing
  per-CPU SKIM scratch word (a global word for UP). The scratch word is
  cleared after each read, including interrupt return's RCX. No user-stack
  memory is accessed and no TCB or full kernel mapping is added to SKIM.
  `trapSyscalls` is now supported in both configurations.
- **0005, SMP IPI barrier.** `ipi_wait()` reset its arrival counter and
  released waiters with two unordered plain stores, and GCC emits them in
  the wrong order. A following remote call (TLB shootdown, remote TCB stall)
  could then lose arrivals, leaving every core spinning in `ipi_wait()`.
  This is an upstream bug that SMP l4h guests hit within seconds.
- **0017 (performance), batched TLB flushes for x86_64 frame remaps.**
  Every 4 KiB `seL4_X86_Page_Map` invalidated the address space on each
  core in its TLB bitmap, an IPI round trip per core. A fork write-protects
  every private page, so a 16 MiB fork with three busy threads took 140 ms.
  - Maps into a not-present entry invalidate nothing. Remaps that only
    raise rights invalidate the address on the current core only.
  - A remap with `seL4_X86_DeferFlush` that only lowers rights (same
    frame, same memory type) leaves the TLBs alone.
    `seL4_X64_PML4_Flush` then flushes the ASID once. The guest uses this
    for the downgrades of one TLB sync (§5). Any other change still
    invalidates at once.
  - Stale entries only grant rights the same frame cap had at the same
    address. Unmapping, the only way to reuse the frame, still invalidates
    at once.
  - After a raise, another core can keep the lower rights cached and take
    a spurious fault. A user thread resumes once Linux finds its PTE
    already allows the access, but any fault of a guest kernel thread
    stops the guest, so the guest must never raise rights in place in its
    kernel VSpace. It does not today: `PAGE_KERNEL` is dirty (no write
    emulation), arch/l4h has no `set_memory_*`, and `os_protect_memory`
    does nothing.
  - The 16 MiB fork now takes 6 ms, and the copy-on-write fault after it
    7.7 µs/page instead of 47.
- **0019, Clear ordinary free RAM once at boot without backing zero pages.**
  Before any user code runs, the kernel scans the free RAM it will hand
  out as Untypeds and clears each page only if a word is non-zero. On Arm
  all secondary CPUs switch to the kernel's translation tables before
  the scan can clear the loader's tables in free RAM. Untypeds and
  bootinfo are then finalized under the kernel lock, before the initial
  thread runs. The scan first cleans and invalidates the cache range to
  account for cache state inherited from boot. These initial caps have a
  zero free index, so their first use does not clear the memory again. Reading
  unbacked memory maps the hypervisor's shared zero page, preserving the
  saving until that memory is written.
  Device regions are never scanned or cleared. Recycled kernel boot
  memory still contains executing code and live data, so it retains the
  usual full free index and is cleared on its first retype.
  The conditional scan is boot code only; runtime Untyped reset is
  unchanged from seL4 and clears unconditionally. Revoke/retype cannot
  re-enable the scan, including through copied or split Untypeds. This
  avoids making runtime clearing depend on reads through the cacheable
  kernel window after a guest has used other memory types. The scan adds
  work proportional to all free RAM during boot, and reuse of previously
  allocated memory backs it again even if it was reported free (§15.4).
- **0020, framebuffer console (x86).** With the command-line option
  `fb_console`, everything the kernel prints (its own messages and host
  components' debug output) is also drawn on the lower half of the
  multiboot2 framebuffer, if it is direct RGB at 32 bpp and below 4 GiB:
  8x8 glyphs
  doubled vertically, wrapping instead of scrolling so the framebuffer is
  never read. For machines whose serial port is out of reach but whose
  screen is not, such as Latitude.sh servers behind their BMC's web proxy
  (§10.1); the `fb_console` setting adds it (§10). The framebuffer is
  checked once the whole memory map has been read, and refused if it
  overlaps usable RAM or starts below 1 MiB, which the memory map leaves
  out and where the APs' boot code goes.
- **0021, extra boot modules (x86).** seL4 loads the first multiboot
  module as the root task and ignores the rest, and their memory is not
  safe: the root task's image is moved over wherever the loader put them,
  and what survives becomes ordinary Untypeds, cleared on retype. The
  kernel now copies each later module (up to 8; it ignores more, and
  ones that end before they start, with a warning) to page-aligned memory above the root task's loaded image and
  below 4 GiB, or stops if there is not enough, leaves that memory out of
  the RAM it
  manages, so it reaches the root task as device Untypeds that retype
  into frames without clearing, and lists the modules with their loader
  strings in a bootinfo chunk (`SEL4_BOOTINFO_HEADER_X86_BOOT_MODULES`).
  This is how dom0 is loaded from disk (§10).
- **0022, TSC frequency from CPUID (x86).** seL4 read the TSC rate from
  the platform info MSR on a fixed list of models ending at Skylake and
  measured it against the PIT everywhere else. Alder Lake and later
  platforms may gate the 8254 clock (on an Alder Lake-P mini PC it
  advances a few ticks in 10 ms, busy or idle), and the PIT wait then
  never ends, before the kernel prints anything. Intel CPUs that
  enumerate the rate in CPUID leaf 0x15 (or the base frequency in 0x16,
  where 0x15 leaves the crystal out) now take it from there, rounded to
  the nearest MHz. With TSC-deadline mode, which all of them have, the
  PIT is then not used at all. QEMU/KVM and Hyper-V report leaf 0x15 as
  zero, so VMs keep measuring with the PIT. A rate rounded up would make
  APIC countdowns (0014, used only without TSC-deadline mode) end up to
  about 250 ppm early: one extra timer interrupt that finds nothing due,
  or a timeslice a few µs short, never a timer signalled early.
- **0023, accessed bits of native frames (x86_64 and aarch64).**
  `seL4_X86_Page_TestAndClearAccessed` / `seL4_ARM_Page_TestAndClearAccessed`
  resolves a frame cap's mapped ASID and address, verifies the physical
  frame, atomically clears its A/AF bit, and returns the old bit. 0023
  itself takes 4 KiB frames; 0029 adds 2 MiB. Unmapped caps, non-native
  mappings and 1 GiB frames are refused; stale mappings
  return `InvalidCapability`. The atomic operation preserves concurrent
  hardware updates to other bits, including x86's dirty bit.

  Clearing does not invalidate TLBs: a cached A=1/AF=1 translation can delay
  the next sample, as with native x86 Linux aging. On x86 a remap also
  writes A=0, and after one that 0017 leaves to the TLBs, other cores'
  cached translations keep the frame's use from showing until they are
  evicted. On AArch64 without hardware AF updates, a later walk faults
  with AF=0. seL4 handles this access-flag fault for an EL0 mapping
  by setting AF and restarting the instruction, without fault IPC to
  Linux. AF=0 translations cannot be cached, so setting AF needs no
  invalidation. Permission and other
  faults still go to the VSpace owner. The loader leaves `TCR_EL1.HA` off;
  enabling hardware AF updates on FEAT_HAFDBS CPUs is a future optimization.
- **0024, no boot without RDCL_NO (x86).** seL4 refused to boot without
  the SKIM window when `IA32_ARCH_CAPABILITIES` reports the CPU vulnerable
  to Meltdown, but only warned when an Intel CPU does not enumerate the
  MSR. Intel CPUs that are not vulnerable report RDCL_NO, which needs the
  MSR, so such a CPU is treated as vulnerable. Builds without SKIM
  now refuse to boot there as well; the
  SKIM variant supports those CPUs through patch 0027.
- **0025, remapped I/O APIC handlers (x86).** `GetIOAPICRemapped` adds a
  16-bit interrupt-remapping table index to the ordinary I/O APIC handler
  arguments. Root publishes the matching VT-d IRTE before invoking it.
  seL4 writes the remappable RTE format and retains its normal pin masking,
  acknowledgement and capability lifecycle; it does not manage the IOMMU.
  The vector and trigger mode must agree with the IRTE for EOI broadcasts.
- **0026, save AArch64 TLS before the kernel lock.** The entry assembly
  saves `TPIDR_EL0` and `TPIDRRO_EL0` with the general registers. A remote
  stall handled while waiting for the lock can switch to idle and return
  without reaching the C entry hook. Saving TLS only in that hook loses
  direct user writes to the thread pointer, potentially restoring zero
  just after exec. The boot regression checks a user-written thread
  pointer in the saved context at the first C syscall entry, before the
  lock can handle a stall.
- **0029, large-frame aliases and accessed bits (x86_64 and aarch64).**
  `Page_DeriveSubframe` derives unmapped 4 KiB capabilities from a
  RAM-backed 2 MiB frame, with a checked aligned offset and intersected
  rights. One call derives up to all 512, consecutive from the offset, into
  a window of consecutive CNode slots that it checks as `Untyped_Retype`
  checks its destination, all before deriving any. The guest makes a RAM
  block's aliases with one call, as it made its frames with one retype.
  It allocates no physical object and never clears live memory.
  The subframe is a smaller region in the capability derivation tree;
  the original Untyped remains an ancestor of both sizes. Deleting the
  large cap leaves its aliases valid; revoking the backing Untyped removes
  all aliases and mappings before the allocation can be reused. Ordinary
  copies and subframe aliases keep seL4's non-revocable-copy semantics:
  deriving an alias does not grant authority to revoke sibling aliases.
  Device frames and other source sizes are refused.

  The patch also extends 0023 to x86 PDE leaves and AArch64 level-2 blocks,
  checking the mapped size and physical address before clearing A/AF. On
  ARM, level-2 access-flag faults are repaired inside seL4, just like the
  existing level-3 faults; permissions are preserved. `run-abitest.sh`
  checks bounds, destination validation, full and failed windows, rights
  attenuation, simultaneous aliases, large-page execution and aging, stale
  caps, parent deletion, revocation and zeroing on subsequent reuse.
- E1 (`trapSyscalls`) is our fix for seL4 issue #477, which is still open
  upstream. Without it, Linux syscalls whose syscall-number register
  happens to hold a valid seL4 syscall number are executed as seL4
  syscalls. Several of those (NBSend\*, Yield, SetTLSBase, the debug calls)
  do not fault without capabilities. `tests/guest/abitest` sweeps all
  seL4 syscall numbers.

**Decision:** l4h carries E1–E3 and the fixes above as patches in
`kernel/patches/`, and proposes them upstream through the seL4 RFC process. They are designed as independent
commits. They have no sel4test cases yet: l4h's integration tests
(`tests/`, e.g. `tests/guest/abitest`) exercise them through the guest.

**Verification note:** the MCS SMP x86_64 configuration is not covered by the
seL4 proofs today, with or without E1–E3. l4h still benefits from seL4's
design and its capability isolation, but it does not claim a verified
configuration on x86. aarch64 is the better long-term path to proof coverage.

---

## 5. The guest kernel: `ARCH=l4h`

**Implementation note.** `arch/l4h` is derived from `arch/um` (UML) and
`arch/x86/um`. UML already provides most of what is needed:
- the separate-address-space kernel;
- x86 signal frames, ptrace and the syscall table;
- software page tables with hardware accessed and software dirty tracking, and a batched
  "TLB sync" to the host.

The UML host layer (`os-Linux`) is replaced by `os-sel4`, which is built
against libsel4. The Kconfig keeps `CONFIG_UML` defined, so generic code
treats l4h like UML (no hardware AVX paths, and so on). The tree is
self-contained.

**Kernel-mode SIMD.** Each vCPU's kTCB has its own seL4 FPU
context, separate from every uTCB's, so kernel SIMD never sees or clobbers
user state and `kernel_fpu_begin()` saves nothing. Its registers are shared
only by the guest-kernel contexts on that vCPU: tasks switched with
`setjmp`/`longjmp` (which keep no vector state) and the softirqs and
interrupt handlers that the guest runs when it polls for events. So, as on
x86, `kernel_fpu_begin()` disables bottom halves and preemption, sets a
per-CPU busy flag that makes `irq_fpu_usable()` false, and loads the
default MXCSR (`arch/l4h/x86/fpu.c`). CPU features come from CPUID masked
by the XCR0 that seL4 sets (§4), and `cpu_has_xfeatures()` checks that XCR0.
As on x86, Skylake-X, Ice Lake and Tiger Lake get `X86_FEATURE_PREFER_YMM`,
so the AES code prefers 256-bit vectors, which do not lower their clock.
With this, `arch/x86/crypto` (AES-NI, VAES/AVX2 XTS for dm-crypt) is built
for l4h (patch 0004 opens its Kconfig menu). AArch64 does the same in
`kernel_neon_begin()` (`arch/l4h/arm64/neon.c`), and `may_use_simd()` asks
it too; the rest of the kernel is
built with `-mgeneral-regs-only` and never touches V0–V31 or FPCR.
`arch/arm64/crypto` (ARMv8 Crypto Extensions AES for dm-crypt, bit-sliced
NEON without them) is built with a small `asm/assembler.h` of the macros it
uses. EL0 cannot read the ID registers, so kernel patch 0018 passes the
boot CPU's ID_AA64ISAR0/1/2 and PFR0/1 to root as a bootinfo chunk, root
copies them into each guest's `l4h_bootinfo.cpu_id`, and the guest derives
AT_HWCAP from them; the AES drivers bind through
`module_cpu_feature_match()` on those HWCAPs. Patches outside `arch/l4h` handle kbuild's UML-style UAPI
headers, restricted DMA pools without a device tree (§15.1), the HRTICK
default, the x86 SIMD crypto menu and event polling in `cond_resched`
(§5.4).

### 5.1 Layout in the Linux tree

```
arch/l4h/
  kernel/   boot, setup, irq, time, smp, process (switch_to), signal glue, ptrace glue
  kernel/skas/   software page tables, uaccess and process/syscall glue
  os-sel4/  freestanding boot, event and user-thread operations against libsel4
  drivers/  virtio_l4h transport, hvc console, l4hctl
  include/  kernel, shared and UAPI headers
  x86/      x86_64 signal frames, TLS, syscall table, vDSO and register glue
  arm64/    native AArch64 ABI, atomics, context switching and module relocations
  configs/defconfig
guest/linux/patches/              changes outside arch/l4h
```

`tools/build-linux.sh` builds with `ARCH=l4h`, using `SUBARCH=x86_64`
by default or `SUBARCH=aarch64` when `L4H_ARCH=aarch64`. Each subarchitecture
uses its native UAPI headers, syscall table and signal-frame layout. AArch64
exports the HWCAPs of the ID registers in bootinfo (AES, PMULL, SHA*, CRC32,
LSE atomics and others; nothing that needs state seL4 does not keep, such
as SVE or pointer authentication), preserves TPIDR_EL0 and all 31 general registers,
and supplies a versioned vDSO with the signal-return trampoline. Its first
syscall argument is saved separately from the x0 return value, including
across restarted syscalls. Executable mappings receive instruction-cache
maintenance through seL4. Both ISAs use the common memory, scheduling and
virtio-l4h code. The Linux base is 6.18; patches outside arch/l4h are in
`guest/linux/patches`.

### 5.2 Address spaces

- **Guest-kernel VSpace**, one per guest:
  - the kernel image;
  - a **direct map of frame-backed guest RAM**: guest-physical address (GPA) *g* maps
    to `PAGE_OFFSET + g`, using 4 KiB frames (see §5.3);
  - vmalloc/module area;
  - on x86_64, BPF JIT images in the 1 GiB below the kernel image (§5.7);
  - per-vCPU event pages;
  - virtio-l4h device pages.

  All vCPU kernel TCBs of the guest share it.
- **Guest-process VSpaces** cache Linux `mm_struct` mappings in a fixed
  pool of host-provided VSpace roots (§5.3). The guest makes their page
  tables and mapping slots from its own RAM. They hold only user mappings,
  plus vDSO and vvar. Userspace extends to `0x7ffffffff000` (exclusive)
  on both ISAs, leaving the final page below 2^47 reserved as seL4 requires
  on x86_64.
  Fixed mappings such as `0x7fffffe00000` can use the last 512 GiB too.
- The two kinds are disjoint, and that disjointness is what isolates the guest
  kernel from guest user code. Every seL4 mapping is user-accessible, so the
  kernel's memory must not be mapped into a process VSpace at all. Kernel and
  user VSpaces can use the same numeric addresses independently. The
  x86_64 guest kernel is linked at `0x60000000`; host-provided special
  pages start at `L4H_SPECIAL_BASE`. Separate VSpaces enforce isolation.
- **uaccess** (`copy_{to,from}_user`, `get_user` and the rest) walks the
  guest's Linux page tables in software and goes through the direct map, as
  UML and L4Linux do. A missing page calls `handle_mm_fault` inline. The cost
  is a few hundred ns per page-crossing access, which is acceptable.
  - Each page is looked up under `mmap_lock` (VMA present) and the PTE
    lock, checked like a hardware access (present, readable but not
    `PROT_NONE`, or writable) and pinned with a page reference for the
    copy, so an unmap on another vCPU cannot free and reuse it meanwhile.
  - In atomic context (futex operations, `*_nofault`) `mmap_lock` is only
    tried and nothing faults: callers fault the page in and retry.
- Kernel `*_nofault` accesses check that the address is mapped in the
  guest-kernel VSpace, since a fault there stops the guest. The direct map
  has holes where RAM blocks became seL4 objects (§15.3), so its range is
  checked block by block (`/dev/mem`, BPF `probe_read_kernel`). A block
  being converted is marked busy first, and its frames are revoked only
  once no access that found it mapped is still between its check and its
  access.

### 5.3 Memory management: Linux page tables mirrored into seL4

- The guest kernel keeps ordinary Linux 4-level software page tables. The PTE
  format belongs to `arch/l4h`; young combines software and hardware state,
  while dirty is maintained in software.
- The seL4 VSpace of each mm is a **cache** of those page tables, filled
  lazily:
  1. A user access to an unmapped address raises an seL4 VMFault, which
     reaches the vCPU kernel TCB.
  2. The kernel runs `handle_mm_fault`.
  3. It copies the frame cap into a slot of that mm's CNode and calls
     `seL4_X86_Page_Map` with the rights from the PTE.
  4. It replies to the fault.

  Optionally, the kernel pre-maps from `set_pte_at` for pages it has just
  faulted in.
- **Hardware accessed and software dirty bits.** Clean writable pages are
  mapped read-only until the first write, whose fault sets `pte_dirty`.
  Aging leaves permissions unchanged: `ptep_test_and_clear_young()` returns
  and clears the software young bit OR the hardware accessed bit, using
  patch 0023 on the frame cap recorded in `as->pages`. The mm's VSpace lock
  protects that cap against unmapping and pool eviction. An mm with no
  VSpace has only its software bit to clear. `ptep_clear_flush_young()` is
  the same operation, with no remap or TLB flush. Each reclaim sample costs
  one seL4 invocation per mapped page. Reads then need no Linux fault;
  AArch64 without hardware AF updates pays one seL4 entry after a new walk.

  The old implementation left old pages readable but never observed reads,
  so reclaim treated read-hot code and data as cold. Software dirty
  tracking is retained because losing a dirty bit can lose data.
  A remap or VSpace eviction can lose one accessed sample; on aarch64,
  where seL4 maps every page with AF set, a remap that only changes
  rights (fork's write-protect, `mprotect`, writeback's `page_mkclean`)
  adds one instead. Callers that only inspect `pte_young()` see the
  software bit: in this configuration that includes smaps' cosmetic
  `Referenced` count, `MADV_COLD`, which then leaves a page's hardware
  bit set for reclaim to find, and the unmapping of file pages, which
  marks them accessed only on the software bit. Reclaim and `clear_refs`
  use test-and-clear. MGLRU, DAMON, idle-page tracking and NUMA balancing
  are disabled and would need hardware-bit support before being enabled.
  `page_aging` uses a test-only module to sample reclaim's hook; it checks
  hot/cold pages after `clear_refs`, no Linux refaults, and data integrity
  during concurrent aging. The ABI test exercises the raw invocation and
  the AArch64 access-flag handler for both reads and instruction fetches.
- **Cap-slot tracking.** Every seL4 mapping needs its own frame-cap copy. PTE
  pages are allocated at order 1, and the second 4 KiB holds a parallel
  512-entry array of CNode slot indices, so unmapping is O(1).
- **Bulk operations.** Exit, `exec` teardown, `fork` COW downgrade and large
  `munmap`/`mprotect` (above a threshold) do not unmap page by page. They
  delete the mm's seL4 VSpace and CNode together, which takes a few
  preemptible kernel operations, and let faults repopulate it. In `fork`, both
  parent and child refault their working sets lazily, so fork followed by exec
  stays cheap.
  *Implemented:* a VSpace that leaves its mm (exit, or eviction from the
  pool) is emptied after the entry is detached, outside the pool lock and
  with interrupts as the caller has them, so other vCPUs keep running. Its
  page tables go first, highest level first: unmapping one invalidates the
  ASID once and removes everything below it, so the frame capabilities
  are then deleted without a TLB shootdown each.
- **TLB coherence** across cores is seL4's job: unmap shoots down the ASID's
  TLB entries. With several vCPUs, `flush_tlb_*` syncs synchronously, so a
  page is never freed while another vCPU can still reach it. The fault-path
  mapping runs under the PTE lock.

  *Revised (v1):* every vCPU also syncs `current->mm` before returning to
  user, and a sync takes the whole pending range of the mm at once. A
  flush may therefore find that its range has already been taken by a
  sync on another vCPU that has not yet applied it. Syncs of an mm are
  serialised by a per-mm lock, held from taking the range until it is
  applied, so that such a flush waits for that sync instead of returning
  while the old mappings are still in the VSpace. Without the lock, the
  freed pages were reused while another thread could still write to them
  through the old mapping. This showed up as `smp_mm_stress` data errors
  on oversubscribed hosts. The lock also keeps two syncs from racing on
  one PTE, where one could map a value that the other had already
  replaced and marked synced.

  *Revised:* a full flush (`flush_tlb_mm`) marks all of user space for
  the sync, not the mm's VMAs. When two mmu_gathers of an mm overlap
  (`munmap` while another thread runs `MADV_DONTNEED`), `tlb_finish_mmu()`
  ends with a full flush, after `munmap` has taken its VMAs out of the
  tree: the PTEs it had cleared were never synced, and other threads kept
  reaching the pages it then freed. The sync walk reads each page-table
  entry once, since it runs while `munmap` may clear entries.

  *Revised:* a user sync leaves any page it cannot map unmapped and goes
  on. Running out of memory for a parent page table was reported as
  `-EFAULT`, which ended the walk: the unmaps after it in the range were
  skipped, and `munmap` freed pages other threads could still reach.
- **VSpace pool.** x86_64 seL4 has only 4096 ASIDs in total (8 pools of
  512). Each guest therefore gets a fixed pool of pre-assigned VSpace roots,
  and the guest kernel recycles them least recently used first. An mm that
  loses its VSpace simply refaults: every successful page fault installs
  the PTE directly. When the last user exits, `arch_exit_mmap()` releases
  its VSpace and page-table objects. Lazy `active_mm` references from idle
  kernel threads and OOM bookkeeping can outlive `waitpid()`; they must
  not retain those objects until `destroy_context()`.
  An exiting task may sleep while it empties its VSpace, so a vCPU that
  finds every entry either running or being emptied gives its CPU away
  and retries; spinning there left those tasks, queued on its own vCPU,
  unable to finish.
- **CSpace naming.** A CNode capability held directly in a root slot cannot
  be named by a 64-bit CPtr, because seL4 keeps resolving through it.
  Capabilities that must be named, such as the root CNode itself and user
  threads' CSpaces, live in a "meta" CNode in root slot 1 (see `abi.h`).
- **Guest RAM.** `l4h-memd` allocates 2 MiB blocks from anywhere in free
  host memory (§16). The guest receives frame caps for the boot blocks and
  Untyped copies for the rest, which it retypes into frames or its own
  kernel objects (§15). There is no separate object quota or DMA RAM
  chunk table: devices see only the host-owned I/O pool. Running out of
  RAM for objects is a guest-local OOM. Destroy revokes the original
  block Untypeds to reclaim everything the guest made.
- **Transparent huge pages.** Linux can allocate 2 MiB anonymous THPs and
  collapse base pages through `khugepaged` or `MADV_COLLAPSE`. The default is
  `transparent_hugepage=madvise`; Linux still disables THP at boot below
  512 MiB of usable RAM, where it can be enabled explicitly through
  `/sys/kernel/mm/transparent_hugepage/enabled` (including `always` in a
  user-supplied initramfs after mounting sysfs). Linux's smaller PTE-mapped
  THP sizes remain disabled by default.

  Guest-owned and hotplug RAM blocks have one canonical 2 MiB seL4 frame
  plus 512 derived 4 KiB aliases. The direct map and base-page mappings
  use those aliases; a huge Linux PMD uses a copy of the large cap, giving
  it one native 2 MiB leaf. Host-created boot-image blocks retain their
  original small caps and use the 512-mapping fallback. The host ABI and
  `L4H_FRAME_CPTR` layout are unchanged. A block still needs its small
  master capabilities, so the savings are in per-process mappings and
  leaf tables, not a 512-fold reduction of all capability storage.

  User VSpaces track small and large leaves separately. A partial update
  drops the whole overlapping large leaf before installing any small
  replacement; unaffected pages can refault. This demotion needs no
  allocation. Promotion removes the old leaf table, invalidating its
  translations once, before deleting its small caps and mapping the large
  frame. Table coverage is tracked explicitly on both ISAs, indexed by
  level and address, so neither adding a table nor promotion scans the
  address space's tables. Accounting, eviction, teardown and failed
  TLB-sync mappings include both sizes;
  a failed remap leaves the affected range unmapped. ARM executable
  mappings synchronize the instruction cache over the full frame size.

  The TLB sync recognizes a huge leaf and applies its entire 2 MiB range,
  even for a partial flush, before clearing `NEEDSYNC` with a compare and
  exchange. A split's temporarily invalid PMD retains its huge marker but
  has all its seL4 mappings removed. Under a PMD that points to a PTE
  table, the sync also drops any 2 MiB leaf left there: a zapped huge PMD
  loses `NEEDSYNC` if another thread's fault installs a table before the
  zap's flush, and the new table may not have a PTE to sync yet.
  Faults, kernel user copies and futexes
  take the PMD lock and resolve the correct tail page. Aging combines the
  software PMD's young bit with its large leaf's A/AF bit, or all 512
  small leaves in the fallback.
  Ordinary folio splitting and migration handle reclaim and object-block
  conversion; native PMD migration and whole-THP swap are not enabled.

  `tests/run-thptest.sh` covers allocation, COW, user copies, futexes,
  VSpace eviction, promotion among thousands of page tables, splitting with pinned pages, partial protection/unmap/discard,
  explicit and background collapse, moving mappings, concurrent writes,
  hardware aging, swap, execute permissions, shared memory and allocation
  fallback. `HPSTRESS_THP=1 tests/run-hotplugstress.sh 15` exercises memory
  hotplug with THP enabled in the workload guests. `tests/run-thpbench.sh` compares
  advised THP with `MADV_NOHUGEPAGE` on the same kernel, in fresh processes
  with alternating trial order. The test module reports the actual native
  large-leaf count, independently of `AnonHugePages`, and both the
  correctness suite and benchmark check it.

### 5.4 Execution model: vCPUs, tasks, syscalls and interrupts

Each guest **vCPU** has:

- a **kernel-context TCB** (`kTCB`) at priority `P_K`, running in the
  guest-kernel VSpace, with its own scheduling context `SC_K`;
- a fault/IPC **endpoint** `EP_v` and a bound **notification** `N_v`;
- a user scheduling context `SC_U`, bound to whichever guest task runs on that
  vCPU.

Each **guest task that has a user context** (each Linux thread) has a
**user-context TCB** (`uTCB`) at priority `P_U < P_K`:

- its VSpace is the mm's VSpace;
- its CSpace is empty;
- `trapSyscalls` (E1) is set;
- its fault handler is a badged copy of `EP_v` for the vCPU it runs on, and
  the badge is the task ID.

uTCBs are created lazily from object blocks in the guest's own RAM. Keeping one TCB per thread,
rather than one per vCPU, means seL4 holds each thread's register and FPU
context, so a context switch never copies FPU state.

```
 user thread T runs on core c ───syscall──► seL4 ──UnknownSyscall fault IPC──► kTCB(v)
   (uTCB_T, SC_U, prio P_U)                                                     │
                                                                  Linux syscall │
   ◄──────────── reply (new regs) ◄── seL4_ReplyRecv(EP_v) ◄────────────────────┘
```

**Return to user, switching from task A to task B:**

```
seL4_TCB_SetSchedParams(uTCB_A, …, SC=null)
seL4_TCB_SetSchedParams(uTCB_B, …, SC=SC_U, fault_ep=EP_v[badge B])
seL4_ReplyRecv(B's reply object, …)   (or seL4_Recv if B was preempted)
```

The second call also migrates B to v's core, because in MCS the core follows
the scheduling context. A preempted B is runnable, so binding `SC_U` is what
resumes it.

**Reply objects.** MCS needs a reply object for every task blocked in a fault.
Each user thread has its own, made with its TCB, and the kernel thread
receives that thread's faults into it.

**Interrupts and preemption:**

- **While a user task runs.** kTCB is blocked in `Recv` on `EP_v`. A signal on
  `N_v` wakes it, and because `P_K > P_U` it preempts the uTCB at once. The
  preempted uTCB is not in a fault state. The kernel either leaves it alone,
  so it resumes when kTCB blocks again, or unbinds `SC_U` to deschedule it and
  saves nothing, because the registers stay in the TCB.
- **While kTCB itself runs guest-kernel code.** Notifications cannot
  interrupt a running thread asynchronously. Interrupt sources therefore
  **set a bit in the vCPU's event page** (a shared frame, as with Xen's
  `evtchn_pending`) and then signal `N_v`. The guest checks the event word, a
  cheap memory load, when it re-enables interrupts, in `cond_resched`
  (patch 0005, so also in every `might_sleep` under
  `CONFIG_PREEMPT_VOLUNTARY`), in `cpu_relax()` when interrupts are on,
  and before blocking. Without the `cpu_relax()` poll, two vCPUs that
  wait in `csd_lock_wait()` for each other's `smp_call_function()`, or
  one that spins on a lock held by the other while it waits so, never
  take the IPI they wait for. The E3 timer only
  signals `N_v`, so the same check also compares `rdtsc` against the
  vCPU's armed deadline. Events delivered on the way back to user mode
  can set work flags after they were checked, so the flags are checked
  again just before the user context runs; and events taken off `N_v`
  while waiting for `SC_U` budget signal it again, so that the user run
  returns for them at once. The default guest configuration uses
  `CONFIG_PREEMPT_VOLUNTARY`. `CONFIG_PREEMPT` compiles `cond_resched`
  out, so `arch/l4h` refuses to build with it.

  *Revised:* `cond_resched` did not poll at first. A loop that waits for
  another task with `cond_resched` and plain spinlocks then never sees
  the timer, so `need_resched` is never set and the task it waits for
  never runs. On a 1-vCPU guest this froze the whole guest, timers and
  console included, with no lockup report: `shrink_dcache_parent` spun
  in `d_walk` on dentries that another task had on its shrink list, which
  Docker's container setup and teardown hit within seconds.
- **Interrupted context.** Events delivered at a polling point interrupted
  the kernel, and their handlers see kernel-mode registers. Only the
  events that stopped a uTCB interrupted user mode and see the task's user
  registers. The task's registers say "user" during the whole syscall,
  so using them everywhere made every tick a user tick: RCU then took a
  quiescent state inside read-side critical sections.
- **Future backstop.** The proposed upcall injection for a kTCB that runs
  too long without polling is not implemented. It would require suspending
  the kTCB and changing its registers to enter an interrupt handler, with
  a safe way to construct the interrupt frame under the guest-owned
  memory model. Current interrupt delivery relies on guest polling.
- **Idle.** kTCB calls `seL4_Wait(N_v)`. Idle consumes no CPU, which is what
  makes 30 mostly-idle guests on 4 cores practical.

**Exceptions.** A UserException fault carries the vector and error code. We
map them to signals, for example #GP to SIGSEGV, #UD to SIGILL and #DE to
SIGFPE. `int3` is used for SIGTRAP and ptrace breakpoints. `int 0x80` is
rejected because there is no 32-bit compat. The legacy vsyscall page is not
supported; we use `vsyscall=none`, which is the modern default.

**TLS and FS/GS.** `arch_prctl(ARCH_SET_FS)` maps to `seL4_TCB_SetTLSBase` or
WriteRegisters `fs_base`. With `KernelFSGSBase=inst`, userspace
`wrfsbase` works natively, and we advertise HWCAP2_FSGSBASE.

**Time.** The clocksource is the TSC, read with `rdtsc` in the kernel and in
the vDSO. On x86_64 the vDSO is Linux's generic one (`lib/vdso`): the
kernel keeps a time page current (`update_vsyscall()`), mapped read-only
four pages below the vDSO text in every process, so `clock_gettime`,
`gettimeofday`, `time` and `clock_getres` do not trap (~40 ns instead of a
~1.4 µs syscall on the nested dev box). The vDSO and its data pages live
in the top 64 KiB of user space (`L4H_VDSO_AREA`), and `STACK_TOP` is a
guard page below that area: a stack randomized to within the data pages
made installing them fail exec past its point of no return, killing
~0.2 % of execs with SIGSEGV. Time namespaces are off: they
would need that page remapped per namespace. The aarch64 vDSO has no time
functions yet; glibc falls back to the syscall there. `l4h-root` passes the TSC frequency, taken from seL4 bootinfo.
The clockevent is a per-vCPU one-shot deadline armed with
`seL4_TCB_SetTimer(kTCB, deadline, L4H_BADGE_TIMER)`, which signals `N_v`.
seL4 signals a timer once, when its deadline has passed on the core that
holds it (E3). A vCPU that migrated may read a TSC slightly behind that
core's, so the guest takes the timer badge as the expiry, not only a
`rdtsc` past the deadline: otherwise such a signal left the vCPU with no
timer armed. Rates go to Linux in kHz and the clockevent counts in units
of 8 TSC ticks, as on x86: Linux takes them as 32-bit values in Hz, which
TSCs of 4.3 GHz and more overflow. `udelay` waits on the TSC too, and
on aarch64 on the counter, a constant `ndelay` included.

*Revised (v1):* the wall clock at boot comes from `L4H_HC_GET_TIME`:
`l4h-root` reads the CMOS RTC once at boot, and each VMM adds the TSC time
since. Guests may correct it with NTP. Without an RTC it
is 0, the epoch.
dom0 can save its corrected time to the machine RTC with `l4hctl rtc-set`
(`L4H_CTL_RTC_SET`, UTC epoch seconds). Root retains the RTC capability;
on x86 it inhibits calendar updates while writing, preserves the data
and hour modes, and writes a century register only if the FADT advertises
one. AArch64 QEMU virt uses the PL031 load register. The write affects
the RTC used on the next host boot; it does not replace the current host
anchor or change running guests' clocks.

**Signals.** The kernel builds the native x86 `rt_sigframe` in user memory
through the direct map. It fetches FPU and XSAVE state with E2, then rewrites
the uTCB's registers with `WriteRegisters`. `rt_sigreturn` reverses this.
As on x86, the handler starts with DF, TF and RF clear and the initial FPU
state, and a handler without `SA_RESTORER`, or a frame that cannot be
written or does not fit on the alternate stack, gets SIGSEGV. The XSAVE
area is 64-byte aligned above the frame, `uc_flags` and the software
bytes say what it holds, and `rt_sigreturn` re-arms an `SS_AUTODISARM`
alternate stack. Signals are delivered on registers read back from the
uTCB when the work flags are handled, not before: another vCPU may raise
one at any time. On aarch64, a syscall's restart is prepared before the
signal is dequeued, as on arm64, so a tracer at the signal stop sees the
rewound PC and no syscall.

**ptrace and coredump** use ReadRegisters/WriteRegisters and E2.
seL4 clears TF in user flags and l4h builds it without the hardware debug
API, so `PTRACE_SINGLESTEP` and enabling debug-register breakpoints fail
with EIO; debuggers use software breakpoints (`int3`). CS and SS read as
Linux's 64-bit user selectors (0x33, 0x2b), which is how gdb tells a
64-bit inferior. They are the selectors user code runs with: patch 0028
lays out seL4's user segments as Linux does, so that `sysretq` and `iretq`
both return with them (before it, `sysretq` returned with CS 0x3b, a data
slot, which faulted when user code reloaded it with `iretq`, as .NET's
`RtlRestoreContext` does). And `NT_X86_XSTATE` carries XCR0
in its software bytes, as on x86.
Seccomp filters and `SIGSYS` see the user instruction pointer
(`KSTK_EIP`, which UML takes from the kernel context switch), and
`SECCOMP_RET_TRAP` leaves the syscall number in RAX, as x86's
`syscall_rollback()` does: sandboxes such as Chromium's check both. The
syscall-restart checks use the low 32 bits of RAX, which is what runs.
`PTRACE_ARCH_PRCTL`, and the fs/gs base in `PEEKUSER`/`POKEUSER` and
`GETREGS`/`SETREGS`, act on the tracee: its fs/gs base is read back from
its TCB (user code may have changed it with `wrfsbase`), and a new value
is kept in its saved registers, marked dirty, until it resumes.

### 5.5 Calls from the guest to the host

The guest kernel makes plain seL4 invocations on capabilities it holds:

- Map and Unmap;
- TCB, SchedContext Bind and Unbind;
- Signal;
- Call to its VMM endpoint for device configuration, power-off and reboot;
- Signal its devices' kick notifications, the attestation device's
  included, which trustd serves even without a TPM (§9.2).

**Direct seL4 invocations rely on capability checks.** The CSpace that
`l4h-root` hands the guest contains:

- the guest's own frames and its Untyped;
- its vCPU SCs, which it can bind but not configure, since it holds no
  SchedControl;
- its own endpoints;
- an MCP no higher than `P_K`.

Host hypercalls and device requests still validate their arguments,
including pool addresses, device indices and lifecycle state.

### 5.6 One guest kernel, and its module tree

- **l4h ships the guest kernel.** seL4's ABI is not stable: syscall
  numbers, invocation labels, object types, message layouts and the user
  context are compiled into `os-sel4` from the l4h seL4 build, and the
  guest relies on the kernel extensions (§4). A guest kernel only works
  with the host it was built with, so guests do not bring their own. The
  UEFI application holds one `vmlinux` (the boot module `guest-kernel`),
  which dom0 and every VM run. `vm_start` takes an initramfs and a command
  line, and root loads the kernel itself; it parses the ELF once, at boot
  (`kimage.rs`).
- **Its module tree.** `tools/build-kmods.sh` builds an EROFS image
  (LZMA, about 9 MiB) of the kernel's `/lib/modules`: its modules, depmod's
  files, and `<release>/build`, the tree to build external modules
  against. That is kbuild's `install-extmod-build` plus what it misses for
  `ARCH=l4h`: the headers outside `arch/l4h/include`, those of the ISA's
  own architecture, `abi.h` and libsel4's headers. Its `Makefile` sets
  `ARCH=l4h`, so `make -C /lib/modules/$(uname -r)/build M=$PWD` works in
  a guest as on any distribution. The image is the boot module
  `guest-kmods`, and is optional.
- **Shared read-only.** Root maps the boot module's own pages read-only
  into every guest at `L4H_KMOD_VA` (bootinfo `kmod_va`, `kmod_size`):
  one copy in host memory for all guests, the one the boot loader
  loaded, with nothing allocated or copied at boot. Each guest's copies
  of the frame capabilities are in a CNode of its arena, about 150 KiB
  with the page tables mapping them for a 9 MiB image. Root knows the
  frame of each module page (`bootmod.rs`): it carved a boot loader's
  modules into frames itself, and modules appended to its image are in
  the image frames seL4 gives it. Guests map the image's last page
  whole, so root clears what follows the image in it before any guest
  exists: a boot loader leaves whatever memory held there, which would
  reach every guest. It refuses an image that shares that page with
  another module. `drivers/kmod.c` makes the image the
  read-only block device `/dev/l4hkmod`, and `mount -t erofs -o ro
  /dev/l4hkmod /lib/modules` gives modprobe the modules and module
  builds the tree.
- **The kernel's text and rodata are shared too.** Every guest maps the
  pages of the kernel's read-only segments from the boot module's frames,
  read-only, so a guest can no longer change its own kernel's code. A
  page is shared when it is all file data of a read-only segment; the
  host saves memory for RAM blocks (§15.2) whose every page is: such a
  block holds only those copies, and memd has no block for it. The
  linker script keeps whatever the kernel writes out of those segments
  (`__ro_after_init` data and the exception table, which is sorted at
  boot, go with the data) and pads text to a page and rodata to a block,
  so the 11.7 MiB of text and 2.3 MiB of rodata on x86_64 are seven
  blocks: 14 MiB per guest. Shared blocks do not count against a guest's
  RAM: they are guest-physical space on top of the RAM it is given, so a
  guest of 256 MiB has 256 MiB of its own and 270 MiB of RAM in its boot
  info. Blocks that are only partly read-only (none with this layout)
  get private copies, as all blocks did before. Writes to shared pages
  fault, which stops the guest (§5.2): a kernel change that writes text
  or rodata shows at boot.
- **Side channel.** Guests share the physical pages of kernel code, as
  with the module image, so one guest can time its access to them to
  learn which kernel code another runs (Flush+Reload). Pages shared this
  way are never written once guests exist, so the kernel's data and other guests' memory
  stay out of reach.
- **Modules may use the l4h ABI.** A module comes from the kernel's own
  build, so it can call seL4 and use the ABI directly. The kernel exports
  its capability allocator (`l4h_slot_alloc`, `l4h_obj_alloc`, …), process
  VSpaces (`l4h_vspace_get`), kernel mappings of frames it did not make
  (`l4h_kernel_map_frame`) and os-sel4's vCPU state. `tests/guest/abitest`
  tests the ABI and E1–E3 below Linux that way, where a freestanding test
  guest used to.
- **Measured.** The kernel and the module image are part of the UEFI
  application, which PCR 4 covers. Launch digests (§9.2) still cover the
  kernel image in guest RAM, which is the same for every guest of a host.

### 5.7 BPF JIT

The guest kernel uses the upstream x86-64 and arm64 BPF JITs
(`arch/x86/net`, `arch/arm64/net`), on by default. Patches 0006 and 0007
adapt them, and `arch/l4h/{x86,arm64}/bpf_jit.c` provide what they need
from the architecture:

- **Reach (x86_64).** The JIT calls helpers in the kernel image with a
  rel32 `call` and leaves a program to the interpreter when a target is
  beyond ±2 GiB. vmalloc follows all of RAM and the I/O pool, which puts it
  out of reach in a guest with more than about 1.5 GiB. So BPF images
  (`EXECMEM_BPF`) go in the 1 GiB below the kernel image, which nothing
  else in the guest-kernel VSpace uses. Modules keep vmalloc: they are built
  with the large code model. The arm64 JIT loads call targets into a
  register, so it keeps vmalloc as well. It builds them with `movz`
  instead of `movn`, since the guest kernel's addresses are in the lower
  half.
- **Code patching.** Guest-kernel memory other than the image's text and
  rodata (§5.6) is mapped writable and executable, so new images are
  written in place. On x86, code that other
  vCPUs may be running (direct tail calls, trampolines) is patched without
  int3, since a breakpoint in the guest kernel goes to the host. Instead,
  `stop_machine()` holds every vCPU with interrupts off, one vCPU writes,
  and each then runs `cpuid` (serializing) before it returns. On arm64 the
  JIT patches only branches and NOPs, which one word-sized store and
  instruction-cache maintenance through seL4 (`flush_icache_range`) make
  safe while other vCPUs run them. Its atomics use LSE when the CPU has it
  (`HWCAP_ATOMICS`), and LL/SC otherwise: `CONFIG_ARM64_LSE_ATOMICS` builds
  that emitter and nothing else in the guest kernel.
- **No exception tables.** A fault of the guest kernel stops the guest
  (§5.2), so a JIT may not emit loads that rely on a fixup.
  Programs with `BPF_PROBE_MEM` loads (BTF pointers, which need
  `CONFIG_DEBUG_INFO_BTF`) are left to the interpreter, which checks the
  address with `l4h_kernel_range_ok()` first. Arena accesses are not offered.
- **What the guest kernel has not.** There is no `%gs` or `TPIDR_EL1`
  per-CPU base, and the guest kernel cannot read `SP_EL0`. So there are no
  per-CPU instructions or private stacks, and on arm64
  `bpf_get_smp_processor_id()` and `bpf_get_current_task()` are not
  inlined. BPF exceptions need an unwinder (`arch_bpf_stack_walk()`), and
  the timed `may_goto` needs x86 per-CPU assembly, so neither is offered.
  The mitigation flags (retpolines, return thunks, IBT, BHB clearing) are
  never set: `cpu_feature_enabled()` folds to 0 every feature that l4h
  does not set (the `x86_capability[]` words CPUID fills, and
  `X86_FEATURE_PREFER_YMM`). arm64 skips its Spectre-BHB sequence for
  classic BPF, which relies on firmware calls.

`tests/run-bpftest.sh` runs the kernel's BPF test vectors (`lib/test_bpf.c`)
through the JIT, and the verifier, JIT, direct tail calls and XDP (generic)
and tcx attachment through `tests/guest/bpftest.c`. On x86_64 the guest has
2 GiB.

### 5.8 Android guests

Android's userspace needs kernel features that other guests do not use.
The shipped kernel has them, so an Android guest runs the same kernel as
every other guest (§5.6). What would change the others stays off until a
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
| SELinux, with audit | `init`, which stops without it | off without `lsm=selinux`; audit is disabled until an audit daemon (logd) enables it |
| PSI | lmkd's memory pressure triggers | off without `psi=1` |
| bootconfig | `androidboot.*` settings appended to the ramdisk | ignored without `bootconfig` |
| userfaultfd, `MREMAP_DONTUNMAP`, `UFFDIO_MOVE` | ART's default (concurrent compacting) garbage collector | unused |
| `/dev/rtc0` with alarms | the `CLOCK_*_ALARM` clocks | present |
| dma-buf heaps, `sync_file` | gralloc buffers and fences | unused |
| DRM with virtio-gpu (dumb buffers on render nodes, patch 0012; ARGB8888 on its plane, patch 0013) or vkms, modules | the display SurfaceFlinger composes for | no display until a driver is loaded |
| evdev, uinput | input | no input devices |
| zram with LZ4 | swap | unconfigured |
| legacy iptables with the matches and targets netd uses, policy routing, `SOCK_DESTROY`, XFRM | netd | empty tables |
| fs-verity, fscrypt, quotas, dm-verity FEC | APKs, file-based encryption, storage accounting, verified partitions | per filesystem |

The base stays mainline 6.18 LTS, not Android's `android17-6.18`
branch: that branch lags the stable releases (6.18.32 against l4h's
6.18.60 in October 2026), and the user ABI is upstream's either way.
Android's own additions are therefore missing but for two that Android
17 cannot boot without, ashmem and dm-default-key (below): `xt_quota2`
(netd's data usage alerts), incremental-fs (incremental app installs),
fuse-bpf (MediaProvider; mainline has FUSE passthrough), dm-user (virtual
A/B snapshots) and the ashmem ioctls on memfds.

- **RTC.** `drivers/rtc_l4h.c` is `/dev/rtc0`: the host's wall clock
  (`L4H_HC_GET_TIME`) plus an offset that setting it changes, which is the
  guest's own and lasts until the guest stops. Alarms are hrtimers. The
  device may wake the system, which alarm timers require of an RTC:
  without one, `timerfd` works on the alarm clocks but `clock_gettime`,
  `clock_nanosleep` and POSIX timers on them fail. The system clock still
  comes from the host at boot, to the nanosecond, so `RTC_HCTOSYS` and
  `RTC_SYSTOHC` are off.
- **Kernel copies are not user faults.** uaccess faulted with
  `FAULT_FLAG_USER`, as in UML. With userfaultfd that let a userfaultfd
  opened with `UFFD_USER_MODE_ONLY`, all that
  `vm.unprivileged_userfaultfd=0` leaves an unprivileged user, hold up the
  kernel's own copies, which is what that mode exists to prevent
  (`handle_uaccess_fault()`). They still wait for `mmap_lock` as user
  faults do.
- **Signals during a userfaultfd wait.** A user fault that a signal
  interrupted gave up only for a fatal signal; for any other it retried at
  once, so the thread spun in the kernel and took no signal until its page
  arrived. ART suspends threads with signals, and the thread that would
  fill the page may wait for them. The fault now returns, the signal is
  delivered, and the access faults again, as `fault_signal_pending()` does
  on other architectures.
- **bootconfig.** `start_kernel()` looks for a bootconfig at the end of
  the initramfs right after `setup_arch()`, which now records the
  initramfs (it was an `early_initcall`).
- **Display.** The graphics menu, DRM included, is only offered with
  `HAS_IOMEM`, which `NO_IOMEM` took away. A guest has no device memory,
  only pages it shares with the host, so `ioremap()` returns NULL
  (`asm/io.h`, as on UML) and `NO_IOMEM` is now off: what needs no device
  memory builds, and a driver that maps some fails its probe. The display
  is vkms, which composes planes in software, raises vblanks from an
  hrtimer and has no output but its writeback connector; SurfaceFlinger
  composes onto it, and screen capture over adb (scrcpy, `screenrecord`)
  shows it. DRM and vkms are modules, from the module tree or Android's
  ramdisk: vkms adds a display as soon as it is loaded. The display the
  host can show is l4h-vmm's virtio-gpu (§8.6), with the `virtio_gpu`
  module.
- **ashmem.** Android 17's libcutils allocates shared memory from
  `/dev/ashmem`: from memfds only with `sys.use_memfd`, which is off, and
  only on a kernel that takes ashmem's ioctls on a memfd, which mainline
  does not. Mainline removed the driver in 5.18; patch 0010 is the C
  driver of the Android kernels' `android15-6.6` branch (`android17-6.18`
  has a Rust one, on Android's own Rust bindings), with what changed since
  (`mm_get_unmapped_area()`, an allocated shrinker).
- **Metadata encryption.** A `keydirectory` in the fstab of `/data` makes
  vold map the partition through Android's `default-key` target, whose
  table is dm-crypt's: `<cipher> <key> <iv_offset> <dev> <start>` and the
  options `allow_discards`, `sector_size:<n>` and `iv_large_sectors`.
  Patch 0009 registers dm-crypt again under that name, at version 2 (vold
  writes an older table below it). Android's target lets through the bios
  of file contents that fscrypt has encrypted already; this one encrypts
  them a second time.
- **mmap layout.** l4h mapped bottom-up from `TASK_UNMAPPED_BASE` with no
  randomization, and had no `vm.mmap_rnd_bits`, which Android's `init`
  stops without (it sets 32 bits on x86_64). mmap now goes below the
  stack, at a random offset of 28 to 32 bits of pages, as on x86_64 and
  arm64 (`ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT`): user space spans 47
  bits on both ISAs.
- **BPF on tracepoints.** bpfloader loads programs on tracepoints
  (`gpu_mem`, `sched`, `power`, `vmscan`), and `system_server` aborts when
  the maps they fill are missing (`ReadProcessGpuUsageKb()`). Programs on
  tracepoints need `BPF_EVENTS`, which needs perf events and kprobe or
  uprobe events. l4h has software perf events (`HAVE_PERF_EVENTS`, no
  PMU: `asm/perf_event.h` hides the host architecture's) and event
  tracing, but no kprobes or uprobes, and patch 0011 lets event tracing
  be enough. The x86-64 JIT failed programs with callbacks ("bpf_jit:
  fatal error"): the verifier gives the JIT `MODULES_VADDR` for a
  callback's address before the last pass, which is above all of RAM
  while l4h's images are below the kernel, so the `mov` shrank in the last
  pass. On l4h it is always a `movabs` (patch 0006).
- **Not yet.** No suspend (`PM_SLEEP`, so no wakeup sources), no vsock
  transport to a host and no 32-bit compat, so Android runs as a
  64-bit-only build. Each guest has 64 process VSpaces (§5.3), which
  Android's hundred and more processes cycle through.

#### Booting Android

Android runs in a VM, which dom0 creates, as any other guest: never as
dom0. `tests/run-android.sh` boots Android 17 so, from the images of
Cuttlefish's 64-bit-only x86_64 build (`aosp_cf_x86_64_only_phone`,
ci.android.com), which `tools/mkandroid.sh` turns into an initramfs and a
disk. dom0 (`tests/guest/init-android`) creates the VM with the disk
(host disk 1), a virtio-gpu display of 720x1200 and a 256 MiB I/O pool,
waits on its console for `init` to run the actions of
`sys.boot_completed=1`, and takes a screenshot (`l4hctl screenshot`),
which must not be blank. The emulator's system images were tried first:
they render only through the emulator's host (goldfish pipes,
gfxstream), where Cuttlefish has a software renderer in the guest.
Nothing of Cuttlefish is changed but what a bootloader and Cuttlefish's
launcher would give it:

- **The initramfs** is the vendor ramdisk and the generic one, then an
  archive of l4h's and a bootconfig. Both ramdisks are legacy LZ4, which
  ends only with the data or a zero frame length: four zero bytes end it
  before l4h's archive. That archive replaces the first-stage fstab (the
  same partitions, without AVB: the device is unlocked) and the modules
  first-stage init loads, built for another kernel, with l4h's
  `virtio_gpu` and what it depends on.
- **The disk** is one GPT, whose partitions first-stage init finds by
  name, on the platform device all virtio-l4h disks hang off
  (`androidboot.boot_devices=virtio-l4h`): misc, frp (the persistent data
  block `system_server` keeps OEM unlocking in without an OemLock HAL),
  metadata, odm, super and userdata. vold encrypts `/data` in place on
  the first boot.
- **odm** is Cuttlefish's ODM partition, its files labelled as the
  platform's policy labels `/odm`, with an init script of l4h's: a
  logcat of errors and boot progress on the console (Cuttlefish logs
  everything to `/dev/hvc2`, which is too much for the console, and l4h
  has no hvc2, so that logcat is disabled), and an empty sensors list
  mounted over the vendor's.
- **The boot properties** are those of Cuttlefish's `guest_swiftshader`
  mode: ANGLE on SwiftShader, minigbm buffers, and Cuttlefish's ranchu
  composer on the virtio-gpu, its framebuffers BGRA; KeyMint and
  Gatekeeper in the guest; a vsock port above 1024 for the lights HAL.
  The HALs that talk to Cuttlefish's host (OemLock, UWB, NFC, Bluetooth,
  the radio, Thread) are left out: naming an APEX in
  `androidboot.vendor.apex.<name>` with no file of that name keeps apexd
  from activating it, and `system_server` would wait for the services
  they declare, or they would start and stop again for good, which fills
  the console. Sensors are none for the same reason.
- **The display.** minigbm allocates the buffers of a virtio-gpu without
  3D as dumb buffers, through the render node (the composer is the DRM
  master on the primary node), which mainline does not allow: patch 0012
  allows it, as the Android kernels do. The composer commits ARGB8888
  framebuffers, which mainline's virtio-gpu plane does not take (XRGB8888
  only): patch 0013 offers ARGB8888 too. The Android kernels offer all
  eight 32-bit formats of the virtio-gpu protocol, but without blob
  scanouts l4h-vmm shows a resource in the format it was created with,
  and dumb buffers are always B8G8R8X8, so the other six would show
  with their bytes in the wrong order. Every buffer
  is mapped through the VM's I/O pool, hence its size.

Android completes its boot about 150 s after the VM starts, on four
vCPUs and 3 GiB, and shows its lock screen (`build/android/screen.png`).

`tests/run-androidtest.sh` boots `tests/guest/androidtest.c` with
Android's command line and a bootconfig: Binder transactions of up to
four pages and a file descriptor passed back, userfaultfd faults from
user code and from kernel copies, signals during such a fault,
`MREMAP_DONTUNMAP` filled back through userfaultfd, `UFFDIO_MOVE`, RTC
alarms and setting, the alarm clocks, code written through one memfd
mapping and run through another, a dma-buf heap, vkms (a mode, page
flips and vblanks, and frames written back that match the buffer
shown), a PSI trigger, zram swap, SELinux, bootconfig and uinput. A
second boot without those parameters checks that SELinux, PSI,
bootconfig and a display stay off.

---

## 6. SMP guests

- vCPU *v* consists of `kTCB_v`, `SC_K,v`, `SC_U,v`, `EP_v` and `N_v`. The
  boot vCPU starts at the ELF entry, and secondaries start at
  `l4h_secondary_entry` when `l4h-root` resumes them at the guest's request.
  CPU hotplug is not supported (`HOTPLUG_CPU` is off).
- **IPIs.** The sender sets a reason bit in the target's IPI word and
  signals `N_target` with the IPI badge (`seL4_Signal` on the target's IPI
  capability).
  seL4 delivers the signal across cores with a hardware IPI when needed.
- **TLB shootdown for guest mms** is seL4's job (§5.3), so
  `flush_tlb_mm_range` only unmaps or invalidates the mirror and never IPIs
  other vCPUs. This is a large saving over a real VM.
- **Lock-holder preemption.** The guest currently uses native qspinlocks
  and qrwlocks. A notification-based paravirtual spinlock slow path is
  future work; a waiter currently spins if the lock holder is descheduled.
  Keeping a guest's vCPUs on distinct cores where possible reduces this
  cost, but oversubscription can still make it expensive.
- `steal_time` comes from `seL4_SchedContext_Consumed` deltas, which the
  balancer publishes in the event page. Guest CFS can then account for steal.

---

## 7. Host scheduling and many guests per core

- **Priorities**, global on each core:

  | Band | Components |
  |------|------------|
  | highest | l4h-netd (switches and NIC drivers), l4h-blkd (disk drivers) |
  | | l4h-vmm instances |
  | | guest `P_K` |
  | lowest | guest `P_U` |

  Every band has MCS budgets, so no component can starve the bands below it.
- **Per-vCPU budgets.**
  - `SC_K` and `SC_U` each get period T (default 5 ms) and a budget derived
    from the guest's CPU cap. Under a cap they split one budget (see below);
    CPU weights are not implemented.
  - Sums across a core may exceed 100%, which is overcommit. Inside the guest
    band, threads with budget left are scheduled round-robin.
  - Caps limit each vCPU's combined kernel and user CPU time, with the
    reconfiguration allowance described below.
- **Placement and balancing.** seL4 does no load balancing, so `l4h-vmmgr`
  runs a balancer at low frequency (about 100 ms):
  - It reads `Consumed` for every SC.
  - It moves vCPUs between cores by re-running `SchedControl_Configure` on
    another core's SchedControl cap. `SC_K` and `SC_U` of a vCPU always move
    together.
  - It spreads busy vCPUs across physical cores before filling SMT siblings,
    preferring to keep a guest's vCPUs on distinct physical cores where
    possible. This reduces execution-resource contention and lock-holder
    preemption.
- **Fairness caveat.** Because `P_K > P_U` for every guest, a guest's kernel
  work can briefly pre-empt another guest's user work, bounded by `SC_K`
  budgets. If measurements show this matters, the balancer can lower `P_K` for
  vCPUs that burn kernel time, or we can trial `seL4_SchedContext_YieldTo`
  from interrupt senders.
- **Memory sizing for 30 guests.** Guest RAM is reserved in full at creation.
  Guest-created CNode slots, page tables and TCBs come from that RAM. Host
  overhead is the I/O pool plus about 6 MiB of objects per guest (§15.2).
  When l4h itself runs in a VM, the host's free memory is reported to the
  hypervisor (§15.4). Ballooning guests and passing on their free page
  reports come later.

**Revised during implementation (v1).**

- **Placement and balancing.** New vCPUs are placed round-robin, visiting
  one logical CPU per physical core before its other SMT threads. At boot,
  root visits each seL4 CPU using its own SC and reads CPUID topology
  (x86 leaves 1F/0B, or AMD topology extensions on Zen and later), then
  returns to its boot CPU. This maps actual CPU IDs, including gaps and
  multiple sockets, without assuming seL4 CPU numbering describes siblings.
  Missing or inconsistent topology falls back to independent CPUs; AArch64
  currently uses that flat topology.

  *Revised:* on x86_64 every CPU a VSpace has run on stays in its TLB
  bitmap until a flush of the VSpace's whole PCID clears the CPUs not
  running it, which only unmapping a page table or invalidating the ASID
  does, and root never does either. So after the visit each page unmap
  in root's VSpace sent every other CPU a shootdown IPI and waited for
  all of them, holding the kernel lock. Root unmaps its window once per
  page it copies into a guest, and on a loaded hypervisor, whose vCPUs
  wait to be scheduled, a boot's image load and launch measurement took
  13 to 48 s instead of 0.2 s, and boots looked hung. Root now flushes
  its VSpace (`seL4_X64_PML4_Flush`, patch 0017) once back on its boot
  CPU, which drops the others (`vspace::flush_tlb_bitmap`).

  Every 100 ms `l4h-vmmgr` reads `SchedContext_Consumed` for both SCs of
  every vCPU.
  - A vCPU is *busy* if it got at least half of its fair share among the
    vCPUs active on its core. Measuring this way still counts a starved
    vCPU on a crowded core.
  - The balancer evens out busy-vCPU counts per physical core first, then
    per logical CPU. It moves at most one vCPU per period, reducing the
    sum of squared counts at the first level that improves. A difference
    of one on logical CPUs also permits a move from a CPU with at least
    two busy vCPUs to a target below 50% utilization, provided physical
    contention does not worsen. Equal-load siblings stay put.
  - Equivalent moves prefer guests with no other vCPU on the target
    physical core, then on the target logical CPU. A moved vCPU stays put
    for 1 s. vCPUs in cooldown still count towards contention.
  - The interval is measured, not assumed: root work such as building a
    guest can delay a period.
  - After moving a vCPU, root flushes the guest kernel's VSpace and all
    of its process VSpaces (`Guest::flush_tlb_bitmaps`), for the same
    reason: threads of a guest's VSpaces run only on its vCPUs' cores, so
    after the flush their bitmaps hold those cores and no others, and
    page unmaps in them no longer interrupt cores the guest has left. A
    VSpace with no other core in its bitmap (unused, or recycled by the
    guest, which empties its page tables) costs only the call; one with
    others costs one IPI round to them. Processes that Linux moves between
    the guest's own vCPUs are the guest's to flush (below). Measured
    (QEMU/KVM, 4 cores, a 1-vCPU dom0 moved to
    the next core every 100 ms, a process mapping, touching and unmapping
    8 pages in a loop):

    | | idle host | loaded host |
    |---|---|---|
    | no migration | 39 µs | 157 µs |
    | migrations, no flush | 290 µs | 80 ms |
    | migrations, flush | 42 µs | 609 µs |

    A migration's flushes (65 VSpaces) took a median 157 µs idle and
    415 µs loaded (90th percentile 33 ms, wall time on a preempted vCPU).
  - The guest flushes a process VSpace itself after Linux moves one of
    its threads to another vCPU: the move marks the mm (`moved`, set by
    `prepare_user()` when the thread's fault endpoint changes vCPU), and
    the next TLB sync or unmap of the mm flushes its VSpace first
    (`mm_flush_moved()`), which drops the core of the vCPU the thread left
    unless another of its threads runs there. A process that moves and
    does not unmap pays nothing; one that does, one flush per move. A
    flush for lowered rights (`L4H_PROT_DEFER_FLUSH`) or emptying the
    VSpace clears the mark too. Measured in a 4-vCPU dom0 on 4 cores, the
    same loop in a process that `sched_setaffinity()` moves to the next
    vCPU every 10 ms: 380 µs a cycle without the flush, 66 µs with it
    (60 µs for either without the moves).
- **CPU caps** (`vm_set_sched`, `l4hctl sched`) give a vCPU one budget,
  a percentage of the 5 ms period, split between its SC_K and SC_U, so
  that the vCPU as a whole stays within the cap. Weights are not
  implemented.
  - Each SC needs at least 200 µs, well above seL4's minimum budget, so
    caps below 8% get a longer period: 1% is 400 µs every 40 ms.
    AArch64 capped vCPUs use at least a 40 ms period to amortize emulated
    GIC timer delivery: 25% gets a shared 10 ms budget every 40 ms.
  - The split adapts. When, in a balancer period, either SC used at
    least 90% of its part, the budget is split in proportion to what each
    used (each keeps at least 200 µs). A user-bound vCPU capped at 25%
    therefore ends up with most of the budget in SC_U, and a syscall-bound
    one the reverse.
    - *Revised:* the first rule gave a saturated SC "what the other used
      plus a quarter". A vCPU alternates between its kernel and user
      threads, so when one SC runs out the other stalls too, and its use
      understates its demand. The split flipped every period (2300/200 µs,
      then about 400/2100 µs). A fork/exec-heavy guest capped at 50% used
      about 20% of its budget: 200 fork+exec took 16 s instead of about
      1 s. The usage ratio survives that throttling.
    - **Remaining cost.** Splitting one budget between two strictly
      alternating SCs still loses capacity, because whichever SC runs out
      first in a period stalls the vCPU while the other's budget goes
      unused. In `tests/run-capperf.sh` (release seL4, nested KVM, noisy),
      200 fork+exec at a 50% cap took 3.9 s with the proportional split.
      With both SCs given the whole budget, an experiment that breaks the
      cap, they took 1.8 s, against 0.4–0.7 s uncapped. So the split still
      costs about 2×, and something else, not yet found, costs about 2×
      more.
  - seL4 keeps the sliding-window limit of a reconfigured SC whose
    thread is runnable; an SC that is idle or unbound starts afresh with
    its new budget. Since the split changes at most once per balancer
    period, that is at most one period's budget extra per change
    (5% of the cap at a 5 ms period, 40% at a 40 ms period).
    Samples covering more CPU time than elapsed (consumption reported
    late when the root task ran late) do not move the split.
  - seL4 refuses to bind an SC whose budget is exhausted to a blocked
    thread. The guest therefore waits for the refill, on 100 µs timers,
    when it moves a capped SC_U to another process: not with
    `seL4_Yield`, which charges SC_K all of its remaining budget.
    *Revised:* a kernel timer deadline that passed during those waits
    was armed again by each of them, so every wait ended at once and the
    vCPU spun on SC_K until the refill. A deadline already past is now
    kept as a pending timer event for after the bind.
  - Under a cap, `P_K > P_U` no longer means that a user context runs
    only once kTCB blocks: when SC_K is out of budget and SC_U is not,
    the context bound to SC_U runs. The guest therefore writes a
    preempted context's registers before it binds SC_U to it, never
    after (`tests/run-captest.sh`).
  - Their SCs hold 16 refills (512-byte objects). With seL4's minimum of
    two, a budget used in many short pieces, as a vCPU that is preempted
    and blocks often uses it, keeps being merged into later refills.
- **Steal time.**
  - The guest accumulates its idle time in the event page (`idle_ticks`).
  - Each balancer period, `l4h-vmmgr` computes, per vCPU,
    `steal = wall − consumed − idle`, counting from the vCPU's first run.
    It publishes the result monotonically as `steal_ns`.
  - The guest returns it as Linux's paravirt steal clock
    (`CONFIG_PARAVIRT_TIME_ACCOUNTING`), so it shows as `st` in /proc/stat
    and top. A guest capped at 25% sees about 75% steal
    (`tests/run-m6test.sh`). `l4hctl top` shows each VM's CPU use over the
  last period.
- **Memory.** Free memory is a set of power-of-two Untyped blocks,
  managed buddy-style. An allocation splits the smallest block that fits;
  free halves merge lazily (§15.2). Guest RAM is allocated as independent
  2 MiB blocks. There is no separate object quota: a guest costs its RAM,
  its I/O pool (4 MiB by default) and about 6 MiB of host objects, so a
  256 MiB guest costs about 266 MiB.

- **Limits.** `l4h-vmmgr` checks a request's memory, ASIDs and CNode slots
  before starting it, and refuses with ENOMEM instead of exhausting itself;
  root does the same for what it makes for the guest (§9.3).
  - x86_64 seL4 has 4096 ASIDs, and a guest holds 66 of them: its
    VSpace, its pool of 64 process VSpaces, and its VMM. That allows about
    61 guests per host; `MAX_GUESTS` is 64.
  - `tests/run-limits.sh` fills the host and checks that it recovers.
  - Every size and address in a control request is range-checked before
    any arithmetic on it (no overflow), and a request that fails half way
    (e.g. no contiguous block large enough for the I/O pool) gives back what it
    took. Free root CNode slots are coalesced ranges, so the slot ranges
    of vNIC ports and disk DMA buffers are reused after a guest is
    destroyed, and splitting a memory block no longer keeps a slot for
    the parent.
  - Interrupt vectors are split: NICs 0–3, the serial monitor 8, disks
    16–79 (at most 64 disks are used).
- **Dashboard.** With a linear framebuffer from the boot loader (GRUB on
  UEFI; seL4 patch 0011 makes the multiboot2 header ask for one),
  `l4h-root` draws a read-only status screen every second: host, VMs (from
  vmmgr's status page, §9.3), disks, switches. Changed character cells only; 8x8 public-domain font.
- **Serial monitor.** `l4h-root` reads COM1 (I/O ports and IOAPIC IRQ 4)
  and runs `help`, `list`, `info`, `destroy <vm>`, `restart-dom0` and
  `reboot`. vmmgr runs `destroy` and `restart-dom0`, which root asks
  through the events page (§9.3); `reboot` resets the host as
  `host_reboot` does, the way out when neither dom0 nor vmmgr answers. The
  kernel keeps using the port for output (`tests/run-monitor.sh`). An
  absent UART (line status reads as `0xff`) disables the monitor. Input
  uses interrupts, including a remapped I/O APIC entry under Intel VT-d.
- **dom0 restart.** If dom0 reboots or crashes, `l4h-vmmgr` destroys it and
  boots it again from the boot image. Other guests keep running, and the
  new dom0 sees them through the control API (`tests/run-m6test.sh`).
- **Density gate.** `tests/run-density.sh` runs 30 guests of 256 MiB on 4
  cores (16 GiB QEMU) with 15 of them spinning. All 30 boot in about 45 s,
  every guest answers on its console within 0.5 s, worst case, and
  destroying them returns all memory.

---

## 8. Devices

### 8.1 Transport: `virtio-l4h` (guest side)

Linux virtio already allows custom transports; `virtio_mmio`, `virtio_ccw`
and `vdpa` are existing examples. `virtio-l4h` provides `virtio_config_ops`
for each device, with no trapped accesses:

- **Device page.** A shared 4 KiB frame laid out like the virtio-mmio register
  file plus the device config space. Reads are plain loads.
- **Synchronous register writes** (status, feature select, queue setup,
  `QueueReady`, reset) go through `seL4_Call(vmm_ep, op, args)`. They are
  rare.
- **Queue kick.** The guest sets a bit in the device page, then calls
  `seL4_Signal(vmm_notif)`. This is asynchronous, and the guest honours
  `VRING_AVAIL_F_NO_NOTIFY` and event-idx suppression, so most kicks are
  avoided.
- **Device interrupt.** The VMM sets an event bit in the target vCPU's event
  page, then signals `N_v`. The `l4h-irq` irqchip maps event bits to Linux
  IRQs. Virtio event owners implement `irq_set_affinity`, so standard Linux
  IRQ affinity writes update the VMM route and effective CPU mask.
- **Queue interrupts.** Virtio block queues have separate events and CPU targets. The transport
  reports these masks to Linux's block queue mapper. Other devices retain
  their device event and CPU target.
  Queue events occupy `80 + 4 * device_index` through that value plus three.
  The 64 device slots therefore use at most event 335 of the existing 512.
  The device page uses reserved fields for the queue event base and four
  CPU targets. A queue target of `UINT32_MAX` retains the device event.
- Discovery happens through the boot-info device table, not PCI or DT
  probing. Vrings and every buffer live in the guest's host-owned I/O
  pool and are addressed by GPA (§15.1). `VIRTIO_F_ACCESS_PLATFORM` is
  required.

### 8.2 Block, shared controllers and raw windows

A physical virtio-blk, virtio-scsi or NVMe PCI controller has one persistent blkd.
`BLK_ATTACH` attaches a finite, 4 KiB aligned LBA window to a guest before
boot. A writable window overlaps no other window of its disk; read-only
windows may overlap each other, so one seeded image can back many guests.
Every window appears as a separate virtio-blk
volume starting at sector zero. There is no image format, host filesystem,
thin provisioning or copy-on-write.

- Guest `virtio_blk` → l4h-vmm → per-client shared queue → blkd → device.
- **Guest queues.** Writable and read-only volumes offer four request queues
  through `VIRTIO_BLK_F_MQ`. Linux can select fewer queues for fewer CPUs.
  Requests include the queue, chain head and generation. Completions return
  only to that queue. The VMM visits queues in round-robin order and signals
  only queues whose used ring changed. Completion retries visit blocked
  queues, without reading every idle queue's shared available ring.
- **Flush and reset.** A flush waits for accepted requests from every queue.
  Later requests wait until the flush completes. Reset drains all accepted
  work before buffers can be reused. Reset of one queue returns completions
  to other queues and drops only the reset queue's completions.
- **Legacy devices.** Every virtio device the host drives (virtio-blk,
  virtio-scsi, virtio-net and the balloon) may also be a legacy (0.9.5)
  one: transitional device ID, registers in I/O BAR 0, no virtio
  capabilities, as on GCE N2 or under a hypervisor whose virtio predates
  1.0. Root gives the driver an IOPort capability for the BAR instead of
  mapping BARs; the driver programs a legacy queue (its size is the
  device's, at a 32-bit page number) and notifies through `QUEUE_NOTIFY`.
  A transitional device that has virtio capabilities is driven as a
  modern one. The disk and NIC drivers still need MSI-X; the balloon,
  which is polled, has none, and so no vector registers.
- Each client has its own immutable pool/window/permission configuration,
  channel and completion notification. The controller supports 512
  clients; blkd's submit loop visits only attached ones.
- Descriptor buffers must lie in that client's host-owned I/O pool. The
  driver translates pool GPAs to physical addresses; the device never sees
  guest RAM. Guest swiotlb performs the remaining payload copy.
- l4h-root and blkd both enforce the overlap rule (`DiskWindow::conflicts`). Request validation uses
  checked arithmetic and verifies block alignment, direction, permissions,
  operation and pool bounds. Hardware request tags are allocated by blkd,
  so identical IDs from different clients cannot collide.
- Submission runs round-robin, with bounded work per client and reserved
  completion capacity for outstanding requests.
- **Volatile attachments.** `BLK_ATTACH` takes flags: `BLK_RO`, and
  `BLK_VOLATILE` for a disk whose contents need not survive a power
  failure, such as the scratch disk of a VM that is discarded with it. Its
  VMM does not offer `VIRTIO_BLK_F_FLUSH`, so the guest treats the disk as
  write-through and turns `fsync`, journal commits and barriers into
  no-ops; blkd completes any flush from that client at once, as it does
  for a device without a volatile write cache. Writes the device has
  cached may be lost. A flush on a consumer SSD or a virtualized disk can
  take tens of milliseconds, and per-commit `fsync` dominates package
  installs and builds there. Other attachments of the disk, and dom0's
  provisioning flush, still flush the device.
- Destroy stops the client's VMM, drains that client's submitted work, then
  releases its mapping and pool. It does not reset a shared controller.
  On a five-second timeout, root suspends the driver and quarantines the
  controller. Its DMA memory remains allocated, and every affected guest
  pool is pinned when destroyed. No new attachment or provisioning write
  is accepted until host reboot.
- dom0 can seed or explicitly zero UNATTACHED ranges using `BLK_WRITE` and
  its ioctl staging buffer (up to 1 MiB per call). A zero-length call flushes
  the controller. Provisioning uses a private 1 MiB DMA scratch area and
  never permits writes overlapping a client, including read-only clients.
- A virtio-scsi controller, modern or legacy (0.9.5 in I/O BAR 0, as on
  GCE), has a host disk per direct-access logical unit (up to 16): blkd
  lists each target's LUNs with REPORT LUNS (LUN 0 alone if that fails)
  and skips other device types. Host disks are numbered by controller in
  PCI order, then target and LUN. Root starts every controller's blkd at
  boot and learns the virtio-scsi units there; each needs 4 MiB of
  physically contiguous DMA memory, and the host fails to boot without
  it, so a disk never lacks its driver later. A controller whose reset
  failed is not started and stays disabled (bus mastering off): its
  disks fail with `EIO`, and the host boots without them.
  blkd clients and quarantine are per controller: a drain
  timeout fails every disk of it. Requests become
  READ/WRITE(10 or 16) and SYNCHRONIZE CACHE commands. The driver uses up to
  four offered request queues, with one bounded slot table and MSI-X vector.
  Submission batches rotate between queues, with one notification per batch.
  Each command retains its queue for
  completion and retry. Provisioning uses queue zero. Requests split when they
  exceed the device's `seg_max` or `max_sectors`. Write protection and the
  write cache come from MODE SENSE; unit attentions and busy statuses are
  retried. Indirect descriptors are used when offered; otherwise each
  command slot owns a fixed run of ring descriptors.
- `DISK_INFO` additionally returns capacity and attachment count;
  `BLK_INFO` enumerates `(vm, start, sectors, read-only)` with a cursor. The legacy
  owner field identifies the first attachment, or -1 when none exist.

`tests/run-sharedblk.sh` checks concurrent clients, overlap and bounds
rejection, provisioning exclusion, destroy during I/O, read-only windows
shared by several guests, more than 64 attachments of one disk,
flush/readback and repeated reuse. Run it with virtio-blk, virtio-scsi (also
with both disks as LUNs of one controller) and NVMe (512 and 4096 byte
logical blocks). `tests/blk-windows.rs` exercises the production
validator on malformed requests and window/pool boundaries.
`tests/run-devicelimit.sh` fills dom0 and normal guests to 64 devices,
checks block I/O and networking at high device indices alongside a GPU,
rejects a 65th device, and restarts dom0 while a full guest survives.

### 8.3 Network: L2 virtual switches only

**Principle.** The hypervisor implements Ethernet switching. Routing,
NAT, DHCP and firewalling belong in a VM.

- **Path.** Guest `virtio_net` → `l4h-vmm` → shared net port rings →
  `l4h-netd` → destination port or uplink NIC. netd combines all switches
  and the uplink NIC drivers in one Rust component: modern and legacy
  virtio-net, gVNIC, Amazon ENA and the Intel X550 (below).
- **Multiple vNICs.** Each vNIC is on one switch and appears as a separate
  `ethN`. It shares the guest's limit of 64 devices with the console,
  memory and attestation devices, disks and, in dom0, control device.
  There are 48 guest ports in all.
- **Switches and uplinks.** The API creates switches dynamically, up to
  52 (one per guest port and NIC; switches are not deleted). Each is
  an L2 broadcast domain with its own learned MAC table. A physical NIC
  can be the uplink of one switch; a switch without an uplink is internal.
  A single netd serves all switches. VLANs, jumbo MTUs, static MAC entries
  and port rate limits are future work.
- **Ports and copies.** A vNIC has TX and RX rings of 2 KiB frame slots
  shared by its VMM and netd. Root adds/removes ports through
  `NETD_ADD_PORT`/`NETD_REMOVE_PORT`; port memory belongs to the guest's
  arena. The guest first bounces buffers through its host-owned I/O pool.
  The VMM copies between that pool and port slots; netd copies slot to
  slot, or slot to NIC DMA buffer. Making the I/O pool itself a netd port
  region could remove the VMM copy in future.
- **Offloads.** Checksum and TSO metadata pass through in the virtio-net
  header. netd validates flags, checksum offsets and GSO type, including
  that a GSO frame is TCP over IPv4/IPv6. Incoherent headers are dropped.
  A frame for a port that cannot take its offload is segmented and
  checksummed in software. Guest vNICs have one RX/TX queue pair.
- **Full rings hold, not drop.** A guest's RX ring has 24 slots, fewer
  than one TCP burst. Frames for a full ring wait in a per-port backlog
  (at most 512 frames and 2 MiB per port) and are
  delivered in order; netd sets `rx_wanted` in the port and the VMM kicks
  netd when it frees RX slots. Likewise frames for an uplink NIC without a
  free TX buffer wait in a per-NIC backlog (512 frames, 4 MiB). All
  backlogs share one pool of 2 KiB chunks, 16 MiB, fixed in netd's
  image; a frame takes whole chunks. Only
  beyond those bounds is a frame dropped, so a guest that stops reading
  costs nobody else. Dropping instead cost a TCP retransmission timeout
  per burst: downloads over the QEMU uplink ran at about 3.5 MB/s, now
  about 40 MB/s on the nested dev box.
- **NIC interrupts and notifications.** netd turns RX interrupts off while
  it drains the NIC's queue (re-checking after turning them on) and takes
  TX interrupts only while frames wait for a TX buffer. It notifies the
  device once per batch, not per frame, and not while the device says it
  is busy with the queue (`VIRTQ_USED_F_NO_NOTIFY`). Each interrupt and
  notification is a VM exit, costly when nested.
- **Receive offloads.** netd's NIC driver negotiates `GUEST_CSUM` and,
  with mergeable RX buffers (`MRG_RXBUF`, 256 × 4 KiB), `GUEST_TSO4/6`,
  so a device that has large frames delivers them whole. Frames from the
  uplink then pass GRO (`offload::Gro`): consecutive full-size segments
  of one TCP flow, merged only where Linux's GRO would merge them, become
  one GSO frame with a partial checksum. Segments without a checksum
  verdict from the device are verified first. A guest thus takes one
  frame per up to 44 segments; every frame costs wakeups on its way.
- **gVNIC.** `l4h-netd/src/gvnic.rs` follows Linux `gve` with the DQO
  queue format and raw DMA addressing (DQO RDA), which C3 and later offer;
  a device without it (GQI formats only) makes netd panic. It
  configures registers in BAR 0 through a big-endian admin queue and rings
  little-endian doorbells in BAR 2. One TX queue (with its completion
  queue) and one RX buffer queue (2 KiB buffers, with its completion
  queue). As Linux, it configures a notification block per MSI-X entry
  but the last; the TX and RX queues' blocks share netd's vector, and the
  management vector stays masked. A DQO block masks itself when it fires;
  netd re-arms the RX block after draining and the TX block only while
  frames wait. Transmit: checksum offload and TSO (a context descriptor;
  the TCP checksum field loses the length, as in `gve_prep_tso`), for
  MSS 88–9728 and headers up to 255 bytes, else netd segments. Buffers are
  freed by packet completions, or by reinjection completions after a miss
  completion. Receive: the device's checksum verdict (with its packet type
  map) becomes `DATA_VALID`, then GRO as for virtio-net; the device's own
  coalescing (RSC) is off. On the revision 0 device of C3, releasing an
  admin queue that is not registered makes the device reset itself about
  a second later, so netd releases only a registered one.
- **ENA.** `l4h-netd/src/ena.rs` follows Linux `ena` for the Elastic
  Network Adapter of Nitro EC2 instances (1d0f:ec20 and the other IDs
  Linux takes). Tested on a c6i.large's secondary ENI through Linux/VFIO
  (`tests/ena-vfio`, compiling the production driver unchanged), and in
  a full UEFI/seL4 boot on c6i.xlarge (`tests/ec2-test.py`). Both LLQ and
  host-memory TX pass packet/checksum/GSO tests, 65,600 checked UDP echoes
  across the 16-bit index wrap, and fresh MSI-X delivery. Host information
  must name a recognized OS class and ENA specification version: l4h uses
  the userspace class, its own strings and spec 2.0. It reports driver
  version 2.0.0; Nitro accepts 1.0.0's host info but rejects CQ creation
  with status 6. See `tests/ec2.md` and the recorded hardware results.
  It resets the device, reads registers readless (the device writes them
  to DMA memory)
  unless the PCI revision says otherwise, and configures it through an
  admin queue of 64-byte commands, polled. One TX and one RX queue, each
  a submission queue with its completion queue, both on MSI-X entry 1;
  entry 0 is the management vector (admin completions and the AENQ's
  events; netd logs link changes and errors, and acknowledges
  keep-alives). Both
  carry netd's one vector. The device masks the I/O vector when it fires;
  netd unmasks it through the TX CQ's register (as Linux, with 20 µs RX
  and 64 µs TX coalescing) after draining RX, and while frames wait. An
  RSS table sends every frame to the RX queue. Transmit: as Linux, the
  low-latency queue (LLQ) in BAR 2, which root maps write-combining when
  it fits netd's 16 MiB window: one 128-byte entry per frame with the
  metadata and buffer descriptors and the frame's first 96 bytes, written
  in 64-bit stores, `sfence`, then the doorbell, at most the device's
  burst between doorbells. Without the BAR or Linux's LLQ layout, the
  descriptors go to a ring in host memory. Every frame has a metadata
  descriptor (meta caching off); partial L4 checksums over IPv4/IPv6 are
  left to the device when it offers them. ENA does no TSO here: netd
  segments. TX buffers hold frames up to the device's MTU, which netd
  sets to its maximum; longer frames are dropped. Receive: 2 KiB buffers,
  a frame spanning several (jumbo frames); an L4 checksum the device
  checked and found good, on an unfragmented frame without an IPv4 header
  error, becomes `DATA_VALID`. Not done: the keep-alive watchdog and
  device reset on errors, which Linux has (netd has no timer), and
  ENA Express.
- **Learning and security.** MAC entries age after 300 s, with at most
  1024 per switch and 8192 in all. A full table drops expired entries and
  then stops learning; unknown unicast, broadcast and multicast are
  flooded within the switch. netd handles at most one ring's worth of
  frames per kick and ignores rings whose indices claim more. MAC lock
  is on by default. Isolated ports exchange no frames with each other,
  but can reach normal ports and the uplink (`--nic ...,isolated`).
- **Intel X550.** `l4h-netd/src/ixgbe.rs` follows Linux `ixgbe` for the
  X550 (8086:1563, 15d1), as on Latitude.sh m4.metal servers. It resets
  the MAC under the SW/FW PHY semaphore but not the PHY, which
  renegotiates the link with the firmware's settings (about 7 s on
  10GBASE-T), then sets up one RX and one TX queue of advanced
  descriptors: 512 RX buffers of 2 KiB (a larger frame spans buffers),
  CRC stripping, no RSC or RSS, promiscuous like the other uplinks. RX
  raises MSI-X entry 0 and TX entry 1, both programmed with netd's one
  vector, so EIMS/EIMC mask them separately; causes clear themselves
  (EIAC) and are moderated to about 20,000 per second. Receive: an L4
  checksum the device verified (L4CS without TCPE, and no IPv4 header
  error) becomes `DATA_VALID`. Transmit: a context descriptor carries
  checksum offload for TCP and UDP over IPv4/IPv6 and TSO (MSS 64–9216);
  as Linux, the TCP checksum field loses the length and the IPv4 length
  and checksum are left to the device; data descriptors take at most
  16 KiB each. `tests/ixgbe-vfio` compiles the driver unchanged into a
  Linux program that drives a real port through VFIO (ARP, ICMP, DNS, UDP
  checksum offload, 4 KB and 60 KB TSO, both interrupt causes); it was
  run on the Latitude.sh hardware before the first boot.
- **Router VMs.** On GCE, the router's uplink vNIC uses the instance's MAC
  address. dom0's first vNIC takes the uplink NIC's MAC by default. The
  router's other vNICs join internal switches and Linux provides NAT or
  routing. QEMU guests can also sit directly on the uplink switch.
- **Tests.** `tests/fuzz-virtq` checks that GRO output segments back into
  exactly the frames that went in, and that corrupted or other-flow
  segments do not merge. `tests/run-nettest.sh` covers DHCP and ping over the QEMU
  uplink, internal switches, multiple vNICs, isolation and MAC lock.
  `tests/run-router.sh` uses a Debian router with nftables masquerade to
  connect an internal guest to the outside.

### 8.4 Console and other devices

- **Console.** Each vCPU writes its console output, as records numbered
  from one counter of the guest, into a ring in its event page, and kicks
  the VMM. The VMM prints the records of all rings in that order into a
  host-owned per-guest ring and to the serial port; root reads that ring
  for `console_read`. Head and tail wrap at twice the ring size, so their
  distance distinguishes full from empty without aliasing unread data.
  The VMM drains at most one ring's worth before polling for other work;
  it carries any remainder forward even when the guest did not kick again.
  It tracks the next sequence, so a ring sampled empty cannot let a later
  record from another vCPU overtake it. A missing sequence gets 100 ms
  from the first observed gap to appear; further kicks do not extend that
  deadline. A one-shot timer wakes the VMM, which can sleep or serve other
  work meanwhile. On expiry it reports the missing records and skips to
  the oldest published sequence, discarding any skipped records that arrive
  later. This can lose late tty output as well as logs, but a stalled
  writer cannot indefinitely hold up other vCPUs' output. Poweroff flushing
  skips gaps immediately, within its byte budget.
  It polls the endpoint with its notification temporarily unbound, so a
  stream of console kicks cannot take precedence over queued hypercalls.
  After rebinding it re-arms any gap deadline: seL4 drops timer expiries
  while no notification is bound. Hypercall arguments are preserved across
  both TCB invocations.
  Writers never wait: output that does not fit is
  counted, and the VMM reports the count, except tty output, which hvc
  holds until the VMM raises the console event for room. Console input
  and power requests use the shared console device page.
- **Control.** `l4hctl`, dom0 only (§9.1).
- **RTC.** `/dev/rtc0`, with alarms, on the host's wall clock (§5.8).
- **Display.** virtio-gpu, 2D (§8.6).
- **Future devices.** virtio-rng, virtio-vsock and virtio-balloon.

### 8.5 IOMMU (AMD-Vi and Intel VT-d)

On an AMD or Intel host, `l4h-root` confines devices with the IOMMU, which it
drives itself (`l4h-root/src/amdvi.rs` and `vtd.rs`, selected by `iommu.rs`). seL4 keeps
`KernelIOMMU` off. seL4's VT-d code was tested on two chipsets, has no
AMD support, and would only let root delegate I/O mappings, which nothing
in l4h needs: root alone gives devices memory.

- **AMD boot.** Before it enables or resets any PCI device, root reads the
  IVRS table and takes over every IOMMU on segment 0. It maps the IOMMU's
  registers and builds one device table for all of them, in which every
  device ID is blocked (V and TV set, no page table, no IR/IW). It sets a
  command buffer and an event log per IOMMU, enables them, and
  invalidates whatever the firmware left cached. The IVHDs give each
  device ID's interrupt pass-through and SysMgt bits, and its alias
  behind a PCI bridge.
- **Domains.** Each requester group root enables gets a domain ID and a
  4-level I/O page table. Devices with the same IVHD alias share that
  domain; attaching a sibling preserves the alias's existing DMA and
  interrupt tables. Each attached device's entry and its alias point to
  these tables. They map the memory the group's devices were given, at its
  physical address, so drivers are unchanged. The virtio drivers accept
  `VIRTIO_F_ACCESS_PLATFORM`.
  Devices sharing a requester can reach each other's mapped buffers and
  raise each other's permitted interrupts: the bridge prevents the IOMMU
  from distinguishing them. Other requester groups remain isolated.
  - A NIC (netd) gets its 4 MiB of DMA memory.
  - A disk controller (blkd) gets blkd's 4 MiB, and each client's I/O
    pool while it is attached. `blkd::remove` unmaps the pool after the
    drain, or after a quarantine. Shared pools are reference-counted per
    domain and allocation, so only the final release removes their
    translations. blkd's own DMA memory stays out of use as before.
  - The balloon (memd) gets its DMA pages. Free page reports name memory
    the device is never given. A balloon that translates them (QEMU's
    `iommu_platform=on`) cannot report.
- **AMD interrupts.** Root remaps them too (`iommu_intremap`, on by default).
  A requester group root enables gets a table of 256 interrupt entries
  (32-bit format), named in its device table entries with IntCtl "remapped".
  `AmdVi::msi_data` fills one entry per vector (fixed delivery to APIC ID
  0, the vector `pci::msi_data` gives) and returns its index. Root puts
  the index in blkd's and netd's MSI data in place of the vector, so the
  drivers write the MSI-X table unchanged. The device can then raise only
  its group's vectors: any other MSI data selects an invalid entry, and the
  IOMMU drops the interrupt. Devices root does not drive get IV set and
  no table, so their MSIs are dropped. The I/O APICs and HPETs (IVHD
  special devices) keep IV 0: seL4 programs them in the compatibility
  format, so their interrupts pass unremapped. A device that spoofs their
  requester ID can still inject any vector; root does not turn on ACS
  source validation. The entries use the 32-bit format, so destinations
  are APIC IDs below 256 (no x2APIC XTEn or GA mode).
  Updates invalidate the interrupt-table cache for every attached group
  member and the alias, including members attached after a handle was issued.
- **AMD unity ranges.** IVMD ranges stay mapped for the devices they name:
  ranges for all devices in one shared domain, others in a domain per
  range. Aliased requests use the alias's entry at boot too. A driven
  group gets the ranges of all its members, including devices without a
  driver. Its new domain is separate from boot-only domains that can
  contain unrelated requesters. Recyclable DMA allocations cannot overlap
  these permanent ranges; overlapping unity ranges retain the union of
  their permissions.
- **AMD tables.** The device table, I/O page tables, command buffers and event
  logs come from 2 MiB chunks of root memory, mapped in root
  (`layout::IOMMU_TABLES`) and kept until reboot. Unmapping clears the
  leaf entries and keeps the tables, so a pool slot that is attached again
  reuses them. Installing a mapping or removing its final owner ends with
  INVALIDATE_IOMMU_PAGES for the domain and a COMPLETION_WAIT. A new map
  does this too, since an IOMMU may cache missing entries (NpCache).
  Root stops if an IOMMU does not
  complete a command within a second, since it could then no longer
  confine anything.
- **AMD faults.** Root reads the event logs every 100 ms (its balance tick)
  and prints up to 8 events per tick: page faults, with the device, the
  address and the domain, and errors.
- **Status.** `l4hctl iommu` (`CTL_IOMMU_INFO`, dom0 only like every
  control call) shows whether the IOMMU is on, off (`iommu=0`), absent
  or unusable; whether interrupts are remapped; the devices confined and
  those behind no IOMMU; and the events logged since boot. `l4hctl info`
  shows the first two in one line.
- **Off.** With no DMAR or IVRS, or `iommu=0` in `l4h.conf`, every operation is a
  no-op and devices reach all memory, as before. `iommu_intremap=0` keeps
  DMA confined but passes every interrupt unremapped. Hosts without a
  supported IOMMU include cloud VMs without a vIOMMU and aarch64. A
  device that no firmware scope covers is reported at enable and left untranslated.
  Root blocks requesters with no attached devices. An integrated GPU that scans out
  of system RAM therefore loses its picture: use `iommu=0` there.

Intel VT-d uses the same driver-facing operations, with these differences:

- **Discovery.** DMAR DRHDs describe segment 0's remapping units. Explicit
  endpoint and PCI bridge scopes take precedence over INCLUDE_PCI_ALL;
  paths are resolved using the bridges' secondary/subordinate buses. Invalid
  lengths, checksums, overlapping scopes and unsupported scope types fail
  discovery before any unit is changed. Other PCI segments are not driven.
- **DMA.** Each unit has a legacy root table and per-bus context tables.
  Missing entries block DMA; each attached requester gets a private 39- or
  48-bit second-level page table and domain ID. Contexts reject translated
  requests and ATS. RMRR ranges are identity mapped for their devices before
  translation is enabled and remain mapped after attach/unmap. Mapping
  beyond the unit's address width is rejected. Root walks PCI bridge
  headers to resolve requester aliases: a conventional bridge uses its
  own BDF, a PCIe-to-PCI bridge uses secondary-bus:00.0, and PCIe ports
  preserve IDs. The outermost alias wins across nested bridges. Devices
  sharing that requester share one domain; attaching another member adds
  its buffers without replacing existing mappings. Shared guest I/O pools
  are reference counted: detaching one disk leaves the pool mapped until
  the last user releases it, then invalidation drains DMA before reuse.
  RMRRs of any member
  remain reserved for the whole group. Phantom functions and device-specific
  requester quirks are not supported.
- **Invalidation.** Units with queued invalidation get a page of 128-bit
  descriptors and a completion word. Maps invalidate cached misses; unmaps
  invalidate the domain's IOTLB and wait for DMA reads and writes to drain.
  Older units can use register invalidation for DMA if they support draining.
  Noncoherent table walkers get CLFLUSH and memory barriers. Tables remain
  allocated until reboot. Command errors or a one-second timeout stop root.
- **Interrupts.** When firmware and every unit support it, root enables
  interrupt remapping with a 256-entry table per unit. Each IRTE permits
  exactly one requester ID and vector, delivered to APIC ID 0. PCI bridge
  aliases apply here too, even when virtio bypasses DMA translation
  (`iommu_platform=off`). Members of a shared requester group can reach
  the group's DMA memory and interrupt entries; hardware cannot isolate
  them from one another. Root logs each device's shared requester at attach.
  The common
  `Iommu::msi` interface returns both address and data: VT-d puts the table
  index in the remappable MSI address (SHV=0), while AMD-Vi uses MSI data.
  Compatibility interrupts are blocked globally, so they cannot bypass
  source validation. Root matches DMAR's I/O APIC scopes to MADT IDs and
  allocates an IRTE for the UART's vector. seL4's `GetIOAPICRemapped`
  extension (patch 0025) programs the pin with that table index and keeps
  ownership of masking and acknowledgement. The UART remains interrupt
  driven; if firmware lacks its I/O APIC scope, root disables the monitor
  with a diagnostic instead of allowing compatibility interrupts. Local
  APIC timers and IPIs are unaffected. Extended interrupt
  mode is not supported. If interrupt remapping is unavailable, DMA remains
  confined and the status reports interrupts as not remapped. As with
  AMD-Vi, requester validation relies on the PCI fabric: root does not
  enable ACS source validation to prevent requester-ID spoofing.
- **Faults.** Root polls the primary fault records, prints up to eight per
  tick with requester ID, reason and fault information, and counts every
  observed record and overflow in `l4hctl iommu`. It masks the unit's fault
  interrupt and invalidation-completion interrupt.

`L4H_QEMU_IOMMU=intel` adds QEMU's `intel-iommu` with interrupt remapping
and caching mode enabled, so cached missing translations must be invalidated.
`tests/run-vtdtest.sh` checks firmware parsing, address bounds, interrupt
source validation and command encodings on the host; `--qemu` also runs
virtio-blk, NVMe, VM lifecycle/unmapping, NIC and serial-monitor tests,
including boot with interrupt remapping or the whole IOMMU disabled.
`tests/vtd-net-qemu.py` checks two NICs and two disks on the root bus,
behind conventional and PCIe-to-PCI bridges, and behind nested bridges. It exercises both
`iommu_platform` settings and repeatedly creates/destroys a second guest
to check packet delivery, disk I/O and shared pool mappings. Its optional
`--tap TAP0 TAP1` uses vhost-net with existing TAP interfaces instead of QEMU's userspace backend;
both interfaces need access to a gateway at 10.0.2.2/24.
An unattached QEMU EDU device also attempts DMA and forged MSIs: its DMA,
another device's valid IRTE, the UART I/O APIC's IRTE, and a non-present
IRTE must all fault. The `--bridge pci|pcie-pci` variants also verify that
an EDU sharing the disk's requester cannot DMA outside the group's buffers.
The UART's redirection entry must use remappable
format, and serial commands must arrive through interrupts. QEMU
10 passes compatibility-format interrupts through regardless of CFIS
(`hw/i386/intel_iommu.c`, `vtd_interrupt_remap_msi`), so that test checks
CFIS is clear but cannot verify compatibility blocking in this emulator.

`L4H_QEMU_IOMMU=amd` (`tools/run-qemu.sh`) adds QEMU's `amd-iommu`
(`intremap=on`, which needs `kernel-irqchip=split`) on a q35 machine,
and sets `iommu_platform=on` for virtio disks and NICs (NVMe always
translates). `run-blktest.sh` passes with it on NVMe and
virtio-blk. With the pool left unmapped, the controller's DMA to it fails
and the guest's mount fails. QEMU's emulation returns no translation but
logs no page fault event, so the event log reader is untested there.
`run-nettest.sh` and `run-ctltest.sh` pass with it too. QEMU's
`amdvi_ir_*` traces show the controller's MSI data 0 remapped to its
vector. Given an index whose entry is invalid, the controller's
interrupts are aborted (`RemapEn is disabled`) and its I/O stalls, while
the I/O APIC's pass unremapped.

`python3 tests/vtd-net-qemu.py --iommu amd` runs the two-NIC, two-controller
bridge regression on AMD-Vi: root bus, conventional PCI, PCIe-to-PCI and
nested PCI bridges, with translated and bypass virtio NIC DMA. Both NICs
must pass traffic after all devices attach, and a second guest must read
and write both disks across repeated create/destroy cycles. Add
`--no-intremap` to check domain sharing with interrupt remapping disabled,
`--controllers 17` to exceed the former 16-entry interrupt-table limit,
or `--tap TAP0 TAP1` to use vhost-net. Logs go in `build/amdvitest`.
The AMD-Vi PCIe-to-PCI case needs QEMU 10.2 or later: QEMU 10.0 caches
the secondary bus number before firmware assigns it, so its DMA arrives
as requester 00:00.0 instead of the alias in IVRS. CI uses conventional
PCI bridges with Debian 13's QEMU 10.0, including remapping disabled and
17 disk controllers sharing an interrupt table.
`python3 tests/amdvi-qemu.py` inspects the devices' and alias's shared
tables, checks that every vector survives, and uses EDU devices to verify
that both an unrelated requester and an aliased sibling cannot write
outside their mapped memory. It checks interrupt-abort traces for an
unrelated requester's attempt to use the group's index and a group
member's attempt to use an unallocated index.

### 8.6 Display: virtio-gpu

`l4h-vmm` serves a virtio-gpu device (2D, one scanout; `gpu.rs`), which
dom0 gives a VM before it starts (`gpu_attach`, `l4hctl create --gpu
WxH`), with the size its display reports as the preferred mode. The
guest uses Linux's `virtio_gpu` driver, a module.

- **The guest's buffers stay in its I/O pool.** As every virtio-l4h
  device, it requires `VIRTIO_F_ACCESS_PLATFORM`, so a resource's backing
  is the I/O pool pages the guest's DMA layer bounced the buffer into,
  and the driver syncs the whole buffer there before every
  `TRANSFER_TO_HOST_2D`. The backing therefore holds what the host
  should show, and the VMM keeps no copy of any resource: a transfer only
  checks its bounds. The I/O pool must hold four images of the scanout
  (`GPU_POOL_IMAGES`); `l4hctl` sizes it so by default.
- **The display area.** `RESOURCE_FLUSH` of the resource on the scanout
  copies the flushed rectangle into the display area: a header (frame
  counter, size, format) and the image, host frames that the VMM and root
  both map. It is the one image the host keeps. The VMM writes it under
  a seqlock (the frame counter is odd during an update), so root's reader
  (`gpu_read`, 1 MiB per call into dom0's control data area) can tell a
  torn copy, which it reports as `-EAGAIN`; `l4hctl screenshot` reads
  again, and writes a PPM. Root takes the image's size from its own
  record, not from the header the VMM writes.
- **The VMM's tables** of resources and their backing (1024 resources,
  65536 pieces of backing, merged where they are contiguous) live in
  host frames of their own, mapped only in that VMM, so VMMs without a
  GPU pay nothing for them. Commands complete at once and in order, so
  a fence is done with its command. There is no cursor plane (the cursor
  queue's commands are dropped), no EDID, no 3D, and no blob resources.
- **Memory.** The display area and tables come from the guest's arena,
  which destroy returns; root maps the display area at
  `layout::DISPLAY`. A 1920 x 1200 display is about 10 MiB.

`tests/run-gputest.sh` has a VM draw with DRM dumb buffers, then flip,
then turn its display off, and checks every pixel of dom0's screenshots
(`gpucheck`), and that the host refuses a display too small or an I/O
pool too small for it, and that destroy returns the memory. Still to
come: something that shows the display live (a VNC server in dom0 on
`gpu_read`, or the host's own framebuffer), input, and a cursor.

---

## 9. Host components

All host components are Rust: no_std, using the rust-sel4 crates `sel4` and
`sel4-root-task`.

Device drivers are also written in Rust, following sDDF's design
(shared queues and block requests that add no host data copy,
virtualiser/switch components) rather than linking sDDF's C drivers.
sDDF's components assume a static, Microkit-shaped system, while l4h
attaches and detaches guests at runtime. A single language and runtime for
the host keeps that dynamic plumbing simple.

| Component | Instances | Role |
|-----------|-----------|------|
| `l4h-root` | 1 | Boots the host and spawns the other components. Owns PCI, the IOMMU, interrupts, disks, reset and the RTC. Makes guests' I/O pools, disk channels and netd ports when vmmgr asks, and authorizes disk and NIC attachments. Serves the control ops on the host's disks, switches and NICs, runs the monitor and the dashboard. |
| `l4h-vmmgr` | 1 | Builds guest CSpaces, kernel VSpaces, vCPUs and boot info, from memory it gets from memd; loads dom0's images (modules) and copies runtime image uploads; spawns guests' VMMs. Runs lifecycle, the control API and balancing (§9.3). |
| `l4h-vmm` | 1 per guest | Serves virtio backends, console and hypercalls using the guest's I/O pool and host-owned shared pages. Never maps guest RAM. |
| `l4h-blkd` | 1 per attached disk | Validates pool addresses and LBA windows and drives a virtio-blk, virtio-scsi or NVMe PCI disk. |
| `l4h-netd` | 1 | Runs all L2 switches, dynamic guest ports and the virtio-net, gVNIC, ENA and X550 uplink drivers. |
| `l4h-trustd` | 1 | Maintains taint/seal flags; with a TPM, quotes its signing key and signs guests' reports (§9.2). |
| `l4h-memd` | 1 | Owns the free memory and every guest's RAM blocks; gives root and vmmgr memory for host objects; reports free memory to the hypervisor (§16). |

**No dynamic allocation.** Host components are built so that nothing a
guest, dom0 or a device does can exhaust their memory: a component that
runs out cannot recover, and with it go every guest it serves (root,
vmmgr or memd: the whole host). So their state is sized when they start, from
constants (`MAX_GUESTS`, queue sizes) or from the host (memd's table),
and lives in fixed arrays and tables, not on a heap. Where allocation is
truly needed, it is bounded by a stated limit that is checked before
the allocation, fails as an error rather than a panic, and is never
made per request on a path whose size a guest or a client controls.
A component without a heap says so (`component!(main, no_heap)`), and
does not link `alloc`. The root task, vmmgr, memd, netd, blkd and the VMM have
no heap; per-request state is in fixed tables, and state too large for
a stack is in statics (`l4h_host::fixed::{StaticCell, Scratch}`).
Every stack has an unmapped page below it, so an overflow faults rather
than writing over statics: root maps each component's stacks (its main
thread's and its keeper's) in a region of their own (`l4h_host::STACK_TOP`;
vmmgr's main stack is 1 MiB, as root's, since it builds guests as root
did), and unmaps the lowest page of its own stack, which seL4 places in its
`.bss`, at boot. Stack probes touch every page of a large frame in
order, so one page catches any overflow. This was missing until root's
1 MiB stack overflowed into its disk table: its allocator's 240 KiB of
tables, now a static, were on the stack, in several copies in a debug
build. The one heap is trustd's, for the third-party AML interpreter of the TPM
start method: its size (`aml::HEAP`) is bounded by the firmware's
tables, which trustd checks first, never by a guest.

**Shared crate boundaries.** `l4h-abi` defines the guest ABI and
`l4h-virtio` implements the shared virtio PCI transport. Host infrastructure
is divided by responsibility:

| Crate | Responsibility | Boundary |
|-------|----------------|----------|
| `l4h-host` | Component protocols, address-space and CSpace layouts, shared data structures, bounded containers, and pure validation helpers. | Independent of seL4 calls, runtime initialization, and task ownership. |
| `l4h-rt` | Component entry, TLS and IPC-buffer setup, panic handling, keeper threads, optional heap, and common runtime conveniences. | Runs a component using the resources its parent provisioned. Task construction and the memd grant allocator belong in `l4h-task`. |
| `l4h-task` | Kernel-object and CSpace allocation, memd grant client, ELF loading, component spawning, CPU topology, and VSpace/scratch mappings. | Callers supply capabilities, storage, mappings, and ASID assignment. Boot setup, resource authorization, and placement policy stay in the executables. |

Both `l4h-rt` and `l4h-task` depend on `l4h-host`; they are independent of
each other. Shared implementation belongs in a library imported through
Cargo. Executables must not import another executable's source files.
Embedding a component's ELF to start it is a separate deployment concern.

Root and vmmgr currently use `l4h-task`: both allocate kernel objects,
construct address spaces, and spawn components. Each supplies its own
CNode, allocator table storage, scratch VSpace and addresses, memory-service
endpoint and exchange slots, and spawning capabilities. Their ASID-pool
ownership and assignment policies remain local.

Other components reuse the library when they need those mechanisms:

- **blkd, netd and trustd** use capabilities and mappings installed by their
  parent. Their runtime needs are covered by `l4h-rt`. Netd's fixed packet
  buffer pool and trustd's bounded AML heap do not allocate kernel objects.
- **l4h-vmm** accesses its mapped I/O pool and relays guest memory-hotplug
  requests. Its memd capability permits only the guest's hotplug operations;
  `l4h-task::memd::MemdLink` serves clients that receive and return Untyped
  grants through exchange slots.
- **l4h-memd** provides the memory service. Its allocator tracks physical
  blocks, ownership, retained capabilities for revocation, and free-page
  reporting. That state belongs to memd; the client allocator in `l4h-task`
  manages objects and arenas made from grants.

Add a `l4h-task` dependency when a component needs its allocation, mapping,
or loading mechanisms. Ordinary IPC and access to already provisioned
resources use `l4h-rt` and seL4. Extract further shared mechanisms when their
semantics match, keeping service-specific policy and accounting local.

Serial output uses seL4's printing syscall; root drives COM1 input for the
monitor. There is no separate serial virtualiser. A kernel print is a
synchronous serial write with interrupts off, which stalls its core for the
whole message and breaks timing, so prints are kept rare:

- The kernel never reports spurious interrupts (`KernelIRQReporting` off);
  QEMU/HVF raises tens of thousands of them.
- Host informational messages (device discovery, guest lifecycle, balancer
  moves) use `info!`, which prints only when `host::VERBOSE`: not in builds
  made with `L4H_RELEASE=1`. Release builds print critical errors only, and
  repeated ones (failed I/O) only the first few times (`l4h_rt::ErrorLimit`).
- Guest consoles, dom0's included, are copied to the serial port only when
  verbose. They always go to the console rings that `console_read` serves.
- The serial monitor's replies and the opt-in watchdog dumps always print.

Host diagnostics from root, vmmgr, VMMs and device services also go to a
shared, bounded log ring (`l4h_host::log`), including `info!` in release
builds, Rust panics and keeper fault reports. `l4hctl logs` reads a snapshot;
`l4hctl logs --follow` polls for new records. `CTL_LOG_READ` is an additive
control operation available only to dom0, with independent sequence cursors
and an explicit count of unavailable records. Guest kernel faults include
the VM id, vCPU and fault registers; guest power requests distinguish power
off, reboot and kernel panic. Guest console text remains in its own rings.

The host ring retains 256 records in 132 KiB, with elapsed host time and
component id on each line. Root owns page-aligned image storage, shares only
those frames with its components, and gives vmmgr frame capabilities to map
into VMMs. Mapping capabilities belong to each component's arena; destroying
a VM neither revokes the shared frames nor clears its diagnostics. Records
are at most 480 bytes including the prefix and newline, with an explicit
truncation marker. Logs are volatile and do not survive a host reboot.

Logging formats on the writer's stack and publishes through atomic memory
operations, without allocating, making an IPC or touching message registers.
Writers never wait on a lock: if a writer is preempted or faults in a slot,
other writers use the remaining slots. Readers validate the slot generation
around atomic payload reads and report overwritten, dropped and incomplete
records as unavailable. No reader can consume another reader's history or
block host progress. Querying requires a functioning dom0 and vmmgr; this
does not capture seL4's own debug stream or make a crashed host queryable.

**Guest boot protocol.** The guest boots without firmware or a bootloader.
vmmgr parses the guest kernel's ELF (§9.1). For runtime guests, the dom0
`l4hctl` client parses the ELF and vmmgr copies uploaded segments and
initramfs bytes into the new guest's boot frames. vmmgr constructs the kernel VSpace
and `struct l4h_bootinfo`, then starts vCPU0 at the entry point with `rdi`
(`x0` on aarch64) pointing at boot info. It holds:

- the guest ABI version (currently 3);
- RAM size, direct-map base, block count and boot-block count;
- the I/O pool GPA and size;
- the vCPU count and pre-assigned VSpace count;
- the device table;
- the command line;
- the time-counter frequency and flags;
- on aarch64, the CPU feature ID registers (EL0 cannot read them).

Capability slots and special mappings, including event-page addresses,
are defined by `include/l4h/abi.h`, the single source of truth. The guest
includes it directly. `host/l4h-abi/src/lib.rs` is a handwritten Rust
mirror with layout assertions; bindings are not generated with bindgen.
The control protocol has its own version, currently 1.

### 9.1 Control plane: dom0 and the runtime API

**Starting dom0.** `tools/build-host.sh` builds the services and root,
and `host/l4h-root/build.rs` embeds the services' ELFs (vmmgr's embeds
l4h-vmm's). The guest kernel
and its module tree (§5.6), dom0's initramfs and the host settings are
named modules (`guest-kernel`, `guest-kmods`, `dom0-initrd`,
`l4h-config`); root has none of them built in. They come from:

- **The UEFI application and the EFI system partition** (deployment). l4h
  ships as one UEFI application per seL4 variant (§10), the same for every
  host. GRUB passes the guest kernel and its module tree from its memdisk,
  and `/l4h/dom0/initrd` and `/l4h/l4h.conf` from the partition, as boot
  modules. On BIOS, GRUB passes the same files from a directory on a
  filesystem (§10). seL4 keeps them intact (patch 0021); root maps them for good,
  since restarting dom0 loads them again. QEMU's multiboot `-initrd` can
  pass the same modules.
- **Root's own ELF** (x86_64 and aarch64; aarch64 has no boot loader
  that passes modules). `tools/add-modules.py` appends the files to a
  built `l4h-root.elf` as one more `PT_LOAD` segment, right after root's
  last one, in the program header of `PT_GNU_STACK` (which seL4
  ignores), and writes the segment's address and size into an anchor
  static in root (`bootmod.rs`). The kernel or the loader then maps the
  files with the rest of root; no Rust is rebuilt. The QEMU scripts do
  this from `L4H_GUEST_KERNEL`, `L4H_GUEST_KMODS`, `L4H_DOM0_INITRD` and
  `L4H_CONFIG` (`tools/dom0-modules.sh`).

Boot loader modules win over appended ones of the same name. Without a
`guest-kernel`, root starts no vmmgr, and no guests, and serves only the
serial monitor. Root maps the guest kernel, its module tree and dom0's
initramfs into vmmgr, which loads dom0 from them.

The settings (dom0's memory, vCPUs, I/O pool, disks and its window of
disk 0, NICs, internal
switches and command line; the uplink NICs, the boot disk, the serial port
and IRQ, the framebuffer console and the watchdog) default to the
`L4H_*` variables root was built with. `l4h.conf` overrides them: one
`key=value` per line, in lowercase without the prefix (`dom0_mem_mb=1024`,
`uplink_nic=01:00.1`). GRUB sources the same file for `serial_port` and
`fb_console`, so it is written as GRUB script: no spaces around `=`, values
with spaces in double quotes. Root reports unknown keys and bad scalar values
and keeps the defaults. Explicit disk windows fail closed as described below. The user manual lists the settings.

For an existing GPT installation, `dom0_disk0_windows=start:count,...`
exposes each selected partition as a separate filesystem device. Both values
use 512-byte sectors and must be multiples of eight. Counts must be positive.
The list replaces disk 0 and requires `dom0_disks` greater than zero and
`dom0_disk0_mb=0`. Invalid, overlapping, excessive or out-of-bounds ranges stop
boot. They never grant access to the whole disk. Other host disks retain their
normal order after these devices.

The complete dom0 device plan must fit within 64 slots, including console,
control, memory-hotplug and attestation devices, all disk windows and NICs.
Oversized plans stop boot; neither the disk nor NIC lists are truncated.
Root reserves every boot disk range before attaching it and retains those
reservations across dom0 restarts. If an attachment fails, dom0 receives a
zero-capacity, read-only virtio-blk device in that position. It completes all
I/O with errors without a driver channel or DMA mappings, so other disks
keep their names and dom0 can still boot from healthy storage or an initramfs.
The reserved range remains unavailable to provisioning and conflicting guest
attachments. When a failed disk cannot report its capacity, root checks the
configured ranges for alignment, overflow and overlap and reserves them;
a whole-disk reservation covers all aligned sectors until host reboot.
The same reservation and dummy device apply to an automatically selected
whole disk whose capacity is not a multiple of eight sectors. This does not
relax validation of explicit windows against a known capacity.

Read the ranges from the physical partition table before configuring them.
Use filesystem UUIDs or labels for root, boot and EFI mounts. Partition UUIDs
and physical device names do not identify these filesystem devices. Include
only filesystem blocks. If a partition has unaligned trailing padding, verify
the filesystem size before excluding that padding. GRUB reads the original
physical GPT before l4h starts. The physical GPT and both headers stay intact.
Boot native Linux for partition changes or boot loader installation. dom0
sees filesystem devices, not the physical partition table.
A storage allocator must use an explicit data range that excludes all system
partitions, boot loader sectors and GPT metadata. Do not infer a tail pool
from these separate dom0 mappings.

dom0 can rewrite the EFI partition when it holds the boot disk, so a
compromised dom0 persists across reboots. That is within dom0's trust
(it decides what runs), and nothing verifies the files: Secure Boot is
off. GRUB measures them into the TPM, though, so a host's attestation
shows what dom0 booted (§9.2).

dom0 is guest #0 and receives a host-owned `l4hctl` device page. Its VMM
has a control forwarding capability to vmmgr. Other guests' VMMs do not.
dom0 runs no host hardware drivers; those stay in blkd and netd.

**API surface.** Requests and responses are synchronous, fixed-layout,
little-endian structs defined in `include/l4h/abi.h` and mirrored in
`l4h-abi`. The control version is 2.

| Area | Implemented operations |
|------|------------------------|
| Host | `host_version`: running host's build version (the tag for a release); `host_info`: cores, free/total bytes, disk, VM and NIC counts; `host_reboot`; `rtc_set`: machine RTC in UTC epoch seconds; `iommu_info`: IOMMU state, interrupt remapping, confined and unconfined devices, events logged (§8.5) |
| Guests | `vm_create`, `vm_load`, `vm_start`, `vm_shutdown`, `vm_destroy`, `vm_list`, `vm_info` (cores for the first six vCPUs), `vm_stats` (CPU use and cap), `vm_set_sched` |
| Block | `blk_attach`: disk, read-only and volatile flags and LBA window; `disk_info`: PCI address, owner, failed flag and kind |
| Network | `switch_create`, `switch_attach_uplink`, `nic_create` (MAC, MAC lock, isolation), `switch_info` (ports and counters), `nic_info` (PCI address, switch, MAC) |
| Console | `console_read` (offset, bytes and lost-byte count), `console_write` |
| Display | `gpu_attach` (scanout size), `gpu_read` (the image, 1 MiB at a time, its size, format and frame; §8.6) |

Devices are attached before start and removed on destroy. Pause/resume,
hotplug, switch deletion, I/O limits and asynchronous event queues remain
future work. A Rust userspace library and CLI live in `tools/l4hctl`;
external orchestration can run in dom0.

**Transport and lifecycle.**

- The `l4hctl` device is a single shared page rather than virtqueues:
  dom0 writes a fixed-layout request (`struct l4h_ctl_req` in `abi.h`),
  bumps the page's `seq` and signals the device's kick, a notification of
  `l4h-vmmgr` itself. vmmgr executes the request, writes the response into
  the same page, sets `done` and raises the device's event; the calling
  task sleeps meanwhile, and the vCPU runs others. Image loads are
  bounded at 1 MiB per call.
- `/dev/l4hctl` takes one ioctl that carries a request, its response and,
  for `VM_LOAD`, a user buffer. The driver stages it in the control
  device's data area, 1 MiB of host-owned frames mapped into dom0, and
  sets the request's source offset to 0 and length to the ioctl buffer
  length: vmmgr never reads dom0's RAM.  The data area is root's memory,
  made once and mapped into every dom0.
- `l4hctl` loads the initramfs with raw `VM_LOAD(vm, gpa, bytes)` writes,
  from the GPA `vm_create` returns. vmmgr copies page by page from the
  data area to the new guest's frames and never parses what guests load.
  The lifecycle is `vm_create` → (`blk_attach` / `nic_create` / `vm_load`)* → `vm_start`
  (loads the guest kernel, writes the boot info and spawns the guest's
  `l4h-vmm`) → `vm_destroy`.
- `vm_shutdown` (`l4hctl shutdown [--reboot]`) is the ACPI-power-button
  equivalent. vmmgr sets `power_request` in the guest's console page
  and raises the console's event line on vCPU 0. The guest runs
  `orderly_poweroff()` or `orderly_reboot()`, which signals init. The
  guest also reads `power_request` once its handler is installed: an
  event raised before that, while it boots, finds no handler.
  `/dev/l4hctl` needs `CAP_SYS_ADMIN` as well as its 0600 mode.
  `vm_pause` is not implemented: suspending the vCPU kernel thread does
  not stop a user thread that holds SC_U.
- `host_reboot` (`l4hctl host-reboot`) resets the machine, so that dom0
  can boot a new l4h or dom0 it wrote to the EFI partition without a way
  in from outside. vmmgr passes it to `l4h-root`, which resets as Linux
  does:
  the FADT's reset register (`RESET_REG_SUP`; system I/O, memory or PCI
  configuration space, prepared at boot), the PCI reset control register
  at 0xcf9 (through root's PCI configuration ports, 0xcf8-0xcff), and the
  keyboard controller. It returns `EIO` only if the machine did not reset;
  aarch64 has no reset yet (`ENOSYS`). Every guest stops without notice:
  dom0 shuts them down first if they matter. Root flushes nothing: a
  guest's flush reaches the disk before it completes (except on a volatile
  attachment), so dom0 syncs what it
  wrote first, and root's serve loop does not block on disks while the
  machine is about to go down.
- Console output goes into a per-guest ring that `l4h-vmm` writes and
  vmmgr reads for `console_read`. It is also copied to the serial port
  with a `[vmN]` line prefix. Console input is a ring in the guest's
  console device page, which hvc polls.
- **Reclaim.** Each guest holds RAM block Untypeds and a host-object
  arena in vmmgr, and in root its I/O pool and an arena for its disk
  channels and netd ports. CNode slots allocated on the guest's behalf are
  tracked: vmmgr and root each keep a bitmap of their free slots and an
  owner byte per slot (`mem::Slots`, 288 KiB for vmmgr's 2^18 slots, 576
  KiB for root's 2^19), and `vm_destroy` deletes the guest's by a scan of
  the owner bytes. `vm_destroy` revokes vmmgr's Untypeds first (its
  VSpaces die first, so nothing is unmapped page by page), returns them
  to the free pool and deletes its slots; then root quiesces the attached
  disks, and only then revokes its own (`VMMGR_GUEST_DEL`, §9.3). ASIDs are released by the kernel
  when VSpaces die. Repeated create/destroy leaves free memory unchanged
  (`tests/run-ctltest.sh`).
- **Disk detach.** A disk window is detached only when its guest is destroyed; the shared controller remains running.
  The device may hold commands that address the guest's I/O pool and
  blkd's DMA memory (queues, PRP lists, request headers), so `l4h-root`:
  1. suspends blkd, so that nothing more is submitted;
  2. resets the device itself, through a mapping of its registers: NVMe
     clears CC.EN and waits up to CAP.TO for CSTS.RDY to clear, which
     aborts every command and deletes the queues; virtio writes 0 to
     `device_status` (an I/O port on a legacy device) and waits until it
     reads back 0. Bus mastering stays
     on meanwhile, so DMA the device finishes while resetting lands in
     memory that still belongs to the guest;
  3. clears bus mastering, memory decoding and MSI-X, and deletes the IRQ
     handler;
  4. only then reclaims blkd's arena and the guest's.

  Clearing bus mastering alone is not a drain: a device can complete a
  command it already started, and it keeps its queue addresses, which it
  would use again when the next attach turns bus mastering back on. If a
  device does not confirm the reset, it is marked failed and never enabled
  again (`blk_attach` returns EIO, `l4hctl disks` says so). The guest's I/O pool
  and blkd's DMA memory are then kept out of the free pool; guest RAM
  and other host objects are reclaimed (§15.1). Disks are also reset at boot,
  with bus mastering off, before anything enables them, since firmware
  may leave a controller running. Without a supported IOMMU (§8.5), nothing
  else confines a device. With one, the pool is unmapped from the device
  after the drain or quarantine, so it is not pinned.
  `tests/run-ctltest.sh` destroys guests in the middle of throttled reads,
  on virtio-blk and NVMe, and checks that the next guest, which reuses the
  memory, sees no disk data appear in it. Before the reset was added, the
  NVMe case wrote 1 MiB of disk data into the next guest, whose init then
  crashed.

**Policy and safety.**

- vmmgr enforces resource accounting for guests (memory, cores), and root
  for what it makes for them and for disk ownership (a writable window is
  attached to at most one VM; read-only windows may be shared). Both reject
  invalid requests. dom0 cannot breach host isolation, but it is fully trusted
  to decide *what* runs. In particular, dom0 can attach any disk to itself.
- If dom0 crashes, the other guests keep running. vmmgr restarts dom0
  from the same images and settings, and the new dom0 recovers state
  with `vm_list` and `switch_info`. The authoritative state lives in
  vmmgr (guests) and root (disks, switches).
- Debugging fallback: a minimal serial monitor in `l4h-root` (`list`,
  `destroy`, `restart-dom0`, `reboot`) stays available on COM1, which is the GCE serial
  console.

### 9.2 Attestation

A guest can prove to a remote verifier what it booted, and on which host.
The chain has four links.

1. **Measured boot.** The firmware measures the UEFI application into
   PCR 4. The application holds seL4, `l4h-root` and every host component
   (§10), so one digest covers the whole host. GRUB's `tpm` module measures
   dom0's kernel, initramfs and `l4h.conf` into PCR 9, and its commands
   into PCR 8. Secure Boot is not needed: nothing is checked at boot, the
   verifier checks afterwards. A BIOS boot (§10) measures none of this:
   BIOS GRUB has no `tpm` module, so such a host's quotes say nothing
   about what it booted.
2. **The host key.** `l4h-trustd` is the only component that maps the
   TPM. Root finds the TPM in the ACPI `TPM2` table (see **TPM interfaces**
   below); trustd polls it at locality 0, sleeping on its kernel timer
   (E3) between polls, from 20 µs up to 2 ms, rather than spinning. It
   runs on the last core at priority `P_K + 1`, with at most 5 ms of every
   20 ms, so that neither a slow TPM nor the firmware's AML can take a
   core from guests. At start, trustd:
   - generates a P-256 key K in software, from TPM randomness;
   - creates the attestation key (AK), a restricted ECDSA P-256 signing
     key. It is a primary key of the endorsement hierarchy, so the same
     template gives the same key on every boot. It has an empty password
     and no dictionary-attack protection (`noDA`). trustd never shuts the
     TPM down orderly, and the TPM counts each such boot as a failed
     authorization, so a protected key would be locked out after a few;
   - quotes PCRs 0–15 with the AK, with `SHA-256("l4h-trustd-key-v1" ‖ K)`
     as qualifying data;
   - extends PCR 15 with that same value.

   The quote shows PCR 15 as zero, which only a quote taken before the
   extension can. So K is the only key trustd issued since the TPM was last
   reset. After start, the TPM is only used for ActivateCredential. With
   swtpm, start takes about 0.4 to 0.6 s. Requests that guests make before
   then are answered once it is done.
3. **Reports on guests.** vmmgr measures each guest as it boots it, dom0
   included. The launch digest is `SHA-256("l4h-launch-v1" ‖ ram_base_va ‖
   entry ‖ kernel_end ‖ RAM[0, kernel_end) ‖ initrd size ‖ initrd ‖ cmdline
   length ‖ cmdline)`, with u64 little-endian integers.
   - vmmgr reads the image back from guest RAM before the guest starts.
     `vm_start` fails if dom0 loaded anything outside the initramfs.
     vmmgr is in the host TCB for this: whoever builds a guest can make
     it run anything.
   - Root writes {instance, RAM, vCPUs, dom0, digest} into a registry page
     that trustd maps read-only. Root never waits for trustd's main
     thread, whose TPM commands can take seconds; its passive flags
     thread answers root independently (below).
   - Each guest gets an attestation device (`L4H_DEV_ATTEST`). Requests are
     asynchronous, so a vCPU never waits for trustd, which answers one
     request at a time and can take seconds for ActivateCredential:
     1. The guest writes its request into the device page, then a new
        sequence number, and signals the kick notification. Its badge is
        the guest's id, so trustd knows who asks, and trustd only answers
        a guest about itself.
     2. trustd answers in the page, sets `done` to the sequence number,
        and asks root (`ROOT_CALL_ATTEST_DONE`) to raise the device's
        event on the guest's vCPU 0. Meanwhile, Linux sleeps the caller.
   - trustd owns the 64 request pages, one per guest id, and root lends
     one to each guest. A page therefore stays mapped in trustd while
     trustd answers a guest that root is destroying. trustd drops an
     answer whose guest's instance changed while it worked.
   - `L4H_ATTEST_REPORT`, with 64 bytes of the guest's data, returns a
     COSE_Sign1 (ES256) signed by K. It carries a CBOR map: `v`, `ram`,
     `data`, `dom0`, `host` (SHA-256 of K), `seal`, `guest`, `taint`, `vcpus`, `launch` and
     `instance` (unique per guest created since boot). The two bitmaps
     are 32-byte strings, bit n in bit n % 8 of byte n / 8. The map stays
     `v: 1`, in deterministic CBOR key order.
   - `L4H_ATTEST_EVIDENCE` returns the host evidence, a CBOR map: K as a
     COSE_Key, the AK's `TPMT_PUBLIC`, the quote (`TPMS_ATTEST`) and its
     signature, the quoted PCR values, and the EK certificate if the TPM
     has one in NV.
   - Results longer than the page come in pieces: each request gives the
     offset its answer starts at. Evidence is fixed at startup. A report,
     whose flags may change between requests, is at most 512 bytes and
     always fits in one answer.
   - Linux exposes both as configfs-tsm reports (provider `l4h`: `inblob`,
     `outblob`, and the evidence as `auxblob`) and through `/dev/l4h-attest`
     (`l4hctl attest`).
4. **Verification.** `tools/l4h-attest.py verify` checks that:
   - the AK is a fixedTPM restricted signing key, and the quote verifies
     under it;
   - the quote's qualifying data is K's hash;
   - the PCR values match the quote's digest, and PCR 15 is zero;
   - the PCRs have the expected values (`--pcr`);
   - the EK certificate chains to the manufacturer's CA (`--ek-ca`);
   - the report verifies under K and carries the verifier's nonce and the
     expected launch digest. `measure` computes the digest from the kernel
     (`vmlinux` in a release's debug archive), initramfs and command line.

   **AK enrollment.** A quote only proves something if the AK is in a real
   TPM. `make-credential` encrypts a secret to the EK (from its certificate)
   and binds it to the AK's name (TPM2_MakeCredential). A guest decrypts it
   with `l4hctl attest activate`. That runs TPM2_ActivateCredential, using a
   PolicySecret(endorsement) session for the EK, and only the TPM that holds
   both keys can do it. The verifier then pins the AK's name (`--ak-name`),
   which stays the same across boots.

   **Rate limit.** ActivateCredential is the only request that uses the
   TPM (about 80 ms each on a discrete Infineon TPM), and trustd answers
   one request at a time, so a guest calling it in a loop would make the
   others wait. Each guest instance may therefore make 5 at once, then
   one a second (GCRA, one timestamp per guest id, reset when a new guest
   takes the id). Beyond that trustd answers `-EAGAIN` without using the
   TPM. Reports, evidence, ACT and SEAL are not limited: they cost no TPM time.

**Taint and seal.** Each guest instance has two set-only 256-bit
bitmaps. Taint bit b records that action b happened; seal bit b prevents
it from happening. `ACT(bits)` atomically refuses with `-EPERM` if any
requested bit is sealed, otherwise taints all of them. `SEAL(bits)` sets
seals. Neither dom0 nor the guest can clear either bitmap. A verifier's
check `taint & mask == 0 && seal & mask == mask` covers the past and the
future; checking taint alone leaves a session key exposed after its report.

| Bits | Who acts | Who seals | Meaning and trust |
|------|----------|-----------|-------------------|
| 0–31 | Host actor (root today) | Guest userspace | Host TCB enforces the refusal; 0 is `CONSOLE_IN`, 1 is `CONSOLE_OUT`, 2–31 reserved |
| 32–63 | Reserved for host actors | Nobody yet | Reserved |
| 64–127 | Guest kernel | Nobody | Bit 64 + Linux's taint flag; trusted as far as the measured kernel |
| 128–255 | Guest userspace | Guest userspace | Workload-defined actions; the workload must honour refusal |

`CONSOLE_WRITE` takes `CONSOLE_IN` before injecting bytes, including
input queued before start. `CONSOLE_READ` and `GPU_READ` take
`CONSOLE_OUT` before disclosing text or pixels. Empty operations do not
taint; a write that finds its ring full conservatively does. Every call
checks seals, including empty calls. An image copied into dom0's data
area taints even if the image changes and the read returns `-EAGAIN`.
dom0's own console reads/writes are exempt. The serial monitor never
injects guest input. Debug builds also copy guest output to the host's
physical serial port; that trusted debug output is not a dom0 control op.

**Rule for new control ops:** reading or changing a running guest's
state outside the devices attached before start needs an action bit,
recorded before the effect and refused after sealing. Register access,
memory dumps, snapshots and migration must follow this rule. An op
without a bit remains available on a sealed guest, so adding one is an
attestation-visible decision. Scheduling, shutdown, destruction and
cooperative memory hotplug remain dom0's availability decisions; host
metadata queries do not disclose guest state. Disk/network choices are
still outside the launch measurement.

A passive thread in trustd is the sole writer of an 8 KiB flags area:
64 entries, each 128 bytes, with a seqlock, instance and the two bitmaps.
Root and the main thread use read-only mappings; only the flags thread
uses the writable alias in trustd's address space. Readers retry an odd
or changed sequence counter. Root assigns monotonically increasing
instances at `VM_CREATE`, stores them in `Guest`, and publishes the same
instance in the registry at start. An entry for another instance reads as
empty. A higher-instance request replaces an entry; an older request gets
`-ESRCH`. Destruction does not clear flags.

The flags endpoint has badged callers: `FLAGS_ROOT` can ACT on defined
host bits, and `FLAGS_TRUSTD` can ACT on guest bits and SEAL defined host
or userspace bits. Kernel bits cannot be sealed. The service validates
all arguments before changing any entry. Its requests are MR0 op, MR1
id, MR2 instance, MR3–6 bitmap and MR7 options; replies are MR0 status,
MR1 instance, MR2–5 taint, MR6–9 seal. At root's priority, it runs on the
caller's donated MCS scheduling context, with no heap, TPM, AML or calls
back to root. A temporary startup SC is removed after its initial
reply/receive handshake. A fault in this thread is a host bug, like a
fault in root.

An actor first checks the seal in a consistent entry. If the taint is
already set, no IPC is needed; otherwise ACT must succeed before the
operation. This costs one IPC per action kind per instance, including
continuous console polling. ACT and SEAL serialize in the flags thread.
An operation that passed its check can land after sealing, but its taint
was set before that seal. Thus a report or SEAL answer showing a clean
sealed bit guarantees that action has never happened and never will.
It does not promise that an already-tainted action is no longer in flight.

Guest requests use the existing attestation page/ioctl: ACT (4) takes a
32-byte bitmap with an optional u32 options word, SEAL (5) a 32-byte
bitmap, and each returns 32 bytes of taint followed by 32 bytes of seal.
An empty ACT reads the flags. `L4H_ACT_SEAL` on userspace bits taints and
seals atomically, giving at-most-once actions even between racing
processes. Failed multi-bit ACTs change nothing. Invalid ranges or
options get `-EINVAL`; an older host lacking these ops gives `-ENOSYS`.
The Linux driver refuses userspace ACTs below bit 128 with `-EPERM`.
Its `add_taint` hook accumulates kernel bits atomically, sends them from
workqueue context, and flushes them under the request lock before any
report. Probe includes existing kernel taints. Failed sends are retained
for retry. The kernel never seals on its own.

`l4hctl attest flags`, `seal console-in|console-out|BIT...`, and
`act [--seal] BIT...` expose the gates; refused actions exit 1. Sysfs
`/sys/kernel/l4h/attest/{taint,seal}` prints bit lists. To seal early, a
measured initramfs calls `l4hctl attest seal console-in` from init; any
input queued before it is still recorded. dom0's `VM_TRUST` (30) reports
only bits 0–63. `l4hctl list` / `vms` shows seals; console output stays
usable after input is sealed.

The verifier prints host names and Linux taint letters and accepts
`--deny-taint` / `--require-seal` as comma-separated names, numbers and
ranges. By default it denies `console-in`; `--deny-taint ''` opts out.
No guest bits are denied by default. An older report with no seal cannot
satisfy a required seal. Bitmaps may grow: at least 32 bytes are required,
and bits beyond their length count as clear.

**Without a TPM.** trustd always starts when built in, on both
architectures. `TPM_NONE`, an unsupported TPM, or TPM initialization
failure leaves a flags-only service: ACT, SEAL and VM_TRUST work, while
REPORT, EVIDENCE and ACTIVATE return `-ENODEV`. Root sets
`L4H_ATTEST_NO_REPORTS` before boot when no TPM was found; trustd sets it
if initialization fails. Linux reads it at probe and on `-ENODEV`, keeps
`/dev/l4h-attest` and only registers configfs-tsm when reports work.
`l4hctl attest report` says `no TPM: flags only`. Local seals still work,
but without a signing key they have no remote proof. A later TPM command
failure returns `-EIO`.

**TPM interfaces.** These follow Linux's `tpm_crb` and `tpm_tis`:

- **FIFO (TIS)**, start method 6: locality 0's registers at 0xfed40000.
- **CRB**, start method 7: the locality registers, with the control area
  at 0x40 in their page, and the command and response buffers that the
  control area names.
- **CRB with the ACPI start method**, 2 or 8: AMD's firmware TPM, which
  runs in the PSP. It has no locality registers and no idle state, and its
  buffers are in reserved RAM. Every command starts with the TPM device's
  `_DSM` (function 1 of GUID `6bbf6cab-…`), which is firmware code in
  AML. Root gives trustd the FADT, the DSDT and the SSDTs. trustd loads
  them into the `acpi` crate's interpreter, finds the `MSFT0101` device
  whose `_DSM` offers that function, runs only that device's and its
  parents' `_INI`, and calls the `_DSM` after setting the start bit, as
  Linux does.
  - Accesses outside trustd's own TPM ranges go to root (`ROOT_CALL_HW`).
    Root refuses RAM, device memory already in use, I/O ports already
    handed out (seL4 refuses to issue them twice), and config writes to
    the PCI functions the host drives. Reads of anything refused return
    all ones.
  - The interpreter runs in trustd, not root, because it still panics on
    some AML. If the main thread faults, root suspends only it and revokes the guests'
    kick capabilities. It marks every attestation page failed and answers
    the request in it with -EIO, so no guest waits for its timeout. No new
    guest gets attestation. The flags thread and its arena stay alive:
    existing seals remain enforced, and actors keep recording taints.
  - The crate is pinned to an upstream commit past 6.1.1, whose buffer
    comparison, which every `_DSM` needs for its UUID check, panics.
- **CRB with Pluton**, start method 13: the start and reply doorbells
  named in the TPM2 table, rung after each request, as Linux does.
  Untested: QEMU has no Pluton.

**Trust.** A report is worth what the host TCB is worth: seL4, root,
trustd, blkd, netd and the guest's VMM (§3), all identified by PCR 4.
dom0 decides what runs but cannot forge a report, because root computes
the launch digests and trustd answers each guest only about itself. What
this does not cover:

- **The event log.** GRUB's multiboot2 path exits boot services without
  fetching the firmware's event log, and seL4 hands boot-services memory to
  root as RAM, so the log is lost. A verifier therefore pins PCR values
  taken from a known-good boot of the same application on the same kind of
  machine. Those values also depend on the firmware (PCRs 0–7) and on
  dom0's files and settings (PCRs 8–9). A small EFI shim in front of GRUB
  could save the log.
- **DMA.** Without a supported IOMMU (§8.5), a malicious device can DMA
  anywhere. With one, it can reach only memory it was given, and raise
  only its own interrupts. A device that spoofs an I/O APIC's requester
  ID can still inject any vector.
- **The cloud provider.** On a cloud VM, the provider's hypervisor and
  vTPM are trusted too, and nothing is encrypted.
- **Disks and networks.** They are dom0's choice and not measured, as for
  confidential VMs.
- **ActivateCredential.** It creates the EK on first use. An RSA EK takes
  a hardware TPM seconds to create, and other guests' requests wait
  behind it (their vCPUs do not). The rate limit bounds what each guest
  asks, not the number of guests: with every guest at its limit, a
  request can wait about one activation per guest.
- **aarch64.** It has no TPM path yet; local flags and seals work.
- **CRB buffer sizes.** trustd uses the buffer sizes from the CRB
  registers. Linux also clips them to the device's `_CRS` because some
  firmware reports larger buffers, and trustd does not do that.

`tests/run-trusttest.sh` checks badge/range validation, atomic gates,
instance reuse, concurrent snapshots and signed verifier policy.
`tests/run-ctltest.sh` also checks flags without a TPM, and
`tests/run-attesttest.sh` checks signed flags, console/display seals,
kernel taints, racing userspace gates and pre-start input. It boots under OVMF with swtpm three times: CRB,
then FIFO, then CRB with the ACPI start method, and checks the whole
chain each time, the credential included. For the third boot, it has GRUB
replace QEMU's TPM2 table with one for start method 2, and add an SSDT
(`tests/ftpm`) with an `MSFT0101` device. That device's `_DSM` does what
the PSP's firmware would: it takes the locality, starts the command, waits
for it, and counts on QEMU's debug port. QEMU ignores the start bit without
a locality, so a command only runs if trustd ran the `_DSM`.
`tools/mkefi.sh` swaps the tables with `L4H_ACPI_TABLES` and
`L4H_ACPI_EXCLUDE`, which can also work around broken firmware tables.

### 9.3 Guest manager: l4h-vmmgr

Root holds every capability on the host: device memory, interrupts, I/O
ports, PCI configuration, the IOMMU and the components' CSpaces. It used
to build and run the guests too, and parse dom0's control requests, so a
bug anywhere on that path ran with all of it. `l4h-vmmgr` now builds and
runs the guests, and root keeps the hardware. Nothing a guest, its VMM or
dom0 sends reaches root; only vmmgr and trustd call it.

- **vmmgr holds** memd grants for guest objects, the guests' CNodes,
  VSpaces, vCPUs and VMMs, every core's SchedControl (copies), and the ASID
  pools: root makes all eight at boot and hands them over, keeping
  ASIDControl. It runs guest creation, image loading and the launch
  digest, start, shutdown and destroy, dom0's boot and restart, the
  balancer and steal time (§7), and the control API. Guests' VMMs call it,
  and guest kernels and VMMs fault to it.
- **Root holds** what devices reach. A guest's I/O pool is root's: root
  maps it into the IOMMU domains of the disks the guest is given, by
  physical address. If vmmgr made the pools and named their addresses, a
  compromised vmmgr could have root give a device any memory, root's own
  included. So vmmgr names guest ids, disk numbers, LBA windows and sizes,
  root checks them against its own table (`vmmgr::RootGuest`), and every
  address root gives the IOMMU, blkd or netd comes from that table.
  Disk channels and netd ports are root's as well, in a per-guest arena
  root revokes when vmmgr is done with the guest. Root also numbers guest
  instances, so they stay unique since boot whatever vmmgr does.
- **The interface** (`l4h_host::vmmgr`) is a handful of calls from vmmgr
  to root, with integers in message registers: `GUEST_NEW` (the pool, the
  attestation device; vmmgr passes the VMM notification that backends
  signal), `GUEST_DEL`, `DISK_ATTACH`, `NIC_ADD`, `TRUST_REGISTER` (the
  launch digest), and `HOST_OP`, which carries the control ops on the
  host's disks, switches and NICs, reset and RTC, as their `CTL_*` number
  and six arguments. vmmgr parses dom0's request and passes these on;
  their data comes back in a result page. Capabilities cross in vmmgr's
  exchange slots, which root reaches through the CNode of vmmgr's it
  holds. Root empties a slot before it puts a capability in it, so a slot
  vmmgr left full cannot make root fail, and takes no capability from
  vmmgr: even the notification blkd and netd signal for a guest's VMM is
  root's, made at `GUEST_NEW`, so it cannot be an endpoint that would
  block them. Root never calls vmmgr, so calls cannot deadlock; it signals
  vmmgr's notification instead, with news in an events page: trustd
  answered a guest (vmmgr raises its attestation device's event), or the
  serial monitor's `destroy` or `restart-dom0`. vmmgr publishes its guests
  in a status page for the monitor's `list` and the dashboard.
- **Destroy** is ordered as before: vmmgr stops the guest and revokes its
  own arena (VSpaces first) and the guest's RAM, then `GUEST_DEL` has root
  forget it in trustd, remove its ports, quiesce its disks and only then
  revoke the pool, which it keeps out of use if a disk did not stop. The
  call is synchronous: a disk reset still holds up vmmgr for its timeout.
- **memd** has two clients. Root calls it for its own memory; vmmgr, with
  a badge of its own (`BADGE_VMMGR`), for its memory and guests' RAM. memd
  is more trusted than vmmgr, so vmmgr gets no capability to memd's CNode:
  the two share a small mailbox CNode instead, and memd keeps the
  original of every block it grants vmmgr, giving a copy. Freeing a grant
  revokes the original, so a mislabelled capability in the mailbox cannot
  confuse memd's table, and memd empties a mailbox slot before it writes
  one. Root mints the endpoints of guests' VMMs to memd
  (badged per guest), since vmmgr's own badged one cannot be minted again.
- **Boot modules.** Root maps the guest kernel, its module tree and dom0's
  initramfs read-only into vmmgr, with a CNode of their frames: guests
  share the kernel's read-only blocks and the module tree as before. Root
  clears what follows the module tree in its last page before mapping it.
  dom0's control data area is root's memory, mapped into vmmgr (read-write,
  for `VM_LOAD` and `GPU_READ`) and root (read-only, for `BLK_WRITE`).
- **dom0's devices.** Root makes the switches at boot, attaches the
  uplinks, and chooses dom0's disks and vNICs (`Dom0Plan`); vmmgr creates
  every dom0 with them.
- **Trust.** vmmgr is in every guest's TCB, as root was: whoever builds a
  guest's CSpace can copy its frames. The console seals (§9.2) are vmmgr's
  to keep: it reads the VMM-written console rings and display areas, and
  acts on trustd's flags with root's former capability. A bug in vmmgr
  reaches guests' memory but not the hardware, the IOMMU, the TPM's ports
  or root.
- **If vmmgr fails**, guests keep running: their vCPUs, disks, networks
  and memory hotplug need nothing of vmmgr. Like blkd, netd and memd it has
  a keeper thread (l4h_rt), which reports the fault and answers every
  later call with a failure, the call vmmgr was serving first (its reply
  object is in `SLOT_REPLY`). So a VMM's call returns instead of blocking
  it, and a guest's power request returns. For dom0's asynchronous control
  requests, the failure service writes EIO, publishes the completion and
  raises the device event, both for an outstanding request and later ones.
  It uses pages and a notification registered before dom0 starts, without
  accessing the manager's mutable guest or allocator state. A keeper takes
  over the main thread's bound notification; a panicking main thread serves
  it itself. Faults of guest kernels and VMMs stay unanswered; those vCPUs
  stop. Nothing can create, change or destroy guests any more, attestation
  answers no longer reach guests, and the balancer stops. The serial
  monitor's `reboot` resets the host.
- **Scheduling.** vmmgr runs on core 0 at `PRIO_KERNEL + 2`, above every
  guest and VMM, with a full budget, and has its own deadline timer for the
  balancer. Its main stack is 1 MiB.

---

## 10. Boot and deployment

Every host image includes trustd, including on aarch64 and machines
without a TPM: its passive flags server enforces guest seals locally.
The TPM enables signing; it does not decide whether seals work (§9.2).

- **Firmware.** UEFI → GRUB (EFI) → multiboot2. QEMU uses OVMF for this
  path, or plain `-kernel` multiboot for development. `tools/mkefi.sh`
  builds l4h as one UEFI application: a standalone GRUB whose memdisk
  holds the seL4 kernel, `l4h-root` (with the service ELFs), the guest
  kernel and its module tree (§5.6). GRUB loads dom0's initramfs and
  `l4h.conf` from the EFI partition it was loaded from or, since
  `$cmdpath` is empty under OVMF, the first partition with
  `/l4h/dom0/initrd` (§9.1). Initramfs images for other guests come
  through the dom0 API.
- **BIOS.** BIOS → GRUB (i386-pc) → multiboot2, for clouds whose VMs boot
  only with BIOS (SeaBIOS), such as DigitalOcean. BIOS GRUB's core image is
  read through the BIOS into conventional memory and must stay within a
  few hundred KiB, so it cannot hold l4h as the UEFI application's memdisk
  does. `tools/mkbios.sh` builds l4h's files instead: the seL4 kernel,
  `l4h-root`, the guest kernel, its module tree and `grub.cfg`, which
  boots them like the UEFI application's script. They live in `bios/` of
  a directory `$l4h` that also holds `dom0/initrd` and `l4h.conf`, and the
  GRUB that runs `grub.cfg` sets `$l4h` first. Two GRUBs do:
  - the disk image's own (`tools/mkimage.sh`): its boot sector is in the
    MBR and its core image, with every module `grub.cfg` needs, in a BIOS
    boot partition. The core image finds the ESP by its volume serial
    and uses its `/l4h`. mkimage.sh writes the boot sector and the core
    image's block list itself, as `grub-bios-setup` would, so that it
    needs no loop device.
  - the distribution's, through a `custom.cfg` menu entry that the Linux
    installer writes, with `$l4h` at `/boot/l4h` (§9.1, the manual).

  `grub.cfg` loads `vbe`, so multiboot2 sets up the framebuffer the kernel
  asks for (patch 0011) for the dashboard and `fb_console`. seL4 finds the
  ACPI tables in GRUB's multiboot2 tags, and the serial port is passed
  explicitly as on UEFI. Nothing else differs: the kernel, root and the
  components do not depend on the firmware. There is no measured boot
  (§9.2).
- **Variants.** The application is the same for every host except for
  seL4 options fixed at build time. `tools/build-efi.sh` builds the
  shipped ones into `build/efi/`: `l4h-generic.efi` (x2APIC, PCID: QEMU,
  GCE), `l4h-xapic-nopcid.efi` (Latitude.sh, below), and
  `l4h-skim-xapic-nopcid.efi` (Meltdown isolation, xAPIC, no PCID). The host
  components do not depend on these options, so all variants share one
  `l4h-root`.
- **Releases.** CI (`.github/workflows/release.yml`) builds, for x86_64
  only, and attaches to the GitHub release of each pushed `v*` tag, with
  `SHA256SUMS`:
  - all three applications, in release mode;
  - `l4h-bios-x86_64.tar.xz`: l4h's BIOS files (`tools/mkbios.sh`), with
    each variant's kernel as `kernel-VARIANT.elf`, for the installer;
  - `l4h-dom0-x86_64.tar.xz` (`tools/build-dom0.sh`): the `ARCH=l4h`
    kernel without debug information, its config, a static `l4hctl` and
    an example `l4h.conf`, for a dom0 of any distribution;
  - `l4h-debug-x86_64.tar.xz`: the applications' build unstripped (root,
    components, each variant's kernel), for `addr2line` on fault
    addresses;
  - `l4h-attest.py`, the attestation verifier (§9.2). The components are packed into root without debug
    information, which was about 20 MiB of each application, loaded and
    kept in root's memory for nothing.

  No aarch64 binaries are published yet.

- **Platform discovery** is done by seL4 using ACPI: MADT, cores and IOAPIC.
  `l4h-root` handles PCI enumeration over MCFG/ECAM, or port I/O config, and
  MSI/MSI-X allocation through `seL4_IRQControl_GetMSI`.

### 10.1 Targets, in order

1. **QEMU (development and CI).** `-cpu host,-vmx` with KVM used only as a
   fast CPU. Devices: virtio-net-pci, virtio-blk-pci, nvme and a 16550 UART.
   l4h drives these with its Rust blkd/netd drivers and serial monitor.
2. **GCP.**
   - **Targets:** N2 with virtio-net and NVMe local SSDs; N2 boot disks
     use virtio-scsi, which blkd drives as a legacy device. Third-generation
     and later types (C3, C3D, N4, C4) require gVNIC (netd's DQO driver)
     and attach disks, the boot disk included, as NVMe.
   - **Boot:** a custom image with GRUB EFI and seL4. Secure Boot is off
     (Shielded VM vTPM and integrity monitoring are optional). The serial
     console is enabled for seL4 and monitor output.
   - **Timer:** E3 shares seL4's LAPIC timer (TSC-deadline where available,
     APIC countdown on N2), so there is no HPET dependency. Patch 0014
     stabilizes TSC/APIC calibration on N2 (§4).
   - **Networking:** virtio-net or gVNIC is the uplink of a switch, and a
     router VM (often dom0) owns the instance MAC (§8.3).
3. **Bare metal: Latitude.sh m4.metal.small** (Supermicro H13SRE-F, AMD
   EPYC 4244P, Intel X550, Micron 7500 NVMe; UEFI). Deployed with
   l4h-sandbox (its `deployments/latitude-sh-l4es`). It needs the
   `xapic-nopcid` variant and these settings, all off by default
   (`l4h.conf` keys, or the `L4H_`-prefixed uppercase variables at build
   time, §9.1):
   - Kernel `L4H_LAPIC_MODE=XAPIC` (`tools/build-kernel.sh`): the firmware
     leaves x2APIC off. `L4H_PCID=OFF`: the CPU has no PCID, and seL4
     otherwise stops in its first boot check. There is no TSC-deadline
     timer; the APIC countdown serves, as on N2. These two are the
     variant: seL4 fixes them at build time.
   - `serial_port`/`serial_irq` (GRUB, seL4, the l4h-root monitor):
     serial-over-LAN is COM2 (0x2f8, IRQ 3), per the ACPI SPCR table.
   - `uplink_nic=bus:dev.fn`: the uplink when it is not the first NIC,
     here the X550's second port. `boot_disk`: the controller that
     becomes host disk 0, so dom0 gets it.
   - `uplink2_nic=bus:dev.fn`: a second uplink, on
     switch 1 (dom0's internal switches follow it), where dom0 gets one
     more vNIC with that NIC's MAC. dom0 tells its vNICs apart by MAC
     (`CTL_SWITCH_INFO` lists each port's VM and MAC), not by order. On Latitude the first port carries the
     private storage network (a tagged VLAN, which l4h passes through).
   - `fb_console=1` (GRUB, seL4, l4h-root): GRUB and the seL4 console
     (patch 0020) on the screen; the dashboard keeps to the upper half.
4. **AWS EC2:** c6i.xlarge boots the generic UEFI image with ENA and NVMe
   EBS. `tools/ec2-image.py` imports a raw disk through the EBS direct API
   and registers a private UEFI/ENA AMI. `tests/build-ec2.sh` and
   `tests/ec2-test.py` cover DHCP, IMDSv2, internet HTTP, jumbo frames, a
   checked 32 MiB TCP download, a four-vCPU self-test, 64 MiB of EBS
   write/readback and four concurrent guests. The runner terminates the
   instance and its volumes; AMIs/snapshots are explicitly retained for
   reuse or deletion. See `tests/ec2.md`. Azure (MANA and NVMe) remains a
   later target.

**Status (v1).**

- **Image.** `tools/mkimage.sh` builds a GPT disk image that boots under
  UEFI and BIOS: the ESP from 1 MiB, then a 1 MiB BIOS boot partition with
  BIOS GRUB's core image, and its boot sector in the MBR. The EFI system
  partition holds:
  - `EFI/BOOT/BOOTX64.EFI`, the l4h application (`tools/mkefi.sh`): GRUB
    with the seL4 kernel, loaded with `multiboot2` and
    `console_port=0x3f8 debug_port=0x3f8` (or `serial_port`), because
    UEFI firmware need not fill in the BIOS data area that seL4 otherwise
    reads the port from, and `l4h-root` as the first `module2`;
  - `/l4h/bios`, l4h's BIOS files (`tools/mkbios.sh`);
  - optionally `/l4h/dom0/initrd` and `/l4h/l4h.conf` (`-i`, `-c`), the
    later `module2`s of both boot paths.
- **Local test.** `tests/run-uefitest.sh` boots that image the way GCE
  would, under OVMF on a q35 machine: NVMe boot disk, virtio-net NIC, KVM
  without VMX. dom0's initramfs and an `l4h.conf` (which
  sets dom0's command line and keeps the boot disk from it) come from the
  EFI partition. dom0 gets DHCP through the virtio-net uplink.
  `tests/run-biostest.sh` boots the same image as a DigitalOcean droplet
  would: SeaBIOS on an i440fx machine, a transitional virtio-blk boot disk
  and virtio-net NIC; it also checks the dashboard's VBE framebuffer.
- **Deployment.** `tools/gce-image.sh` packages the image as
  `disk.raw.tar.gz` and prints the `gcloud` import and instance commands
  (N2, `nic-type=VIRTIO_NET`; `nic-type=GVNIC` on C3 and later; image
  features `UEFI_COMPATIBLE,GVNIC`).
- **Tested on GCE** (`tests/gce-test.sh`, n2-standard-4 with virtio-net;
  c3-standard-4-lssd with gVNIC, `BOOT_DISK_INTERFACE=NVME NIC_TYPE=GVNIC`):
  UEFI boot, DHCP and internet access through the NIC, a 10 MB download
  (about 96 MB/s on N2, 44 MB/s on C3), a 4-vCPU guest self-test, a local
  SSD (NVMe, 4 KiB blocks) passed through, 12 small guests.
  - GCE's virtio-net is a legacy (0.9.5) device: registers in I/O BAR 0,
    no virtio capabilities. netd drives both kinds; root gives it the I/O
    port capability.
  - dom0's first vNIC takes the uplink NIC's MAC address, since the VPC
    only delivers frames for it.
  - N2 attaches the boot disk and SCSI persistent disks to one legacy
    virtio-scsi controller without indirect descriptors, as targets 1, 2,
    ... (LUN 0). Each is a host disk; `SCSI_DISK_GB=10 tests/gce-test.sh`
    reads the boot disk and writes an extra blank one.
  - C3's gVNIC is revision 0 (admin queue by page frame number) with DQO
    RDA, 1024-entry rings, MTU 1460 and 9 MSI-X entries.

### 10.2 Partitioning large machines with Xen

seL4's big kernel lock limits how far one l4h scales across cores, so a
machine with many cores runs several l4h instances side by side, as Xen
HVM guests. l4h needs no VT-x of its own (§10.1), so an ordinary HVM
guest suffices. Each instance gets a slice of the cores and memory and
its own NIC, passed through whole: no SR-IOV.

- **Xen and dom0.** `tools/build-xen-dom0.sh` builds, from Debian 13
  packages, the Xen 4.20 hypervisor and a minimal dom0. That dom0 is
  Debian's kernel plus a 22 MiB initramfs with busybox, the `xl`
  toolstack, QEMU as the device model and the Xen driver modules.
  - Its init (`tools/xen/dom0-init`) starts xenstored, xenconsoled and a
    QEMU that serves the guests' disks (`backendtype=qdisk`).
  - It hands each device named with `xen-pciback.hide=(BB:DD.F)...` on
    dom0's command line to pciback. Built-in drivers such as virtio-pci
    have already bound them by the time the module loads.
  - It then starts the `xl` configurations in `/etc/l4h-xen`.
  - dom0 serves no guest traffic: it only creates the partitions.
- **Firmware.** The guests boot the usual l4h application and image
  (§10) under OVMF, as on GCE.
  - It must be the Xen build, OvmfXen (`tools/build-ovmf-xen.sh`, from
    edk2-stable202502), referenced with `bios_path_override`.
  - Debian's OVMF does not support Xen anymore: it finds none of the
    ACPI tables hvmloader builds, so GRUB has no RSDP to give seL4.
  - OvmfXen also changes GRUB's heap use enough to trip a GRUB 2.12 bug,
    which `tools/mkefi.sh` works around: GRUB grows its heap through boot
    services even after multiboot2 has exited them.
- **Passthrough.** Each partition's `pci = [...]` names its NIC. Xen maps
  the NIC's DMA through the IOMMU and its MSI-X through interrupt
  remapping, and l4h's netd drives it as on bare metal.
  - libxl warns that the kernel cannot reset a device that has no
    function-level reset. This applies to QEMU's virtio-net, not to NICs
    such as the X550.
- **Test.** `tests/run-xentest.sh` nests the whole setup in QEMU/KVM.
  - The outer machine is q35 with an emulated VT-d IOMMU (interrupt
    remapping, caching mode) and two virtio-net NICs on one hub.
    `iommu_platform` makes the NICs' DMA go through the IOMMU.
  - Xen starts two l4h partitions, each with one NIC and a disk image.
  - Each partition's dom0 pings the other's across the hub.

---

## 11. Portability to aarch64

| Concern | x86_64 | aarch64 |
|---------|--------|---------|
| seL4 support | MCS, SMP | MCS, SMP, and the best proof coverage |
| syscall trap (E1) | `syscall`, number in `rdx` | `svc`, number in `x7`; the same flag applies, and the fault carries Linux's x8 (patch 0007) |
| FPU access (E2) | XSAVE area | V-regs + FPSR/FPCR |
| Guest VA | 47-bit | 48-bit TTBR0 |
| TLS | `fs_base` | `TPIDR_EL0` (`seL4_TCB_SetTLSBase`) |
| Timer (E3) | LAPIC TSC-deadline or countdown | ARM generic timer |
| vDSO clock | `rdtsc` | `cntvct_el0` |
| Drivers | Rust virtio-net/blk/scsi PCI, NVMe | Same drivers; ECAM, BAR assignment and GICv2m MSI-X |
| Boot | multiboot2 / UEFI | rust-sel4 loader, entry at EL1 or EL2 |

Rules that keep the port cheap:

1. ISA code lives only in `arch/l4h/<isa>/` and in `host/*/src/arch/<isa>.rs`.
2. Nothing in the protocols depends on the ISA: boot info, event pages,
   virtio-l4h, host block and net queues. Fields are fixed-width and little-endian.
3. No use of x86-only seL4 features such as I/O ports outside drivers, EPT or
   `GetStatusBits`.
4. Guest RAM has 4 KiB aliases and optional 2 MiB process mappings on both ISAs.
5. CI builds both ISAs from day one, even before arm64 boots.

**Status (v1).**

- **Kernel.** seL4 aarch64 (QEMU `virt`, MCS, SMP, EL1, no hypervisor
  support) builds with all l4h patches, from `kernel/configs/l4h-aarch64.cmake`
  via `tools/build-kernel-aarch64.sh`.
  - E1 (trapSyscalls), E2 (FPU access), E3 (timers), patch 0005 (IPI
    barrier) and patch 0006 (lazy timer) are ISA-neutral.
  - Patch 0007 makes aarch64 report **x8**, the Linux syscall number,
    in the UnknownSyscall fault of trapping threads. seL4's own number is
    in x7, and x8 is not otherwise part of the fault message.
  - FaultIP points at the `svc` instruction, so the guest advances it by
    4 (x86_64: by 2).
  - Patch 0015 uses inner-shareable broadcast TLB maintenance at EL1, on
    full 16-bit ASIDs. The kernel refuses to boot unless the loader has
    set `TCR_EL1.AS` (16-bit ASIDs): with 8-bit ASIDs, address spaces whose
    seL4 ASIDs differ only in the upper 8 bits share TLB entries. Secondary
    cores check it too, and stop if they fail it. The broadcasts reach only
    the issuing core's VMID, which tags EL1&0 TLB entries whenever EL2 is
    enabled: the loader gives every core VMID 0.
    Patch 0016 reads the architectural counter frequency at boot for MCS
    budget and consumed-time conversions; the same image handles TCG's
    62.5 MHz counter and Apple M4 HVF's 24 MHz counter.
  - Patch 0018 passes ID_AA64ISAR0/1/2_EL1 and ID_AA64PFR0/1_EL1 to the
    root task as an extra bootinfo chunk, for the guests' HWCAPs (§5).
    They are the boot core's alone, and the guest advertises optional
    instructions from them (CRC32, AES, SHA, atomics, DotProd, LRCPC and
    others): on a CPU whose cores differ in these, a guest process may use
    an instruction that faults on another core it runs on. The HWCAP
    allowlist only leaves out state that seL4 does not save. l4h therefore
    requires cores with the same features; others need the fields
    intersected across the cores guests run on, or guests kept off the
    cores that lack a feature.
- **Boot.** rust-sel4's kernel loader only entered EL2 kernels.
  `third_party/patches/rust-sel4/0001` adds the EL1 path: it drops from EL2
  with the EL1 translation regime set up and no traps. Both EL1 paths set
  `TCR_EL1.AS` when `ID_AA64MMFR0_EL1.ASIDBits` reports 16-bit ASIDs.
  At EL2 the loader clears `HCR_EL2.E2H` before setting up its own
  translation (firmware may leave VHE on; CPUs where E2H is RES1 are
  refused), and the drop to EL1 sets `VTTBR_EL2` (VMID 0), `MDCR_EL2`
  (no debug or PMU traps, all counters to EL1), `VPIDR_EL2` and
  `VMPIDR_EL2` (what EL1 reads as `MIDR_EL1` and `MPIDR_EL1`) and, with a
  GICv3, `ICC_SRE_EL2`, all of which reset to UNKNOWN values. The
  fine-grained trap registers (FEAT_FGT) and `HCRX_EL2` are left to the
  firmware to initialize for a lower EL, as TF-A does; QEMU resets them to
  zero, which traps none of the registers seL4 uses. Both paths
  invalidate EL1's TLB before turning its MMU on, which matters when the
  loader ran at EL1 with its own tables.
  `tools/build-loader-aarch64.sh` applies the patch and builds the loader.
  Patch 0002 also supports direct EL1 entry, initializes the EL1 translation
  regime and selects QEMU's HVC PSCI conduit when EL2 is unavailable.
  The run script disables virtualization by default; its optional
  `L4H_QEMU_VIRTUALIZATION=on` tests the EL2 path.
- **Host.** All components build for AArch64. QEMU `virt` uses GICv2,
  `highmem-ecam=off,highmem-mmio=off`, a 16 MiB ECAM at 0x3f000000 and
  the 32-bit PCI memory aperture. The root assigns memory BARs before starting devices. GICv2m
  supplies 64 MSI interrupts (SPIs 80–143), divided between NICs and up to
  48 disks. MSI address/data are passed explicitly to the common drivers.
  The PL031 supplies wall time and the PL011 receives serial monitor input.
- **Linux.** The native AArch64 ABI, signals and FPSIMD context records,
  ptrace register sets, TLS, SMP, atomics, setjmp/longjmp, syscall restart,
  instruction-cache maintenance and module relocations are implemented.
  Modules use the large code model, like the guest kernel.
- **Tests.** `run-abitest.sh` covers the ABI with an attached PCI disk. `L4H_ARCH=aarch64` selects the Linux integration tests, including
  1/4-vCPU self-tests, modules, virtio-blk/NVMe, VM lifecycle, networking and
  the serial monitor. CI has a QEMU/TCG job for these paths. The assembled
  image also runs directly on Apple Silicon macOS using QEMU/HVF with
  `kernel-irqchip=off`; 1/4-vCPU self-tests pass on an Apple M4.
  `tools/run-image-aarch64.sh` selects HVF on macOS.
- **Platform scope.** This configuration targets QEMU `virt` with GICv2m.
  The existing UEFI/GCE images target x86_64; other ARM boards require their
  own platform description and interrupt routing.

---

## 12. Performance expectations, to be measured

| Operation | Native KVM guest | l4h, estimate | Notes |
|-----------|------------------|---------------|-------|
| null syscall | ~50 ns | ~0.4–1 µs | Fault IPC slowpath plus ReplyRecv. Comparable to Xen PV x86_64 or gVisor systrap. |
| page fault (anon) | ~1 µs | ~2–4 µs | Fault IPC, `handle_mm_fault` and `Page_Map`. |
| context switch | ~1–2 µs | ~2–3 µs | Two `SetSchedParams` and a reply. No FPU copying. |
| `clock_gettime` | vDSO | vDSO (rdtsc) | No trap on x86_64 (~40 ns); a syscall on aarch64. |
| fork+exec | baseline | 1.5–3× | Lazy refault. |
| disk I/O | | near native | One copy by the guest kernel through its I/O pool, plus two host queue hops. |
| network | | copies through pool and port slots | The guest bounces through its I/O pool; VMM and netd copy between pool, port and NIC buffers (§8.3). |

**Distribution check.** `tests/run-debian.sh` boots Debian 13 with
systemd as dom0 from a passed-through virtio-blk disk, on 2 vCPUs:
- systemd reaches "running" with no failed units;
- DHCP and DNS work over the user-mode uplink;
- `apt-get update` and `apt-get install` succeed;
- `ping` works.
The image comes from `tests/mkdebian.sh`.
`tests/run-workload.sh` covers the M2 and M3 gates on that image, with 4
vCPUs:
- fio random writes with crc32c verification, direct I/O, libaio,
  queue depth 16: 13.4k IOPS, all verified;
- busybox built with `make -j4` in 124 s, and the result runs;
- a clean `e2fsck -f` of the disk on the host;
- a checksum intact after a second boot.

**Measured before the I/O pool and RAM blocks (`tests/run-bench.sh`).**
These figures describe the earlier memory design; §15.2 records the
measurements after those changes. The network rows were measured again
on the current design, after the netd changes of §8.3. The test machine is unusual: the
dev box is itself a Hyper-V VM, so QEMU/KVM runs *nested*. Every VM exit
of seL4 (timer MSR writes, IPIs, EOIs, HLT wakeups) costs tens of
microseconds, against roughly one on a single-level cloud hypervisor.
Figures dominated by exits are therefore pessimistic here.

| Operation | l4h, nested KVM | Notes |
|-----------|-----------------|-------|
| getpid | 1.2–1.3 µs | Was 20 µs before kernel patch 0006. MCS reprogrammed the TSC deadline, a VM exit, on every scheduling-context switch. It now keeps an earlier armed deadline. Of the ~3,200-cycle seL4 round trip, most is the two thread switches (an address-space switch and an eager FPU swap each, ~640 cycles) and four kernel entries and exits; Linux itself takes ~440 cycles. A fastpath for the trapped syscall and its reply was tried and saved only ~6 %. |
| `clock_gettime` | ~40 ns | vDSO; was a ~1.4 µs syscall before it had time functions. |
| page fault (first touch) | 5–6.5 µs | |
| pipe round trip | 10 µs (same vCPU) | 37 µs between 2 vCPUs, which needs cross-core IPIs. |
| fork+exit+wait | 340–450 µs | |
| disk, 1 MiB direct | 830 MB/s write, 1.2–1.9 GB/s read | Zero-copy, close to the QEMU backend's own speed. |
| disk, 4 KiB read latency | ~200 µs | Two cross-core wakeups: guest → VMM → blkd and back. |
| guest↔guest ping | 1.4 ms | Four component hops per direction, with cross-core wakeups. |
| guest↔guest TCP | 670–710 MB/s | 1 vCPU each, sender ~70 % busy (`run-bench`, `netbench` with 256 KiB writes and 1 MiB reads). Checksum offload and TSO pass through the switch. Busybox `nc` as the tool gives ~8 MB/s with its vCPU saturated: earlier figures here (~30 MB/s) measured `nc`. |
| dom0 ↔ host over a tap NIC (vhost) | 380–620 MB/s down, 410–490 MB/s up | 256 MiB with wget / a 256 KiB-write sender. A plain Linux VM on the same QEMU: 0.5–1.3 GB/s. Was 26 MB/s down before GRO and batched notifications (§8.3), 3.5 MB/s while full RX rings dropped frames. |
| dom0 ↔ host over QEMU user net | ~165 MB/s down, ~37 MB/s up | QEMU's user networking caps a plain Linux VM at ~440 / ~84 MB/s; it takes no TSO, so netd segments uploads in software. |

Next steps for I/O latency:
- place each guest's VMM, blkd and netd work on the guest's core, or use
  passive servers on the caller's scheduling context;
- poll briefly before blocking, which trades CPU for wakeups;
- measure on GCE, where exits are about 20× cheaper.

The design prioritizes I/O and idle density, the cloud workload, over
syscall-heavy microbenchmarks. Benchmarks: lmbench lat_syscall/lat_ctx/
lat_pagefault, fio, iperf3, kernel compile, and a 30-guest idle-density test.

**Stage 1 baseline: guest THP using small-frame backing, measured 2026-10-30.**
`tests/run-thpbench.sh 1` and `tests/run-thpbench.sh 4` compare
`MADV_NOHUGEPAGE` with `MADV_HUGEPAGE` on the same Linux 6.18.58-l4h kernel.
Each mode/trial uses a fresh process, alternating order; the table gives
medians of five trials after one warmup pair. The guest has 512 MiB of RAM.
QEMU 10.0.13 uses KVM with four host vCPUs and 4 GiB, on an i7-13700H
exposed through an eight-vCPU Hyper-V development VM. Builds and other QEMU
tests were stopped during measurement; these remain nested, shared-host results.
The benchmark explicitly enables `madvise` policy and defrag, and disables
background underused splitting while delaying `khugepaged` scanning.

| Operation | 1 vCPU, base | 1 vCPU, THP | 4 vCPUs, base | 4 vCPUs, THP |
|-----------|--------------|-------------|---------------|--------------|
| Dense 64 MiB first-touch, ms | 65.212 | 26.226 | 68.487 | 28.034 |
| Minor faults during first-touch | 16,387 | 35 | 16,387 | 35 |
| Random page-stride read, ns/access | 17.64 | 16.81 | 18.21 | 15.78 |
| Fork + exit + wait, ms | 4.546 | 1.487 | 4.910 | 1.949 |
| Fork + COW-write 64 MiB + wait, ms | 95.372 | 128.847 | 98.050 | 152.392 |
| Partial protection changes in 32 PMDs, ms | 0.186 | 25.753 | 0.299 | 26.434 |
| Unmap after protection changes, ms | 12.206 | 10.768 | 13.090 | 10.862 |
| Sparse 64 MiB first-touch, ms | 0.196 | 18.962 | 3.446 | 24.641 |
| Sparse RSS, KiB | 128 | 65,536 | 128 | 65,536 |
| Dense `VmPTE`, KiB | 1,102 | 1,102 | 1,102 | 1,102 |

Dense first-touch writes one byte per 4 KiB; sparse first-touch writes one
per 2 MiB. Protection changes make one 4 KiB page in each PMD read-only,
then writable. Each fork measurement averages eight forks of the populated
mapping. The COW child writes and verifies every base page; its parent checks
that the original data remains intact. All THP trials verify full huge-page
coverage. The counters include three minor faults outside the data mapping.

First-touch is about 2.5 times faster, and fork about 2.5–3 times faster.
COW is 35–55% slower, and partial operations pay for splitting and synchronizing
the 512 base mappings. Sparse writes allocate 512 times as much resident data.
These costs support the opt-in default. There is no hardware huge-page TLB
benefit: random-read ranges overlap, and `VmPTE` (including seL4 mapping costs
and Linux's deposited PTE tables) is unchanged. For example, one-vCPU dense
first-touch ranges were 63.972–68.207 ms with base pages and 23.143–27.728 ms
with THP. Full ranges, raw trials, environment and correctness checks are in
[`tests/results/thp-nested-kvm-2026-10-30.txt`](tests/results/thp-nested-kvm-2026-10-30.txt).

**Native seL4 2 MiB backing, measured 2026-10-30.**
The same paired benchmark at `c53b9e6` (the results file records `ad54855`,
a hash rewritten before publication) now verifies 32 native large leaves
for each dense THP trial and zero for base-page trials. The environment,
policy and five-trial method are the same as above. A monitor sampled every
half second during QEMU execution and observed no other QEMU or compiler
jobs. These are still measurements on a shared, nested Hyper-V/KVM host.

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

Dense first-touch is 11.7–12.5 times faster with THP, and fork is 4.8–11.1
times faster. Reported `VmPTE` drops by about 81%: a PMD uses one mapped
frame cap instead of 512 and needs no seL4 leaf page table. Linux still
keeps its deposited PTE table, and the kernel direct map retains small
aliases. The absolute `VmPTE` value also includes unrelated process mappings.

COW remains 23–29% slower than base pages. Linux splits a shared PMD for
base-page COW, and the backend still pays for installing the small mappings.
Partial protection changes also retain substantial split costs. Sparse RSS
remains 128 KiB versus 64 MiB, a normal Linux THP allocation tradeoff. These
results support keeping the `madvise` default. Full ranges, raw trials and
validation are in
[`tests/results/thp-native-backing-nested-kvm-2026-10-30.txt`](tests/results/thp-native-backing-nested-kvm-2026-10-30.txt).

---

## 13. Repository layout and plan

```
l4h/
  DESIGN.md
  kernel/            seL4 (git submodule, pinned) + patches/ (E1–E3) + configs
  guest/linux/       arch/l4h sources, patches/ for anything outside arch/, defconfig (Linux 6.18 LTS)
  host/              Rust workspace: l4h-abi, l4h-host, l4h-rt, l4h-root, l4h-vmm, l4h-blkd, l4h-netd, l4h-trustd, l4h-virtio
  tools/l4hctl/      dom0 userspace CLI and library for the control API
  third_party/sddf/  submodule (design reference; no linked C drivers)
  tools/             build-kernel.sh, build-linux.sh, build-kmods.sh (the guest kernel's module tree), build-host.sh, mkefi.sh (UEFI application), build-efi.sh (its variants), add-modules.py (the guest kernel and dom0 into a built root), mkbios.sh (BIOS files), mkimage.sh (UEFI and BIOS disk), run-qemu.sh, run-uefi.sh, run-bios.sh, mkinitramfs.sh, l4h-attest.py (attestation verifier), swtpm.sh (a software TPM for QEMU)
  tests/             host-level integration tests driven by QEMU + expect-style console scripting
```

**Test environment.** This machine has KVM, so QEMU uses it only as a fast
CPU to mimic a cloud VM. The guest CPU is `-cpu host,-vmx -smp 4`, with
`virtio-blk-pci`, `nvme` and `virtio-net-pci` devices, and UEFI via OVMF or
plain multiboot. seL4 never uses VT-x. The dev box has 32 GiB of RAM, which
is reported as less because of host ballooning. The 30-guest test therefore
uses a 16 GiB QEMU machine and guests of 256–512 MiB.

**Original milestones and gates.** These record the development plan,
not a claim that every proposed gate or feature has been completed.
M0–M6 have working v1 implementations, with the tests and limitations
described above. M7 has reached N2 and C3 (gVNIC). M8 includes AArch64 Linux/PCI support and virtqueue fuzzing; upcall
injection and paravirtual spinlocks remain future work.

1. **M0, platform.**
   - Toolchains and the seL4 MCS SMP build.
   - A Rust `l4h-root` hello world boots in QEMU on 4 cores.
   - E1, E2 and E3 implemented, tested through the guest ABI test
     (`tests/guest/abitest`).
2. **M1, single-vCPU guest (dom0 only).**
   - dom0 with embedded images and build-time settings boots `arch/l4h`
     to an initramfs shell over the hvc console.
   - Covers syscalls, page faults, signals, fork/exec, mmap/mprotect and
     futex, plus the E3 timer and the vDSO.
   - Gate: busybox, then a static test suite (LTP subset).
3. **M2, SMP guests.**
   - vCPU bring-up and IPIs; PV spinlocks remain future work.
   - Gate: `stress-ng` and LTP on 4 vCPUs; `make -j4` of a kernel inside the
     guest.
4. **M3, virtio-l4h and blk passthrough.**
   - One Rust blkd per attached disk, with virtio-blk and NVMe drivers.
   - Gate: fio and fsck, with data integrity across guest reboots.
5. **M4, control API.**
   - The `l4hctl` device and `/dev/l4hctl`, the dom0 CLI, and the
     `vm_*` and `blk_*` operations.
   - Gate: dom0 creates, starts and destroys guests at runtime, and console
     attach works.
6. **M5, networking.**
   - vswitch with multiple switches, multiple vNICs per VM, and uplink ports.
   - The Rust netd virtio-net driver and the net backend in the VMM.
   - `switch_*` and `nic_*` operations.
   - Gate: guest↔guest iperf3 and ping, a router VM doing NAT to the outside,
     and MAC-lock tests.
7. **M6, density.**
   - Budgets, the balancer, steal time and dom0 restart.
   - Gate: 30 guests on 4 cores stay responsive, and destroy/recreate loops
     leak no Untyped.
8. **M7, GCP.**
   - Bring-up on N2 with virtio-net and NVMe (existing drivers).
   - Then the gVNIC driver (DQO) and C3/N4.
   - A GCE image builder.
   - Gate: the M3–M6 tests pass on GCE.
9. **M8, hardening and portability.**
   - The upcall-injection backstop (future), the host-owned I/O pool
     (implemented, §15.1), and fuzzing of the VMM, switch and control-API
     parsers (virtqueue and pool fuzzing implemented).
   - AArch64 Linux and PCI on QEMU virt (implemented, §11).

---

## 14. Review decisions

Decided on 2026-10-17:

1. **seL4 patches:** carry E1–E3 and propose them upstream.
2. **Targets:** QEMU with virtio devices first, then GCP. AWS and Azure come
   later.
3. **Networking:** the hypervisor provides only L2 virtual switches, with
   multiple vNICs per VM. Routing and NAT are done by a VM.
4. **Control plane:** a runtime API, available only to dom0, the first guest
   started at boot (§9.1).
5. **Guest kernel:** Linux 6.18 LTS with out-of-tree `arch/l4h` patches.

Still open, but not blocking M0–M3:

- Memory: is fixed reservation, with no overcommit, acceptable for v1?
  This is the current assumption.
- The API wire format beyond v1 fixed structs, if external orchestration
  needs a richer schema. That would be added in dom0 userspace.

---

## 15. Guest-owned memory

Implemented from the design "guest-owned memory (2 MiB Untyped RAM,
host-owned I/O pool)", revision 2, in its three phases. Goal: a guest's
paging structures and other kernel objects come from its own RAM, so that
its host overhead is a small fixed amount instead of growing with its RAM.
The precondition is that no device and no host component ever touches
memory the guest can retype.

### 15.1 Host-owned I/O pool and restricted DMA (phase 1)

- **The pool.** At create time `l4h-root` allocates the guest's I/O pool as
  one physically contiguous Untyped of `io_pool` bytes (default 4 MiB; a
  power of two from 1 to 256 MiB; `l4hctl create --io-pool`, dom0 with
  `dom0_io_pool_mb` or `L4H_DOM0_IO_POOL_MB`, whose default is sized from
  its vNICs, see "Receive buffers" below). It retypes it into frames and maps them into the
  guest kernel's VSpace at `ram_base_va + io_pool_gpa`, where
  `io_pool_gpa` is RAM rounded up to 2 MiB (boot info `io_pool_gpa`,
  `io_pool_size`), and into the guest's `l4h-vmm`. The guest gets these
  mappings only, no capability to the pool at all (stronger than the
  design, which gave it frame-cap copies: it never needs them).
- **Guest kernel.** `arch/l4h` no longer selects `NO_DMA`: it has
  dma-direct (device addresses are GPAs) with `SWIOTLB` and
  `DMA_RESTRICTED_POOL`. The pool is added to memblock and reserved, so it
  has struct pages but never enters the page allocator.
  `guest/linux/patches/0002` adds `swiotlb_dev_init_pool(dev, base, size)`
  and lets `DMA_RESTRICTED_POOL` be built without OF. The pool gets one
  swiotlb area per possible CPU, as far as areas of whole 128-slot
  segments allow (a free run never crosses a segment, so no allocation
  reaches into an area whose lock it does not hold), and a
  full pool does not warn: it is normal back-pressure.
  - The transport registers one platform device, `virtio-l4h`, binds it to
    the pool and makes it the parent (DMA device) of every virtio device.
    Vrings are coherent allocations from the pool; buffers bounce.
  - It requires `VIRTIO_F_ACCESS_PLATFORM`, and fails a queue the host
    refuses.
- **VMM.** `GuestMem` is a window on the pool only (`IO_POOL_VA`); it
  checks every guest address against `[io_pool_gpa, +io_pool_size)` with
  overflow-safe arithmetic. A driver that does not accept
  `ACCESS_PLATFORM` fails `FEATURES_OK`; a queue outside the pool is
  refused, and `DRIVER_OK` then fails (status `DEVICE_NEEDS_RESET`) until
  the device is reset. Chains with any buffer or indirect table outside
  the pool are returned unused, and so are chains longer than the queue
  size, indirect descriptors included (virtio 1.x §2.7.5.3.1): a chain
  is collected into a fixed array of that size.
- **Request size.** A block request bounces entirely through the pool, and
  one that cannot fit even in an empty pool would be requeued forever. The
  VMM therefore offers `VIRTIO_BLK_F_SIZE_MAX` with `size_max` such that
  `seg_max * size_max` is at most a quarter of the pool (72 KiB segments,
  about 1 MiB per request, with 4 MiB; 16 KiB with 1 MiB).
- **Receive buffers.** A virtio-net driver keeps its receive ring full, so
  its buffers hold pool memory all the time. The VMM offers
  `GUEST_TSO4/6` without `MRG_RXBUF` or indirect descriptors, so Linux
  posts "big" buffers of 18 pages in 19 descriptors: a 256-entry ring
  holds 13, 936 KiB. dom0 with three vNICs (two uplinks and the sandbox
  switch) held 2.8 MiB of a 4 MiB pool in page-sized pieces, and under a
  burst of writes a disk request (segments of 36 contiguous 2 KiB slots)
  found no room, was requeued for ever, and dom0's disk stopped with no
  request in flight anywhere below the guest (seen on a Latitude.sh node,
  2026-10-22). So the VMM sizes each receive queue
  (`host::iopool::rx_queue_size`): the largest power of two from 32 to
  256 whose full rings, for all the guest's NICs together, hold at most
  half the pool, which leaves a quarter beyond the largest request. A
  4 MiB pool keeps 256-entry rings for one NIC and 128 for three. dom0's
  default pool (`dom0_io_pool_mb` 0) is the smallest power of two, at
  least 4 MiB, with full rings for its vNICs (`host::iopool::for_nics`):
  8 MiB for three.
- **blk-mux.** blkd's client data region is the pool: every segment must
  lie in it and is translated with one offset (`host::blk::Pool`). The
  RAM chunk tables of blkd and the VMM are gone.
- **Hypercalls and other host access.** The device register pages and the
  console ring were already host pages. The only hypercall that passed a
  guest buffer by GPA was the control API's `VM_LOAD`: its source is now
  an offset in the control device's data area, 1 MiB of host frames mapped
  into dom0 (`l4h_dev_desc.data_va`), so `l4h-root` never reads guest RAM.
  `L4H_CTL_LOAD_MAX` is 1 MiB. ABI version 2.
- **Disk detach (F1).** Destroy still suspends blkd and resets the device
  (`blkd::detach`, `reset`) before any memory is reused. Only the pool and
  blkd's DMA memory can be device targets now, so a device that does not
  confirm the reset pins those (`Guest::destroy(pin_pool)`), not the
  guest's RAM. With a supported IOMMU the pool is unmapped from the device
  instead, and only blkd's DMA memory stays pinned (§8.5).
- **Tests.** `tests/guest/abitest` plays a hostile driver against a virtio-blk
  disk: no `ACCESS_PLATFORM`, rings in RAM or across the pool's end,
  header, data or status in RAM, a buffer past the pool's end; a read
  through the pool still works. `tests/fuzz-virtq` places the pool at
  random GPAs (including 0 and the top of the address space), aims
  descriptors and rings inside, at the edges of and outside it, checks
  queue setup both ways, checks blkd's pool check, and checks that no
  chain outside the pool reaches blkd. `run-blktest.sh` adds 8 parallel
  direct writers and readers (more than the pool holds); it also passes
  with `L4H_DOM0_IO_POOL_MB=1`.

### 15.2 Guest RAM as 2 MiB Untypeds (phase 2)

- **seL4 semantics, settled first** (`tests/guest/abitest`,
  `untyped_copy_test` and `ram_blocks_test`, seL4 16.0.0). An Untyped can be copied only while
  it has no children; the copy is a revocable MDB child of the original, and
  copying sets the original's free index to "full", so the two can never
  hand out the same memory. The guest retypes and revokes through its copy;
  a retype from a copy without children starts at its base and the memory
  is zeroed (reset); a copy with children cannot be copied again; revoking
  the original deletes the copy and everything retyped from it. So the
  design's first scheme works as intended: l4h-root keeps the original of
  every block and gives the guest a copy. The fallback (only cap to a
  2 MiB Untyped under a parent) was not needed.
- **Blocks.** Guest RAM is `ram / 2 MiB` blocks (RAM is rounded up to
  2 MiB), each a 2 MiB Untyped split from any free memory: guest RAM is no
  longer physically contiguous at all, and the chunk table and
  `VMM_MAX_RAM_CHUNKS` are gone. The originals stay in the guest's arena
  (`Arena::owned`), so destroy revokes them as before. Each block costs the
  host one root CNode slot. The kernel image's shared blocks (§5.6) are
  added to these, and have no Untyped.
- **Boot blocks.** `l4h-root` turns a block into host frames (a level-2 RAM
  CNode, 512 frames, mapped in the direct map) when an image is loaded into
  it (the kernel, or an initramfs). Shared blocks get their level-2 CNode
  at create, holding read-only copies of the kernel's frames; nothing is
  loaded into them (`VM_LOAD` there fails). At `VM_START` the boot blocks
  are the prefix of RAM up to the end of the kernel, the initrd (if it is
  not empty) and anything loaded, plus `BOOT_SLACK` (one) block for the
  guest kernel's memory until it has mapped the rest; at least one block
  must be left for the guest. dom0 chooses the initrd's address, so the
  prefix can be nearly all of the guest's RAM, and each boot block costs
  the host up to 32 KiB (its level-2 CNode and a page table, with the
  alignment between them) and three root slots: before it fills any,
  `VM_START` checks that the host can afford the blocks not yet filled
  (`Guest::boot_cost`) and reserves room in the guest's arena for them
  and the VMM's remaining objects (`Arena::reserve`), and fails with
  `ENOMEM` otherwise. The VMM's three large CNodes (its CSpace and the
  CNodes keeping its mappings) are made at guest creation, before loads
  can fill or fragment the arena; the remaining startup objects are small
  enough for that reservation's guarantee. `VM_LOAD` likewise
  checks and reserves the overhead of its unfilled blocks before loading,
  so a full arena table returns `ENOMEM` even when host RAM remains free.
  Deviation: the design counted two slack blocks as boot blocks
  *and* as the guest's first object pool, which cannot both hold (the
  guest has no Untyped for a boot block); here the slack block is frames
  for early `memblock` allocations, and object blocks come from the
  Untyped blocks.
- **Capabilities (ABI version 3).** Root slot `L4H_SLOT_BLOCKS` is the block
  CNode: slot `b` holds the Untyped copy of every non-boot block. Frames
  are named through two levels: root slot `L4H_SLOT_RAM_L1_BASE + n` is a
  level-1 CNode (radix 9) for GiB `n`, whose slot `j` holds the level-2
  CNode (radix 9) of block `512 n + j`; `L4H_FRAME_CPTR(gpa)` keeps its old
  value. l4h-root installs the level-2 CNodes of boot blocks (it keeps its
  own capability to them, to load images); the guest retypes its own
  into the others. Boot info: `nr_blocks`, `boot_blocks`; the Untyped
  quota (`L4H_SLOT_UNTYPED_BASE`, `bootinfo.untyped[]`) is gone, and
  `VM_CREATE`'s quota argument is ignored (`l4hctl --quota` removed).
- **Guest early boot** (`kernel/caps.c`, `l4h_caps_init`): memblock knows
  only the boot blocks. The guest marks some non-boot blocks as object
  blocks, creates its first capability CNode and the user CSpace from
  them, then for every other block retypes its level-2 RAM CNode (into its
  level-1 slot), one 2 MiB frame and its 512 subframe aliases, and maps
  the aliases at `ram_base_va + GPA`
  (read-write, execute-never), adding page tables from object blocks. Each
  block is added to memblock once mapped; object blocks are added and
  reserved, so they have struct pages.
- **Objects.** `l4h_obj_alloc` takes objects from Untyped *chunks* of 16,
  64 or 128 KiB (by object size, as the old quota allocator did) that it
  carves out of object blocks, one open block per class. Whole-block
  Untypeds and large frames use a separate 2 MiB class, also exercised by
  the capability lifetime tests. seL4 reuses an
  Untyped's memory only when all its children are gone; with whole 2 MiB
  blocks as the unit, a few long-lived objects (TCBs, a process's page
  tables) pinned each block, freed page tables were never reused, and
  `smp_mm_stress` exhausted 32 MiB of objects and slowed down sevenfold.
  A chunk resets as soon as its own objects are gone; a block is free
  when all its chunks are, and then forgets them. Slot CNodes (128 KiB)
  come straight from a block, since a chunk needs a slot. An empty one is
  deleted, and its block can become free, once a CNode's worth of slots is
  free in the others. Each mapping takes a slot, so a process with many
  mappings of the zero page costs memory without RSS: its mappings and
  seL4 page tables count in its page-table bytes, which the OOM killer
  ranks by. In this phase
  the object blocks are fixed at boot, 4 MiB plus RAM/32 out of the
  guest's own RAM (the old default quota, 16 MiB plus RAM/16, left a
  128 MiB guest too little RAM for ctltest's 80 MiB tmpfs); §15.3 makes
  them dynamic. `/proc/meminfo` shows `L4hObjects` (RAM in
  object blocks) and `L4hObjectsUsed` (in chunks with live objects).
  Deviation: the design's per-vCPU open blocks are per class only. All
  allocations take one lock anyway, and per-vCPU blocks would multiply the
  partly used blocks by the number of vCPUs.
- **Host accounting.** The ×2 safety factor is gone: an arena starts with
  an estimate of what its owner needs and grows from the free blocks
  (1 MiB at a time) when it runs out (`Arena::retype`). The VMM's estimate
  went from 8 MiB to what it maps (image and 512 KiB stack; it has no heap).
- **Buddy merging.** With RAM coming back in 2 MiB blocks, the host's free
  memory would end up in 2 MiB pieces, and an I/O pool (4 MiB) could no
  longer be found. `Alloc` now keeps the Untyped of every block it
  splits, and merges two free halves again by deleting them. It merges
  lazily, only when no free block is large enough (`merge_up_to`): the
  next retype of a merged parent makes seL4 clear everything its children
  used, and merging eagerly up to GiB blocks made every guest create clear
  a GiB of memory (create took 470 ms instead of 150).
- AArch64 uses the same host and Linux guest RAM-block conversion and
  reclamation paths. Only its paging-object operations differ.
- **Measured** (`tests/run-vmbench.sh`, nested QEMU/KVM, debug builds;
  host memory beyond a booted guest's RAM, and median latencies):

  | | main | phase 1 | phase 2 |
  |---|---|---|---|
  | overhead, 64 MiB guest | 41 MiB | 43 MiB | 10 MiB |
  | overhead, 128 MiB | 48 MiB | 49 MiB | 10 MiB |
  | overhead, 256 MiB | 62 MiB | 60 MiB | 10 MiB |
  | overhead, 512 MiB | 90 MiB | 82 MiB | 10 MiB |
  | create (call returns), 128 MiB | 389 ms | 316 ms | 128 ms |
  | create to init ready, 128 MiB | 446 ms | 344 ms | 258 ms |
  | create, 512 MiB | 1266 ms | 931 ms | 143 ms |
  | destroy, stopped guest | 345 ms | 39 ms | 119 ms |

  The overhead is the 4 MiB I/O pool plus about 6 MiB of host objects,
  whatever the RAM. Creating a guest no longer retypes its RAM: that
  moved into the guest's boot (create-to-ready minus create, about 130 ms
  for 128 MiB, was 57 ms). Phase 1 made create and destroy faster because
  the VMM no longer maps guest RAM.
- **Throughput** (`tests/run-bench.sh`, 1 vCPU). These runs were taken on
  a shared, heavily loaded development machine (load average about 10 on
  8 CPUs). Repeated runs of the same build differed by up to 3x, so the
  numbers below are only indicative and need repeating on a quiet host:

  | | main | this branch |
  |---|---|---|
  | disk write, 1 MiB direct | 376–1236 MB/s, 51–68 % CPU | 429–512 MB/s, 68–78 % CPU |
  | disk read, 1 MiB direct | 316–1167 MB/s, 88–91 % CPU | 447–598 MB/s, 82–88 % CPU |
  | disk 4K read latency | 69–163 µs | 351–374 µs |
  | guest↔guest TCP | 9–10 MB/s | 15–18 MB/s |

  (The TCP figures measured busybox `nc` copying in small chunks, which
  saturates a vCPU; `run-bench` now uses `netbench`, §12.)

  A slower disk path is expected, because every request is now copied
  through the swiotlb pool. Earlier runs on a quieter machine gave phase 1
  974 MB/s write and 750 MB/s read, against 1148–1210 and 910–1182 on
  main. The 4K latency gap is larger than the copy alone explains, and
  has not been investigated yet.

### 15.3 Converting blocks between frames and objects (phase 3)

- **At boot** the guest makes object blocks only of what onlining needs
  (a 16 KiB RAM CNode and a 4 KiB page table per frame block, and a slot
  CNode), plus the reserve; everything else starts as frames. A
  4-vCPU 256 MiB dom0 boots with 6 object blocks (12 MiB), of which
  2.6 MiB is used.
- **Classes.** Ordinary objects come from chunks of four classes, each with its
  own open block: small objects, 4 KiB objects (TCBs), page tables, and
  CNodes. Page tables have a class of their own because they die
  together when a process exits or loses its VSpace; mixed with TCBs,
  they pinned their chunks and blocks did not drain.
- **Free blocks.** A block is free when none of its chunks has live
  objects; it then forgets its chunks. Free blocks are either in the
  **reserve** or **spare**. Allocations (in atomic context, under
  page-table and capability locks) take a spare block, else a reserve
  block, and never wait. A worker (`objmem_balance`, on the unbound
  workqueue, also run synchronously by `l4h_objmem_wait`) keeps the
  reserve at its target and returns spare blocks beyond the watermark to
  frame mode. Both targets default to one block per vCPU, at most 1/32 of
  RAM.
  - Deviation: the design's per-vCPU reserve is one reserve counted per
    vCPU; allocations take a global lock anyway.
- **Frame -> object** (`frames_to_objects`): an order-9 allocation from the
  page allocator (`GFP_KERNEL | __GFP_RETRY_MAYFAIL`, so it reclaims and
  compacts; an order-9 page is a whole aligned block), retrying past boot
  blocks, which have no Untyped. If this fails, the guest scans frame
  blocks with `alloc_contig_range`, isolating the selected range and
  migrating its pages synchronously. Direct compaction only uses
  `MIGRATE_SYNC_LIGHT` and can defer or skip busy and dirty pages; an
  order-9 failure alone does not establish OOM. Revoking the block's
  Untyped copy then deletes its 512 frames with every mapping and copy of
  them; the pages stay allocated, so they are out of the page allocator.
  Boot blocks and blocks already holding objects are excluded from the
  fallback scan. The migration runs with `PF_MEMALLOC`, as direct
  compaction does, so it skips locked folios instead of waiting for them:
  a kernel mapping can wait for object memory while holding folio locks
  (EROFS decompresses into locked page cache folios through
  `vm_map_ram`), and waiting for one of them under `objmem_mutex`
  deadlocked the guest.
- **Kernel mappings** (vmap, vmalloc, percpu) cannot be left to fault
  again: a guest-kernel fault stops the guest. A kernel TLB sync that
  finds no memory leaves those PTEs unsynced and marks the range again,
  and `flush_cache_vmap` retries until it succeeds, sleeping between
  tries, waiting for object memory and allocating a page so that reclaim
  or the OOM killer runs when an atomic allocation failed.
- **Object -> frame** (`objects_to_frames`): the highest spare block is
  revoked (it has no children), gets its 512 frames back in its RAM CNode
  (which is kept), is mapped again, and its pages go back to the page
  allocator (`__free_pages` for buddy allocations, `free_contig_range`
  for isolated ranges, or `free_reserved_page` for blocks that were
  object blocks since boot). Isolated ranges hold one reference per page
  and must not be freed as a single order-9 allocation.
- **When there is no memory for objects.** Atomic callers get `-ENOMEM`:
  a TLB sync that cannot map a page leaves it unmapped and goes on (its
  unmaps must all happen; before, an error ended the sync early), so the
  page faults again. The fault path and the creation of a user context,
  which may sleep, call `l4h_objmem_wait()`; if no block could be
  converted (no free 2 MiB range), `l4h_objmem_oom()` calls the OOM
  killer, as a failed page-table allocation would on native Linux.
  Creating a user context no longer panics on a failure.
- **Accounting.** `/proc/meminfo` has `L4hObjects` (RAM in object blocks,
  out of the page allocator) and `L4hObjectsUsed`; `/proc/l4h_objmem`
  shows block counts, targets and conversions, plus `contig_attempts`
  and `contig_successes` for the synchronous migration fallback.
- **Test** (`tests/run-objtest.sh`): a fragmentation regression fills most
  free RAM, retains one movable anonymous page per physical 2 MiB block,
  and discards the rest. With direct compaction's fragmentation threshold
  set to 1000 and proactive compaction disabled, a child touches a page
  every 2 MiB of a 16 GiB mapping.
  This must grow object memory through synchronous migration and preserve
  the retained pages' contents. Before the fallback, this reproduced an
  objmem OOM with 162 MiB free in a 256 MiB guest.
  The stress phases use 8 processes that each
  touch a page every 2 MiB of a 1 GiB mapping (4096 page tables, 16 MiB):
  object blocks grow by converting frame blocks, and go back when they
  exit. The same three times while `selftest`'s
  `smp_mm_stress`, `smp_unmap_vis` and `smp_fork_storm` run, five times.
  Then a process maps sparse memory until RAM is exhausted: the OOM
  killer kills it, the guest carries on, and conversions work afterwards.
  With the fallback, a 1-vCPU 256 MiB run made nine synchronous
  conversions in the fragmentation regression; the later exhaustion
  phase reached 6 MiB free before OOM and recovered successfully.
  The full suite also passed with 4 vCPUs, using ten synchronous
  conversions in the fragmentation regression.
- **Fragmentation** (§9 of the design): long-lived objects can still pin
  partly empty chunks, and unmovable Linux pages can prevent a whole
  frame block from being isolated. Compaction of object memory (rebuilding
  VSpace mirrors into fresh blocks) remains future work.
- Phase 3 is shared by x86_64 and AArch64; only the paging-structure
  operations differ. The measurements above are from x86_64.

### 15.4 Free page reporting to the hypervisor

When l4h runs in a VM (QEMU/KVM for development and tests), memory it has
not given to a guest should not occupy the hypervisor's RAM.

- **Device.** `l4h-memd` (§16) drives a virtio-balloon PCI device that offers
  free page reporting (`VIRTIO_BALLOON_F_REPORTING`; QEMU
  `-device virtio-balloon-pci,free-page-reporting=on`, which
  `tools/run-qemu.sh`, `run-uefi.sh` and `run-image-aarch64.sh` add unless
  `L4H_BALLOON=0`). Only the reporting queue is used: no inflation or
  deflation, no statistics. QEMU numbers its queues by the features it
  offers, so the reporting queue is 2, plus one for the statistics queue
  and one for free page hinting if offered. `l4h-root` finds it on PCI,
  enables it and maps its BARs and three DMA pages into memd; a legacy
  balloon (§8.2) gets its I/O ports instead of BAR mappings. The device
  has no interrupt: memd's 100 ms timer polls it (`l4h-memd/src/balloon.rs`).
- **What is reported.** The allocator's free blocks (§15.2) of 2 MiB or
  more, once free for 2 s (as Linux does), so that memory freed and
  allocated again soon is not reported. A report is one chain of
  device-writable buffers, one per block or per 2 GiB of one, at most 32;
  one report is in flight at a time. Each free block is *free* (since a
  time), *reporting* or *reported*. Splitting a block passes its state to
  the halves, and merging two reported halves gives a reported parent.
- **Reuse.** A block being reported must not be used until the device
  returns it. Allocation skips such blocks, and waits (up to 2 s) for the
  report when nothing else fits. Reported blocks are used like others: the
  hypervisor has dropped their contents, which read as zero, as seL4 would
  make them anyway. Touching them backs them again.
- **Zeroing.** Kernel patch 0019 scans ordinary free RAM once during
  kernel boot, clearing only nonzero pages and issuing Untypeds with a
  zero free index. Their first use, including splitting into guest RAM
  blocks, preserves unbacked zero pages. Every runtime reset clears
  unconditionally, so reusing a previously allocated block backs its
  reset range again even if QEMU had dropped it. Free page reporting can
  still release blocks once they are unused.
- **Historical measurements with the former runtime scan**
  (`tests/run-balloontest.sh`: QEMU with 4 GiB and KVM,
  256 MiB dom0, a 1 GiB guest that fills 768 MiB of tmpfs, destroyed, all
  twice; QEMU's resident memory):

  | | idle | guest filled | guest destroyed |
  |---|---|---|---|
  | before | 618 MiB | 1642 MiB | 1642 MiB |
  | runtime scan only | 292 MiB | 1128–1260 MiB | 1128–1260 MiB |
  | runtime scan and reporting | 293 MiB | 1133 MiB | 307–310 MiB |

  These measurements predate restricting the scan to boot; they do not
  describe the memory cost of repeated reuse with unconditional resets.

  With the boot-only scan and reporting, a subsequent run of the same
  test used 259 MiB idle, 1091 MiB with the first guest and 264 MiB after
  destroying it; the second guest used 1289 MiB and destruction returned
  to 265 MiB. Both rounds passed the data-integrity and reclamation
  checks. The second allocation pays for unconditional reset while
  initial allocation still benefits from unbacked zero pages.

- **Not covered.** Memory a guest holds but does not use stays backed
  once the guest has written it: guests have no balloon, and their free
  pages are not reported. A guest's `page_reporting` device passing GPAs
  through the VMM to `l4h-memd`, which holds the guest's blocks and can
  translate them to physical addresses and report them, is the natural
  next step.

---

## 16. l4h-memd: the owner of memory

Phase 1 of the memory hotplug design (draft 2, "l4h memory hotplug and
l4h-memd"): one component owns all free RAM and all guest RAM, so that
guest memory can later grow and shrink without going through `l4h-root`.
Behaviour is unchanged.

- **Boot.** Root starts with every boot Untyped, as before, and allocates
  from them until memd runs: its own first objects, the module copies and
  memd itself (`memd::spawn`, right after the host facts are known). It
  then moves every free block of 2 MiB or more to memd
  (`Alloc::hand_over`), keeping the
  parents of blocks it had split: memd cannot merge those with their
  buddies, which concerns only the blocks root split at boot. Device
  Untypeds stay with root.
- **memd's table.** memd allocates nothing (no heap: `component!(main,
  no_heap)`). What it knows of memory is a table with a 24-byte entry
  per 2 MiB unit of physical address space, up to the end of the last
  block it gets, which root sizes, zeroes and maps when it spawns memd
  (`TABLE_VA`; 12 KiB for a 1 GiB host, 12 MiB for 1 TiB). memd never
  handles less than 2 MiB: root keeps the smaller boot Untypeds, and asks
  for no grant below 2 MiB. A block of 2^(21+k) bytes ("order k") is
  described by the entry of its first unit, and the free blocks of each
  order are on lists linked through their entries: those not reported to
  the hypervisor in the order they were freed, and those reported. So
  taking, freeing and finding a buddy are O(1), taking a block of order k
  is O(orders), and nothing scans the free blocks except a merge (below)
  and the report timer, which reads only the blocks it reports.
- **memd's CSpace** is one CNode (`SpawnArgs::cnode_bits`) with a slot
  for every block of every order that fits in the table, at a fixed
  place (`l4h_host::memd::block_slots`): two slots per 2 MiB unit, to
  the next power of two (64 KiB of CNode for a 1 GiB host). The halves
  of a split block are always in consecutive slots, which is what a
  retype needs, and no request can fill the CNode. Root holds its
  capability, and passes Untypeds by moving them into memd's exchange
  slots (`l4h_host::memd`); memd never calls root, and l4h-root calls it
  synchronously.
- **Root's memory** comes in *grants*: when root's free blocks cannot
  meet a request, it takes an untouched Untyped of 16 MiB (or exactly the
  request, if larger; or 2 MiB, if memd has no 16 MiB block) from memd
  (`MEMD_ALLOC`) and splits it as before.
  Grants are never merged with each other. When a destroy or a failed
  create leaves root more than 48 MiB of free blocks, it merges them and
  returns whole grants (`MEMD_FREE`) beyond 32 MiB (`Alloc::trim`).
  Merging after every destroy instead made creates a fifth slower: the
  next retype of a merged block clears all its halves used (§15.2). Host
  objects, arenas, I/O pools and ASID pools come from root's blocks, as
  before.
- **Merging** in memd is lazy for the same reason: free buddies merge
  only when no block is large enough for a request, in one pass over the
  free blocks of the smaller orders. A pass that finds nothing more to
  merge is not repeated until a block is freed or a report returns, so a
  host whose free memory is in 2 MiB pieces does not pay a pass per
  grant.
- **Guest RAM is memd's** (`MEMD_GUEST_*`). At create, root gives memd a
  copy of the guest's block CNode capability, and memd takes the guest's
  2 MiB blocks. When an image is loaded into a block, memd gives root a
  copy of its Untyped, which root fills with frames as before (a boot
  block). At boot, memd copies the Untypeds of the other blocks into the
  block CNode, past the shared blocks of the kernel image (§5.6), which
  memd has no block for: its block b is the guest's b plus the shared
  blocks below it. At destroy, once root has reclaimed its arena, memd revokes
  every original: that deletes the guest's copies, everything the guest
  made of them, and root's copies of boot blocks with their frames. The
  order matters: with the VSpace roots (in the arena) gone first,
  deleting the guest's frames unmaps nothing; the other way round, each
  frame was unmapped with a TLB shootdown, and destroying a stopped
  128 MiB guest took 585 ms instead of about 120. Root no longer holds a
  slot per guest RAM block.
- **Free page reporting** (§15.4) moved with the free memory: memd keeps
  the reported, reporting and free states of its blocks and drives the
  device. Root's cache (at most 32 MiB beyond what is in use) is not
  reported.
- **Free memory** for `host_info`, the monitor and the dashboard is root's
  free blocks plus memd's, which memd publishes in a status page mapped
  read-only into root (`l4h_host::memd::Status`).
- **Trust.** memd joins the host TCB. It cannot read memory: every
  Untyped it has handed out has a child, so it cannot retype it, and
  revoking it first makes seL4 clear the memory before it is used again.
  It can revoke what it handed out, including root's grants, and if it
  faults, root's next call to it never returns: the host stops.
- **Scheduling.** memd runs on core 0 at `PRIO_KERNEL + 2`, above every
  guest, with a full budget: root waits for it.
- **Limits.** None but the table: its size follows the host's memory,
  and no request makes memd use more of anything. A 1 TiB host needs
  12 MiB of table and 64 MiB of CNode.

## 17. Memory hotplug

dom0 can add memory to a running VM and take it back, 128 MiB at a time.
dom0 gets the mechanism only: it sets a VM's target and reads how much is
plugged; deciding the sizes is left to it. Memory that is not plugged
costs nothing: no frames, seL4 objects or struct pages, only guest
address space. The properties of §15 hold: a guest's host overhead is
fixed (16 KiB more), no host component reads guest RAM, and revoking a
guest's Untypeds reclaims everything it made. Plugging does not go
through `l4h-root`.

- **Region and units.** Every guest has a hotplug region, from its I/O
  pool's end rounded up to 128 MiB to the 64 GiB guest-physical limit
  (`L4H_GPA_END`), in *hotplug blocks* of 128 MiB (`L4H_HP_SIZE`, 64 RAM
  blocks, one Linux memory block). Boot info: `hp_gpa`, `hp_count` (at
  most 512). ABI version 5.
- **Capabilities.** Root slot `L4H_SLOT_HP` holds a level-1 hotplug CNode
  (radix 9, guard 3) that root makes, the only host memory the region
  costs. Before plugging hotplug block m, the guest retypes a level-2
  CNode (radix 6, 2 KiB) into its slot m from its own object memory;
  memd copies the Untypeds of the block's 64 blocks into it
  (`L4H_HP_BLOCK_CPTR(m, i)`). Frames of hotplugged memory are named by
  `L4H_FRAME_CPTR` like the rest of RAM: the guest makes the level-1 RAM
  CNodes of the region's GiBs (16 KiB each) when it first plugs there.
- **Control** (control version 3). `VM_SET_MEM` (vm, bytes): root rounds
  the part above boot RAM up to whole hotplug blocks, clamps it to the
  region, sets memd's target (`MEMD_SET_TARGET`), signals the VMM
  (`VMM_BADGE_MEM`) and returns. `VM_MEM_INFO`: boot, region, target and
  plugged bytes, from memd's status page; `VM_LIST` counts plugged memory.
  `l4hctl mem VM [MB] [--wait[=SECS]]`. Lowering a target revokes
  nothing: the guest gives back what it can, and `plugged > target` tells
  dom0 that it cannot give back more (it may wait or destroy the VM).
  Targets and plugged state live in memd, so a dom0 restart changes no VM.
  A reboot (destroy and create) starts with an empty region.
- **memd.** Per guest: the region's size, the target, a bitmap of plugged
  hotplug blocks, and for each the head of a list of its 64 units through
  the table (`HP_HEADS`, 128 KiB of BSS for all guests). VMMs call memd
  on its service endpoint with capabilities badged `BADGE_VMM | guest`,
  for their own guest's `MEMD_HP_PLUG`, `MEMD_HP_UNPLUG` and
  `MEMD_HP_STATE` only; memd still calls no one. A plug checks the range,
  the bitmap and the target, takes 64 free blocks and copies them into the
  guest's level-2 CNode; a copy that fails (no CNode, or something in the
  slot) undoes the plug. It takes only blocks that need no free page
  report to come back, so a guest never holds memd waiting: short of
  128 MiB of them it answers `EBUSY`. An unplug revokes and frees the 64
  originals; destroy revokes every plugged block with the rest. A token
  bucket per guest allows 8 plugs or unplugs a second after a burst of 16
  (`EBUSY` beyond): memd runs on core 0 above every guest, and this bounds
  the time one guest can take from it.
- **VMM.** The memory device (`L4H_DEV_MEM`, `struct l4h_mem_page`) is
  one more device page: target, plugged count and bitmap, which the VMM
  refreshes from memd (`MEMD_HP_STATE`) at start, after each request and
  when root signals a new target, raising the device's event then. A
  request (op, m) becomes one memd call; memd does every check. The guest
  writes it in the page and kicks the VMM, which answers in the page and
  raises the device's event.
- **Guest kernel.** `arch/l4h` moved from FLATMEM to `SPARSEMEM_VMEMMAP`
  with 128 MiB sections, and `ARCH_FORCE_MAX_ORDER` 9: Linux puts a memory
  block's memmap in the block (`memmap_on_memory`) only if it is whole
  pageblocks, and a 128 MiB block's memmap is 2 MiB. The vmemmap is 2 GiB
  of VA below the last PGD slot, mirrored into seL4 by the kernel TLB sync
  like vmalloc; the boot memmap is mapped directly at boot
  (`l4h_map_kernel_early`), before the sync can work (its mappings need
  slab memory), and its PTEs are left up to date so that later syncs skip
  them. `end_iomem`, and so `VMALLOC_START`, moved above the region.
  `arch_add_memory` and `arch_remove_memory` only add and remove the
  memmap: the driver maps the frames first. Nothing can allocate more
  than 2 MiB at once any more: patch 0002's swiotlb slot array, 3 MiB for
  a 256 MiB I/O pool, is now `kvcalloc`ed.
- **A plugged hotplug block** (`drivers/memhp.c`, `l4h_hp_map`):

  | Blocks | Use |
  |---|---|
  | 0 | its memmap (`MHP_MEMMAP_ON_MEMORY`) |
  | 1–62 | RAM |
  | 63 | the level-2 RAM CNodes of blocks 0–62 and the page tables mapping them in the direct map (1.26 MiB), retyped straight from its Untyped; its pages stay `PageOffline` |

  The guest sees 124 MiB of each block. A plug takes from its other
  memory only the 2 KiB level-2 hotplug CNode, a level-1 RAM CNode per
  new GiB, a 1 KiB table of page-table slots, and the vmemmap's page
  tables (a Linux and an seL4 page table per hotplug block, kept for the
  next plug there). Plug: those CNodes, a plug request, map,
  `add_memory_driver_managed`. Block 63's pages are skipped by an online
  page callback, and a memory notifier drops and restores their
  reference around offlining, as virtio-mem does for unplugged ranges, so
  offlining skips them. Unplug: `offline_and_remove_memory`, then
  revoking the copy of block 63 deletes the page tables and RAM CNodes
  (and with them every frame), then the other copies, then
  an unplug request. A guest that skips that only harms itself. When
  memd is too busy to take a block back (`EBUSY`), it stays pending, and
  the driver retries every second until memd has it, whether or not the
  target changes again. If a failed plug's rollback finds that Linux will
  not let go of the block, the block stays plugged and in use: nothing
  Linux may still use is unmapped or given back.
- **Zones.** The guest boots with `memory_hotplug.memmap_on_memory=1` in
  front of its command line, and memory is added offline
  (`MHP_DEFAULT_ONLINE_TYPE_OFFLINE`): the driver onlines every hotplug
  block to `ZONE_MOVABLE`, which can always be offlined. Linux may online
  a block itself as it is added (`auto_online_blocks`,
  `memhp_default_state=`, a udev rule): a block found online in another
  zone is offlined and onlined again to `ZONE_MOVABLE`, or, if it cannot
  be offlined, left where it is. The design had
  the kernel's `auto-movable` policy (movable up to three times boot RAM,
  then `ZONE_NORMAL`), for the kernel memory a bigger VM's processes
  need. That policy put every block in `ZONE_NORMAL` here; with the driver
  choosing zones on the same ratio instead, the stress test left VMs
  stuck above their target for good: a block in `ZONE_NORMAL` collects
  unmovable kernel pages, and offlining it fails (`EBUSY`) long after the
  VM is idle. In l4h the kernel memory that grows most with a VM's
  processes, their seL4 page tables and slots, comes from boot RAM anyway
  (hotplug blocks are never object blocks, below), so `ZONE_NORMAL` in
  hotplugged memory would serve only Linux's page tables and slabs.
  Unplug tries the highest block first, then the others.
- **Headroom.** Offlining moves whatever it can elsewhere, and memory
  that cannot be reclaimed (tmpfs without swap) then fills what is left:
  a guest shrunk to just above its tmpfs panicked, deadlocked on memory.
  The driver unplugs a block only if available memory stays above a
  sixteenth of RAM (at least 64 MiB) without it; otherwise the guest stays
  above its target, and retries every 10 s. Hotplug blocks
  are never object blocks of the allocator (§15.3): the order-9 fast path
  sets those pages aside, and the fallback scans boot RAM only. Seen
  from the allocator, hotplugged memory is page cache and anonymous
  memory; object memory still comes from boot RAM.
- **Test.** `tests/run-hotplugtest.sh`: a 256 MiB VM grows to 2 GiB
  (MemTotal follows, object memory does not grow, the host's free memory
  falls by the plugged amount), fills 1200 MiB of tmpfs, shrinks short of
  512 MiB without losing the data, empties tmpfs and reaches 512 MiB (the
  host gets the memory back), grows to 1 GiB and is destroyed, after which
  all host memory is back. `tests/run-hotplugstress.sh [rounds]`: three
  2-vCPU VMs under memory load (`tests/guest/hpstress.c`, which checks
  anonymous memory that unplugging migrates; `smp_mm_stress`; tmpfs
  files) get random targets from 256 MiB to 1.5 GiB every few seconds,
  4.5 GiB in all on a host with 3.7 GiB free, and one is destroyed in the
  middle of a resize every 15 rounds. Then the workloads stop and every
  VM must get back to 256 MiB, with no bad data, no kernel BUG or
  WARNING, and all host memory back after destroy.
