# seL4 kernel configuration for l4h on aarch64 (QEMU virt; see DESIGN.md §12).
# EL1 kernel: no hardware virtualization, like x86_64 without VT-x.
set(KernelPlatform "qemu-arm-virt" CACHE STRING "")
set(KernelSel4Arch "aarch64" CACHE STRING "")
set(KernelArmHypervisorSupport OFF CACHE BOOL "")
set(KernelIsMCS ON CACHE BOOL "")
set(KernelMaxNumNodes "4" CACHE STRING "")
set(KernelFastpath OFF CACHE BOOL "")
set(KernelVerificationBuild OFF CACHE BOOL "")
set(KernelOptimisation "-O2" CACHE STRING "")
set(QEMU_MEMORY "2048" CACHE STRING "")
set(ARM_CPU "cortex-a57" CACHE STRING "")
set(KernelAllowSMCCalls ON CACHE BOOL "")
# Guests and host components read the virtual counter (seL4 deadlines).
set(KernelArmExportVCNTUser ON CACHE BOOL "")
set(KernelRootCNodeSizeBits "19" CACHE STRING "")
set(KernelMaxNumBootinfoUntypedCaps "230" CACHE STRING "")
set(KernelRetypeFanOutLimit "16384" CACHE STRING "")
set(KernelTimerTickMS "2" CACHE STRING "")
set(KernelDebugBuild ON CACHE BOOL "")
# Debug syscalls only for host components (see l4h-x86_64.cmake).
set(KernelDebugSyscallMinMCP "101" CACHE STRING "")
set(KernelPrinting ON CACHE BOOL "")
# Kernel prints stall the core; spurious interrupts are frequent under
# QEMU/HVF (see l4h-x86_64.cmake).
set(KernelIRQReporting OFF CACHE BOOL "")
