# seL4 kernel configuration for l4h on x86_64 (see DESIGN.md §4).
set(KernelPlatform "pc99" CACHE STRING "")
set(KernelSel4Arch "x86_64" CACHE STRING "")
set(KernelIsMCS ON CACHE BOOL "")
set(KernelMaxNumNodes "64" CACHE STRING "")
set(KernelFastpath ON CACHE BOOL "")
set(KernelVerificationBuild OFF CACHE BOOL "")
set(KernelOptimisation "-O2" CACHE STRING "")
set(KernelFSGSBase "inst" CACHE STRING "")
set(KernelXSave "XSAVEOPT" CACHE STRING "")
# x87 | SSE | AVX
set(KernelXSaveFeatureSet "7" CACHE STRING "")
set(KernelXSaveSize "832" CACHE STRING "")
set(KernelSupportPCID ON CACHE BOOL "")
set(KernelLAPICMode "X2APIC" CACHE STRING "")
set(KernelIOMMU OFF CACHE BOOL "")
set(KernelVTX OFF CACHE BOOL "")
# The Meltdown "skim window" is incompatible with preserving user RSP across
# syscalls (patch 0004); l4h targets CPUs that are not affected by Meltdown.
# On an affected CPU (IA32_ARCH_CAPABILITIES.RDCL_NO clear, or an Intel CPU
# without the MSR, e.g. Intel before Cascade Lake) any guest could read all
# RAM through the kernel window, so the kernel refuses to boot there
# (patch 0024, DESIGN.md §4).
set(KernelSkimWindow OFF CACHE BOOL "")
set(KernelRootCNodeSizeBits "19" CACHE STRING "")
set(KernelMaxNumBootinfoUntypedCaps "230" CACHE STRING "")
set(KernelRetypeFanOutLimit "16384" CACHE STRING "")
set(KernelMultiboot2Header ON CACHE BOOL "")
# Ask a multiboot2 loader (GRUB on UEFI) for a linear framebuffer, for the
# host dashboard; optional, and ignored by QEMU's multiboot1 loader.
set(KernelMultibootGFXMode "linear" CACHE STRING "")
set(KernelMultibootGFXDepth "32" CACHE STRING "")
set(KernelMultibootGFXWidth "1024" CACHE STRING "")
set(KernelMultibootGFXHeight "768" CACHE STRING "")
set(KernelHugePage ON CACHE BOOL "")
set(KernelTimerTickMS "2" CACHE STRING "")
# Debug builds by default; L4H_RELEASE=1 tools/build-kernel.sh turns
# KernelDebugBuild (assertions, debug syscalls) off.  Printing stays on: the
# host components log to the serial port through the kernel.
set(KernelDebugBuild ON CACHE BOOL "")
set(KernelPrinting ON CACHE BOOL "")
# Every kernel print is a synchronous serial write with interrupts off, which
# stalls the core for the whole message.  Spurious interrupts are harmless and
# frequent under some hypervisors (QEMU/HVF): never report them.  Host
# components print only critical errors in release builds (host::VERBOSE).
set(KernelIRQReporting OFF CACHE BOOL "")
# Debug syscalls (some halt the machine) only for host components: guest
# threads have an MCP of at most L4H_PRIO_KERNEL (100).
set(KernelDebugSyscallMinMCP "101" CACHE STRING "")
