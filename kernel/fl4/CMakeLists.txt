cmake_minimum_required(VERSION 3.16)

# Build FL4 and its own libsel4 through the seL4-compatible CMake interface.
# FL4_SOURCE names the private copy of a pinned revision (tools/build-fl4.sh).
list(APPEND CMAKE_MODULE_PATH "${FL4_SOURCE}/cmake")
find_package(seL4 REQUIRED)
# AArch64 is cross-compiled: the platform settings choose the toolchain
# (CROSS_COMPILER_PREFIX), which project() needs (tools/build-fl4-aarch64.sh).
if(KernelPlatform STREQUAL "qemu-arm-virt")
  sel4_configure_platform_settings()
endif()
project(l4h_fl4 C ASM)
sel4_import_kernel()
sel4_import_libsel4()
set_target_properties(sel4 PROPERTIES EXCLUDE_FROM_ALL ON)
add_custom_target(l4h_kernel ALL DEPENDS kernel.elf sel4_generated)
