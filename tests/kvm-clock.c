/* Exercise the kernel's boot-time pvclock reader without privileged MSRs. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BOOT_CODE
#define BOOT_BSS
#define ALIGN(n) __attribute__((aligned(n)))
#define BIT(n) (1u << (n))
#define CPUID_KVM_EBX 0x4b4d564b
#define CPUID_KVM_ECX 0x564b4d56
#define CPUID_KVM_EDX 0x4d
#define kpptr_to_paddr(p) ((uintptr_t)(p))

static unsigned features, version, multiplier, writes;
static int shift, hypervisor = 1, kvm = 1;
static uint32_t max_leaf = 0x40000001, last_msr;
static uint64_t last_value;
static uint32_t x86_cpuid_eax(uint32_t leaf, uint32_t sub)
{
    (void)sub;
    return leaf == 0x40000000 ? max_leaf : features;
}
static uint32_t x86_cpuid_ebx(uint32_t leaf, uint32_t sub)
{
    (void)leaf; (void)sub;
    return kvm ? CPUID_KVM_EBX : 0;
}
static uint32_t x86_cpuid_ecx(uint32_t leaf, uint32_t sub)
{
    (void)sub;
    return leaf == 1 ? (hypervisor ? BIT(31) : 0) : CPUID_KVM_ECX;
}
static uint32_t x86_cpuid_edx(uint32_t leaf, uint32_t sub)
{
    (void)leaf; (void)sub;
    return CPUID_KVM_EDX;
}
static void x86_wrmsr(uint32_t msr, uint64_t value);
#include <plat/machine/kvm-clock.h>

static void x86_wrmsr(uint32_t msr, uint64_t value)
{
    writes++;
    last_msr = msr;
    last_value = value;
    if (value & 1) {
        assert((value & 31) == 1);
        volatile struct kvm_clock_info *p = (void *)(uintptr_t)(value & ~1ull);
        p->version = version;
        p->mul = multiplier;
        p->shift = shift;
    }
}

static void check(uint32_t expected, uint32_t msr)
{
    writes = 0;
    assert(tsc_kvm_mhz() == expected);
    assert(writes == (msr ? 2 : 0));
    if (msr) {
        assert(last_msr == msr);
        assert(last_value == 0); /* even invalid data must unregister */
    }
}

int main(void)
{
    assert(sizeof(struct kvm_clock_info) == 32);
    features = BIT(3) | BIT(0);
    version = 2;
    multiplier = 1590728628u; /* ~2.7 GHz, not C3's CPUID.15 1.9 GHz */
    check(2700, 0x4b564d01);
    multiplier = 3181457256u; shift = -1;
    check(2700, 0x4b564d01);
    multiplier = 2147483648u; shift = 1;
    check(1000, 0x4b564d01);
    features = BIT(0); max_leaf = 0;
    check(1000, 0x12); /* legacy KVM signature and MSR */
    features = BIT(3); max_leaf = 0x40000001;
    version = 1;
    check(0, 0x4b564d01); /* in-progress update never consumed */
    version = 0;
    check(0, 0x4b564d01); /* host did not initialize the buffer */
    version = 4; multiplier = 0;
    check(0, 0x4b564d01);
    multiplier = 1; shift = -31;
    check(0, 0x4b564d01); /* overflow */
    shift = -128;
    check(0, 0x4b564d01);
    shift = 127;
    check(0, 0x4b564d01);
    features = 0;
    check(0, 0);
    features = BIT(3); kvm = 0;
    check(0, 0);
    kvm = 1; hypervisor = 0;
    check(0, 0);
    hypervisor = 1; max_leaf = 0x40000000;
    check(0, 0);
    puts("KVM clock: kernel scale, feature checks and buffer lifetime passed");
}
