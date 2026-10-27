//! Physical cores indexed by seL4 CPU number. CPU numbers and APIC IDs
//! need not be contiguous or ordered by SMT sibling.

/// CPUs a topology can describe: at least seL4's KernelMaxNumNodes in
/// either configuration (sched.rs checks it).
pub const MAX_CPUS: usize = 64;

pub struct Topology {
    cpus: usize,
    /// The first seL4 CPU belonging to each CPU's physical core.
    physical: [u8; MAX_CPUS],
    /// One thread of every physical core, then the second threads, etc.
    order: [u8; MAX_CPUS],
}

impl Topology {
    pub fn flat(cpus: usize) -> Self {
        assert!(cpus <= MAX_CPUS, "{} CPUs, at most {}", cpus, MAX_CPUS);
        let mut t = Self { cpus, physical: [0; MAX_CPUS], order: [0; MAX_CPUS] };
        for cpu in 0..cpus {
            t.physical[cpu] = cpu as u8;
            t.order[cpu] = cpu as u8;
        }
        t
    }

    pub fn from_ids(ids: &[u32]) -> Self {
        let mut t = Self::flat(ids.len());
        for (cpu, id) in ids.iter().enumerate() {
            t.physical[cpu] = ids.iter().position(|other| other == id).unwrap() as u8;
        }
        let physical = &t.physical[..t.cpus];
        // The keys are distinct, so an unstable sort gives the one order.
        t.order[..t.cpus].sort_unstable_by_key(|&cpu| {
            let cpu = cpu as usize;
            (physical[..cpu].iter().filter(|&&p| p == physical[cpu]).count(), physical[cpu])
        });
        t
    }

    /// The topology as (CPUs, each CPU's physical core, the placement
    /// order), as root passes it to vmmgr.
    pub fn raw(&self) -> (usize, [u8; MAX_CPUS], [u8; MAX_CPUS]) {
        (self.cpus, self.physical, self.order)
    }

    pub fn from_raw(cpus: usize, physical: [u8; MAX_CPUS], order: [u8; MAX_CPUS]) -> Self {
        assert!(cpus <= MAX_CPUS && physical.iter().chain(&order).all(|&c| (c as usize) < cpus.max(1)));
        Self { cpus, physical, order }
    }

    /// Each CPU's physical core (its first seL4 CPU).
    pub fn physical(&self) -> &[u8] {
        &self.physical[..self.cpus]
    }

    pub fn core(&self, cpu: usize) -> usize {
        self.physical[cpu] as usize
    }

    pub fn same_core(&self, a: usize, b: usize) -> bool {
        self.core(a) == self.core(b)
    }

    pub fn placement(&self, n: usize) -> usize {
        self.order[n % self.cpus] as usize
    }
}

/// Decode the SMT level of CPUID.1F/0B. Keep the package bits in the ID:
/// equal core numbers in different sockets are different physical cores.
#[cfg(target_arch = "x86_64")]
fn smt_id(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Option<u32> {
    if ebx & 0xffff == 0 || (ecx >> 8) & 0xff != 1 {
        return None;
    }
    // Clear thread bits instead of shifting: hybrid CPUs can report
    // different SMT widths, and their physical IDs must not collide.
    Some(edx & (u32::MAX << (eax & 0x1f)))
}

#[cfg(target_arch = "x86_64")]
fn physical_id() -> Option<(u32, u32)> {
    physical_id_from(core::arch::x86_64::__cpuid_count)
}

#[cfg(target_arch = "x86_64")]
fn physical_id_from(cpuid: impl Fn(u32, u32) -> core::arch::x86_64::CpuidResult) -> Option<(u32, u32)> {
    // Intel SDM, CPUID extended topology enumeration: prefer 1F to 0B.
    let max = cpuid(0, 0).eax;
    for leaf in [0x1f, 0x0b] {
        if max >= leaf {
            let r = cpuid(leaf, 0);
            if let Some(id) = smt_id(r.eax, r.ebx, r.ecx, r.edx) {
                return Some((r.edx, id));
            }
        }
    }
    // AMD topology extensions (Zen and later). Older AMD compute-unit
    // topology is deliberately left flat.
    let vendor = cpuid(0, 0);
    let ext = cpuid(0x8000_0000, 0).eax;
    if (vendor.ebx, vendor.edx, vendor.ecx) == (0x6874_7541, 0x6974_6e65, 0x444d_4163) && ext >= 0x8000_001e {
        let features = cpuid(0x8000_0001, 0);
        let family = ((features.eax >> 8) & 0xf) + ((features.eax >> 20) & 0xff);
        if family >= 0x17 && features.ecx & (1 << 22) != 0 {
            let r = cpuid(0x8000_001e, 0);
            let threads = ((r.ebx >> 8) & 0xff) + 1;
            let shift = threads.next_power_of_two().trailing_zeros();
            return Some((r.eax, r.eax & (u32::MAX << shift)));
        }
    }
    None
}

/// Visit the CPUs before starting any components. Reading CPUID on each
/// CPU avoids assumptions about seL4's enumeration or disabled threads.
/// Restore root's SC to its boot CPU before doing anything else, and drop
/// the other CPUs from its VSpace's TLB bitmap: else every page root
/// unmaps from then on (one per page it copies into a guest, window.rs)
/// interrupts them all, and on a loaded hypervisor, whose vCPUs wait to
/// be scheduled, a guest's boot slowed from 0.2 s to tens of seconds.
#[cfg(all(target_arch = "x86_64", not(test)))]
pub fn discover(
    cpus: usize,
    boot_cpu: usize,
    sched_context: sel4::cap::SchedContext,
    vspace: sel4::cap::VSpace,
    sched_control_base: usize,
) -> Topology {
    assert!(cpus <= MAX_CPUS);
    let move_to = |cpu| {
        crate::cap_at::<sel4::cap_type::SchedControl>(sched_control_base + cpu)
            .sched_control_configure_flags(sched_context, 5000, 5000, 0, 0, 0)
    };
    if physical_id().is_none() {
        return Topology::flat(cpus);
    }
    let mut ids = [0; MAX_CPUS];
    let mut apics = [0; MAX_CPUS];
    let mut n = 0;
    for cpu in 0..cpus {
        if move_to(cpu).is_err() {
            break;
        }
        let Some((apic, id)) = physical_id() else { break };
        if apics[..n].contains(&apic) {
            break;
        }
        apics[n] = apic;
        ids[n] = id;
        n += 1;
    }
    move_to(boot_cpu).expect("restore root CPU after topology discovery");
    crate::vspace::flush_tlb_bitmap(vspace);
    if n == cpus {
        Topology::from_ids(&ids[..n])
    } else {
        sel4::debug_println!("l4h-task: CPU topology unavailable; using flat placement");
        Topology::flat(cpus)
    }
}

#[cfg(all(target_arch = "aarch64", not(test)))]
pub fn discover(
    cpus: usize,
    _boot_cpu: usize,
    _sched_context: sel4::cap::SchedContext,
    _vspace: sel4::cap::VSpace,
    _sched_control_base: usize,
) -> Topology {
    Topology::flat(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn placement_spreads_before_using_siblings() {
        let t = Topology::from_ids(&[9, 9, 42, 42]);
        assert_eq!((0..8).map(|n| t.placement(n)).collect::<Vec<_>>(), [0, 2, 1, 3, 0, 2, 1, 3]);
        assert!(t.same_core(0, 1));
        assert!(!t.same_core(1, 2));
    }

    #[test]
    fn sparse_unordered_and_partial_sibling_sets() {
        let t = Topology::from_ids(&[42, 7, 42, 99, 7, 42]);
        assert_eq!(t.physical(), [0, 1, 0, 3, 1, 0]);
        assert_eq!((0..6).map(|n| t.placement(n)).collect::<Vec<_>>(), [0, 1, 3, 2, 4, 5]);
        let flat = Topology::flat(4);
        assert_eq!((0..4).map(|n| flat.placement(n)).collect::<Vec<_>>(), [0, 1, 2, 3]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cpuid_smt_level_keeps_socket_bits_and_rejects_missing_leaves() {
        assert_eq!(smt_id(1, 2, 1 << 8, 0x103), Some(0x102));
        assert_eq!(smt_id(0, 1, 1 << 8, 7), Some(7));
        assert_ne!(smt_id(0, 1, 1 << 8, 2), smt_id(1, 2, 1 << 8, 4));
        assert_eq!(smt_id(1, 0, 1 << 8, 3), None);
        assert_eq!(smt_id(1, 2, 2 << 8, 3), None);
        // Exercise the host's CPUID path as well.
        let _ = physical_id();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn prefer_leaf_1f_and_fall_back_to_0b_or_flat() {
        use core::arch::x86_64::CpuidResult;
        let zero = CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 };
        let read = |leaf, _| match leaf {
            0 => CpuidResult { eax: 0x1f, ..zero },
            0x1f => CpuidResult { eax: 1, ebx: 2, ecx: 1 << 8, edx: 0x103 },
            0x0b => CpuidResult { eax: 1, ebx: 2, ecx: 1 << 8, edx: 0x205 },
            _ => zero,
        };
        assert_eq!(physical_id_from(read), Some((0x103, 0x102)));
        assert_eq!(
            physical_id_from(|leaf, sub| if leaf == 0x1f { zero } else { read(leaf, sub) }),
            Some((0x205, 0x204))
        );
        assert_eq!(physical_id_from(|_, _| zero), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn amd_zen_topology_requires_the_feature_bit() {
        use core::arch::x86_64::CpuidResult;
        let zero = CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 };
        let read = |leaf, _| match leaf {
            0 => CpuidResult { eax: 0x10, ebx: 0x6874_7541, edx: 0x6974_6e65, ecx: 0x444d_4163 },
            0x8000_0000 => CpuidResult { eax: 0x8000_001e, ..zero },
            0x8000_0001 => CpuidResult { eax: (0xf << 8) | (8 << 20), ecx: 1 << 22, ..zero },
            0x8000_001e => CpuidResult { eax: 0x103, ebx: 1 << 8, ..zero },
            _ => zero,
        };
        assert_eq!(physical_id_from(read), Some((0x103, 0x102)));
        assert_eq!(physical_id_from(|leaf, sub| if leaf == 0x8000_0001 { zero } else { read(leaf, sub) }), None);
    }
}
