//! Run the multikernel shim's real reader against a model of KVM's MSR.
#[path = "../boot/l4h-mkshim/src/kvm_clock.rs"]
mod kvm_clock;

mod io {
    use std::cell::RefCell;
    #[derive(Clone)]
    pub struct Host {
        pub hypervisor: bool,
        pub kvm: bool,
        pub max_leaf: u32,
        pub features: u32,
        pub version: u32,
        pub mul: u32,
        pub shift: i8,
        pub writes: Vec<(u32, u64)>,
    }
    impl Default for Host {
        fn default() -> Self {
            Self { hypervisor: true, kvm: true, max_leaf: 0x4000_0001,
                features: 9, version: 2, mul: 1590728628, shift: 0, writes: vec![] }
        }
    }
    thread_local! { pub static HOST: RefCell<Host> = RefCell::new(Host::default()); }
    pub fn cpuid(leaf: u32, _: u32) -> [u32; 4] {
        HOST.with_borrow(|h| match leaf {
            1 => [0, 0, if h.hypervisor { 1 << 31 } else { 0 }, 0],
            0x4000_0000 => [h.max_leaf, if h.kvm { 0x4b4d_564b } else { 0 }, 0x564b_4d56, 0x4d],
            0x4000_0001 => [h.features, 0, 0, 0],
            _ => panic!("unexpected CPUID leaf {leaf:x}"),
        })
    }
    pub fn wrmsr(msr: u32, value: u64) {
        HOST.with_borrow_mut(|h| {
            h.writes.push((msr, value));
            if value & 1 != 0 {
                assert_eq!(value & 31, 1);
                let p = (value & !1) as *mut u8;
                unsafe {
                    p.cast::<u32>().write_volatile(h.version);
                    p.add(24).cast::<u32>().write_volatile(h.mul);
                    p.add(28).cast::<i8>().write_volatile(h.shift);
                }
            }
        });
    }
}

#[test]
fn scale_features_and_buffer_lifetime() {
    use io::Host;
    let check = |host: Host, expected, msr| {
        io::HOST.set(host);
        assert_eq!(kvm_clock::tsc_mhz(), expected);
        io::HOST.with_borrow(|h| {
            assert_eq!(h.writes.len(), if msr == 0 { 0 } else { 2 });
            if msr != 0 { assert_eq!(h.writes.last(), Some(&(msr, 0))); }
        });
    };
    let msr = 0x4b56_4d01;
    check(Host::default(), 2700, msr);
    check(Host { mul: 3181457256, shift: -1, ..Host::default() }, 2700, msr);
    check(Host { mul: 2147483648, shift: 1, ..Host::default() }, 1000, msr);
    check(Host { features: 1, max_leaf: 0, ..Host::default() }, 2700, 0x12);
    for version in [0, 1] { check(Host { version, ..Host::default() }, 0, msr); }
    check(Host { mul: 0, ..Host::default() }, 0, msr);
    for shift in [-128, -31, 127] {
        check(Host { mul: 1, shift, ..Host::default() }, 0, msr);
    }
    check(Host { features: 0, ..Host::default() }, 0, 0);
    check(Host { kvm: false, ..Host::default() }, 0, 0);
    check(Host { hypervisor: false, ..Host::default() }, 0, 0);
    check(Host { max_leaf: 0x4000_0000, ..Host::default() }, 0, 0);
}
