//! The production CTL_VM_START handler with a guest that records its boot.
use l4h_abi as abi;

const EINVAL: i64 = 22;
const ENOENT: i64 = 2;
const ENOMEM: i64 = 12;
const EBUSY: i64 = 16;
const MAX_GUESTS: usize = 2;

#[derive(PartialEq, Eq)]
enum State { Created }
struct Pool { size: usize }
struct Kernel { end: usize }
struct Wins { a: () }

struct Guest {
    state: State,
    vmm: Option<()>,
    root_pending: bool,
    pool: Pool,
    vcpus: Vec<()>,
    devices: Vec<()>,
    boots: usize,
}
impl Guest {
    fn boot_cost(&self, _: usize, _: (usize, usize)) -> Option<(usize, usize)> { Some((0, 0)) }
    fn reserve(&mut self, _: &mut (), _: usize) -> bool { true }
}

mod vmm {
    pub fn start_bytes(_: usize, _: usize, _: usize) -> usize { 0 }
}
mod guest {
    /// As the production one: a guest's boot info is written once.
    pub fn boot(g: &mut super::Guest, _: &mut (), _: &mut (), _: &(), _: &super::Kernel, _: (usize, usize), _: &[u8]) -> bool {
        g.boots += 1;
        g.boots == 1
    }
}

struct Vmmgr { guests: [Option<Guest>; MAX_GUESTS], kernel: Option<Kernel>, alloc: (), wins: Wins, info: (), started: usize }
impl Vmmgr {
    fn with_guest<R>(&mut self, id: usize, f: impl FnOnce(&mut Self, &mut Guest) -> R) -> Option<R> {
        let mut g = self.guests[id].take()?;
        let r = f(self, &mut g);
        self.guests[id] = Some(g);
        Some(r)
    }
    fn can_afford(&self, _: usize, _: usize, _: usize) -> bool { true }
    fn start_guest(&mut self, id: usize) -> Result<(), i64> {
        let g = self.guests[id].as_ref().unwrap();
        if g.root_pending { return Err(EBUSY); }
        self.started += 1;
        Ok(())
    }
}

fn cstr(data: &[u8]) -> &[u8] { data }

include!(env!("L4H_VM_START_TEST_SRC"));

#[test]
fn start_refused_for_a_pending_disk_can_be_retried() {
    let g = Guest { state: State::Created, vmm: None, root_pending: true, pool: Pool { size: 0 },
        vcpus: vec![()], devices: vec![], boots: 0 };
    let mut h = Vmmgr { guests: [None, Some(g)], kernel: Some(Kernel { end: 0 }), alloc: (), wins: Wins { a: () }, info: (), started: 0 };
    let req = abi::CtlReq { op: abi::CTL_VM_START, args: [1, 0, 0, 0, 0, 0], ..unsafe { core::mem::zeroed() } };
    assert_eq!(execute(&mut h, 0, &req), Err(EBUSY));
    assert_eq!(h.guests[1].as_ref().unwrap().boots, 0, "a refused start must not prepare the guest");
    h.guests[1].as_mut().unwrap().root_pending = false;
    assert_eq!(execute(&mut h, 0, &req), Ok(()));
    assert_eq!((h.guests[1].as_ref().unwrap().boots, h.started), (1, 1));
}
