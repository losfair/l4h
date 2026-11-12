//! Production VMM install checks, with the capability syscalls modeled.
extern crate self as sel4;
use l4h_host as host;
use std::cell::Cell;

pub type Result<T> = std::result::Result<T, ()>;
#[derive(Clone, Copy)] pub struct CapRights;
pub trait HasCPtrWithDepth { fn tag(&self) -> u32; }
#[derive(Clone, Copy)] pub struct AbsoluteCPtr { tag: u32 }
impl HasCPtrWithDepth for AbsoluteCPtr { fn tag(&self) -> u32 { self.tag } }
impl AbsoluteCPtr {
    fn copy(&self, _: &Self, _: CapRights) -> Result<()> { Ok(()) }
}
struct Cnode;
impl Cnode {
    fn absolute_cptr(&self, cap: impl HasCPtrWithDepth) -> AbsoluteCPtr { AbsoluteCPtr { tag: cap.tag() } }
}
struct Component {
    id: u32,
    kind: u32,
    local_cnode: Cnode,
    destination_tag: Cell<u32>,
    installed: Cell<usize>,
}
impl Component {
    fn slot(&self, _: u64) -> AbsoluteCPtr { AbsoluteCPtr { tag: self.destination_tag.get() } }
    fn identify_cap(&self, source: &AbsoluteCPtr) -> Option<u32> { Some(source.tag) }
    fn live(&self, _: u64, _: &str, mut put: impl FnMut() -> Result<()>) -> Result<()> {
        put()?;
        self.installed.set(self.installed.get()+1);
        // The running VMM replaces its destination immediately. Auditing
        // that slot here would mistake its change for our installation.
        self.destination_tag.set(host::wiring::CAP_NOTIFICATION);
        Ok(())
    }
}
include!(env!("L4H_VMM_AUDIT_TEST_SRC"));

fn component(tag: u32) -> Component {
    Component { id: 1, kind: host::KIND_VMM, local_cnode: Cnode,
        destination_tag: Cell::new(tag), installed: Cell::new(0) }
}

#[test]
fn live_install_audits_its_source_before_a_child_can_change_the_slot() {
    let c = component(0);
    let ep = AbsoluteCPtr { tag: host::wiring::CAP_ENDPOINT };
    assert_eq!(c.give_live(host::SLOT_ROOT_EP, ep, CapRights, "parent"), Ok(()));
    assert_eq!(c.installed.get(), 1);
    assert_eq!(c.destination_tag.get(), host::wiring::CAP_NOTIFICATION);
}

#[test]
fn live_endpoint_or_notification_in_an_undeclared_slot_is_rejected_before_install() {
    for tag in [host::wiring::CAP_ENDPOINT, host::wiring::CAP_NOTIFICATION] {
        let c = component(0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.give_live(host::SLOT_VSPACE, AbsoluteCPtr { tag }, CapRights, "wrong slot")
        }));
        assert!(outcome.is_err());
        assert_eq!(c.installed.get(), 0);
    }
}

#[test]
fn parent_endpoint_audit_checks_dynamic_mints_and_rejects_the_wrong_object_type() {
    component(host::wiring::CAP_ENDPOINT).audit_vmm_copy(host::SLOT_ROOT_EP);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        component(host::wiring::CAP_NOTIFICATION).audit_vmm_copy(host::SLOT_ROOT_EP)
    }));
    assert!(outcome.is_err());
}
