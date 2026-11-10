//! Compile normally, then require each deliberately mismatched variant
//! to fail (run-devicetest.sh).
use l4h_host::{blk, mailbox, net, wiring::{self, E, o, p}};

#[cfg(not(wrong_edge))]
const EDGE: E<p::Root, p::Blkd, o::Notification, blk::call::Proto> = wiring::ROOT_BLKD_CALL;
#[cfg(wrong_edge)]
const EDGE: E<p::Root, p::Blkd, o::Notification, net::call::Proto> = E::new(wiring::ROOT_BLKD_CALL.0);

pub fn post(page: &mailbox::Mailbox) {
    let _ = EDGE;
    let mut client = mailbox::Client::<net::call::Proto>::new(page);
    #[cfg(not(wrong_protocol))]
    let request = net::call::Request::RemovePort { port: 7 };
    #[cfg(wrong_protocol)]
    let request = blk::call::Request::Add { client: 7, unit: 0, dom0: false, n: 0 };
    client.send(&request);
}
