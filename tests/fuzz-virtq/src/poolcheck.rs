//! netd's backlog pool (host/l4h-netd/src/pool.rs) against backlogs that
//! stall: whatever the others hold, a backlog always takes frames that fit
//! in its reserve, and the chunks it accounts for come back when it drains.

use crate::Rng;
use crate::host::net;
use crate::pool::{self, BACKLOGS, CHUNK, CHUNKS, Fifo, RESERVED};

const HDR: [u8; net::HDR_SIZE] = [0; net::HDR_SIZE];
/// netd's per-port limits (l4h-netd's main.rs).
const FRAMES: usize = 512;
const PORT_CHUNKS: usize = (2 << 20) / CHUNK;

/// Fill every backlog but one as a stalled port's would fill, then check
/// the last; then `n` rounds of random pushes and pops.  The pool can be
/// taken once a process: run once.  Returns the frames pushed.
pub fn check(rng: &mut Rng, n: u64) -> u64 {
    let p = pool::take();
    let big = vec![0u8; net::MAX_FRAME];
    let mut qs = [Fifo::EMPTY; BACKLOGS];
    let mut pushed = 0;
    for q in &mut qs[..BACKLOGS - 1] {
        while p.push(q, &big, &HDR, FRAMES, PORT_CHUNKS) {
            pushed += 1;
        }
        assert!(q.chunks >= RESERVED, "a stalled backlog got less than its reserve");
    }
    let held: usize = qs.iter().map(|q| q.chunks).sum();
    assert!(held <= CHUNKS);
    let last = &mut qs[BACKLOGS - 1];
    assert!(p.push(last, &big, &HDR, FRAMES, PORT_CHUNKS) && p.push(last, &big, &HDR, FRAMES, PORT_CHUNKS),
        "{} stalled backlogs took the last one's reserve", BACKLOGS - 1);
    for q in &mut qs {
        p.clear(q);
    }
    // All of it came back: one backlog alone fills up to its own limit.
    let one = &mut qs[0];
    while p.push(one, &big, &HDR, FRAMES, PORT_CHUNKS) {}
    assert_eq!(one.chunks, PORT_CHUNKS / net::MAX_FRAME.div_ceil(CHUNK) * net::MAX_FRAME.div_ceil(CHUNK));
    p.clear(one);
    for _ in 0..n {
        let i = rng.below(BACKLOGS as u64) as usize;
        let q = &mut qs[i];
        if rng.below(3) == 0 {
            p.pop(q);
            continue;
        }
        let len = 1 + rng.below(net::MAX_FRAME as u64) as usize;
        let reserved = q.frames < FRAMES && q.chunks + len.div_ceil(CHUNK) <= RESERVED;
        let ok = p.push(q, &big[..len], &HDR, FRAMES, PORT_CHUNKS);
        assert!(ok || !reserved, "backlog {i} with {} chunks refused a frame of {len} bytes in its reserve", q.chunks);
        pushed += ok as u64;
        assert!(qs.iter().map(|q| q.chunks).sum::<usize>() <= CHUNKS);
    }
    for q in &mut qs {
        p.clear(q);
        assert_eq!((q.frames, q.chunks), (0, 0));
    }
    pushed
}

#[test]
fn stalled_backlogs_leave_the_others_their_reserve() {
    check(&mut Rng(0x5eed), 20_000);
}
