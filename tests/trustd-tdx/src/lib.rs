//! trustd's Intel TDX parts free of seL4 (host/l4h-trustd/src/tdx.rs and
//! the CBOR encoder it writes with), compiled unchanged; the tests are in
//! tdx.rs.  Run with tests/run-trusttest.sh.
#![no_std]
#[path = "../../../host/l4h-trustd/src/cbor.rs"]
pub mod cbor;
#[path = "../../../host/l4h-trustd/src/tdx.rs"]
pub mod tdx;
