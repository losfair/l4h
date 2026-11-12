//! nicd for Google Virtual NIC (gVNIC), as on GCE C3, N4, C4 and later:
//! registers in BAR 0, doorbells in BAR 2, two notification blocks and the
//! management vector in MSI-X.

#![no_std]
#![no_main]

mod gvnic;

use l4h_nicdrv as sdk;

sdk::driver!(gvnic::Gvnic, gvnic::MANIFEST);
