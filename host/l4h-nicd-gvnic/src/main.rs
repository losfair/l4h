//! nicd for Google Virtual NIC (gVNIC), using DQO RDA or GQI QPL:
//! registers in BAR 0, doorbells in BAR 2, two notification blocks and the
//! management vector in MSI-X.

#![no_std]
#![no_main]

mod gvnic;

use l4h_nicdrv as sdk;

sdk::driver!(gvnic::Gvnic, gvnic::MANIFEST);
