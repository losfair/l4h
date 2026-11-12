//! nicd for the Intel 82574L and 82583V (Linux e1000e), as QEMU's
//! `e1000e` device: registers in BAR 0, MSI-X with an entry each for RX
//! and TX.

#![no_std]
#![no_main]

mod e1000e;

use l4h_nicdrv as sdk;

sdk::driver!(e1000e::E1000e, e1000e::MANIFEST);
