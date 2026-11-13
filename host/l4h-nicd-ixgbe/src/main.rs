//! nicd for the Intel X550 (Linux ixgbe), as on Latitude.sh m4.metal
//! servers: registers in BAR 0, MSI-X with an entry each for RX and TX.

#![no_std]
#![no_main]

mod ixgbe;

use l4h_nicdrv as sdk;

sdk::driver!(ixgbe::Ixgbe, ixgbe::MANIFEST);
