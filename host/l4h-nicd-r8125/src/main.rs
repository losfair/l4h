//! nicd for the Realtek RTL8125B (RTL8125BG) 2.5 GbE controller (Linux
//! `r8169`): registers in BAR 2, one MSI-X entry for every cause.

#![no_std]
#![no_main]

mod r8125;

use l4h_nicdrv as sdk;

sdk::driver!(r8125::R8125, r8125::MANIFEST);
