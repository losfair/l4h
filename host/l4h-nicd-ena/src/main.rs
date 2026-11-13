//! nicd for the Amazon Elastic Network Adapter (Linux ena), as on every
//! Nitro EC2 instance: registers in BAR 0, the low-latency queue memory in
//! BAR 2 (write-combining) if there is one, MSI-X with the management entry
//! and one for the I/O queues.

#![no_std]
#![no_main]

mod ena;

use l4h_nicdrv as sdk;

sdk::driver!(ena::Ena, ena::MANIFEST);
