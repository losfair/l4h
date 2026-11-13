//! nicd for virtio-net PCI devices, modern (virtio 1.x) and legacy (0.9.5,
//! as on N2 GCE instances).

#![no_std]
#![no_main]

mod virtio_net;

use l4h_nicdrv as sdk;

sdk::driver!(virtio_net::VirtioNet, virtio_net::MANIFEST);
