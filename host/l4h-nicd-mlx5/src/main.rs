//! nicd for the NVIDIA ConnectX-5 (15b3:1017): the initialization segment,
//! the MSI-X table and the lower UAR aperture in BAR 0, of which root maps
//! 16 MiB.  The driver refuses a UAR beyond it before any access.

#![no_std]
#![no_main]

mod mlx5;

use l4h_nicdrv as sdk;

sdk::driver!(mlx5::Mlx5, mlx5::MANIFEST);
