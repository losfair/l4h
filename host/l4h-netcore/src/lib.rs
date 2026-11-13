//! Frame code netd and the NIC drivers share: virtio-net offload metadata,
//! segmentation and receive offload (offload.rs).

#![no_std]

pub mod offload;
pub use offload::Frame;
