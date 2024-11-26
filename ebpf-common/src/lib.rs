//! Common stuff between userspace and kernelspace.

#![cfg_attr(not(feature = "user"), no_std)]

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct AllocationValue {
    pub size: usize,
    pub stackid: i64,
}

#[cfg(feature = "user")]
mod pod {
    use aya::Pod;

    use crate::AllocationValue;

    unsafe impl Pod for AllocationValue {}
}
