//! Common stuff between userspace and kernelspace.

#![cfg_attr(not(feature = "user"), no_std)]

use core::ffi::c_void;

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct Event {
    pub addr: *const c_void,
    pub size: usize,
    pub stackid: u32,
    pub kind: EventKind,
}

#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub enum EventKind {
    Alloc,
    Free,
}
