//! Common stuff between userspace and kernelspace.

#![cfg_attr(not(feature = "user"), no_std)]

use core::ffi::c_void;

// Default value of kernel.perf_event_max_stack
pub const MAX_STACK_DEPTH: u8 = 127;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct Event {
    pub addr: *const c_void,
    pub size: usize,
    pub stack: [u64; MAX_STACK_DEPTH as usize],
    pub stack_len: u8,
    pub kind: EventKind,
}

#[repr(u8)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub enum EventKind {
    Alloc,
    Free,
}
