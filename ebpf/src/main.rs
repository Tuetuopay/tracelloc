#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use core::ptr::null;

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, BPF_F_REUSE_STACKID, BPF_F_USER_STACK},
    cty::{c_void, size_t},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf, StackTrace},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use aya_log_ebpf::info;
use tracelloc_ebpf_common::{AllocationValue, Event, EventKind};

macro_rules! tracking_map {
    ($name:ident, $arg:ty) => {
        #[map]
        static mut $name: HashMap<u32, $arg> = HashMap::with_max_entries(1_000, BPF_F_NO_PREALLOC);
    };
    ($name:ident, ($($args:ty),+)) => {
        #[map]
        static mut $name: HashMap<u32, ($($args),+)> = HashMap::with_max_entries(1_000, BPF_F_NO_PREALLOC);
    };
}

tracking_map!(MALLOCS, usize);
tracking_map!(CALLOCS, (usize, usize));
tracking_map!(FREES, *const c_void);
tracking_map!(REALLOCS, (*const c_void, usize));

#[map]
static mut ALLOCATIONS: HashMap<*const c_void, AllocationValue> =
    HashMap::with_max_entries(1_000_000, BPF_F_NO_PREALLOC);
#[map]
static mut STACKS: StackTrace = StackTrace::with_max_entries(1_000, 0);
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

#[uprobe]
fn malloc(ctx: ProbeContext) {
    let Some(size) = ctx.arg::<size_t>(0) else { return };
    let _ = unsafe { MALLOCS.insert(&ctx.tgid(), &size, 0) };
}

#[uretprobe]
fn malloc_ret(ctx: RetProbeContext) {
    let Some(ptr) = ctx.ret::<*const c_void>() else { return };
    let args = unsafe { MALLOCS.get(&ctx.tgid()).copied() };
    let Some(size) = args else { return };

    let _ = unsafe { MALLOCS.remove(&ctx.tgid()) };
    on_alloc(&ctx, ptr, size);
}

#[uprobe]
fn calloc(ctx: ProbeContext) {
    let Some(nmemb) = ctx.arg::<size_t>(0) else { return };
    let Some(size) = ctx.arg::<size_t>(1) else { return };
    let _ = unsafe { CALLOCS.insert(&ctx.tgid(), &(nmemb, size), 0) };
}

#[uretprobe]
fn calloc_ret(ctx: RetProbeContext) {
    let Some(ptr) = ctx.ret::<*const c_void>() else { return };
    let args = unsafe { CALLOCS.get(&ctx.tgid()).copied() };
    let Some((nmemb, size)) = args else { return };
    let size = nmemb * size;

    let _ = unsafe { CALLOCS.remove(&ctx.tgid()) };
    on_alloc(&ctx, ptr, size);
}

#[uprobe]
fn free(ctx: ProbeContext) {
    let Some(ptr) = ctx.arg::<*const c_void>(0) else { return };
    let _ = unsafe { FREES.insert(&ctx.tgid(), &ptr, 0) };
}

#[uretprobe]
fn free_ret(ctx: RetProbeContext) {
    let args = unsafe { FREES.get(&ctx.tgid()).copied() };
    let Some(ptr) = args else { return };

    let _ = unsafe { FREES.remove(&ctx.tgid()) };
    on_free(&ctx, ptr);
}

#[uprobe]
fn realloc(ctx: ProbeContext) {
    let Some(ptr) = ctx.arg::<*const c_void>(0) else { return };
    let Some(size) = ctx.arg::<size_t>(1) else { return };
    let _ = unsafe { REALLOCS.insert(&ctx.tgid(), &(ptr, size), 0) };
}

#[uretprobe]
fn realloc_ret(ctx: RetProbeContext) {
    let Some(new_ptr) = ctx.ret::<*const c_void>() else { return };
    let args = unsafe { REALLOCS.get(&ctx.tgid()).copied() };
    let Some((old_ptr, new_size)) = args else { return };

    let _ = unsafe { REALLOCS.remove(&ctx.tgid()) };
    if old_ptr == null() && new_ptr != null() {
        // Do nothing: a realloc(null, >0) is documented as being equivalent to a malloc. which it
        // is, since it basically calls malloc. and since we hook malloc, we'll know.
        // on_alloc(&ctx, new_ptr, new_size);
    } else if new_size == 0 && old_ptr != null() {
        // Do nothing: similarly, a realloc(ptr, 0) is documented as being equivalent to a free.
        // which it is, since it basically calls free. and since we hook free, we'll know.
        // on_free(&ctx, old_ptr);
    } else {
        on_free(&ctx, old_ptr);
        on_alloc(&ctx, new_ptr, new_size);
    }
}

fn on_alloc<C: EbpfContext>(ctx: &C, ptr: *const c_void, size: usize) {
    unsafe {
        let stackid = STACKS.get_stackid(ctx, (BPF_F_USER_STACK | BPF_F_REUSE_STACKID) as u64);
        let stackid = match stackid {
            Ok(id) => id as u32,
            Err(_) => return,
        };

        if ptr != null() {
            let _ = ALLOCATIONS.insert(&ptr, &AllocationValue { size, stackid }, 0);
        }

        if let Some(mut event) = EVENTS.reserve::<Event>(0) {
            let evt = event.as_mut_ptr();
            (*evt).addr = ptr;
            (*evt).size = size;
            (*evt).stackid = stackid;
            (*evt).kind = EventKind::Alloc;
            event.submit(0);
        } else {
            info!(ctx, "Ring buffer is full for send!");
        }
    }
}

fn on_free<C: EbpfContext>(ctx: &C, ptr: *const c_void) {
    unsafe {
        let Some(&AllocationValue { size, stackid }) = ALLOCATIONS.get(&ptr) else { return };

        if ptr != null() {
            let _ = ALLOCATIONS.remove(&ptr);
        }

        if let Some(mut event) = EVENTS.reserve::<Event>(0) {
            let evt = event.as_mut_ptr();
            (*evt).addr = ptr;
            (*evt).size = size;
            // (*evt).stackid = stackid;
            (*evt).kind = EventKind::Free;
            event.submit(0);
        } else {
            info!(ctx, "Ring buffer is full for free!");
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
