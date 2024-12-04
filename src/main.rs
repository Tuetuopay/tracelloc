//! Tracelloc is a tool to track allocations in a Rust program.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    os::{fd::AsRawFd, raw::c_void},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Map, MapData, MapError, RingBuf},
    programs::UProbe,
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use clap::Parser;
use elf::SymResolver;
use size::Size;
use tokio::{
    io::unix::{AsyncFd, AsyncFdReadyGuard},
    select,
    signal::{ctrl_c, unix::SignalKind},
    time::interval,
};
use tracelloc_ebpf_common::{Event, EventKind, Memcall};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

mod elf;
mod range_map;

macro_rules! ebpf_elf {
    ($var:ident($name:literal)) => {
        static $var: &'static [u8] =
            include_bytes_aligned!(concat!("../ebpf/target/bpfel-unknown-none/release/", $name));
    };
}

ebpf_elf!(TRACELLOC("tracelloc"));

pub const COLOR_RST: &str = "\x1b[39m";
pub const COLOR_BLU: &str = "\x1b[34m";
pub const COLOR_YLW: &str = "\x1b[33m";
pub const COLOR_MGT: &str = "\x1b[35m";

/// `tracelloc` is a tool to track allocations in Rust programs.
#[derive(Parser)]
struct Tracelloc {
    /// PID to attach to.
    #[clap(long, short)]
    pid: i32,
    /// Top N things to show.
    #[clap(long, default_value = "2")]
    top: usize,
    /// Output the collected data as a flamegraph-compatible file on exit or on SIGUSR1.
    #[clap(long)]
    flamegraph: Option<String>,
    /// Print outstanding allocations that old (seconds)
    #[clap(long)]
    age: Option<u64>,
    /// Set the size, in bytes, of the events ring buffer. Will be rounded down to the nearest
    /// power-of-two multiple of the page size. Defaults to 2048 * 4096.
    #[clap(long, default_value = "8388608")]
    events_size: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Tracelloc { pid, top, flamegraph, age, events_size } = Tracelloc::parse();

    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let page_size = page_size::get();
    let pow = 63 - (events_size / page_size).leading_zeros();
    let events_size = (((events_size / page_size) >> pow) << pow) * page_size;
    info!(
        "Using an events ringbuf size of {events_size} bytes ({})",
        Size::from_bytes(events_size)
    );

    let symbol_filter = &[
        " as core::future::future::Future>::poll",
        " as core:ops::function::Fn<Args>>::call",
        " as core:ops::function::FnMut<Args>>::call_mut",
        " as core:ops::function::FnOnce<Args>>::call_once",
        " as futures_core::future::TryFuture>::try_poll",
        "^core::ops::function::FnOnce::call_once{{vtable.shim}}",
        "^hyper::proto::h2::server::H2Stream<F,B>::poll2",
        "^__rust_try",
        "^std::panic::catch_unwind",
        "^std::panicking",
        "^std::sys::backtrace",
        "^std::thread::local::LocalKey<T>",
        "^tokio::runtime",
    ];
    let symbol_filter = symbol_filter.iter().map(|&s| s.to_owned()).collect();

    info!("Loading symbols");
    let symbols = SymResolver::new(pid)?.with_symbol_filter(symbol_filter);

    info!("Loading eBPF");
    let mut ebpf = EbpfLoader::new()
        .set_max_entries("EVENTS", events_size as u32)
        .load(&TRACELLOC)
        .context("Failed to load eBPF program")?;
    EbpfLogger::init(&mut ebpf).context("aya-log")?;

    instrument(&mut ebpf, pid, "libc", "malloc")?;
    instrument(&mut ebpf, pid, "libc", "calloc")?;
    instrument(&mut ebpf, pid, "libc", "free")?;
    instrument(&mut ebpf, pid, "libc", "realloc")?;
    instrument(&mut ebpf, pid, "libc", "reallocarray")?;

    let mut events = take_map::<RingBuf<MapData>>(&mut ebpf, "EVENTS")?;
    let events_fd = AsyncFd::new(events.as_raw_fd()).context("fd")?;

    let mut allocs = HashMap::new();
    let mut allocators = HashMap::new();

    let mut sigusr1 = tokio::signal::unix::signal(SignalKind::user_defined1())?;

    info!("Waiting for ^C");
    let mut tick_print = interval(Duration::from_secs(1));
    let mut tick_gc = interval(Duration::from_secs(10));
    loop {
        select! {
            _ = ctrl_c() => break,
            _ = tick_print.tick() => print_stats(&symbols, &allocs, &allocators, top, age)?,
            _ = tick_gc.tick() => gc_allocators(&mut allocators),
            guard = events_fd.readable() => {
                handle_events(&mut events, &mut allocs, &mut allocators, guard?)?;
            }
            _ = sigusr1.recv(), if flamegraph.is_some() => {
                output_flamegraph(&symbols, &allocators, flamegraph.as_deref().unwrap())?;
                info!("Dumped flamegraph data to {}", flamegraph.as_deref().unwrap());
            }
        };
    }

    if let Some(flamegraph) = flamegraph {
        info!("Outputting flamegraph data to {flamegraph}");
        output_flamegraph(&symbols, &allocators, &flamegraph)?;
    }

    info!("Cleaning up...");

    Ok(())
}

fn get_uprobe<'ebpf>(ebpf: &'ebpf mut Ebpf, name: &str) -> Result<&'ebpf mut UProbe> {
    let probe: &'ebpf mut UProbe = ebpf
        .program_mut(name)
        .context("program not found")?
        .try_into()
        .context("program not uprobe")?;
    probe.load()?;
    Ok(probe)
}

fn take_map<M: TryFrom<Map, Error = MapError>>(ebpf: &mut Ebpf, name: &str) -> Result<M> {
    let map = ebpf.take_map(name).with_context(|| format!("Map {name} not found"))?;
    let map = M::try_from(map).with_context(|| format!("Invalid map type for {name}"))?;
    Ok(map)
}

fn instrument(ebpf: &mut Ebpf, pid: i32, target: &'static str, name: &'static str) -> Result<()> {
    let name_ret = format!("{name}_ret");
    let prog_ret = get_uprobe(ebpf, &name_ret).with_context(|| name_ret.clone())?;
    prog_ret.attach(Some(name), 0, target, Some(pid)).with_context(|| name_ret)?;
    let prog = get_uprobe(ebpf, name).context(name)?;
    prog.attach(Some(name), 0, target, Some(pid))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct Allocation {
    /// Size of the allocation.
    size: usize,
    /// Stack trace that allocated the memory.
    stack: Vec<u64>,
    /// Timestamp of the memory allocation
    birth: Instant,
}

fn handle_events(
    events: &mut RingBuf<MapData>,
    allocations: &mut HashMap<*const c_void, Allocation>,
    allocators: &mut HashMap<Vec<u64>, usize>,
    mut guard: AsyncFdReadyGuard<'_, i32>,
) -> Result<()> {
    while let Some(event) = events.next() {
        let event = unsafe { &*event.as_ptr().cast::<Event>() };
        handle_event(allocations, allocators, event)?;
    }
    guard.clear_ready();
    Ok(())
}

fn handle_event(
    allocations: &mut HashMap<*const c_void, Allocation>,
    allocators: &mut HashMap<Vec<u64>, usize>,
    event: &Event,
) -> Result<()> {
    let addr = event.addr;
    if matches!(event.kind, EventKind::Alloc) {
        let size = event.size;
        let stack = event.stack[..event.stack_len as usize].to_vec();
        let alloc = Allocation { size, stack, birth: Instant::now() };
        if let Some(old_alloc) = allocations.insert(addr, alloc.clone()) {
            // Let's assume we missed a free somewhere.
            debug!("Found old {old_alloc:016x?} for addr {addr:016x?}");
            let total_size = allocators.entry(old_alloc.stack).or_default();
            *total_size = total_size.saturating_sub(old_alloc.size);
        }
        let total_size = allocators.entry(alloc.stack).or_default();
        *total_size = total_size.saturating_add(size);
    } else {
        let Some(alloc) = allocations.remove(&addr) else {
            debug!("Dropped {event:016x?}: allocation not found");
            return Ok(());
        };
        let total_size = allocators.entry(alloc.stack).or_default();
        *total_size = total_size.saturating_sub(alloc.size);
    }

    Ok(())
}

fn print_stats(
    symbols: &SymResolver,
    allocations: &HashMap<*const c_void, Allocation>,
    allocators: &HashMap<Vec<u64>, usize>,
    top: usize,
    age: Option<u64>,
) -> Result<()> {
    let mut allocs = allocations.iter().collect::<Vec<_>>();
    allocs.sort_by_key(|(_ptr, alloc)| alloc.size);
    let total = Size::from_bytes(allocs.iter().map(|(_ptr, alloc)| alloc.size).sum::<usize>());
    println!("==> {top} top allocations out of {} for a total of {total}", allocs.len());
    for &(&ptr, Allocation { size, stack, birth }) in allocs.iter().rev().take(top) {
        let size = Size::from_bytes(*size);
        println!("    {COLOR_BLU}0x{ptr:016x?}{COLOR_RST}: {size} ({:?} old)", birth.elapsed());
        symbols.print_stacktrace(stack);
    }

    if let Some(age) = age {
        let age = Duration::from_secs(age);
        let mut allocs = allocations
            .iter()
            .filter(|(_, alloc)| alloc.birth.elapsed() >= age)
            .collect::<Vec<_>>();
        allocs.sort_by_key(|(_ptr, alloc)| alloc.size);
        let total = Size::from_bytes(allocs.iter().map(|(_ptr, alloc)| alloc.size).sum::<usize>());
        println!(
            "==> {top} top allocations older than {age:?} out of {} for a total of {total}",
            allocs.len()
        );
        for &(&ptr, Allocation { size, stack, birth }) in allocs.iter().rev().take(top) {
            let size = Size::from_bytes(*size);
            println!("    {COLOR_BLU}0x{ptr:016x?}{COLOR_RST}: {size} ({:?} old)", birth.elapsed());
            symbols.print_stacktrace(stack);
        }
    }

    let mut allocs = allocators.iter().collect::<Vec<_>>();
    allocs.sort_by_key(|(_stack, size)| *size);
    println!("==> {top} top allocators out of {}:", allocs.len());
    for (i, &(stack, &size)) in allocs.iter().rev().take(top).enumerate() {
        if size == 0 {
            continue;
        }

        let size = Size::from_bytes(size);
        println!("  {i:>4}: {size}");
        symbols.print_stacktrace(stack);
    }

    println!("");
    Ok(())
}

fn gc_allocators(allocators: &mut HashMap<Vec<u64>, usize>) {
    allocators.retain(|_stack, size| *size > 0);
}

fn output_flamegraph(
    symbols: &SymResolver,
    allocators: &HashMap<Vec<u64>, usize>,
    file: &str,
) -> Result<()> {
    let mut allocs = allocators
        .iter()
        .filter(|(_stack, &size)| size > 0)
        .map(|(stack, size)| {
            // Take the first frame that's not from libc and set it as the root.
            let root = stack
                .iter()
                .rev()
                .find_map(|ip| match symbols.resolve_file(*ip as usize) {
                    Some(path) if !path.contains("libc.so") => Some(path),
                    _ => None,
                })
                .unwrap_or("[unknown]");
            let syms = stack
                .iter()
                .rev()
                .filter_map(|ip| match symbols.resolve(*ip as usize) {
                    Some(sym) if symbols.is_filtered_out(&sym) => None,
                    Some(sym) => Some(sym.name()),
                    None => Some("[unknown]"),
                })
                .collect::<Vec<_>>();
            let pretty_size = Size::from_bytes(*size);
            format!("{root};{} ({pretty_size}) {size}", syms.join(";"))
        })
        .collect::<Vec<_>>();
    allocs.sort();

    let mut f = BufWriter::new(File::create(file)?);
    for alloc in allocs {
        writeln!(f, "{alloc}")?;
    }
    f.flush()?;

    Ok(())
}
