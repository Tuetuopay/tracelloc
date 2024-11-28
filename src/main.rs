//! Tracelloc is a tool to track allocations in a Rust program.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    os::{fd::AsRawFd, raw::c_void},
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Map, MapData, MapError, RingBuf, StackTraceMap},
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
    signal::ctrl_c,
    time::interval,
};
use tracelloc_ebpf_common::{Event, EventKind, Memcall};
use tracing::{debug, error, info};
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
    #[clap(long, default_value = "15")]
    top: usize,
    /// Output the collected data as a flamegraph-compatible file on exit.
    #[clap(long)]
    flamegraph: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Tracelloc { pid, top, flamegraph } = Tracelloc::parse();

    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let symbol_filter = &[
        "<tokio::runtime::blocking::task::BlockingTask<T> as core::future::future::Future>::poll",
        "__rust_try",
        "std::panic::catch_unwind",
        "std::panicking",
        "std::sys::backtrace",
        "std::thread::local::LocalKey<T>",
        "tokio::runtime",
    ];
    let symbol_filter = symbol_filter.iter().map(|&s| s.to_owned()).collect();

    info!("Loading symbols");
    let symbols = SymResolver::new(pid)?.with_symbol_filter(symbol_filter);

    info!("Loading eBPF");
    let mut ebpf = EbpfLoader::new().load(&TRACELLOC).context("Failed to load eBPF program")?;
    EbpfLogger::init(&mut ebpf).context("aya-log")?;

    instrument(&mut ebpf, pid, "libc", "malloc")?;
    instrument(&mut ebpf, pid, "libc", "calloc")?;
    instrument(&mut ebpf, pid, "libc", "free")?;
    instrument(&mut ebpf, pid, "libc", "realloc")?;

    let mut stacks = take_map::<StackTraceMap<MapData>>(&mut ebpf, "STACKS")?;
    let mut events = take_map::<RingBuf<MapData>>(&mut ebpf, "EVENTS")?;
    let events_fd = AsyncFd::new(events.as_raw_fd()).context("fd")?;

    let mut allocs = HashMap::new();
    let mut allocators = HashMap::new();

    info!("Waiting for ^C");
    let mut tick_print = interval(Duration::from_secs(1));
    let mut tick_gc = interval(Duration::from_secs(10));
    loop {
        select! {
            _ = ctrl_c() => break,
            _ = tick_print.tick() => print_stats(&symbols, &allocs, &allocators, top)?,
            _ = tick_gc.tick() => gc_allocators(&mut allocators),
            guard = events_fd.readable() => {
                handle_event(&mut events, &mut stacks, &mut allocs, &mut allocators, guard?).await?;
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
}

async fn handle_event(
    events: &mut RingBuf<MapData>,
    stacks: &mut StackTraceMap<MapData>,
    allocations: &mut HashMap<*const c_void, Allocation>,
    allocators: &mut HashMap<Vec<u64>, usize>,
    mut guard: AsyncFdReadyGuard<'_, i32>,
) -> Result<()> {
    let Some(item) = events.next() else {
        guard.clear_ready();
        return Ok(());
    };
    let event = unsafe { &*item.as_ptr().cast::<Event>() };
    let addr = event.addr;
    let size = event.size;

    if matches!(event.kind, EventKind::Alloc) {
        let stackid = event.stackid;
        let Ok(stack) = stacks.get(&stackid, 0) else {
            debug!("Dropped {event:016x?}: stack not found");
            return Ok(());
        };
        let stack = stack.frames().iter().map(|frame| frame.ip).collect::<Vec<_>>();
        let alloc = Allocation { size, stack };
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
        *total_size = total_size.saturating_sub(size);
    }

    Ok(())
}

fn print_stats(
    symbols: &SymResolver,
    allocations: &HashMap<*const c_void, Allocation>,
    allocators: &HashMap<Vec<u64>, usize>,
    top: usize,
) -> Result<()> {
    let mut allocs = allocations.iter().collect::<Vec<_>>();
    allocs.sort_by_key(|(_ptr, alloc)| alloc.size);
    let total = Size::from_bytes(allocs.iter().map(|(_ptr, alloc)| alloc.size).sum::<usize>());
    println!("==> {top} top allocations out of {} for a total of {total}", allocs.len());
    for &(&ptr, Allocation { size, stack }) in allocs.iter().rev().take(top) {
        let size = Size::from_bytes(*size);
        println!("    {COLOR_BLU}0x{ptr:016x?}{COLOR_RST}: {size}");
        symbols.print_stacktrace(stack);
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
