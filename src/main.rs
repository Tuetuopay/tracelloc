//! Tracelloc is a tool to track allocations in a Rust program.

use std::time::Duration;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, StackTraceMap},
    programs::UProbe,
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use clap::Parser;
use elf::SymResolver;
use tokio::{select, signal::ctrl_c, time::interval};
use tracelloc_ebpf_common::AllocationValue;
use tracing::{error, info};
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

/// `tracelloc` is a tool to track allocations in Rust programs.
#[derive(Parser)]
struct Tracelloc {
    /// PID to attach to.
    #[clap(long, short)]
    pid: i32,
    /// Top N things to show.
    #[clap(long, default_value = "15")]
    top: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let Tracelloc { pid, top } = Tracelloc::parse();

    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();

    info!("Loading symbols");
    let symbols = SymResolver::new(pid)?;

    info!("Loading eBPF");
    let mut ebpf = EbpfLoader::new().load(&TRACELLOC).context("Failed to load eBPF program")?;
    EbpfLogger::init(&mut ebpf).context("aya-log")?;

    instrument(&mut ebpf, pid, "libc", "malloc")?;
    instrument(&mut ebpf, pid, "libc", "calloc")?;
    instrument(&mut ebpf, pid, "libc", "free")?;
    instrument(&mut ebpf, pid, "libc", "realloc")?;

    let allocs = ebpf.take_map("ALLOCATIONS").context("ALLOCATIONS")?;
    let allocs =
        HashMap::<MapData, u64, AllocationValue>::try_from(allocs).context("ALLOCATIONS")?;
    let allocators = ebpf.take_map("ALLOCATORS").context("ALLOCATORS")?;
    let allocators = HashMap::<MapData, i64, u64>::try_from(allocators).context("ALLOCATORS")?;
    let stacks = ebpf.take_map("STACKS").context("STACKS")?;
    let stacks = StackTraceMap::try_from(stacks).context("STACKS")?;

    info!("Waiting for ^C");
    let mut tick = interval(Duration::from_secs(1));
    loop {
        select! {
            _ = ctrl_c() => break,
            _ = tick.tick() => (),
        }

        let mut allocs = match allocs.iter().collect::<Result<Vec<_>, _>>() {
            Ok(allocs) => allocs,
            Err(e) => {
                error!("Failed to list allocations: {e}");
                continue;
            }
        };
        allocs.sort_by_key(|(_ptr, v)| v.size);
        allocs.reverse();
        let total = allocs.iter().map(|(_, v)| v.size).sum::<usize>();
        println!("==> {top} top allocations out of {} for a total of {total} bytes:", allocs.len());
        for (ptr, AllocationValue { size, .. }) in allocs.iter().take(top).copied() {
            println!("    0x{ptr:016x}: {size} bytes");
        }

        let mut allocs = match allocators.iter().collect::<Result<Vec<_>, _>>() {
            Ok(allocs) => allocs,
            Err(e) => {
                error!("Failed to list allocators: {e}");
                continue;
            }
        };
        allocs.sort_by_key(|(_stack, size)| *size);
        allocs.reverse();
        println!("==> {top} top allocators out of {}:", allocs.len());
        for (stackid, size) in allocs.iter().take(top) {
            println!("    {stackid:>8}: {size} bytes");

            let stackid = *stackid as u32;
            let Ok(stack) = stacks.get(&stackid, 0) else { continue };
            for frame in stack.frames() {
                match symbols.resolve(frame.ip as usize) {
                    Some(sym) => println!("                0x{:016x}: {sym}", frame.ip),
                    None => println!("                0x{:016x}: ???", frame.ip),
                }
            }
        }

        println!("");
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

fn instrument(ebpf: &mut Ebpf, pid: i32, target: &'static str, name: &'static str) -> Result<()> {
    let name_ret = format!("{name}_ret");
    let prog_ret = get_uprobe(ebpf, &name_ret).with_context(|| name_ret.clone())?;
    prog_ret.attach(Some(name), 0, target, Some(pid)).with_context(|| name_ret)?;
    let prog = get_uprobe(ebpf, name).context(name)?;
    prog.attach(Some(name), 0, target, Some(pid))?;
    Ok(())
}
