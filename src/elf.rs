//! Utilities for loading and parsing ELF files.

use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    rc::Rc,
};

use anyhow::{Context, Result};
use object::{
    read::elf::{ElfFile64, SectionHeader},
    Object, ObjectSection, ObjectSymbol,
};
use tracing::debug;

use crate::{range_map::RangeMap, COLOR_BLU, COLOR_MGT, COLOR_RST, COLOR_YLW};

#[derive(Debug)]
struct Symbol {
    file: Rc<String>,
    name: String,
    addr: usize,
    size: usize,
}

#[derive(Debug)]
pub struct SymResolver {
    symbols: RangeMap<Symbol>,
    maps: RangeMap<Rc<String>>,
    /// Symbol blacklist because Rust stack traces tend to be very verbose (tokio:runtime etc).
    filter: HashSet<String>,
}

impl SymResolver {
    pub fn new(pid: i32) -> Result<Self> {
        let maps = load_maps(pid).context("load process maps")?;
        let mut symbols = RangeMap::new();
        for (file, maps) in &maps {
            load_file_symbols(&mut symbols, &maps, file).with_context(|| file.to_owned())?;
        }

        let maps = maps
            .into_iter()
            .flat_map(|(file, map)| {
                let file = Rc::new(file);
                map.into_iter().map(move |(r, _v)| (r, file.clone()))
            })
            .collect();

        Ok(Self { symbols, maps, filter: HashSet::new() })
    }

    pub fn with_symbol_filter(self, blacklist: HashSet<String>) -> Self {
        Self { filter: blacklist, ..self }
    }

    pub fn resolve(&self, addr: usize) -> Option<Sym> {
        let sym = self.symbols.get(addr)?;
        Some(Sym { file: &sym.file, name: &sym.name, offset: addr - sym.addr, size: sym.size })
    }

    pub fn resolve_file(&self, addr: usize) -> Option<&str> {
        let file = self.maps.get(addr)?;
        Some(&file)
    }

    pub fn is_filtered_out(&self, symbol: &Sym) -> bool {
        self.filter.iter().any(|filter| {
            if filter.starts_with('^') {
                symbol.name.starts_with(&filter[1..])
            } else {
                symbol.name.contains(filter)
            }
        })
    }

    pub fn print_stacktrace(&self, stack: &[u64]) {
        fn p_ip(ip: u64) {
            print!("        {COLOR_BLU}0x{ip:016x}{COLOR_RST}: ");
        }

        let mut filtered = 0usize;
        for ip in stack {
            match self.resolve(*ip as usize) {
                Some(sym) if self.is_filtered_out(&sym) => filtered += 1,
                Some(sym) => {
                    if filtered > 0 {
                        println!("         ({filtered} filtered out)");
                    }
                    p_ip(*ip);
                    println!("{sym}");
                }
                None => {
                    p_ip(*ip);
                    print!("???");
                    match self.resolve_file(*ip as usize) {
                        Some(file) => println!(" in {COLOR_MGT}{file}{COLOR_RST}"),
                        None => println!(""),
                    }
                }
            }
        }
    }
}

pub struct Sym<'a> {
    file: &'a str,
    name: &'a str,
    offset: usize,
    size: usize,
}

impl<'a> Sym<'a> {
    pub fn name(&self) -> &'a str {
        &self.name
    }
}

impl<'a> fmt::Display for Sym<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Sym { file, name, offset, size } = self;
        write!(
            f,
            "{COLOR_YLW}{name}{COLOR_RST}+0x{offset:x}/0x{size:x} in {COLOR_MGT}{file}{COLOR_RST}"
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct Mapping {
    start: usize,
    end: usize,
    offset: usize,
}

fn load_maps(pid: i32) -> Result<HashMap<String, RangeMap<Mapping>>> {
    let mut ret = HashMap::new();

    let file = format!("/proc/{pid}/maps");
    let maps = fs::read_to_string(&file).with_context(|| file)?;
    for line in maps.lines() {
        let items = line.split_whitespace().collect::<Vec<_>>();
        let [addrs, offset, file] = match items.as_slice() {
            // Anonymous mapping
            [_addrs, _perms, _offset, _dev, _inode] => continue,
            // Anonymous mappings, like the program's heap/stack/etc
            [_addrs, _perms, _offset, _dev, _inode, name] if name.starts_with("[") => continue,
            // The backing file has been deleted :/
            [_addrs, _perms, _offset, _dev, _inode, "(deleted)"] => continue,
            // Non-executable mapping
            [_addrs, perms, _offset, _dev, _inode, _name] if !perms.contains('x') => continue,
            // What we actually want o/
            &[addrs, _perms, offset, _dev, _inode, file] => [addrs, offset, file],
            // Anything else, though not supposed to happen.
            _ => continue,
        };
        let Some((start, end)) = addrs.split_once('-') else { continue };
        let start = usize::from_str_radix(start, 16)?;
        let end = usize::from_str_radix(end, 16)?;
        let offset = usize::from_str_radix(offset, 16)?;

        ret.entry(file.to_owned())
            .or_insert_with(|| RangeMap::new())
            .insert(start..end, Mapping { start, end, offset });
    }

    Ok(ret)
}

fn load_file_symbols(
    symbols: &mut RangeMap<Symbol>,
    maps: &RangeMap<Mapping>,
    file: &str,
) -> Result<()> {
    debug!("Loading symbols from {file}");
    let data = fs::read(file)?;
    let obj: ElfFile64 = ElfFile64::parse(&*data)?;
    let endian = obj.endian();

    // Build a reverse mapping of the maps. Basically:
    // - maps translates the process' address space to the elf address space
    // - reverse translates the elf address space to the process' one, at least its base address.
    let map_rev = maps
        .iter()
        .map(|(_, v)| (v.offset..(v.offset + (v.end - v.start)), (v.start, v.offset)))
        .collect::<RangeMap<_>>();

    let file = Rc::new(file.to_owned());
    for sym in obj.symbols() {
        let Some(idx) = sym.section_index() else { continue };
        let Ok(sec) = obj.section_by_index(idx) else { continue };

        let Ok(name) = sym.name() else { continue };
        let name = rustc_demangle::demangle(name).to_string();

        let sec_off = sec.elf_section_header().sh_offset(endian) as usize;
        let Some(&(map_base, map_off)) = map_rev.get(sec_off) else { continue };

        // sym = pc - map_base + map_off - sec_off + sec_addr
        // => pc = (map_base - map_off) + (sec_off - sec_addr) + sym
        let map_start = map_base - map_off;
        let sec_off = sec_off.wrapping_sub(sec.address() as usize);
        let vaddr = map_start.wrapping_add(sec_off) + sym.address() as usize;

        let symbol = Symbol { file: file.clone(), name, addr: vaddr, size: sym.size() as usize };
        symbols.insert(vaddr..(vaddr + sym.size() as usize), symbol);
    }

    Ok(())
}
