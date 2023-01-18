use std::{
    collections::{btree_map, BTreeMap},
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cwdemangle::{demangle, DemangleOptions};
use ppc750cl::Ins;
use serde::{forward_to_deserialize_any, Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::util::{
    elf::process_elf,
    obj::{
        ObjInfo, ObjReloc, ObjRelocKind, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind,
    },
    tracker::{Relocation, Tracker},
};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutSymbol {
    pub kind: ObjSymbolKind,
    pub name: String,
    pub size: u32,
    pub flags: ObjSymbolFlagSet,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutReloc {
    pub offset: u32,
    pub kind: ObjRelocKind,
    pub symbol: usize,
    pub addend: i32,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub symbol: usize,
    pub hash: String,
    pub signature: String,
    pub symbols: Vec<OutSymbol>,
    pub relocations: Vec<OutReloc>,
}

/// Creates a fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }};
}

pub fn check_signature(mut data: &[u8], sig: &FunctionSignature) -> Result<bool> {
    let sig_data = STANDARD.decode(&sig.signature)?;
    // println!(
    //     "\nChecking signature {} {} (size {})",
    //     sig.symbols[sig.symbol].name, sig.hash, sig.symbols[sig.symbol].size
    // );
    // for chunk in sig_data.chunks_exact(8) {
    //     let ins = u32::from_be_bytes(*array_ref!(chunk, 0, 4));
    //     let i = Ins::new(ins, 0);
    //     println!("=> {}", i.simplified());
    // }
    for chunk in sig_data.chunks_exact(8) {
        let ins = u32::from_be_bytes(*array_ref!(chunk, 0, 4));
        let pat = u32::from_be_bytes(*array_ref!(chunk, 4, 4));
        if (u32::from_be_bytes(*array_ref!(data, 0, 4)) & pat) != ins {
            return Ok(false);
        }
        data = &data[4..];
    }
    Ok(true)
}

pub fn check_signatures(obj: &mut ObjInfo, addr: u32, sig_str: &str) -> Result<bool> {
    let signatures: Vec<FunctionSignature> = serde_yaml::from_str(sig_str)?;
    let (_, data) = obj.section_data(addr, 0)?;
    let mut name = None;
    for signature in &signatures {
        if name.is_none() {
            name = Some(signature.symbols[signature.symbol].name.clone());
        }
        if check_signature(data, signature)? {
            log::debug!("Found {} @ {:#010X}", signature.symbols[signature.symbol].name, addr);
            apply_signature(obj, addr, signature)?;
            return Ok(true);
        }
    }
    if let Some(name) = name {
        log::debug!("Didn't find {} @ {:#010X}", name, addr);
    }
    Ok(false)
}

pub fn apply_symbol(obj: &mut ObjInfo, target: u32, sig_symbol: &OutSymbol) -> Result<usize> {
    let target_section_index = obj.section_at(target).ok().map(|section| section.index);
    if let Some(target_section_index) = target_section_index {
        let target_section = &mut obj.sections[target_section_index];
        if !target_section.section_known {
            if let Some(section_name) = &sig_symbol.section {
                target_section.name = section_name.clone();
                target_section.kind = match section_name.as_str() {
                    ".init" | ".text" | ".dbgtext" => ObjSectionKind::Code,
                    ".ctors" | ".dtors" | ".rodata" | ".sdata2" | "extab" | "extabindex" => {
                        ObjSectionKind::ReadOnlyData
                    }
                    ".bss" | ".sbss" | ".sbss2" => ObjSectionKind::Bss,
                    ".data" | ".sdata" => ObjSectionKind::Data,
                    name => bail!("Unknown section {name}"),
                };
                target_section.section_known = true;
            }
        }
    }
    let target_symbol_idx = if let Some((symbol_idx, existing)) =
        obj.symbols.iter_mut().enumerate().find(|(_, symbol)| {
            symbol.address == target as u64
                && symbol.kind == sig_symbol.kind
                // HACK to avoid replacing different ABS symbols
                && (symbol.section.is_some() || symbol.name == sig_symbol.name)
        }) {
        // TODO apply to existing
        log::debug!("Replacing {:?} with {}", existing, sig_symbol.name);
        *existing = ObjSymbol {
            name: sig_symbol.name.clone(),
            demangled_name: demangle(&sig_symbol.name, &DemangleOptions::default()),
            address: target as u64,
            section: target_section_index,
            size: if existing.size_known { existing.size } else { sig_symbol.size as u64 },
            size_known: existing.size_known || sig_symbol.size != 0,
            flags: sig_symbol.flags,
            kind: sig_symbol.kind,
        };
        symbol_idx
    } else {
        let target_symbol_idx = obj.symbols.len();
        obj.symbols.push(ObjSymbol {
            name: sig_symbol.name.clone(),
            demangled_name: demangle(&sig_symbol.name, &DemangleOptions::default()),
            address: target as u64,
            section: target_section_index,
            size: sig_symbol.size as u64,
            size_known: sig_symbol.size != 0,
            flags: sig_symbol.flags,
            kind: sig_symbol.kind,
        });
        target_symbol_idx
    };
    match sig_symbol.name.as_str() {
        "_SDA_BASE_" => obj.sda_base = Some(target),
        "_SDA2_BASE_" => obj.sda2_base = Some(target),
        "_stack_addr" => obj.stack_address = Some(target),
        "_stack_end" => obj.stack_end = Some(target),
        "_db_stack_addr" => obj.db_stack_addr = Some(target),
        "__ArenaLo" => obj.arena_lo = Some(target),
        "__ArenaHi" => obj.arena_hi = Some(target),
        _ => {}
    }
    Ok(target_symbol_idx)
}

pub fn apply_signature(obj: &mut ObjInfo, addr: u32, signature: &FunctionSignature) -> Result<()> {
    let section_index = obj.section_at(addr)?.index;
    let in_symbol = &signature.symbols[signature.symbol];
    let symbol_idx = apply_symbol(obj, addr, in_symbol)?;
    let mut tracker = Tracker::new(obj);
    for reloc in &signature.relocations {
        tracker.known_relocations.insert(addr + reloc.offset);
    }
    tracker.process_function(obj, &obj.symbols[symbol_idx])?;
    for (&reloc_addr, reloc) in &tracker.relocations {
        if reloc_addr < addr || reloc_addr >= addr + in_symbol.size {
            continue;
        }
        let offset = reloc_addr - addr;
        let sig_reloc = match signature.relocations.iter().find(|r| r.offset == offset) {
            Some(reloc) => reloc,
            None => continue,
        };
        let target = match (reloc, sig_reloc.kind) {
            (&Relocation::Absolute(addr), ObjRelocKind::Absolute)
            | (&Relocation::Hi(addr), ObjRelocKind::PpcAddr16Hi)
            | (&Relocation::Ha(addr), ObjRelocKind::PpcAddr16Ha)
            | (&Relocation::Lo(addr), ObjRelocKind::PpcAddr16Lo)
            | (&Relocation::Rel24(addr), ObjRelocKind::PpcRel24)
            | (&Relocation::Rel14(addr), ObjRelocKind::PpcRel14)
            | (&Relocation::Sda21(addr), ObjRelocKind::PpcEmbSda21) => {
                (addr as i64 - sig_reloc.addend as i64) as u32
            }
            _ => bail!("Relocation mismatch: {:?} != {:?}", reloc, sig_reloc.kind),
        };
        let sig_symbol = &signature.symbols[sig_reloc.symbol];
        let target_symbol_idx = apply_symbol(obj, target, sig_symbol)?;
        let obj_reloc = ObjReloc {
            kind: sig_reloc.kind,
            address: reloc_addr as u64,
            target_symbol: target_symbol_idx,
            addend: sig_reloc.addend as i64,
        };
        // log::info!("Applying relocation {:#010X?}", obj_reloc);
        obj.sections[section_index].relocations.push(obj_reloc);
    }
    for reloc in &signature.relocations {
        let addr = addr + reloc.offset;
        if !tracker.relocations.contains_key(&addr) {
            let sig_symbol = &signature.symbols[reloc.symbol];
            bail!("Missing relocation @ {:#010X}: {:?} -> {:?}", addr, reloc, sig_symbol);
        }
    }
    Ok(())
}

pub fn compare_signature(existing: &mut FunctionSignature, new: &FunctionSignature) -> Result<()> {
    ensure!(
        existing.symbols.len() == new.symbols.len(),
        "Mismatched symbol count: {} != {}\n{:?}\n{:?}",
        new.symbols.len(),
        existing.symbols.len(),
        new.symbols,
        existing.symbols,
    );
    ensure!(
        existing.relocations.len() == new.relocations.len(),
        "Mismatched relocation count: {} != {}",
        new.relocations.len(),
        existing.relocations.len()
    );
    for (idx, (a, b)) in existing.symbols.iter_mut().zip(&new.symbols).enumerate() {
        if a != b {
            // If mismatched sections, clear
            if a.name == b.name
                && a.size == b.size
                && a.flags == b.flags
                && a.kind == b.kind
                && a.section != b.section
            {
                log::warn!("Clearing section for {} ({:?} != {:?})", a.name, a.section, b.section);
                a.section = None;
            } else if !a.name.starts_with('@') {
                log::error!("Symbol {} mismatch: {:?} != {:?}", idx, a, b);
            }
        }
    }
    for (a, b) in existing.relocations.iter().zip(&new.relocations) {
        if a != b {
            log::error!("Relocation {} mismatch: {:?} != {:?}", a.offset, a, b);
        }
    }
    Ok(())
}

pub fn generate_signature(
    path: &Path,
    symbol_name: &str,
) -> Result<Option<(Vec<u8>, FunctionSignature)>> {
    let mut out_symbols: Vec<OutSymbol> = Vec::new();
    let mut out_relocs: Vec<OutReloc> = Vec::new();
    let mut symbol_map: BTreeMap<usize, usize> = BTreeMap::new();

    let mut obj = process_elf(path)?;
    if obj.sda2_base.is_none()
        || obj.sda_base.is_none()
        || obj.stack_address.is_none()
        || obj.stack_end.is_none()
        || obj.db_stack_addr.is_none()
    // || obj.arena_hi.is_none()
    // || obj.arena_lo.is_none()
    {
        log::warn!("Failed to locate all abs symbols {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?}", obj.sda2_base, obj.sda_base, obj.stack_address, obj.stack_end, obj.db_stack_addr, obj.arena_hi, obj.arena_lo);
        return Ok(None);
    }
    let mut tracker = Tracker::new(&obj);
    // tracker.ignore_addresses.insert(0x80004000);
    for symbol in &obj.symbols {
        if symbol.kind != ObjSymbolKind::Function {
            continue;
        }
        if symbol.name != symbol_name && symbol.name != symbol_name.replace("TRK", "TRK_") {
            continue;
        }
        // log::info!("Tracking {}", symbol.name);
        tracker.process_function(&obj, symbol)?;
    }
    tracker.apply(&mut obj, true)?; // true
    for symbol in &obj.symbols {
        if symbol.kind != ObjSymbolKind::Function {
            continue;
        }
        if symbol.name != symbol_name && symbol.name != symbol_name.replace("TRK", "TRK_") {
            continue;
        }
        let section_idx = symbol.section.unwrap();
        let section = &obj.sections[section_idx];
        let out_symbol_idx = out_symbols.len();
        out_symbols.push(OutSymbol {
            kind: symbol.kind,
            name: symbol.name.clone(),
            size: symbol.size as u32,
            flags: symbol.flags,
            section: Some(section.name.clone()),
        });
        // println!(
        //     "Building signature for {} ({:#010X}-{:#010X})",
        //     symbol.name,
        //     symbol.address,
        //     symbol.address + symbol.size
        // );
        let relocations = section.build_relocation_map()?;
        let mut instructions = section.data[(symbol.address - section.address) as usize
            ..(symbol.address - section.address + symbol.size) as usize]
            .chunks_exact(4)
            .map(|c| (u32::from_be_bytes(c.try_into().unwrap()), !0u32))
            .collect::<Vec<(u32, u32)>>();
        for (idx, (ins, pat)) in instructions.iter_mut().enumerate() {
            let addr = (symbol.address as usize + idx * 4) as u32;
            if let Some(reloc) = relocations.get(&addr) {
                let symbol_idx = match symbol_map.entry(reloc.target_symbol) {
                    btree_map::Entry::Vacant(e) => {
                        let target = &obj.symbols[reloc.target_symbol];
                        let symbol_idx = out_symbols.len();
                        e.insert(symbol_idx);
                        out_symbols.push(OutSymbol {
                            kind: target.kind,
                            name: target.name.clone(),
                            size: if target.kind == ObjSymbolKind::Function {
                                0
                            } else {
                                target.size as u32
                            },
                            flags: target.flags,
                            section: target.section.map(|idx| obj.sections[idx].name.clone()),
                        });
                        symbol_idx
                    }
                    btree_map::Entry::Occupied(e) => *e.get(),
                };
                match reloc.kind {
                    ObjRelocKind::Absolute => {
                        *ins = 0;
                        *pat = 0;
                    }
                    ObjRelocKind::PpcAddr16Hi
                    | ObjRelocKind::PpcAddr16Ha
                    | ObjRelocKind::PpcAddr16Lo => {
                        *ins = *ins & !0xFFFF;
                        *pat = !0xFFFF;
                    }
                    ObjRelocKind::PpcRel24 => {
                        *ins = *ins & !0x3FFFFFC;
                        *pat = !0x3FFFFFC;
                    }
                    ObjRelocKind::PpcRel14 => {
                        *ins = *ins & !0xFFFC;
                        *pat = !0xFFFC;
                    }
                    ObjRelocKind::PpcEmbSda21 => {
                        *ins = *ins & !0x1FFFFF;
                        *pat = !0x1FFFFF;
                    }
                }
                out_relocs.push(OutReloc {
                    offset: addr - (symbol.address as u32),
                    kind: reloc.kind,
                    symbol: symbol_idx,
                    addend: reloc.addend as i32,
                    // instruction: format!("{}", Ins::new(*ins, addr).simplified()),
                });
            }
            // println!("{}", Ins::new(*ins, addr).simplified());
        }
        // if out_symbols.is_empty() || out_relocs.is_empty() {
        //     bail!("Failed to locate any symbols or relocs");
        // }
        // println!("Data: {:#010X?}", instructions);

        let mut data = vec![0u8; instructions.len() * 8];
        for (idx, &(ins, pat)) in instructions.iter().enumerate() {
            data[idx * 8..idx * 8 + 4].copy_from_slice(&ins.to_be_bytes());
            data[idx * 8 + 4..idx * 8 + 8].copy_from_slice(&pat.to_be_bytes());
        }
        // println!(
        //     "OK: Data (len {}): {:X?} | SYMBOLS: {:?} | RELOCS: {:?}",
        //     data.len(),
        //     data,
        //     out_symbols,
        //     out_relocs
        // );
        let encoded = STANDARD.encode(&data);
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        let mut hash_buf = [0u8; 40];
        let hash_str = base16ct::lower::encode_str(&hash, &mut hash_buf)
            .map_err(|e| anyhow!("Failed to encode hash: {e}"))?;
        return Ok(Some((data, FunctionSignature {
            symbol: 0,
            hash: hash_str.to_string(),
            signature: encoded,
            symbols: out_symbols,
            relocations: out_relocs,
        })));
    }
    Ok(None)
}
