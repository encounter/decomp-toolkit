use std::{
    collections::{btree_map, BTreeMap},
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cwdemangle::{demangle, DemangleOptions};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::{
    analysis::{
        cfa::SectionAddress,
        tracker::{Relocation, Tracker},
        RelocationTarget,
    },
    array_ref,
    obj::{
        ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolKind, SectionIndex, SymbolIndex,
    },
    util::elf::process_elf,
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
    pub symbol: u32,
    pub addend: i32,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub symbol: u32,
    pub hash: String,
    pub signature: String,
    pub symbols: Vec<OutSymbol>,
    pub relocations: Vec<OutReloc>,
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

pub fn parse_signatures(sig_str: &str) -> Result<Vec<FunctionSignature>> {
    Ok(serde_yaml::from_str(sig_str)?)
}

pub fn check_signatures_str(
    section: &ObjSection,
    addr: u32,
    sig_str: &str,
) -> Result<Option<FunctionSignature>> {
    check_signatures(section, addr, &parse_signatures(sig_str)?)
}

pub fn check_signatures(
    section: &ObjSection,
    addr: u32,
    signatures: &Vec<FunctionSignature>,
) -> Result<Option<FunctionSignature>> {
    let data = section.data_range(addr, 0)?;
    let mut name = None;
    for signature in signatures {
        if name.is_none() {
            name = Some(signature.symbols[signature.symbol as usize].name.clone());
        }
        if check_signature(data, signature)? {
            log::debug!(
                "Found {} @ {:#010X} (hash {})",
                signature.symbols[signature.symbol as usize].name,
                addr,
                signature.hash
            );
            return Ok(Some(signature.clone()));
        }
    }
    // if let Some(name) = name {
    //     log::debug!("Didn't find {} @ {:#010X}", name, addr);
    // }
    Ok(None)
}

pub fn apply_symbol(
    obj: &mut ObjInfo,
    target: SectionAddress,
    sig_symbol: &OutSymbol,
) -> Result<SymbolIndex> {
    let mut target_section_index =
        if target.section == SectionIndex::MAX { None } else { Some(target.section) };
    if let Some(target_section_index) = target_section_index {
        let target_section = &mut obj.sections[target_section_index];
        if !target_section.section_known {
            if let Some(section_name) = &sig_symbol.section {
                target_section.rename(section_name.clone())?;
            }
        }
    }
    if sig_symbol.kind == ObjSymbolKind::Unknown
        && (sig_symbol.name.starts_with("_f_") || sig_symbol.name.starts_with("_SDA"))
    {
        // Hack to mark linker generated symbols as ABS
        target_section_index = None;
    }
    let demangled_name = demangle(&sig_symbol.name, &DemangleOptions::default());
    let target_symbol_idx = obj.add_symbol(
        ObjSymbol {
            name: sig_symbol.name.clone(),
            demangled_name,
            address: target.address as u64,
            section: target_section_index,
            size: sig_symbol.size as u64,
            size_known: sig_symbol.size > 0 || sig_symbol.kind == ObjSymbolKind::Unknown,
            flags: sig_symbol.flags,
            kind: sig_symbol.kind,
            ..Default::default()
        },
        false,
    )?;
    Ok(target_symbol_idx)
}

pub fn apply_signature(
    obj: &mut ObjInfo,
    addr: SectionAddress,
    signature: &FunctionSignature,
) -> Result<()> {
    let in_symbol = &signature.symbols[signature.symbol as usize];
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
        let offset = reloc_addr.address - addr.address;
        let sig_reloc = match signature.relocations.iter().find(|r| r.offset == offset) {
            Some(reloc) => reloc,
            None => continue,
        };
        let target = match (reloc, sig_reloc.kind) {
            (&Relocation::Absolute(RelocationTarget::Address(addr)), ObjRelocKind::Absolute)
            | (&Relocation::Hi(RelocationTarget::Address(addr)), ObjRelocKind::PpcAddr16Hi)
            | (&Relocation::Ha(RelocationTarget::Address(addr)), ObjRelocKind::PpcAddr16Ha)
            | (&Relocation::Lo(RelocationTarget::Address(addr)), ObjRelocKind::PpcAddr16Lo)
            | (&Relocation::Rel24(RelocationTarget::Address(addr)), ObjRelocKind::PpcRel24)
            | (&Relocation::Rel14(RelocationTarget::Address(addr)), ObjRelocKind::PpcRel14)
            | (&Relocation::Sda21(RelocationTarget::Address(addr)), ObjRelocKind::PpcEmbSda21) => {
                SectionAddress::new(
                    addr.section,
                    (addr.address as i64 - sig_reloc.addend as i64) as u32,
                )
            }
            _ => bail!("Relocation mismatch: {:?} != {:?}", reloc, sig_reloc.kind),
        };
        let sig_symbol = &signature.symbols[sig_reloc.symbol as usize];
        // log::info!("Processing relocation {:#010X} {:?} -> {:#010X} {:?}", reloc_addr, reloc, target, sig_symbol);
        let target_symbol_idx = apply_symbol(obj, target, sig_symbol)?;
        let obj_reloc = ObjReloc {
            kind: sig_reloc.kind,
            target_symbol: target_symbol_idx,
            addend: sig_reloc.addend as i64,
            module: None,
        };
        // log::info!("Applying relocation {:#010X?}", obj_reloc);
        obj.sections[addr.section].relocations.insert(reloc_addr.address, obj_reloc)?;
    }
    for reloc in &signature.relocations {
        let addr = addr + reloc.offset;
        if !tracker.relocations.contains_key(&addr) {
            let sig_symbol = &signature.symbols[reloc.symbol as usize];
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

pub fn generate_signature<P>(path: P, symbol_name: &str) -> Result<Option<FunctionSignature>>
where P: AsRef<Path> {
    let mut out_symbols: Vec<OutSymbol> = Vec::new();
    let mut out_relocs: Vec<OutReloc> = Vec::new();
    let mut symbol_map: BTreeMap<SymbolIndex, u32> = BTreeMap::new();

    let mut obj = process_elf(path)?;
    if obj.kind == ObjKind::Executable
        && (obj.sda2_base.is_none()
            || obj.sda_base.is_none()
            || obj.stack_address.is_none()
            || obj.stack_end.is_none()
            || obj.db_stack_addr.is_none())
    {
        log::warn!(
            "Failed to locate all abs symbols {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?} {:#010X?}",
            obj.sda2_base,
            obj.sda_base,
            obj.stack_address,
            obj.stack_end,
            obj.db_stack_addr,
            obj.arena_hi,
            obj.arena_lo
        );
        return Ok(None);
    }
    let mut tracker = Tracker::new(&obj);
    // tracker.ignore_addresses.insert(0x80004000);
    for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
        if symbol.name != symbol_name && symbol.name != symbol_name.replace("TRK", "TRK_") {
            continue;
        }
        tracker.process_function(&obj, symbol)?;
    }
    tracker.apply(&mut obj, true)?; // true
    for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
        if symbol.name != symbol_name && symbol.name != symbol_name.replace("TRK", "TRK_") {
            continue;
        }
        let section_idx = symbol.section.unwrap();
        let section = &obj.sections[section_idx];
        // let out_symbol_idx = out_symbols.len();
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
        let mut instructions = section.data[(symbol.address - section.address) as usize
            ..(symbol.address - section.address + symbol.size) as usize]
            .chunks_exact(4)
            .map(|c| (u32::from_be_bytes(c.try_into().unwrap()), !0u32))
            .collect::<Vec<(u32, u32)>>();
        for (idx, (ins, pat)) in instructions.iter_mut().enumerate() {
            let addr = (symbol.address as usize + idx * 4) as u32;
            if let Some(reloc) = section.relocations.at(addr) {
                let symbol_idx = match symbol_map.entry(reloc.target_symbol) {
                    btree_map::Entry::Vacant(e) => {
                        let target = &obj.symbols[reloc.target_symbol];
                        let symbol_idx = out_symbols.len() as u32;
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
                            section: target
                                .section
                                .and_then(|idx| obj.sections.get(idx))
                                .map(|section| section.name.clone()),
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
                        *ins &= !0xFFFF;
                        *pat = !0xFFFF;
                    }
                    ObjRelocKind::PpcRel24 => {
                        *ins &= !0x3FFFFFC;
                        *pat = !0x3FFFFFC;
                    }
                    ObjRelocKind::PpcRel14 => {
                        *ins &= !0xFFFC;
                        *pat = !0xFFFC;
                    }
                    ObjRelocKind::PpcEmbSda21 => {
                        *ins &= !0x1FFFFF;
                        *pat = !0x1FFFFF;
                    }
                }
                out_relocs.push(OutReloc {
                    offset: addr - (symbol.address as u32),
                    kind: reloc.kind,
                    symbol: symbol_idx,
                    addend: reloc.addend as i32,
                });
            }
        }

        let mut data = vec![0u8; instructions.len() * 8];
        for (idx, &(ins, pat)) in instructions.iter().enumerate() {
            data[idx * 8..idx * 8 + 4].copy_from_slice(&ins.to_be_bytes());
            data[idx * 8 + 4..idx * 8 + 8].copy_from_slice(&pat.to_be_bytes());
        }

        let encoded = STANDARD.encode(&data);
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        let mut hash_buf = [0u8; 40];
        let hash_str = base16ct::lower::encode_str(&hash, &mut hash_buf)
            .map_err(|e| anyhow!("Failed to encode hash: {e}"))?;
        return Ok(Some(FunctionSignature {
            symbol: 0,
            hash: hash_str.to_string(),
            signature: encoded,
            symbols: out_symbols,
            relocations: out_relocs,
        }));
    }
    Ok(None)
}
