use std::{fs::File, vec::Vec};

use anyhow::{ensure, Result};
use itertools::Itertools;
use pdb::{self, FallibleIterator, SectionOffset};
use typed_path::Utf8NativePathBuf;

use crate::obj::{
    ObjDataKind, ObjSection, ObjSections, ObjSymbol, ObjSymbolFlagSet, ObjSymbolKind,
    ObjSymbolScope,
};

pub fn try_parse_pdb(
    path: &Utf8NativePathBuf,
    section_addrs: &ObjSections,
) -> Result<Vec<ObjSymbol>> {
    let mut addr_vec: Vec<ObjSymbol> = vec![];
    let mut dbfile = pdb::PDB::open(File::open(path)?)?;

    // setup configgery
    let mut pdb2dtk_section_table: [u8; 32] =
        std::array::from_fn::<u8, 32, _>(|x: usize| -> u8 { x as u8 });
    let symtable = dbfile.global_symbols()?;
    let pdbmap = dbfile.address_map()?;
    let mut iter = symtable.iter();

    // build PDB -> DTK section lookup table
    ensure!(section_addrs.len() <= 32, "Oh god, why does your XEX have more than 32 sections?");
    {
        let mut dtk_iter = section_addrs.iter();
        let sec_headers = dbfile.sections()?.unwrap();
        while let Some(dtk_section) = dtk_iter.next() {
            sec_headers.iter().enumerate().for_each(|x| {
                log::trace!("PDBPDBPDB || {:x}: {}", x.1.virtual_address, x.1.name());
                if x.1.name() == dtk_section.1.name {
                    pdb2dtk_section_table[x.0 + 1] = dtk_section.0 as u8;
                    log::debug!(
                        "Remapping PDB section {} (no. {}) to DTK section {} (no. {})",
                        x.1.name(),
                        x.0 + 1,
                        dtk_section.1.name,
                        dtk_section.0
                    );
                }
            });
        }
    }

    // churn through actual symbols
    while let Some(symbol) = iter.next()? {
        match symbol.parse() {
            // Public is all the shit available to everyone
            Ok(pdb::SymbolData::Public(data)) => {
                let symoffset: SectionOffset =
                    data.offset.to_section_offset(&pdbmap).unwrap_or_default();
                addr_vec.push(ObjSymbol {
                    name: data.name.to_string().into(),
                    demangled_name: None,
                    address: symoffset.offset as u64
                        + section_addrs
                            .get(pdb2dtk_section_table[symoffset.section as usize] as u32)
                            .unwrap_or(&ObjSection::default())
                            .address,
                    section: Some(symoffset.section as u32),
                    size: 0,
                    size_known: false,
                    flags: ObjSymbolFlagSet::default(),
                    kind: if data.function {
                        ObjSymbolKind::Function
                    } else {
                        ObjSymbolKind::Object
                    },
                    align: None,
                    data_kind: ObjDataKind::Unknown,
                    name_hash: None,
                    demangled_name_hash: None,
                });
            }
            _ => {}
        }
    }

    // churn through procedures and mark symbols as funcs
    iter = symtable.iter();
    while let Some(symbol) = iter.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Procedure(data)) => {
                let symoffset: SectionOffset = data.offset.to_section_offset(&pdbmap).unwrap();
                log::debug!("{:#?}", symoffset);
                match addr_vec.iter_mut().find(|x| {
                    x.address
                        == symoffset.offset as u64
                            + section_addrs
                                .get(pdb2dtk_section_table[symoffset.section as usize] as u32)
                                .unwrap_or(&ObjSection::default())
                                .address
                }) {
                    Some(func) => {
                        func.kind = ObjSymbolKind::Function;
                        func.flags.set_scope(if data.global {
                            ObjSymbolScope::Global
                        } else {
                            ObjSymbolScope::Local
                        });
                        func.size = data.len as u64;
                        func.size_known = true;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // sort vec
    addr_vec.sort_by(|l, r| {
        if l.section == r.section {
            Ord::cmp(&l.address, &r.address)
        } else {
            Ord::cmp(&l.section, &r.section)
        }
    });

    {
        // weed out xidata symbols (jeff finds them later)
        let xidata_symbols: Vec<ObjSymbol> = addr_vec
            .iter()
            .enumerate()
            .filter_map(|(_, x)| if x.name.contains("__imp_") { Some(x.clone()) } else { None })
            .collect_vec();
        let mut vec_it = xidata_symbols.iter().rev();
        while let Some(sym) = vec_it.next() {
            match addr_vec.iter().enumerate().find_map(|x| {
                if x.1.name.contains(sym.name.as_str()) {
                    Some(x.0)
                } else {
                    None
                }
            }) {
                Some(idx) => _ = addr_vec.remove(idx),
                _ => {}
            };
        }
    }

    // fixup last symbols per section
    let mut vec_it = addr_vec.iter_mut().peekable();
    while let Some(sym) = vec_it.next() {
        match vec_it.peek() {
            Some(next_sym) => {
                if sym.section != next_sym.section {
                    sym.size = 4;
                    sym.size_known = true;
                }
            }
            _ => {}
        }
    }
    Ok(addr_vec)
}
