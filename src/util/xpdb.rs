use std::{fs::File, vec::Vec};

use anyhow::Result;
use pdb::{self, FallibleIterator, SectionOffset, SymbolIndex};
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
    let symtable = dbfile.global_symbols()?;
    let pdbmap = dbfile.address_map()?;
    let mut iter = symtable.iter();
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
                            .get((symoffset.section - 1) as u32)
                            .unwrap_or(&ObjSection::default())
                            .address,
                    section: Some(symoffset.section as u32),
                    size: 0,
                    size_known: false,
                    flags: ObjSymbolFlagSet::default(),
                    kind: ObjSymbolKind::Object,
                    align: None,
                    data_kind: ObjDataKind::Unknown,
                    name_hash: None,
                    demangled_name_hash: None,
                });
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

    // fixup last symbols per section
    let mut vec_it = addr_vec.iter_mut().peekable();
    while let Some(sym) = vec_it.next() {
        match vec_it.peek() {
            Some(next_sym) => {
                if sym.section != next_sym.section {
                    sym.size = 1;
                    sym.size_known = true;
                }
            }
            _ => {}
        }
    }
    Ok(addr_vec)
}
