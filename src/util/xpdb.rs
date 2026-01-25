use std::{collections::BTreeMap, fs::File};

use anyhow::Result;
use pdb::{self, FallibleIterator, SectionOffset};
use typed_path::Utf8NativePathBuf;

use crate::analysis::cfa::SectionAddress;

pub fn try_parse_pdb(path: Utf8NativePathBuf, section_addrs: &Vec<u32>) -> Result<()> {
    let mut addr_map: BTreeMap<SectionAddress, String> = BTreeMap::new();
    let mut dbfile = pdb::PDB::open(File::open(path)?)?;
    let symtable = dbfile.global_symbols()?;
    let pdbmap = dbfile.address_map()?;
    let mut iter = symtable.iter();
    while let Some(symbol) = iter.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) => {
                let symoffset: SectionOffset =
                    data.offset.to_section_offset(&pdbmap).unwrap_or_default();
                addr_map.insert(
                    SectionAddress {
                        section: symoffset.section as u32,
                        address: symoffset.offset + section_addrs[symoffset.section as usize],
                    },
                    data.name.to_string().into(),
                );
            }
            _ => {}
        }
    }
    println!("{:#?}", addr_map);
    Ok(())
}
