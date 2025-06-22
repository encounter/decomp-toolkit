use std::{
    collections::{hash_map, HashMap},
    fs,
    io::Cursor,
    num::NonZeroU64,
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use cwdemangle::demangle;
use flagset::Flags;
use indexmap::IndexMap;
use itertools::Itertools;
use objdiff_core::obj::split_meta::{SplitMeta, SHT_SPLITMETA, SPLITMETA_SECTION};
use object::{
    Architecture, BinaryFormat, Endianness, File, Object, ObjectComdat, ObjectKind, ObjectSection,
    ObjectSegment, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget, SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection
};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    array_ref,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    },
    util::{
        comment::{CommentSym, MWComment},
        reader::{Endian, FromReader, ToWriter},
    },
};

pub fn process_xex(path: &Utf8NativePath) -> Result<ObjInfo> {
    // look at cmd\dol\split

    println!("xex: {path}");
    let std_path = path.to_path_buf();
    let data = fs::read(std_path).expect("Failed to read file");
    let obj_file = object::File::parse(&*data).expect("Failed to parse object file");
    let architecture = ObjArchitecture::PowerPc;
    let kind = ObjKind::Executable;

    // TODO: rename this to the underlying executable name found in the xex
    let mut obj_name = "jeff";

    let mut sections: Vec<ObjSection> = vec![];
    let mut section_indexes: Vec<Option<usize>> = vec![None /* ELF null section */];
    for section in obj_file.sections() {
        if section.size() == 0 {
            section_indexes.push(None);
            continue;
        }
        let section_name = section.name()?;
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            // SectionKind::Other if section_name == ".comment" => ObjSectionKind::Comment,
            _ => {
                section_indexes.push(None);
                continue;
            }
        };
        section_indexes.push(Some(sections.len())); // the .XBLD and .reloc section indices aren't pushed. is that intentional?
        // should we do anything with section.flags()? xex uses COFF
        sections.push(ObjSection {
            name: section_name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section.uncompressed_data()?.to_vec(),
            align: section.align(),
            // the index of the section in the exe - starts at 1 instead of 0 for some reason, so offset it by -1
            elf_index: (section.index().0 - 1) as ObjSectionIndex,
            // everything below this line doesn't really matter for the purposes of an xex
            relocations: Default::default(),
            virtual_address: None, // Loaded from section symbol
            file_offset: section.file_range().map(|(v, _)| v).unwrap_or_default(),
            section_known: true,
            splits: Default::default(),
        });
    }

    // for an xex, no mw_comment or split_meta

        // pub symbols: ObjSymbols,

        // // Extracted
        // pub link_order: Vec<ObjUnit>,
        // pub blocked_relocation_sources: AddressRanges,
        // pub blocked_relocation_targets: AddressRanges,

        // // From .ctors, .dtors and extab
        // pub known_functions: BTreeMap<SectionAddress, Option<u32>>,

    // Create object
    let mut obj = ObjInfo::new(kind, architecture, obj_name.to_string(), vec![], sections);
    obj.entry = NonZeroU64::new(obj_file.entry()).map(|n| n.get());

    Ok(obj)
}