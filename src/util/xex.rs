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
    analysis::cfa::SectionAddress, array_ref, obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    }, util::{
        comment::{CommentSym, MWComment},
        reader::{Endian, FromReader, ToWriter},
    }
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

    // Create object
    let mut obj = ObjInfo::new(kind, architecture, obj_name.to_string(), vec![], sections);
    obj.entry = NonZeroU64::new(obj_file.entry()).map(|n| n.get());

    // add known function boundaries from pdata
    // pdata info: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section
    let pdata_section = obj.sections.by_name(".pdata")?.map(|(_, s)| s).ok_or_else(|| anyhow::anyhow!(".pdata section not found"))?;
    let text_index = obj.sections.by_name(".text")?.map(|(_, s)| s).ok_or_else(|| anyhow::anyhow!(".text section not found"))?.elf_index;
            
    for (i, chunk) in pdata_section.data.chunks_exact(8).enumerate() {
        // the addr where this function begins
        let start_addr = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        // if we encounter 0's, that's the end of usable pdata entries
        if start_addr == 0 {
            log::info!("Found {} known funcs from pdata!", i);
            // log::info!("Encountered 0 at addr 0x{:08X}", pdata_section.address + (8 * i) as u64);
            break;
        }
        // some metadata for this function, including function size
        let word = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
        // let num_prologue_insts = word & 0xFF; // The number of instructions in the function's prolog.
        let num_insts_in_func = (word >> 8) & 0x3FFFFF; // The number of instructions in the function.
        // let flag_32bit = (word & 0x4000) != 0; // If set, the function consists of 32-bit instructions. If clear, the function consists of 16-bit instructions.
        // let exception_flag = (word & 0x8000) != 0; // If set, an exception handler exists for the function. Otherwise, no exception handler exists.
        
        // log::info!("Found func {} from 0x{:08X}-0x{:08X}", i, start_addr, start_addr + (num_insts_in_func * 4));
        let start = SectionAddress::new(text_index, start_addr);
        obj.known_functions.insert(start, Some(num_insts_in_func * 4));
    }

    // some xidata notes (idk where else to put them lol)
    // part 1:
    // seems to be many many lis/addi/mtctr/bctrs in sequence
    // e.g. lis r11, 0x82XX / addi r11, r11, 0xXXXX / mtctr r11 / bctr
    // indirect function calls? stubs?
    // matches up just fine

    // part 2: a bunch of 0's

    // part 3:
    // many lis/lwz/mtctr/bctrs in sequence
    // e.g. lis r11, 0xXXXX / lwz r11, 0xXXXX(r11) / mtctr r11/ bctr / zero-padding
    // this does not quite match up with the ground truth, but I suspect the difference comes from relocs

    // .idata: partially zero'ed out and offsetted from ground truth in debug, completely gone from release
    // .XBLD: zero'ed out in debug, completely gone from release
    // .reloc: zero'ed out regardless

    Ok(obj)
}