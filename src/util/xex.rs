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
use objdiff_core::obj::split_meta::{SplitMeta, SHT_SPLITMETA, SPLITMETA_SECTION};
use object::{
    Architecture, BinaryFormat, Endianness, File, Object, ObjectComdat, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, Relocation, RelocationFlags, RelocationTarget, SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection
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

pub fn process_xex(path: &Utf8NativePath) {
    println!("xex: {path}");
    let std_path = path.to_path_buf();
    let data = fs::read(std_path).expect("Failed to read file");
    let obj_file = object::File::parse(&*data).expect("Failed to parse object file");

    println!("Format:        {:?}", obj_file.format());
    println!("Architecture:  {:?}", obj_file.architecture());
    println!("Kind:          {:?}", obj_file.kind());
    println!("Endianness:    {:?}", obj_file.endianness());
    println!("Entry point:   0x{:X}", obj_file.entry());

    println!("\n--- Sections ---");
    for section in obj_file.sections() {
        let name = section.name().unwrap_or("<unnamed>");
        println!(
            "Section: {:<20} addr: 0x{:08X} size: 0x{:06X} bytes flags: {:?}",
            name,
            section.address(),
            section.size(),
            section.flags()
        );
    }

    println!("\n--- Symbols ---");
    for symbol in obj_file.symbols() {
        let name = symbol.name().unwrap_or("<unnamed>");
        println!(
            "Symbol: {:<30} addr: 0x{:08X} size: {:<5} kind: {:?} scope: {:?} section: {:?}",
            name,
            symbol.address(),
            symbol.size(),
            symbol.kind(),
            symbol.scope(),
            symbol.section()
        );
    }

    println!("\n--- Segments ---");
    for segment in obj_file.segments() {
        println!(
            "Segment: addr: 0x{:08X} size: 0x{:08X} bytes",
            segment.address(),
            segment.size()
        );
    }
    // let obj_file = object::File::parse(path);
}