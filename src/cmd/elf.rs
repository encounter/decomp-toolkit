use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    fs,
    fs::{DirBuilder, File},
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::{Context, Error, Result};
use argh::FromArgs;
use object::{
    write::{SectionId, SymbolId},
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SectionFlags,
    SectionIndex, SectionKind, SymbolFlags, SymbolKind, SymbolScope, SymbolSection,
};

use crate::util::{
    asm::write_asm,
    elf::{process_elf, write_elf},
    obj::ObjKind,
    split::split_obj,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing ELF files.
#[argh(subcommand, name = "elf")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Disasm(DisasmArgs),
    Fixup(FixupArgs),
    Split(SplitArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles an ELF file.
#[argh(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argh(positional)]
    /// input file
    elf_file: PathBuf,
    #[argh(positional)]
    /// output file (.o) or directory (.elf)
    out: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Fixes issues with GNU assembler built object files.
#[argh(subcommand, name = "fixup")]
pub struct FixupArgs {
    #[argh(positional)]
    /// input file
    in_file: PathBuf,
    #[argh(positional)]
    /// output file
    out_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits an executable ELF into relocatable objects.
#[argh(subcommand, name = "split")]
pub struct SplitArgs {
    #[argh(positional)]
    /// input file
    in_file: PathBuf,
    #[argh(positional)]
    /// output directory
    out_dir: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Fixup(c_args) => fixup(c_args),
        SubCommand::Split(c_args) => split(c_args),
    }
}

fn disasm(args: DisasmArgs) -> Result<()> {
    let obj = process_elf(&args.elf_file)?;
    match obj.kind {
        ObjKind::Executable => {
            let split_objs = split_obj(&obj)?;

            let asm_dir = args.out.join("asm");
            let include_dir = args.out.join("include");
            DirBuilder::new().recursive(true).create(&include_dir)?;
            fs::write(&include_dir.join("macros.inc"), include_bytes!("../../assets/macros.inc"))?;

            for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
                let out_path = asm_dir.join(file_name_from_unit(unit, ".s"));
                if let Some(parent) = out_path.parent() {
                    DirBuilder::new().recursive(true).create(parent)?;
                }
                let mut w = BufWriter::new(File::create(out_path)?);
                write_asm(&mut w, split_obj)?;

                let name = format!("$(OBJ_DIR)/asm/{}", file_name_from_unit(unit, ".o"));
                println!("    {name: <70}\\");
            }
        }
        ObjKind::Relocatable => {
            if let Some(parent) = args.out.parent() {
                DirBuilder::new().recursive(true).create(parent)?;
            }
            let mut w = BufWriter::new(File::create(args.out)?);
            write_asm(&mut w, &obj)?;
        }
    }
    Ok(())
}

fn split(args: SplitArgs) -> Result<()> {
    let obj = process_elf(&args.in_file)?;

    let mut file_map = HashMap::<String, object::write::Object>::new();

    let split_objs = split_obj(&obj)?;
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj)?;
        match file_map.entry(unit.clone()) {
            hash_map::Entry::Occupied(_) => {
                return Err(Error::msg(format!("Duplicate file {unit}")));
            }
            hash_map::Entry::Vacant(e) => e.insert(out_obj),
        };
    }

    let mut rsp_file = BufWriter::new(File::create("rsp")?);
    for unit in &obj.link_order {
        let object = file_map
            .get(unit)
            .ok_or_else(|| Error::msg(format!("Failed to find object file for unit '{unit}'")))?;
        let out_path = args.out_dir.join(file_name_from_unit(unit, ".o"));
        writeln!(rsp_file, "{}", out_path.to_string_lossy())?;
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        let mut file = BufWriter::new(File::create(out_path)?);
        object.write_stream(&mut file).map_err(|e| Error::msg(format!("{e:?}")))?;
        file.flush()?;
    }
    rsp_file.flush()?;
    Ok(())
}

fn file_name_from_unit(str: &str, suffix: &str) -> String {
    let str = str.strip_suffix(ASM_SUFFIX).unwrap_or(str);
    let str = str.strip_prefix("C:").unwrap_or(str);
    let str = str
        .strip_suffix(".c")
        .or_else(|| str.strip_suffix(".cp"))
        .or_else(|| str.strip_suffix(".cpp"))
        .or_else(|| str.strip_suffix(".s"))
        .or_else(|| str.strip_suffix(".o"))
        .unwrap_or(str);
    let str = str.replace('\\', "/");
    let str = str.strip_prefix('/').unwrap_or(&str);
    format!("{str}{suffix}")
}

const ASM_SUFFIX: &str = " (asm)";

fn fixup(args: FixupArgs) -> Result<()> {
    let in_buf = fs::read(&args.in_file).with_context(|| {
        format!("Failed to open input file: '{}'", args.in_file.to_string_lossy())
    })?;
    let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
    let mut out_file =
        object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());

    // Write file symbol first
    let mut file_symbol_found = false;
    for symbol in in_file.symbols() {
        if symbol.kind() != SymbolKind::File {
            continue;
        }
        let mut out_symbol = to_write_symbol(&symbol, &[])?;
        out_symbol.name.append(&mut ASM_SUFFIX.as_bytes().to_vec());
        out_file.add_symbol(out_symbol);
        file_symbol_found = true;
        break;
    }
    // Create a file symbol if not found
    if !file_symbol_found {
        let file_name = args.in_file.file_name().ok_or_else(|| {
            Error::msg(format!("'{}' is not a file path", args.in_file.to_string_lossy()))
        })?;
        let file_name = file_name.to_str().ok_or_else(|| {
            Error::msg(format!("'{}' is not valid UTF-8", file_name.to_string_lossy()))
        })?;
        let mut name_bytes = file_name.as_bytes().to_vec();
        name_bytes.append(&mut ASM_SUFFIX.as_bytes().to_vec());
        out_file.add_symbol(object::write::Symbol {
            name: name_bytes,
            value: 0,
            size: 0,
            kind: SymbolKind::File,
            scope: SymbolScope::Compilation,
            weak: false,
            section: object::write::SymbolSection::Absolute,
            flags: SymbolFlags::None,
        });
    }

    // Write section symbols & sections
    let mut section_ids: Vec<Option<SectionId>> = vec![];
    for section in in_file.sections() {
        // Skip empty sections or metadata sections
        if section.size() == 0 || section.kind() == SectionKind::Metadata {
            section_ids.push(None);
            continue;
        }
        let section_id =
            out_file.add_section(vec![], section.name_bytes()?.to_vec(), section.kind());
        section_ids.push(Some(section_id));
        let out_section = out_file.section_mut(section_id);
        if section.kind() == SectionKind::UninitializedData {
            out_section.append_bss(section.size(), section.align());
        } else {
            out_section.set_data(section.uncompressed_data()?.into_owned(), section.align());
        }
        if has_section_flags(section.flags(), object::elf::SHF_ALLOC)? {
            // Generate section symbol
            out_file.section_symbol(section_id);
        }
    }

    // Write symbols
    let mut symbol_ids: Vec<Option<SymbolId>> = vec![];
    let mut addr_to_sym: BTreeMap<SectionId, BTreeMap<u32, SymbolId>> = BTreeMap::new();
    for symbol in in_file.symbols() {
        // Skip section and file symbols, we wrote them above
        if matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File | SymbolKind::Null) {
            symbol_ids.push(None);
            continue;
        }
        let out_symbol = to_write_symbol(&symbol, &section_ids)?;
        let section_id = out_symbol.section.id();
        let symbol_id = out_file.add_symbol(out_symbol);
        symbol_ids.push(Some(symbol_id));
        if symbol.size() != 0 {
            if let Some(section_id) = section_id {
                match addr_to_sym.entry(section_id) {
                    btree_map::Entry::Vacant(e) => e.insert(BTreeMap::new()),
                    btree_map::Entry::Occupied(e) => e.into_mut(),
                }
                .insert(symbol.address() as u32, symbol_id);
            }
        }
    }

    // Write relocations
    for section in in_file.sections() {
        let section_id = match section_ids[section.index().0] {
            Some(id) => id,
            None => continue,
        };
        for (addr, reloc) in section.relocations() {
            let mut target_symbol_id = match reloc.target() {
                RelocationTarget::Symbol(idx) => match symbol_ids[idx.0] {
                    Some(id) => Ok(id),
                    None => {
                        let in_symbol = in_file.symbol_by_index(idx)?;
                        match in_symbol.kind() {
                            SymbolKind::Section => in_symbol
                                .section_index()
                                .ok_or_else(|| Error::msg("Section symbol without section"))
                                .and_then(|section_idx| {
                                    section_ids[section_idx.0].ok_or_else(|| {
                                        Error::msg("Relocation against stripped section")
                                    })
                                })
                                .map(|section_idx| out_file.section_symbol(section_idx)),
                            _ => Err(Error::msg("Missing symbol for relocation")),
                        }
                    }
                },
                RelocationTarget::Section(section_idx) => section_ids[section_idx.0]
                    .ok_or_else(|| Error::msg("Relocation against stripped section"))
                    .map(|section_id| out_file.section_symbol(section_id)),
                target => Err(Error::msg(format!("Invalid relocation target '{target:?}'"))),
            }?;

            // Attempt to replace section symbols with direct symbol references
            let mut addend = reloc.addend();
            let target_sym = out_file.symbol(target_symbol_id);
            if target_sym.kind == SymbolKind::Section {
                if let Some(&new_symbol_id) = target_sym
                    .section
                    .id()
                    .and_then(|id| addr_to_sym.get(&id))
                    .and_then(|map| map.get(&(addend as u32)))
                {
                    target_symbol_id = new_symbol_id;
                    addend = 0;
                }
            }

            let kind = match reloc.kind() {
                // This is a hack to avoid replacement with a section symbol
                // See [`object::write::elf::object::elf_fixup_relocation`]
                RelocationKind::Absolute => RelocationKind::Elf(object::elf::R_PPC_ADDR32),
                other => other,
            };

            out_file.add_relocation(section_id, object::write::Relocation {
                offset: addr,
                size: reloc.size(),
                kind,
                encoding: reloc.encoding(),
                symbol: target_symbol_id,
                addend,
            })?;
        }
    }

    let mut out = BufWriter::new(File::create(&args.out_file).with_context(|| {
        format!("Failed to create output file: '{}'", args.out_file.to_string_lossy())
    })?);
    out_file.write_stream(&mut out).map_err(|e| Error::msg(format!("{e:?}")))?;
    out.flush()?;
    Ok(())
}

fn to_write_symbol_section(
    section: SymbolSection,
    section_ids: &[Option<SectionId>],
) -> Result<object::write::SymbolSection> {
    match section {
        SymbolSection::None => Ok(object::write::SymbolSection::None),
        SymbolSection::Absolute => Ok(object::write::SymbolSection::Absolute),
        SymbolSection::Common => Ok(object::write::SymbolSection::Common),
        SymbolSection::Section(idx) => section_ids
            .get(idx.0)
            .and_then(|&opt| opt)
            .map(object::write::SymbolSection::Section)
            .ok_or_else(|| Error::msg("Missing symbol section")),
        _ => Ok(object::write::SymbolSection::Undefined),
    }
}

fn to_write_symbol_flags(flags: SymbolFlags<SectionIndex>) -> Result<SymbolFlags<SectionId>> {
    match flags {
        SymbolFlags::Elf { st_info, st_other } => Ok(SymbolFlags::Elf { st_info, st_other }),
        SymbolFlags::None => Ok(SymbolFlags::None),
        _ => Err(Error::msg("Unexpected symbol flags")),
    }
}

fn to_write_symbol(
    symbol: &object::read::Symbol,
    section_ids: &[Option<SectionId>],
) -> Result<object::write::Symbol> {
    Ok(object::write::Symbol {
        name: symbol.name_bytes()?.to_vec(),
        value: symbol.address(),
        size: symbol.size(),
        kind: symbol.kind(),
        scope: symbol.scope(),
        weak: symbol.is_weak(),
        section: to_write_symbol_section(symbol.section(), section_ids)?,
        flags: to_write_symbol_flags(symbol.flags())?,
    })
}

fn has_section_flags(flags: SectionFlags, flag: u32) -> Result<bool> {
    match flags {
        SectionFlags::Elf { sh_flags } => Ok(sh_flags & flag as u64 == flag as u64),
        _ => Err(Error::msg("Unexpected section flags")),
    }
}
