use std::{
    collections::{btree_map::Entry, BTreeMap},
    fs,
    fs::File,
    io::{BufWriter, Write},
};

use anyhow::{Context, Error, Result};
use argh::FromArgs;
use object::{
    write::{SectionId, SymbolId},
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SectionFlags,
    SectionIndex, SectionKind, SymbolFlags, SymbolKind, SymbolSection,
};

use crate::util::{asm::write_asm, elf::process_elf};

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
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles an ELF file.
#[argh(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argh(positional)]
    /// input file
    elf_file: String,
    #[argh(positional)]
    /// output directory
    out_dir: String,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Fixes issues with GNU assembler built object files.
#[argh(subcommand, name = "fixup")]
pub struct FixupArgs {
    #[argh(positional)]
    /// input file
    in_file: String,
    #[argh(positional)]
    /// output file
    out_file: String,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Fixup(c_args) => fixup(c_args),
    }
}

fn disasm(args: DisasmArgs) -> Result<()> {
    let obj = process_elf(&args.elf_file)?;
    write_asm(&args.out_dir, &obj)?;
    for unit in obj.link_order {
        let name = format!("$(OBJ_DIR)/asm/{}", file_name_from_unit(&unit));
        println!("    {name: <70}\\");
    }
    Ok(())
}

fn file_name_from_unit(str: &str) -> String {
    let str = str.strip_prefix("C:").unwrap_or(str);
    let str = str
        .strip_suffix(".c")
        .or_else(|| str.strip_suffix(".cp"))
        .or_else(|| str.strip_suffix(".cpp"))
        .or_else(|| str.strip_suffix(".s"))
        .unwrap_or(str);
    let str = str.replace('\\', "/");
    format!("{}.o", str.strip_prefix('/').unwrap_or(&str))
}

fn fixup(args: FixupArgs) -> Result<()> {
    let in_buf = fs::read(&args.in_file).context("Failed to open input file")?;
    let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
    let mut out_file =
        object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());

    // Write file symbol(s) first
    for symbol in in_file.symbols() {
        if symbol.kind() != SymbolKind::File {
            continue;
        }
        out_file.add_symbol(to_write_symbol(&symbol, &[])?);
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
                let map = match addr_to_sym.entry(section_id) {
                    Entry::Vacant(e) => e.insert(BTreeMap::new()),
                    Entry::Occupied(e) => e.into_mut(),
                };
                map.insert(symbol.address() as u32, symbol_id);
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
            let mut symbol = match reloc.target() {
                RelocationTarget::Symbol(idx) => match symbol_ids[idx.0] {
                    Some(id) => id,
                    None => {
                        let in_symbol = in_file.symbol_by_index(idx)?;
                        match in_symbol.kind() {
                            SymbolKind::Section => {
                                let section_idx = match in_symbol.section_index() {
                                    Some(id) => id,
                                    None => {
                                        return Err(Error::msg("Missing section for relocation"))
                                    }
                                };
                                let section_id = match section_ids[section_idx.0] {
                                    Some(id) => id,
                                    None => {
                                        return Err(Error::msg("Missing section for relocation"))
                                    }
                                };
                                out_file.section_symbol(section_id)
                            }
                            _ => return Err(Error::msg("Missing symbol for relocation")),
                        }
                    }
                },
                RelocationTarget::Section(idx) => {
                    let section_id = match section_ids[idx.0] {
                        Some(id) => id,
                        None => return Err(Error::msg("Missing section for relocation")),
                    };
                    out_file.section_symbol(section_id)
                }
                RelocationTarget::Absolute => todo!("Absolute relocation target"),
                _ => return Err(Error::msg("Invalid relocation target")),
            };
            let mut addend = reloc.addend();

            // Attempt to replace section symbols with direct symbol references
            let target_sym = out_file.symbol(symbol);
            if target_sym.kind == SymbolKind::Section {
                if let Some(new_symbol_id) = target_sym
                    .section
                    .id()
                    .and_then(|id| addr_to_sym.get(&id))
                    .and_then(|map| map.get(&(addend as u32)))
                {
                    symbol = *new_symbol_id;
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
                symbol,
                addend,
            })?;
        }
    }

    let mut out =
        BufWriter::new(File::create(&args.out_file).context("Failed to create out file")?);
    out_file.write_stream(&mut out).map_err(|e| Error::msg(format!("{e:?}")))?;
    out.flush()?;
    Ok(())
}

fn to_write_symbol_section(
    section: SymbolSection,
    section_ids: &[Option<SectionId>],
) -> Result<object::write::SymbolSection> {
    Ok(match section {
        SymbolSection::None => object::write::SymbolSection::None,
        SymbolSection::Absolute => object::write::SymbolSection::Absolute,
        SymbolSection::Common => object::write::SymbolSection::Common,
        SymbolSection::Section(idx) => match section_ids.get(idx.0).and_then(|opt| *opt) {
            Some(section_id) => object::write::SymbolSection::Section(section_id),
            None => return Err(Error::msg("Missing symbol section")),
        },
        _ => object::write::SymbolSection::Undefined,
    })
}

fn to_write_symbol_flags(flags: SymbolFlags<SectionIndex>) -> Result<SymbolFlags<SectionId>> {
    Ok(match flags {
        SymbolFlags::Elf { st_info, st_other } => SymbolFlags::Elf { st_info, st_other },
        SymbolFlags::None => SymbolFlags::None,
        _ => return Err(Error::msg("Unexpected symbol flags")),
    })
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
