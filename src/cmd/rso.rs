use std::{
    io::{BufRead, Seek, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use argp::FromArgs;
use object::{
    elf::{R_PPC_NONE, R_PPC_REL24},
    Architecture, Endianness, Object, ObjectKind, ObjectSection, ObjectSymbol, SectionKind,
    SymbolIndex, SymbolKind, SymbolSection,
};

use crate::util::{
    file::{buf_reader, buf_writer, map_file},
    reader::{Endian, ToWriter},
    rso::{
        process_rso, symbol_hash, RsoHeader, RsoRelocation, RsoSectionHeader, RsoSymbol,
        RSO_SECTION_NAMES,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing RSO files.
#[argp(subcommand, name = "rso")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Make(MakeArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views RSO file information.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// RSO file
    rso_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Make RSO file from ELF.
#[argp(subcommand, name = "make")]
pub struct MakeArgs {
    #[argp(positional, arg_name = "ELF File")]
    /// elf file
    input: PathBuf,

    #[argp(option, short = 'o', arg_name = "File")]
    /// output file path
    output: PathBuf,

    #[argp(option, short = 'm', arg_name = "Name")]
    /// module name (or path). Default: input name
    module_name: Option<String>,

    #[argp(option, short = 'e', arg_name = "File")]
    /// Path of file containing the symbols allowed to be exported (Divided by `\n`)
    export: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Make(c_args) => make(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let rso = {
        let file = map_file(args.rso_file)?;
        let obj = process_rso(&mut file.as_reader())?;
        #[allow(clippy::let_and_return)]
        obj
    };
    println!("Read RSO module {}", rso.name);
    Ok(())
}

fn make(args: MakeArgs) -> Result<()> {
    let file = map_file(&args.input)?;
    let obj_file = object::read::File::parse(file.as_slice())?;
    match obj_file.architecture() {
        Architecture::PowerPc => {}
        arch => bail!("Unexpected architecture: {arch:?}"),
    };
    ensure!(obj_file.endianness() == Endianness::Big, "Expected big endian");

    let module_name = match args.module_name {
        Some(n) => n,
        None => args.input.display().to_string(),
    };

    let symbols_to_export = match args.export {
        Some(export_file_path) => {
            let export_file_reader = buf_reader(export_file_path)?;
            export_file_reader.lines().map_while(Result::ok).collect()
        }
        None => vec![],
    };

    match obj_file.kind() {
        ObjectKind::Executable => {
            make_sel(obj_file, &args.output, &module_name, symbols_to_export)?
        }
        ObjectKind::Relocatable => {
            make_rso(obj_file, &args.output, &module_name, symbols_to_export)?
        }
        kind => bail!("Unexpected ELF type: {kind:?}"),
    }

    Ok(())
}

fn make_sel<P: AsRef<Path>>(
    _file: object::File,
    _output: P,
    _module_name: &str,
    _symbols_to_export: Vec<String>,
) -> Result<()> {
    bail!("Making SEL file is not supported at the momment");
}

fn make_rso<P: AsRef<Path>>(
    file: object::File,
    output: P,
    module_name: &str,
    symbols_to_export: Vec<String>,
) -> Result<()> {
    let mut out = buf_writer(output)?;

    let try_populate_symbol_index_and_offset =
        |name: &str, index: &mut u8, offset: &mut u32| -> Result<()> {
            let Some(sym) = file.symbol_by_name(name) else {
                return Ok(());
            };

            let si = sym
                .section_index()
                .with_context(|| format!("Failed to find symbol `{}` section index", name))?;
            let addr = sym.address();

            *index = si.0 as u8;
            *offset = addr as u32;

            Ok(())
        };

    let pad_to_alignment =
        |out: &mut std::io::BufWriter<std::fs::File>, alignment: u64| -> Result<()> {
            if alignment == 0 {
                return Ok(());
            }

            const ZERO_BUF: [u8; 32] = [0u8; 32];
            let pos = out.stream_position()?;
            let mut count = (!(alignment - 1) & ((alignment + pos) - 1)) - pos;

            while count > 0 {
                let slice_size = std::cmp::min(ZERO_BUF.len(), count as usize);
                out.write_all(&ZERO_BUF[0..slice_size])?;
                count -= slice_size as u64;
            }

            Ok(())
        };

    let mut header = RsoHeader::new();

    try_populate_symbol_index_and_offset(
        "_prolog",
        &mut header.prolog_section,
        &mut header.prolog_offset,
    )?;
    try_populate_symbol_index_and_offset(
        "_epilog",
        &mut header.epilog_section,
        &mut header.epilog_offset,
    )?;
    try_populate_symbol_index_and_offset(
        "_unresolved",
        &mut header.unresolved_section,
        &mut header.unresolved_offset,
    )?;

    header.to_writer(&mut out, Endian::Big)?;
    header.section_info_offset = out.stream_position()? as u32;
    {
        // Write Sections Info Table (Blank)
        let blank_section = RsoSectionHeader::default();
        for _ in file.sections() {
            header.num_sections += 1;
            blank_section.to_writer(&mut out, Endian::Big)?;
        }
    }

    let mut rso_sections: Vec<RsoSectionHeader> = vec![];
    for section in file.sections() {
        let is_valid_section =
            section.name().is_ok_and(|n| RSO_SECTION_NAMES.iter().any(|&s| s == n));
        let section_size = section.size();

        if !is_valid_section || section_size == 0 {
            rso_sections.push(RsoSectionHeader::default());
            continue;
        }

        if section.kind() == SectionKind::UninitializedData {
            header.bss_size += section_size as u32;
            rso_sections.push(RsoSectionHeader { offset_and_flags: 0, size: section_size as u32 });
            continue;
        }

        pad_to_alignment(&mut out, section.align())?;
        let section_offset_in_file = out.stream_position()?;
        let section_data = section.data()?;
        out.write_all(section_data)?;
        rso_sections.push(RsoSectionHeader {
            offset_and_flags: section_offset_in_file as u32,
            size: section_size as u32,
        });
    }

    pad_to_alignment(&mut out, 4)?;
    header.name_offset = out.stream_position()? as u32;

    // Rewind and write the correct section info table
    out.seek(std::io::SeekFrom::Start(header.section_info_offset as u64))?;
    for section in &rso_sections {
        section.to_writer(&mut out, Endian::Big)?;
    }

    // Write the module name
    out.seek(std::io::SeekFrom::Start(header.name_offset as u64))?;

    let module_name = module_name.as_bytes();
    out.write_all(module_name)?;
    header.name_size = module_name.len() as u32;

    // Accumulate exported and imported symbol
    let mut import_symbol_table: Vec<RsoSymbol> = vec![];
    let mut export_symbol_table: Vec<RsoSymbol> = vec![];
    for symbol in file.symbols() {
        let sym_binding = match symbol.flags() {
            object::SymbolFlags::Elf { st_info, st_other: _ } => st_info >> 4,
            flag => bail!("Unknown symbol flag found `{:?}`", flag),
        };

        let symbol_name = match symbol.name() {
            std::result::Result::Ok(n) => {
                if n.is_empty() {
                    continue;
                }

                n
            }
            Err(_) => continue,
        };

        // In the [`RsoSymbol::name_offset`] field we would store the symbol index temp
        match symbol.section_index() {
            Some(section_index)
                if sym_binding != object::elf::STB_LOCAL && section_index.0 != 0 =>
            {
                // Symbol to export
                if !symbols_to_export.iter().any(|s| s == symbol_name) {
                    continue;
                }

                let hash = symbol_hash(symbol_name);
                export_symbol_table.push(RsoSymbol {
                    name_offset: symbol.index().0 as u32,
                    offset: symbol.address() as u32,
                    section_index: section_index.0 as u32,
                    hash: Some(hash),
                });
            }
            None => {
                if matches!(symbol.kind(), SymbolKind::File) {
                    continue;
                }

                if symbol.section() == SymbolSection::Absolute {
                    if !symbols_to_export.iter().any(|s| s == symbol_name) {
                        continue;
                    }

                    // Special Symbols
                    let hash = symbol_hash(symbol_name);
                    export_symbol_table.push(RsoSymbol {
                        name_offset: symbol.index().0 as u32,
                        offset: symbol.address() as u32,
                        section_index: 0xFFF1_u32,
                        hash: Some(hash),
                    });
                    continue;
                }

                // Symbol to import
                import_symbol_table.push(RsoSymbol {
                    name_offset: symbol.index().0 as u32,
                    offset: symbol.address() as u32,
                    section_index: 0, // Relocation offset
                    hash: None,
                });
            }
            _ => continue,
        }
    }

    // Accumulate relocations
    let mut imported_relocations: Vec<RsoRelocation> = vec![];
    let mut exported_relocations: Vec<RsoRelocation> = vec![];

    for section in file.sections() {
        let is_valid_section =
            section.name().is_ok_and(|n| RSO_SECTION_NAMES.iter().any(|&s| s == n));
        if !is_valid_section {
            continue;
        }

        let relocation_section_idx = section.index().0 as u32;
        let relocation_section_offset =
            rso_sections[relocation_section_idx as usize].offset_and_flags;

        for (reloc_addr, reloc) in section.relocations() {
            let reloc_target_symbol_idx = match reloc.target() {
                object::RelocationTarget::Symbol(t) => t,
                _ => continue,
            };

            let std::result::Result::Ok(reloc_target_symbol) =
                file.symbol_by_index(reloc_target_symbol_idx)
            else {
                bail!(
                    "Failed to find relocation `{:08X}` symbol ({})",
                    reloc_addr,
                    reloc_target_symbol_idx.0
                );
            };

            let reloc_type = match reloc.flags() {
                object::RelocationFlags::Elf { r_type } => r_type,
                _ => continue,
            };

            if reloc_type == R_PPC_NONE {
                continue;
            }

            match reloc_target_symbol.section_index() {
                None => {
                    // Imported symbol relocation
                    // Get the symbol index inside the import symbol table
                    let symbol_table_idx = match import_symbol_table
                        .iter()
                        .position(|s| s.name_offset == reloc_target_symbol_idx.0 as u32)
                    {
                        Some(idx) => idx,
                        // We should always find the symbol. If not, it means a logic error in the symbol accumulator loop
                        // panic?
                        None => {
                            bail!("Failed to find imported symbol in the accumulated symbol table.")
                        }
                    };

                    let id_and_type = ((symbol_table_idx as u32) << 8) | (reloc_type & 0xFF);
                    imported_relocations.push(RsoRelocation {
                        // Convert the relocation offset from being section relative to file relative
                        offset: relocation_section_offset + reloc_addr as u32,
                        id_and_type,
                        target_offset: 0,
                    });
                }
                Some(reloc_symbol_section_idx) => {
                    // Exported symbol relocation
                    let id_and_type =
                        ((reloc_symbol_section_idx.0 as u32) << 8) | (reloc_type & 0xFF);
                    exported_relocations.push(RsoRelocation {
                        // Convert the relocation offset from being section relative to file relative
                        offset: relocation_section_offset + reloc_addr as u32,
                        id_and_type,
                        target_offset: reloc.addend() as u32 + reloc_target_symbol.address() as u32,
                    });
                }
            }

            // Apply relocation with the `_unresolved` as the symbol, if the module export the function
            if reloc_type == R_PPC_REL24
                && header.unresolved_offset != 0
                && header.unresolved_section == relocation_section_idx as u8
            {
                let target_section = file
                    .section_by_index(object::SectionIndex(relocation_section_idx as usize))
                    .unwrap();
                let target_section_data = target_section.data().unwrap();

                // Copy instruction
                let mut intruction_buff = [0u8; 4];
                intruction_buff.copy_from_slice(
                    &target_section_data[(reloc_addr as usize)..(reloc_addr + 4) as usize],
                );
                let target_instruction = u32::from_be_bytes(intruction_buff);

                let off_diff = header.unresolved_offset as i64 - reloc_addr as i64;
                let replacement_instruction =
                    (off_diff as u32 & 0x3fffffcu32) | (target_instruction & 0xfc000003u32);
                let intruction_buff = replacement_instruction.to_be_bytes();

                let relocation_file_offset = relocation_section_offset as u64 + reloc_addr;
                let current_stream_pos = out.stream_position()?;
                out.seek(std::io::SeekFrom::Start(relocation_file_offset))?;
                out.write_all(&intruction_buff)?;
                out.seek(std::io::SeekFrom::Start(current_stream_pos))?;
            }
        }
    }

    // Sort imported relocation, by symbol index
    imported_relocations.sort_by(|lhs, rhs| {
        let lhs_symbol_idx = lhs.id();
        let rhs_symbol_idx = rhs.id();
        rhs_symbol_idx.cmp(&lhs_symbol_idx)
    });

    // Sort Export Symbol by Hash
    export_symbol_table.sort_by(|lhs, rhs| rhs.hash.unwrap().cmp(&lhs.hash.unwrap()));

    {
        // Write Export Symbol Table
        pad_to_alignment(&mut out, 4)?;
        header.export_table_offset = out.stream_position()? as u32;
        header.export_table_size = (export_symbol_table.len() * 16) as u32;

        let mut export_symbol_name_table: Vec<u8> = vec![];
        for export_symbol in &mut export_symbol_table {
            let export_elf_symbol =
                file.symbol_by_index(SymbolIndex(export_symbol.name_offset as usize)).unwrap();
            let export_elf_symbol_name = export_elf_symbol.name().unwrap();
            export_symbol.name_offset = export_symbol_name_table.len() as u32;
            export_symbol.to_writer(&mut out, Endian::Big)?;

            export_symbol_name_table.extend_from_slice(export_elf_symbol_name.as_bytes());
            export_symbol_name_table.push(0u8); // '\0'
        }

        // Write Export Symbol Name Table
        pad_to_alignment(&mut out, 4)?;
        header.export_table_name_offset = out.stream_position()? as u32;
        out.write_all(&export_symbol_name_table)?;
    }

    {
        // Write Imported Symbol Relocation
        pad_to_alignment(&mut out, 4)?;
        header.external_rel_offset = out.stream_position()? as u32;
        header.external_rel_size = (imported_relocations.len() * 12) as u32;

        for reloc in &imported_relocations {
            reloc.to_writer(&mut out, Endian::Big)?;
        }
    }

    {
        pad_to_alignment(&mut out, 4)?;
        header.import_table_offset = out.stream_position()? as u32;
        header.import_table_size = (import_symbol_table.len() * 12) as u32;

        let mut import_symbol_name_table: Vec<u8> = vec![];

        for (import_symbol_idx, import_symbol) in import_symbol_table.iter_mut().enumerate() {
            let import_elf_symbol_idx = import_symbol.name_offset as usize;
            let import_elf_symbol =
                file.symbol_by_index(SymbolIndex(import_elf_symbol_idx)).unwrap();
            let import_elf_symbol_name = import_elf_symbol.name().unwrap();
            import_symbol.name_offset = import_symbol_name_table.len() as u32;

            // Gather the index of the first relocation that utilize this symbol
            let first_relocation_offset = imported_relocations
                .iter()
                .position(|r| r.id() == import_symbol_idx as u32)
                .map(|idx| idx * 12)
                .unwrap_or(usize::MAX) as u32;
            import_symbol.section_index = first_relocation_offset;
            import_symbol.to_writer(&mut out, Endian::Big)?;

            import_symbol_name_table.extend_from_slice(import_elf_symbol_name.as_bytes());
            import_symbol_name_table.push(0u8); // '\0'
        }

        // Write Export Symbol Name Table
        pad_to_alignment(&mut out, 4)?;
        header.import_table_name_offset = out.stream_position()? as u32;
        out.write_all(&import_symbol_name_table)?;
    }

    {
        // Write Internal Relocation Table
        pad_to_alignment(&mut out, 4)?;
        header.internal_rel_offset = out.stream_position()? as u32;
        header.internal_rel_size = (exported_relocations.len() * 12) as u32;

        for reloc in &exported_relocations {
            reloc.to_writer(&mut out, Endian::Big)?;
        }
    }

    pad_to_alignment(&mut out, 32)?;
    out.seek(std::io::SeekFrom::Start(0))?;
    header.to_writer(&mut out, Endian::Big)?;

    Ok(())
}
