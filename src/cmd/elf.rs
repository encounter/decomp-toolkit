use std::{
    collections::{btree_map, btree_map::Entry, hash_map, BTreeMap, HashMap, HashSet},
    fs,
    fs::{DirBuilder, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use argh::FromArgs;
use object::{
    write::{Mangling, SectionId, SymbolId},
    Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SectionFlags,
    SectionIndex, SectionKind, SymbolFlags, SymbolKind, SymbolScope, SymbolSection,
};
use ppc750cl::Ins;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::util::{
    asm::write_asm,
    config::write_symbols,
    elf::{process_elf, write_elf},
    obj::{ObjKind, ObjReloc, ObjRelocKind, ObjSymbolFlagSet, ObjSymbolKind},
    sigs::{check_signature, compare_signature, generate_signature, FunctionSignature},
    split::split_obj,
    tracker::Tracker,
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
    Config(ConfigArgs),
    Disasm(DisasmArgs),
    Fixup(FixupArgs),
    Signatures(SignaturesArgs),
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

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generates configuration files from an executable ELF.
#[argh(subcommand, name = "config")]
pub struct ConfigArgs {
    #[argh(positional)]
    /// input file
    in_file: PathBuf,
    #[argh(positional)]
    /// output directory
    out_dir: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Builds function signatures from an ELF file.
#[argh(subcommand, name = "sigs")]
pub struct SignaturesArgs {
    #[argh(positional)]
    /// input file(s)
    files: Vec<PathBuf>,
    #[argh(option, short = 's')]
    /// symbol name
    symbol: String,
    #[argh(option, short = 'o')]
    /// output yml
    out_file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Config(c_args) => config(c_args),
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Fixup(c_args) => fixup(c_args),
        SubCommand::Split(c_args) => split(c_args),
        SubCommand::Signatures(c_args) => signatures(c_args),
    }
}

fn config(args: ConfigArgs) -> Result<()> {
    log::info!("Loading {}", args.in_file.display());
    let mut obj = process_elf(&args.in_file)?;

    DirBuilder::new().recursive(true).create(&args.out_dir)?;
    let symbols_path = args.out_dir.join("symbols.txt");
    let mut symbols_writer = BufWriter::new(
        File::create(&symbols_path)
            .with_context(|| format!("Failed to create '{}'", symbols_path.display()))?,
    );
    write_symbols(&mut symbols_writer, &obj)?;

    Ok(())
}

fn disasm(args: DisasmArgs) -> Result<()> {
    log::info!("Loading {}", args.elf_file.display());
    let obj = process_elf(&args.elf_file)?;
    match obj.kind {
        ObjKind::Executable => {
            log::info!("Splitting {} objects", obj.link_order.len());
            let split_objs = split_obj(&obj)?;

            let asm_dir = args.out.join("asm");
            let include_dir = args.out.join("include");
            DirBuilder::new().recursive(true).create(&include_dir)?;
            fs::write(include_dir.join("macros.inc"), include_bytes!("../../assets/macros.inc"))?;

            let mut files_out = File::create(args.out.join("link_order.txt"))?;
            for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
                let out_path = asm_dir.join(file_name_from_unit(unit, ".s"));
                log::info!("Writing {}", out_path.display());

                if let Some(parent) = out_path.parent() {
                    DirBuilder::new().recursive(true).create(parent)?;
                }
                let mut w = BufWriter::new(File::create(out_path)?);
                write_asm(&mut w, split_obj)?;
                w.flush()?;

                writeln!(files_out, "{}", file_name_from_unit(unit, ".o"))?;
            }
            files_out.flush()?;
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
    ensure!(obj.kind == ObjKind::Executable, "Can only split executable objects");

    let mut file_map = HashMap::<String, Vec<u8>>::new();

    let split_objs = split_obj(&obj)?;
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj)?;
        match file_map.entry(unit.clone()) {
            hash_map::Entry::Vacant(e) => e.insert(out_obj),
            hash_map::Entry::Occupied(_) => bail!("Duplicate file {unit}"),
        };
    }

    let mut rsp_file = BufWriter::new(File::create("rsp")?);
    for unit in &obj.link_order {
        let object = file_map
            .get(unit)
            .ok_or_else(|| anyhow!("Failed to find object file for unit '{unit}'"))?;
        let out_path = args.out_dir.join(file_name_from_unit(unit, ".o"));
        writeln!(rsp_file, "{}", out_path.display())?;
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        let mut file = File::create(&out_path)
            .with_context(|| format!("Failed to create '{}'", out_path.display()))?;
        file.write_all(object)?;
        file.flush()?;
    }
    rsp_file.flush()?;
    Ok(())
}

fn file_name_from_unit(str: &str, suffix: &str) -> String {
    let str = str.strip_suffix(ASM_SUFFIX).unwrap_or(str);
    let str = str.strip_prefix("C:").unwrap_or(str);
    let str = str.strip_prefix("D:").unwrap_or(str);
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
    let in_buf = fs::read(&args.in_file)
        .with_context(|| format!("Failed to open input file: '{}'", args.in_file.display()))?;
    let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
    let mut out_file =
        object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());
    out_file.set_mangling(Mangling::None);

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
        let file_name = args
            .in_file
            .file_name()
            .ok_or_else(|| anyhow!("'{}' is not a file path", args.in_file.display()))?;
        let file_name = file_name
            .to_str()
            .ok_or_else(|| anyhow!("'{}' is not valid UTF-8", file_name.to_string_lossy()))?;
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
                                .ok_or_else(|| anyhow!("Section symbol without section"))
                                .and_then(|section_idx| {
                                    section_ids[section_idx.0].ok_or_else(|| {
                                        anyhow!("Relocation against stripped section")
                                    })
                                })
                                .map(|section_idx| out_file.section_symbol(section_idx)),
                            _ => Err(anyhow!("Missing symbol for relocation")),
                        }
                    }
                },
                RelocationTarget::Section(section_idx) => section_ids[section_idx.0]
                    .ok_or_else(|| anyhow!("Relocation against stripped section"))
                    .map(|section_id| out_file.section_symbol(section_id)),
                target => Err(anyhow!("Invalid relocation target '{target:?}'")),
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
                RelocationKind::Absolute => RelocationKind::Elf(if addr & 3 == 0 {
                    object::elf::R_PPC_ADDR32
                } else {
                    object::elf::R_PPC_UADDR32
                }),
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

    let mut out =
        BufWriter::new(File::create(&args.out_file).with_context(|| {
            format!("Failed to create output file: '{}'", args.out_file.display())
        })?);
    out_file.write_stream(&mut out).map_err(|e| anyhow!("{e:?}"))?;
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
            .ok_or_else(|| anyhow!("Missing symbol section")),
        _ => Ok(object::write::SymbolSection::Undefined),
    }
}

fn to_write_symbol_flags(flags: SymbolFlags<SectionIndex>) -> Result<SymbolFlags<SectionId>> {
    match flags {
        SymbolFlags::Elf { st_info, st_other } => Ok(SymbolFlags::Elf { st_info, st_other }),
        SymbolFlags::None => Ok(SymbolFlags::None),
        _ => Err(anyhow!("Unexpected symbol flags")),
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
        _ => Err(anyhow!("Unexpected section flags")),
    }
}

fn signatures(args: SignaturesArgs) -> Result<()> {
    // Process response files (starting with '@')
    let mut files = Vec::with_capacity(args.files.len());
    for path in args.files {
        let path_str =
            path.to_str().ok_or_else(|| anyhow!("'{}' is not valid UTF-8", path.display()))?;
        match path_str.strip_prefix('@') {
            Some(rsp_file) => {
                let reader = BufReader::new(
                    File::open(rsp_file)
                        .with_context(|| format!("Failed to open file '{rsp_file}'"))?,
                );
                for result in reader.lines() {
                    let line = result?;
                    if !line.is_empty() {
                        files.push(PathBuf::from(line));
                    }
                }
            }
            None => {
                files.push(path);
            }
        }
    }

    let mut signatures: HashMap<Vec<u8>, FunctionSignature> = HashMap::new();
    for path in files {
        log::info!("Processing {}", path.display());
        let (data, signature) = match generate_signature(&path, &args.symbol) {
            Ok(Some(signature)) => signature,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("Failed: {:?}", e);
                continue;
            }
        };
        log::info!("Comparing hash {}", signature.hash);
        if let Some((_, existing)) = signatures.iter_mut().find(|(a, b)| *a == &data) {
            compare_signature(existing, &signature)?;
        } else {
            signatures.insert(data, signature);
        }
    }
    let mut signatures = signatures.into_iter().map(|(a, b)| b).collect::<Vec<FunctionSignature>>();
    log::info!("{} unique signatures", signatures.len());
    signatures.sort_by_key(|s| s.signature.len());
    let out =
        BufWriter::new(File::create(&args.out_file).with_context(|| {
            format!("Failed to create output file '{}'", args.out_file.display())
        })?);
    serde_yaml::to_writer(out, &signatures)?;
    Ok(())
}
