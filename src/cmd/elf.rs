use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    fs,
    fs::DirBuilder,
    io::{Cursor, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use argp::FromArgs;
use objdiff_core::obj::split_meta::{SplitMeta, SPLITMETA_SECTION};
use object::{
    elf,
    write::{Mangling, SectionId, SymbolId},
    FileFlags, Object, ObjectSection, ObjectSymbol, 
    RelocationTarget, SectionFlags, SectionIndex, SectionKind, SymbolFlags, SymbolIndex,
    SymbolKind, SymbolScope, SymbolSection,
};

use crate::{
    obj::ObjKind,
    util::{
        asm::write_asm,
        comment::{CommentSym, MWComment},
        config::{write_splits_file, write_symbols_file},
        elf::{process_elf, write_elf},
        file::{buf_writer, process_rsp},
        reader::{Endian, FromReader},
        signatures::{compare_signature, generate_signature, FunctionSignature},
        split::split_obj,
        IntoCow, ToCow,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing ELF files.
#[argp(subcommand, name = "elf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Config(ConfigArgs),
    Disasm(DisasmArgs),
    Fixup(FixupArgs),
    Signatures(SignaturesArgs),
    Split(SplitArgs),
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles an ELF file.
#[argp(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argp(positional)]
    /// input file
    elf_file: PathBuf,
    #[argp(positional)]
    /// output file (.o) or directory (.elf)
    out: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Fixes issues with GNU assembler built object files.
#[argp(subcommand, name = "fixup")]
pub struct FixupArgs {
    #[argp(positional)]
    /// input file
    in_file: PathBuf,
    #[argp(positional)]
    /// output file
    out_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits an executable ELF into relocatable objects.
#[argp(subcommand, name = "split")]
pub struct SplitArgs {
    #[argp(positional)]
    /// input file
    in_file: PathBuf,
    #[argp(positional)]
    /// output directory
    out_dir: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Generates configuration files from an executable ELF.
#[argp(subcommand, name = "config")]
pub struct ConfigArgs {
    #[argp(positional)]
    /// input file
    in_file: PathBuf,
    #[argp(positional)]
    /// output directory
    out_dir: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Builds function signatures from an ELF file.
#[argp(subcommand, name = "sigs")]
pub struct SignaturesArgs {
    #[argp(positional)]
    /// input file(s)
    files: Vec<PathBuf>,
    #[argp(option, short = 's')]
    /// symbol name
    symbol: String,
    #[argp(option, short = 'o')]
    /// output yml
    out_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about an ELF file.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional)]
    /// input file
    input: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Config(c_args) => config(c_args),
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Fixup(c_args) => fixup(c_args),
        SubCommand::Split(c_args) => split(c_args),
        SubCommand::Signatures(c_args) => signatures(c_args),
        SubCommand::Info(c_args) => info(c_args),
    }
}

fn config(args: ConfigArgs) -> Result<()> {
    log::info!("Loading {}", args.in_file.display());
    let obj = process_elf(&args.in_file)?;

    DirBuilder::new().recursive(true).create(&args.out_dir)?;
    write_symbols_file(args.out_dir.join("symbols.txt"), &obj, None)?;
    write_splits_file(args.out_dir.join("splits.txt"), &obj, false, None)?;
    Ok(())
}

fn disasm(args: DisasmArgs) -> Result<()> {
    log::info!("Loading {}", args.elf_file.display());
    let obj = process_elf(&args.elf_file)?;
    match obj.kind {
        ObjKind::Executable => {
            log::info!("Splitting {} objects", obj.link_order.len());
            let split_objs = split_obj(&obj, None)?;

            let asm_dir = args.out.join("asm");
            let include_dir = args.out.join("include");
            DirBuilder::new().recursive(true).create(&include_dir)?;
            fs::write(include_dir.join("macros.inc"), include_bytes!("../../assets/macros.inc"))?;

            let mut files_out = buf_writer(args.out.join("link_order.txt"))?;
            for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
                let out_path = asm_dir.join(file_name_from_unit(&unit.name, ".s"));
                log::info!("Writing {}", out_path.display());

                let mut w = buf_writer(out_path)?;
                write_asm(&mut w, split_obj)?;
                w.flush()?;

                writeln!(files_out, "{}", file_name_from_unit(&unit.name, ".o"))?;
            }
            files_out.flush()?;
        }
        ObjKind::Relocatable => {
            let mut w = buf_writer(args.out)?;
            write_asm(&mut w, &obj)?;
            w.flush()?;
        }
    }
    Ok(())
}

fn split(args: SplitArgs) -> Result<()> {
    let obj = process_elf(&args.in_file)?;
    ensure!(obj.kind == ObjKind::Executable, "Can only split executable objects");

    let mut file_map = HashMap::<String, Vec<u8>>::new();

    let split_objs = split_obj(&obj, None)?;
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj, false)?;
        match file_map.entry(unit.name.clone()) {
            hash_map::Entry::Vacant(e) => e.insert(out_obj),
            hash_map::Entry::Occupied(_) => bail!("Duplicate file {}", unit.name),
        };
    }

    let mut rsp_file = buf_writer("rsp")?;
    for unit in &obj.link_order {
        let object = file_map
            .get(&unit.name)
            .ok_or_else(|| anyhow!("Failed to find object file for unit '{}'", unit.name))?;
        let out_path = args.out_dir.join(file_name_from_unit(&unit.name, ".o"));
        writeln!(rsp_file, "{}", out_path.display())?;
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        fs::write(&out_path, object)
            .with_context(|| format!("Failed to write '{}'", out_path.display()))?;
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

// fn fixup(args: FixupArgs) -> Result<()> {
//     let obj = process_elf(&args.in_file)?;
//     let out = write_elf(&obj)?;
//     fs::write(&args.out_file, &out).context("Failed to create output file")?;
//     Ok(())
// }

fn fixup(args: FixupArgs) -> Result<()> {
    let in_buf = fs::read(&args.in_file)
        .with_context(|| format!("Failed to open input file: '{}'", args.in_file.display()))?;
    let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
    let mut out_file =
        object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());
    out_file.flags =
        FileFlags::Elf { os_abi: elf::ELFOSABI_SYSV, abi_version: 0, e_flags: elf::EF_PPC_EMB };
    out_file.mangling = Mangling::None;

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
        if has_section_flags(section.flags(), elf::SHF_ALLOC)? {
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

            out_file.add_relocation(section_id, object::write::Relocation {
                offset: addr,
                symbol: target_symbol_id,
                addend,
                flags: reloc.flags(),
            })?;
        }
    }

    let mut out = buf_writer(&args.out_file)?;
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

fn to_write_symbol_flags(
    flags: SymbolFlags<SectionIndex, SymbolIndex>,
) -> Result<SymbolFlags<SectionId, SymbolId>> {
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
    let files = process_rsp(&args.files)?;

    let mut signatures: HashMap<String, FunctionSignature> = HashMap::new();
    for path in files {
        log::info!("Processing {}", path.display());
        let signature = match generate_signature(&path, &args.symbol) {
            Ok(Some(signature)) => signature,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("Failed: {:?}", e);
                continue;
            }
        };
        log::info!("Comparing hash {}", signature.hash);
        if let Some(existing) = signatures.get_mut(&signature.hash) {
            compare_signature(existing, &signature)?;
        } else {
            signatures.insert(signature.hash.clone(), signature);
        }
    }
    let mut signatures = signatures.into_values().collect::<Vec<FunctionSignature>>();
    log::info!("{} unique signatures", signatures.len());
    signatures.sort_by_key(|s| s.signature.len());
    let mut out = buf_writer(&args.out_file)?;
    serde_yaml::to_writer(&mut out, &signatures)?;
    out.flush()?;
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let in_buf = fs::read(&args.input)
        .with_context(|| format!("Failed to open input file: '{}'", args.input.display()))?;
    let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;

    println!("ELF type: {:?}", in_file.kind());
    println!("Section count: {}", in_file.sections().count());
    println!("Symbol count: {}", in_file.symbols().count());
    println!(
        "Relocation count: {}",
        in_file.sections().map(|s| s.relocations().count()).sum::<usize>()
    );

    println!("\nSections:");
    println!(
        "{: >15} | {: <10} | {: <10} | {: <10} | {: <10}",
        "Name", "Type", "Size", "File Off", "Index"
    );
    for section in in_file.sections().skip(1) {
        let kind_str = match section.kind() {
            SectionKind::Text => "code".to_cow(),
            SectionKind::Data => "data".to_cow(),
            SectionKind::ReadOnlyData => "rodata".to_cow(),
            SectionKind::UninitializedData => "bss".to_cow(),
            SectionKind::Metadata => continue, // "metadata".to_cow()
            SectionKind::Other => "other".to_cow(),
            _ => format!("unknown: {:?}", section.kind()).into_cow(),
        };
        println!(
            "{: >15} | {: <10} | {: <#10X} | {: <#10X} | {: <10}",
            section.name()?,
            kind_str,
            section.size(),
            section.file_range().unwrap_or_default().0,
            section.index().0
        );
    }

    println!("\nSymbols:");
    println!("{: >15} | {: <10} | {: <10} | {: <10}", "Section", "Address", "Size", "Name");
    for symbol in in_file.symbols().filter(|s| s.is_definition()) {
        let section_str = if let Some(section) = symbol.section_index() {
            in_file.section_by_index(section)?.name()?.to_string().into_cow()
        } else {
            "ABS".to_cow()
        };
        let size_str = if symbol.section_index().is_none() {
            "ABS".to_cow()
        } else {
            format!("{:#X}", symbol.size()).into_cow()
        };
        println!(
            "{: >15} | {: <#10X} | {: <10} | {: <10}",
            section_str,
            symbol.address(),
            size_str,
            symbol.name()?
        );
    }

    if let Some(comment_section) = in_file.section_by_name(".comment") {
        let data = comment_section.uncompressed_data()?;
        if !data.is_empty() {
            let mut reader = Cursor::new(&*data);
            let header = MWComment::from_reader(&mut reader, Endian::Big)
                .context("While reading .comment section")?;
            println!("\nMetrowerks metadata (.comment):");
            println!("\tVersion: {}", header.version);
            println!(
                "\tCompiler version: {}.{}.{}.{}",
                header.compiler_version[0],
                header.compiler_version[1],
                header.compiler_version[2],
                header.compiler_version[3]
            );
            println!("\tPool data: {}", header.pool_data);
            println!("\tFloat: {:?}", header.float);
            println!(
                "\tProcessor: {}",
                if header.processor == 0x16 {
                    "Gekko".to_cow()
                } else {
                    format!("{:#X}", header.processor).into_cow()
                }
            );
            println!(
                "\tIncompatible return small structs: {}",
                header.incompatible_return_small_structs
            );
            println!(
                "\tIncompatible sfpe double params: {}",
                header.incompatible_sfpe_double_params
            );
            println!("\tUnsafe global reg vars: {}", header.unsafe_global_reg_vars);
            println!("\n{: >10} | {: <6} | {: <6} | {: <10}", "Align", "Vis", "Active", "Symbol");
            for symbol in in_file.symbols() {
                let comment_sym = CommentSym::from_reader(&mut reader, Endian::Big)?;
                if symbol.is_definition() {
                    println!(
                        "{: >10} | {: <#6X} | {: <#6X} | {: <10}",
                        comment_sym.align,
                        comment_sym.vis_flags,
                        comment_sym.active_flags,
                        symbol.name()?
                    );
                }
            }
            ensure!(
                data.len() - reader.position() as usize == 0,
                ".comment section data not fully read"
            );
        }
    }

    if let Some(split_meta_section) = in_file.section_by_name(SPLITMETA_SECTION) {
        let data = split_meta_section.uncompressed_data()?;
        if !data.is_empty() {
            let meta =
                SplitMeta::from_section(split_meta_section, in_file.endianness(), in_file.is_64())
                    .context("While reading .note.split section")?;
            println!("\nSplit metadata (.note.split):");
            if let Some(generator) = &meta.generator {
                println!("\tGenerator: {}", generator);
            }
            if let Some(module_name) = &meta.module_name {
                println!("\tModule name: {}", module_name);
            }
            if let Some(module_id) = meta.module_id {
                println!("\tModule ID: {}", module_id);
            }
            if let Some(virtual_addresses) = &meta.virtual_addresses {
                println!("\tVirtual addresses:");
                println!("\t{: >10} | {: <10}", "Addr", "Symbol");
                for (symbol, addr) in in_file.symbols().zip(virtual_addresses) {
                    if symbol.is_definition() {
                        println!("\t{: >10} | {: <10}", format!("{:#X}", addr), symbol.name()?);
                    }
                }
            }
        }
    }

    Ok(())
}
