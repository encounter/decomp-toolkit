use std::{
    collections::{btree_map, BTreeMap},
    io::{stdout, Cursor, Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use argp::FromArgs;
use object::{elf, Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, Section};

use crate::util::{
    dwarf::{
        process_address, process_type, process_variable_location, read_debug_section, type_string,
        ud_type, ud_type_def, ud_type_string, AttributeKind, TagKind,
    },
    file::{buf_writer, map_file},
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DWARF 1.1 information.
#[argp(subcommand, name = "dwarf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Dump(DumpArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Dumps DWARF 1.1 info from an object or archive.
#[argp(subcommand, name = "dump")]
pub struct DumpArgs {
    #[argp(positional)]
    /// Input object. (ELF or archive)
    in_file: PathBuf,
    #[argp(option, short = 'o')]
    /// Output file. (Or directory, for archive)
    out: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Dump(c_args) => dump(c_args),
    }
}

fn dump(args: DumpArgs) -> Result<()> {
    let file = map_file(&args.in_file)?;
    let buf = file.as_slice();
    if buf.starts_with(b"!<arch>\n") {
        let mut archive = ar::Archive::new(buf);
        while let Some(result) = archive.next_entry() {
            let mut e = match result {
                Ok(e) => e,
                Err(e) => bail!("Failed to read archive entry: {:?}", e),
            };
            let name = String::from_utf8_lossy(e.header().identifier()).to_string();
            let mut data = vec![0u8; e.header().size() as usize];
            e.read_exact(&mut data)?;
            let obj_file = object::read::File::parse(&*data)?;
            let debug_section = match obj_file.section_by_name(".debug") {
                Some(section) => {
                    log::info!("Processing '{}'", name);
                    section
                }
                None => {
                    log::warn!("Object '{}' missing .debug section", name);
                    continue;
                }
            };
            if let Some(out_path) = &args.out {
                // TODO make a basename method
                let name = name.trim_start_matches("D:").replace('\\', "/");
                let name = name.rsplit_once('/').map(|(_, b)| b).unwrap_or(&name);
                let file_path = out_path.join(format!("{}.txt", name));
                let mut file = buf_writer(file_path)?;
                dump_debug_section(&mut file, &obj_file, debug_section)?;
                file.flush()?;
            } else {
                println!("\nFile {}:", name);
                dump_debug_section(&mut stdout(), &obj_file, debug_section)?;
            }
        }
    } else {
        let obj_file = object::read::File::parse(buf)?;
        let debug_section = obj_file
            .section_by_name(".debug")
            .ok_or_else(|| anyhow!("Failed to locate .debug section"))?;
        if let Some(out_path) = &args.out {
            let mut file = buf_writer(out_path)?;
            dump_debug_section(&mut file, &obj_file, debug_section)?;
            file.flush()?;
        } else {
            dump_debug_section(&mut stdout(), &obj_file, debug_section)?;
        }
    }
    Ok(())
}

fn dump_debug_section<W: Write>(
    w: &mut W,
    obj_file: &object::File<'_>,
    debug_section: Section,
) -> Result<()> {
    let mut data = debug_section.uncompressed_data()?.into_owned();

    // Apply relocations to data
    for (addr, reloc) in debug_section.relocations() {
        match reloc.kind() {
            RelocationKind::Absolute | RelocationKind::Elf(elf::R_PPC_UADDR32) => {
                let target = match reloc.target() {
                    RelocationTarget::Symbol(symbol_idx) => {
                        let symbol = obj_file.symbol_by_index(symbol_idx)?;
                        (symbol.address() as i64 + reloc.addend()) as u32
                    }
                    _ => bail!("Invalid .debug relocation target"),
                };
                data[addr as usize..addr as usize + 4].copy_from_slice(&target.to_be_bytes());
            }
            RelocationKind::Elf(elf::R_PPC_NONE) => {}
            _ => bail!("Unhandled .debug relocation type {:?}", reloc.kind()),
        }
    }

    let mut reader = Cursor::new(&*data);
    let tags = read_debug_section(&mut reader)?;

    for (&addr, tag) in &tags {
        log::debug!("{}: {:?}", addr, tag);
    }

    let mut units = Vec::<String>::new();
    if let Some((_, mut tag)) = tags.first_key_value() {
        loop {
            match tag.kind {
                TagKind::CompileUnit => {
                    let unit = tag
                        .string_attribute(AttributeKind::Name)
                        .ok_or_else(|| anyhow!("CompileUnit without name {:?}", tag))?;
                    if units.contains(unit) {
                        log::warn!("Duplicate unit '{}'", unit);
                    } else {
                        units.push(unit.clone());
                    }

                    let children = tag.children(&tags);
                    let mut typedefs = BTreeMap::<u32, Vec<u32>>::new();
                    for child in children {
                        match child.kind {
                            TagKind::GlobalSubroutine | TagKind::Subroutine => {
                                let _is_prototyped =
                                    child.string_attribute(AttributeKind::Prototyped).is_some();
                                if let (Some(_hi), Some(_lo)) = (
                                    child.address_attribute(AttributeKind::HighPc),
                                    child.address_attribute(AttributeKind::LowPc),
                                ) {}
                                let name = child
                                    .string_attribute(AttributeKind::Name)
                                    .ok_or_else(|| anyhow!("Subroutine without name"))?;
                                let udt = ud_type(&tags, child)?;
                                let ts = ud_type_string(&tags, &typedefs, &udt)?;
                                writeln!(w, "{} {}{} {{", ts.prefix, name, ts.suffix)?;
                                for tag in child.children(&tags) {
                                    match tag.kind {
                                        TagKind::LocalVariable => {}
                                        _ => continue,
                                    }
                                    let type_attr = tag.type_attribute().ok_or_else(|| {
                                        anyhow!("LocalVariable without type attr")
                                    })?;
                                    let var_type = process_type(type_attr)?;
                                    let ts = type_string(&tags, &typedefs, &var_type)?;
                                    let name = tag
                                        .string_attribute(AttributeKind::Name)
                                        .ok_or_else(|| anyhow!("LocalVariable without name"))?;
                                    write!(w, "\t{} {}{};", ts.prefix, name, ts.suffix)?;
                                    if let Some(location) =
                                        tag.block_attribute(AttributeKind::Location)
                                    {
                                        if !location.is_empty() {
                                            write!(
                                                w,
                                                " // {}",
                                                process_variable_location(location)?
                                            )?;
                                        }
                                    }
                                    writeln!(w)?;
                                }
                                writeln!(w, "}}")?;
                            }
                            TagKind::Typedef => {
                                let name = child
                                    .string_attribute(AttributeKind::Name)
                                    .ok_or_else(|| anyhow!("Typedef without name"))?;
                                let attr = child
                                    .type_attribute()
                                    .ok_or_else(|| anyhow!("Typedef without type attribute"))?;
                                let t = process_type(attr)?;
                                let ts = type_string(&tags, &typedefs, &t)?;
                                writeln!(w, "typedef {} {}{};", ts.prefix, name, ts.suffix)?;

                                // TODO fundamental typedefs?
                                if let Some(ud_type_ref) =
                                    child.reference_attribute(AttributeKind::UserDefType)
                                {
                                    match typedefs.entry(ud_type_ref) {
                                        btree_map::Entry::Vacant(e) => {
                                            e.insert(vec![child.key]);
                                        }
                                        btree_map::Entry::Occupied(e) => {
                                            e.into_mut().push(child.key);
                                        }
                                    }
                                }
                            }
                            TagKind::GlobalVariable | TagKind::LocalVariable => {
                                let name = child
                                    .string_attribute(AttributeKind::Name)
                                    .ok_or_else(|| anyhow!("Variable without name"))?;
                                let address = if let Some(location) =
                                    child.block_attribute(AttributeKind::Location)
                                {
                                    Some(process_address(location)?)
                                } else {
                                    None
                                };
                                if let Some(type_attr) = child.type_attribute() {
                                    let var_type = process_type(type_attr)?;
                                    // log::info!("{:?}", var_type);
                                    // if let TypeKind::UserDefined(key) = var_type.kind {
                                    //     let ud_tag = tags
                                    //         .get(&key)
                                    //         .ok_or_else(|| anyhow!("Invalid UD type ref"))?;
                                    //     let ud_type = ud_type(&tags, ud_tag)?;
                                    //     log::info!("{:?}", ud_type);
                                    // }
                                    let ts = type_string(&tags, &typedefs, &var_type)?;
                                    let st = if child.kind == TagKind::LocalVariable {
                                        "static "
                                    } else {
                                        ""
                                    };
                                    let address_str = match address {
                                        Some(addr) => format!(" : {:#010X}", addr),
                                        None => String::new(),
                                    };
                                    let size = var_type.size(&tags)?;
                                    writeln!(
                                        w,
                                        "{}{} {}{}{}; // size: {:#X}",
                                        st, ts.prefix, name, ts.suffix, address_str, size,
                                    )?;
                                }
                            }
                            TagKind::StructureType
                            | TagKind::ArrayType
                            | TagKind::EnumerationType
                            | TagKind::UnionType
                            | TagKind::ClassType
                            | TagKind::SubroutineType => {
                                let udt = ud_type(&tags, child)?;
                                if child.string_attribute(AttributeKind::Name).is_some() {
                                    writeln!(w, "{}", ud_type_def(&tags, &typedefs, &udt)?)?;
                                } else {
                                    // log::warn!("No name for tag: {:?}", child);
                                }
                            }
                            _ => {
                                log::warn!("Unhandled CompileUnit child {:?}", child.kind);
                            }
                        }
                    }
                    // println!("Children: {:?}", children.iter().map(|c| c.kind).collect::<Vec<TagKind>>());
                }
                _ => {
                    log::warn!("Expected CompileUnit, got {:?}", tag.kind);
                    break;
                }
            }
            if let Some(next) = tag.next_sibling(&tags) {
                tag = next;
            } else {
                break;
            }
        }
    }
    // log::info!("Link order:");
    // for x in units {
    //     log::info!("{}", x);
    // }
    Ok(())
}
