use std::{ time::UNIX_EPOCH };

use anyhow::{ensure, Result};
use argp::FromArgs;
use chrono::FixedOffset;
use object::read::pe::PeFile32;
use typed_path::Utf8NativePathBuf;

use crate::{
    analysis::{cfa::{AnalyzerState}, pass::{AnalysisPass, FindSaveRestSledsXbox}}, 
    util::{
        path::native_path,
        xex::{extract_exe, process_xex, XexCompression, XexEncryption, XexInfo}
    }
};
use crate::analysis::objects::detect_strings;
use crate::analysis::objects::{detect_objects, detect_strings};
use crate::analysis::tracker::Tracker;
use crate::util::asm::write_asm;
use crate::util::config::write_symbols_file;
use crate::util::file::buf_writer;
use crate::util::xex::list_exe_sections;

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing Xex files.
#[argp(subcommand, name = "xex")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Disasm(DisasmArgs),
    Extract(ExtractArgs),
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles an Xex file.
#[argp(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    xex_file: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output file (.o) or directory (.elf)
    out: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts an exe from an Xex file.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    xex_file: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output file
    exe_file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about an Xex file.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    input: Utf8NativePathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
        SubCommand::Info(c_args) => info(c_args),
    }
}

// references:
// https://github.com/zeroKilo/XEXLoaderWV/blob/master/XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java#L120
// https://github.com/emoose/idaxex/blob/5b7de7b964e67fc049db0c61e4cba5d13ee69cec/formats/xex.hpp

fn extract(args: ExtractArgs) -> Result<()> {
    // validate that our input is an .xex
    let xex_ext = args.xex_file.extension();
    ensure!(xex_ext.is_some() && xex_ext.unwrap() == "xex", "Need to provide a valid input xex!");
    // and our output is an .exe
    let exe_ext = args.exe_file.extension();
    ensure!(exe_ext.is_some() && exe_ext.unwrap() == "exe", "Need to provide a valid output exe path!");
    // then, grab the exe
    let exe_bytes = extract_exe(&args.xex_file)?;
    // ...and write it to the desired output path
    std::fs::write(args.exe_file, exe_bytes)?;
    Ok(())
}

// look at dol info function too!
// dol load_analyze_dol as well
fn disasm(args: DisasmArgs) -> Result<()> {
    log::info!("Loading {}", args.xex_file);

    // extract_exe(&args.xex_file);

    // step 1. process xex, and return an ObjInfo
    let mut obj = process_xex(&args.xex_file)?;
    
    let mut state = AnalyzerState::default();

    // step 2. find common functions (save/restore reg funcs, XAPI calls)
    // rename the save/restore gpr/fpr funcs that were previously found in pdata
    FindSaveRestSledsXbox::execute(&mut state, &obj)?;

    state.detect_functions(&obj)?;
    log::info!(
        "Discovered {} functions",
        state.functions.iter().filter(|(_, i)| i.end.is_some()).count()
    );
    // give each found function a symbol
    state.apply(&mut obj)?;

    println!("Checking for relocatable targets...");
    // look at dol's split_write_obj
    let mut tracker = Tracker::new(&obj);
    // TODO: don't process imps
    tracker.process(&obj)?;

    println!("Applying relocatable targets...");
    tracker.apply(&mut obj, true)?;

    println!("Detecting objects");
    detect_objects(&mut obj)?;

    println!("Detecting strings");
    detect_strings(&mut obj)?;

    println!("Writing asm");
    // let mut w = buf_writer(&args.out)?;
    // write_asm(&mut w, &obj)?;
    // w.flush()?;

    write_symbols_file(&args.out, &obj, None)?;

    Ok(())
}

// fn file_stem_from_unit(str: &str) -> String {
//     let str = str.strip_suffix(ASM_SUFFIX).unwrap_or(str);
//     let str = str.strip_prefix("C:").unwrap_or(str);
//     let str = str.strip_prefix("D:").unwrap_or(str);
//     let str = str
//         .strip_suffix(".c")
//         .or_else(|| str.strip_suffix(".cp"))
//         .or_else(|| str.strip_suffix(".cpp"))
//         .or_else(|| str.strip_suffix(".s"))
//         .or_else(|| str.strip_suffix(".o"))
//         .unwrap_or(str);
//     let str = str.replace('\\', "/");
//     str.strip_prefix('/').unwrap_or(&str).to_string()
// }

// const ASM_SUFFIX: &str = " (asm)";

// // fn fixup(args: FixupArgs) -> Result<()> {
// //     let obj = process_elf(&args.in_file)?;
// //     let out = write_elf(&obj)?;
// //     fs::write(&args.out_file, &out).context("Failed to create output file")?;
// //     Ok(())
// // }

// fn fixup(args: FixupArgs) -> Result<()> {
//     let in_buf = fs::read(&args.in_file)
//         .with_context(|| format!("Failed to open input file: '{}'", args.in_file))?;
//     let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
//     let mut out_file =
//         object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());
//     out_file.flags =
//         FileFlags::Elf { os_abi: elf::ELFOSABI_SYSV, abi_version: 0, e_flags: elf::EF_PPC_EMB };
//     out_file.mangling = Mangling::None;

//     // Write file symbol first
//     let mut file_symbol_found = false;
//     for symbol in in_file.symbols() {
//         if symbol.kind() != SymbolKind::File {
//             continue;
//         }
//         let mut out_symbol = to_write_symbol(&symbol, &[])?;
//         out_symbol.name.append(&mut ASM_SUFFIX.as_bytes().to_vec());
//         out_file.add_symbol(out_symbol);
//         file_symbol_found = true;
//         break;
//     }
//     // Create a file symbol if not found
//     if !file_symbol_found {
//         let file_name = args
//             .in_file
//             .file_name()
//             .ok_or_else(|| anyhow!("'{}' is not a file path", args.in_file))?;
//         let mut name_bytes = file_name.as_bytes().to_vec();
//         name_bytes.append(&mut ASM_SUFFIX.as_bytes().to_vec());
//         out_file.add_symbol(object::write::Symbol {
//             name: name_bytes,
//             value: 0,
//             size: 0,
//             kind: SymbolKind::File,
//             scope: SymbolScope::Compilation,
//             weak: false,
//             section: object::write::SymbolSection::Absolute,
//             flags: SymbolFlags::None,
//         });
//     }

//     // Write section symbols & sections
//     let mut section_ids: Vec<Option<SectionId>> = vec![None /* ELF null section */];
//     for section in in_file.sections() {
//         // Skip empty sections or metadata sections
//         if section.size() == 0 || section.kind() == SectionKind::Metadata {
//             section_ids.push(None);
//             continue;
//         }
//         let section_id =
//             out_file.add_section(vec![], section.name_bytes()?.to_vec(), section.kind());
//         section_ids.push(Some(section_id));
//         let out_section = out_file.section_mut(section_id);
//         if section.kind() == SectionKind::UninitializedData {
//             out_section.append_bss(section.size(), section.align());
//         } else {
//             out_section.set_data(section.uncompressed_data()?.into_owned(), section.align());
//         }
//         if has_section_flags(section.flags(), elf::SHF_ALLOC)? {
//             // Generate section symbol
//             out_file.section_symbol(section_id);
//         }
//     }

//     // Write symbols
//     let mut symbol_ids: Vec<Option<SymbolId>> = vec![None /* ELF null symbol */];
//     let mut addr_to_sym: BTreeMap<SectionId, BTreeMap<u32, SymbolId>> = BTreeMap::new();
//     for symbol in in_file.symbols() {
//         // Skip section and file symbols, we wrote them above
//         if matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File) {
//             symbol_ids.push(None);
//             continue;
//         }
//         let out_symbol = to_write_symbol(&symbol, &section_ids)?;
//         let section_id = out_symbol.section.id();
//         let symbol_id = out_file.add_symbol(out_symbol);
//         symbol_ids.push(Some(symbol_id));
//         if symbol.size() != 0 {
//             if let Some(section_id) = section_id {
//                 match addr_to_sym.entry(section_id) {
//                     btree_map::Entry::Vacant(e) => e.insert(BTreeMap::new()),
//                     btree_map::Entry::Occupied(e) => e.into_mut(),
//                 }
//                 .insert(symbol.address() as u32, symbol_id);
//             }
//         }
//     }

//     // Write relocations
//     for section in in_file.sections() {
//         let section_id = match section_ids[section.index().0] {
//             Some(id) => id,
//             None => continue,
//         };
//         for (addr, reloc) in section.relocations() {
//             let mut target_symbol_id = match reloc.target() {
//                 RelocationTarget::Symbol(idx) => match symbol_ids[idx.0] {
//                     Some(id) => Ok(id),
//                     None => {
//                         let in_symbol = in_file.symbol_by_index(idx)?;
//                         match in_symbol.kind() {
//                             SymbolKind::Section => in_symbol
//                                 .section_index()
//                                 .ok_or_else(|| anyhow!("Section symbol without section"))
//                                 .and_then(|section_idx| {
//                                     section_ids[section_idx.0].ok_or_else(|| {
//                                         anyhow!("Relocation against stripped section")
//                                     })
//                                 })
//                                 .map(|section_idx| out_file.section_symbol(section_idx)),
//                             _ => Err(anyhow!("Missing symbol for relocation")),
//                         }
//                     }
//                 },
//                 RelocationTarget::Section(section_idx) => section_ids[section_idx.0]
//                     .ok_or_else(|| anyhow!("Relocation against stripped section"))
//                     .map(|section_id| out_file.section_symbol(section_id)),
//                 target => Err(anyhow!("Invalid relocation target '{target:?}'")),
//             }?;

//             // Attempt to replace section symbols with direct symbol references
//             let mut addend = reloc.addend();
//             let target_sym = out_file.symbol(target_symbol_id);
//             if target_sym.kind == SymbolKind::Section {
//                 if let Some(&new_symbol_id) = target_sym
//                     .section
//                     .id()
//                     .and_then(|id| addr_to_sym.get(&id))
//                     .and_then(|map| map.get(&(addend as u32)))
//                 {
//                     target_symbol_id = new_symbol_id;
//                     addend = 0;
//                 }
//             }

//             out_file.add_relocation(section_id, object::write::Relocation {
//                 offset: addr,
//                 symbol: target_symbol_id,
//                 addend,
//                 flags: reloc.flags(),
//             })?;
//         }
//     }

//     let mut out = buf_writer(&args.out_file)?;
//     out_file.write_stream(&mut out).map_err(|e| anyhow!("{e:?}"))?;
//     out.flush()?;
//     Ok(())
// }

// fn to_write_symbol_section(
//     section: SymbolSection,
//     section_ids: &[Option<SectionId>],
// ) -> Result<object::write::SymbolSection> {
//     match section {
//         SymbolSection::None => Ok(object::write::SymbolSection::None),
//         SymbolSection::Absolute => Ok(object::write::SymbolSection::Absolute),
//         SymbolSection::Common => Ok(object::write::SymbolSection::Common),
//         SymbolSection::Section(idx) => section_ids
//             .get(idx.0)
//             .and_then(|&opt| opt)
//             .map(object::write::SymbolSection::Section)
//             .ok_or_else(|| anyhow!("Missing symbol section")),
//         _ => Ok(object::write::SymbolSection::Undefined),
//     }
// }

// fn to_write_symbol_flags(
//     flags: SymbolFlags<SectionIndex, SymbolIndex>,
// ) -> Result<SymbolFlags<SectionId, SymbolId>> {
//     match flags {
//         SymbolFlags::Elf { st_info, st_other } => Ok(SymbolFlags::Elf { st_info, st_other }),
//         SymbolFlags::None => Ok(SymbolFlags::None),
//         _ => Err(anyhow!("Unexpected symbol flags")),
//     }
// }

// fn to_write_symbol(
//     symbol: &object::read::Symbol,
//     section_ids: &[Option<SectionId>],
// ) -> Result<object::write::Symbol> {
//     Ok(object::write::Symbol {
//         name: symbol.name_bytes()?.to_vec(),
//         value: symbol.address(),
//         size: symbol.size(),
//         kind: symbol.kind(),
//         scope: symbol.scope(),
//         weak: symbol.is_weak(),
//         section: to_write_symbol_section(symbol.section(), section_ids)?,
//         flags: to_write_symbol_flags(symbol.flags())?,
//     })
// }

// fn has_section_flags(flags: SectionFlags, flag: u32) -> Result<bool> {
//     match flags {
//         SectionFlags::Elf { sh_flags } => Ok(sh_flags & flag as u64 == flag as u64),
//         _ => Err(anyhow!("Unexpected section flags")),
//     }
// }

// fn signatures(args: SignaturesArgs) -> Result<()> {
//     // Process response files (starting with '@')
//     let files = process_rsp(&args.files)?;

//     let mut signatures: HashMap<String, FunctionSignature> = HashMap::new();
//     for path in files {
//         log::info!("Processing {}", path);
//         let signature = match generate_signature(&path, &args.symbol) {
//             Ok(Some(signature)) => signature,
//             Ok(None) => continue,
//             Err(e) => {
//                 eprintln!("Failed: {e:?}");
//                 continue;
//             }
//         };
//         log::info!("Comparing hash {}", signature.hash);
//         if let Some(existing) = signatures.get_mut(&signature.hash) {
//             compare_signature(existing, &signature)?;
//         } else {
//             signatures.insert(signature.hash.clone(), signature);
//         }
//     }
//     let mut signatures = signatures.into_values().collect::<Vec<FunctionSignature>>();
//     log::info!("{} unique signatures", signatures.len());
//     signatures.sort_by_key(|s| s.signature.len());
//     let mut out = buf_writer(&args.out_file)?;
//     serde_yaml::to_writer(&mut out, &signatures)?;
//     out.flush()?;
//     Ok(())
// }

// const MODULE_FLAGS: [&str; 8] = [ "Title Module", "Exports To Title", "System Debugger", "DLL Module", "Module Patch", "Patch Full", "Patch Delta", "User Mode" ];

fn info(args: InfoArgs) -> Result<()> {
    let xex = XexInfo::from_file(&args.input)?;
    println!("Jeff: Retrieving Xex info...");
    println!("shoutouts go to xorloser for the original XexTool!\n");

    println!("Xex Info:");
    println!("  {}", if xex.is_dev_kit { "Devkit" } else { "Retail"} );
    let bff = xex.opt_header_data.base_file_format.as_ref().unwrap();
    println!("  {}", if bff.compression == XexCompression::Compressed { "Compressed" } else { "Uncompressed"} );
    println!("  {}", if bff.encryption == XexEncryption::No { "Unencrypted" } else { "Encrypted"} );
    println!("");

    println!("Basefile Info:");
    println!("  Original PE Name: {}", xex.opt_header_data.original_name);
    println!("  Load address: 0x{:08X}", xex.opt_header_data.image_base);
    println!("  Entry point: 0x{:08X}", xex.opt_header_data.entry_point);
    print!("  File time: 0x{:08X} - ", xex.opt_header_data.file_timestamp);
    // formatting in EST because EST is the superior timezone and i will not hear otherwise
    let dur = std::time::Duration::from_secs(xex.opt_header_data.file_timestamp as u64);
    let datetime = chrono::DateTime::<chrono::Utc>::from(UNIX_EPOCH + dur);
    let est = FixedOffset::west_opt(5 * 3600).unwrap();
    let dt_est = datetime.with_timezone(&est);
    println!("{}", dt_est.format("%a %b %d %H:%M:%S %Y"));
    println!("");

    println!("Static Libraries:");
    let mut idx = 1;
    for lib in xex.opt_header_data.static_libs {
        println!("  {}. {}: v{}.{}.{}.{}", idx, lib.name, lib.major, lib.minor, lib.build, lib.qfe);
        idx += 1;
    }
    println!("");

    // TODO: import libraries
    list_exe_sections(&PeFile32::parse(&*xex.exe_bytes).expect("Failed to parse object file"));

    Ok(())
}
