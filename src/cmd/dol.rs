use std::{
    collections::{hash_map, BTreeMap, HashMap},
    fs,
    fs::{DirBuilder, File},
    io::{BufRead, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use argh::FromArgs;

use crate::{
    analysis::{
        cfa::AnalyzerState,
        objects::{detect_object_boundaries, detect_strings},
        pass::{AnalysisPass, FindSaveRestSleds, FindTRKInterruptVectorTable},
        signatures::{apply_signatures, apply_signatures_post},
        tracker::Tracker,
    },
    obj::{
        split::{split_obj, update_splits},
        ObjInfo, ObjRelocKind, ObjSectionKind, ObjSymbolKind,
    },
    util::{
        asm::write_asm,
        config::{apply_splits, parse_symbol_line, write_splits, write_symbols},
        dol::process_dol,
        elf::{process_elf, write_elf},
        file::{map_file, map_reader},
        lcf::{asm_path_for_unit, generate_ldscript, obj_path_for_unit},
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DOL files.
#[argh(subcommand, name = "dol")]
pub struct Args {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Split(SplitArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views DOL file information.
#[argh(subcommand, name = "info")]
pub struct InfoArgs {
    #[argh(positional)]
    /// DOL file
    dol_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits a DOL into relocatable objects.
#[argh(subcommand, name = "split")]
pub struct SplitArgs {
    #[argh(positional)]
    /// input file
    in_file: PathBuf,
    #[argh(positional)]
    /// output directory
    out_dir: PathBuf,
    #[argh(option, short = 's')]
    /// path to symbols file
    symbols_file: Option<PathBuf>,
    #[argh(option, short = 'p')]
    /// path to splits file
    splits_file: Option<PathBuf>,
    #[argh(option, short = 'e')]
    /// ELF file to validate against (debugging only)
    elf_file: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Split(c_args) => split(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let mut obj = process_dol(&args.dol_file)?;
    apply_signatures(&mut obj)?;

    let mut state = AnalyzerState::default();
    state.detect_functions(&obj)?;
    log::info!("Discovered {} functions", state.function_slices.len());

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    apply_signatures_post(&mut obj)?;

    println!("{}:", obj.name);
    println!("Entry point: {:#010X}", obj.entry);
    println!("\nSections:");
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Name", "Address", "Size", "File Off");
    for section in &obj.sections {
        println!(
            "\t{: >10} | {:#010X} | {: <#10X} | {: <#10X}",
            section.name, section.address, section.size, section.file_offset
        );
    }
    println!("\nDiscovered symbols:");
    println!("\t{: >23} | {: <10} | {: <10}", "Name", "Address", "Size");
    for (_, symbol) in obj.symbols.for_range(..) {
        if symbol.name.starts_with('@') || symbol.name.starts_with("fn_") {
            continue;
        }
        if symbol.size_known {
            println!("\t{: >23} | {:#010X} | {: <#10X}", symbol.name, symbol.address, symbol.size);
        } else {
            let size_str = if symbol.section.is_none() { "ABS" } else { "?" };
            println!("\t{: >23} | {:#010X} | {: <10}", symbol.name, symbol.address, size_str);
        }
    }
    println!("\n{} discovered functions from exception table", obj.known_functions.len());
    Ok(())
}

fn split(args: SplitArgs) -> Result<()> {
    log::info!("Loading {}", args.in_file.display());
    let mut obj = process_dol(&args.in_file)?;

    if let Some(splits_path) = &args.splits_file {
        if splits_path.is_file() {
            let map = map_file(splits_path)?;
            apply_splits(map_reader(&map), &mut obj)?;
        }
    }

    let mut state = AnalyzerState::default();

    if let Some(symbols_path) = &args.symbols_file {
        if symbols_path.is_file() {
            let map = map_file(symbols_path)?;
            for result in map_reader(&map).lines() {
                let line = match result {
                    Ok(line) => line,
                    Err(e) => bail!("Failed to process symbols file: {e:?}"),
                };
                if let Some(symbol) = parse_symbol_line(&line, &mut obj)? {
                    obj.add_symbol(symbol, true)?;
                }
            }
        }
    }

    // TODO move before symbols?
    log::info!("Performing signature analysis");
    apply_signatures(&mut obj)?;

    log::info!("Detecting function boundaries");
    state.detect_functions(&obj)?;
    log::info!("Discovered {} functions", state.function_slices.len());

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

    log::info!("Performing relocation analysis");
    let mut tracker = Tracker::new(&obj);
    tracker.process(&obj)?;

    log::info!("Applying relocations");
    tracker.apply(&mut obj, false)?;

    log::info!("Detecting object boundaries");
    detect_object_boundaries(&mut obj)?;

    log::info!("Detecting strings");
    detect_strings(&mut obj)?;

    if let Some(symbols_path) = &args.symbols_file {
        let mut symbols_writer = BufWriter::new(
            File::create(symbols_path)
                .with_context(|| format!("Failed to create '{}'", symbols_path.display()))?,
        );
        write_symbols(&mut symbols_writer, &obj)?;
    }

    if let Some(splits_path) = &args.splits_file {
        let mut splits_writer = BufWriter::new(
            File::create(splits_path)
                .with_context(|| format!("Failed to create '{}'", splits_path.display()))?,
        );
        write_splits(&mut splits_writer, &obj)?;
    }

    log::info!("Adjusting splits");
    update_splits(&mut obj)?;

    log::info!("Splitting {} objects", obj.link_order.len());
    let split_objs = split_obj(&obj)?;

    // Create out dirs
    let asm_dir = args.out_dir.join("asm");
    let include_dir = args.out_dir.join("include");
    let obj_dir = args.out_dir.clone();
    DirBuilder::new().recursive(true).create(&include_dir)?;
    fs::write(include_dir.join("macros.inc"), include_str!("../../assets/macros.inc"))?;

    log::info!("Writing object files");
    let mut file_map = HashMap::<String, Vec<u8>>::new();
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_obj = write_elf(split_obj)?;
        match file_map.entry(unit.clone()) {
            hash_map::Entry::Vacant(e) => e.insert(out_obj),
            hash_map::Entry::Occupied(_) => bail!("Duplicate file {unit}"),
        };
    }

    let mut rsp_file = BufWriter::new(File::create(args.out_dir.join("rsp"))?);
    for unit in &obj.link_order {
        let object = file_map
            .get(unit)
            .ok_or_else(|| anyhow!("Failed to find object file for unit '{unit}'"))?;
        let out_path = obj_dir.join(obj_path_for_unit(unit));
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

    // Generate ldscript.lcf
    fs::write(args.out_dir.join("ldscript.lcf"), generate_ldscript(&obj)?)?;

    log::info!("Writing disassembly");
    // let mut files_out = File::create(args.out_dir.join("build.ps1"))?;
    // writeln!(files_out, "$ErrorActionPreference = 'Stop'")?;
    // writeln!(
    //     files_out,
    //     "$asflags = '-mgekko', '-I', '{}', '--defsym', 'version=0', '-W', '--strip-local-absolute', '-gdwarf-2'",
    //     include_dir.display()
    // )?;
    // writeln!(files_out, "$env:PATH = \"$env:PATH;C:\\devkitPro\\devkitPPC\\bin\"")?;
    for (unit, split_obj) in obj.link_order.iter().zip(&split_objs) {
        let out_path = asm_dir.join(asm_path_for_unit(unit));

        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        let mut w = BufWriter::new(File::create(&out_path)?);
        write_asm(&mut w, split_obj)?;
        w.flush()?;

        // let obj_path = obj_dir.join(obj_path_for_unit(unit));
        // writeln!(files_out, "Write-Host 'Compiling {}'", obj_path.display())?;
        // writeln!(
        //     files_out,
        //     "powerpc-eabi-as @asflags -o '{}' '{}'",
        //     obj_path.display(),
        //     out_path.display()
        // )?;
        // writeln!(
        //     files_out,
        //     "dtk elf fixup '{}' '{}'",
        //     obj_path.display(),
        //     obj_path.display()
        // )?;
    }
    // files_out.flush()?;

    // (debugging) validate against ELF
    if let Some(file) = &args.elf_file {
        validate(&obj, file, &state)?;
    }

    Ok(())
}

fn validate<P: AsRef<Path>>(obj: &ObjInfo, elf_file: P, state: &AnalyzerState) -> Result<()> {
    let real_obj = process_elf(elf_file)?;
    for real_section in &real_obj.sections {
        let obj_section = match obj.sections.get(real_section.index) {
            Some(v) => v,
            None => {
                log::error!(
                    "Section {} {} doesn't exist in DOL",
                    real_section.index,
                    real_section.name
                );
                continue;
            }
        };
        if obj_section.kind != real_section.kind || obj_section.name != real_section.name {
            log::warn!(
                "Section mismatch: {} {:?} ({}) should be {} {:?}",
                obj_section.name,
                obj_section.kind,
                obj_section.index,
                real_section.name,
                real_section.kind
            );
        }
    }
    let mut real_functions = BTreeMap::<u32, String>::new();
    for section in &real_obj.sections {
        if section.kind != ObjSectionKind::Code {
            continue;
        }
        for (_symbol_idx, symbol) in real_obj.symbols.for_section(section) {
            real_functions.insert(symbol.address as u32, symbol.name.clone());
            match state.function_bounds.get(&(symbol.address as u32)) {
                Some(&end) => {
                    if symbol.size > 0 && end != (symbol.address + symbol.size) as u32 {
                        log::warn!(
                            "Function {:#010X} ({}) ends at {:#010X}, expected {:#010X}",
                            symbol.address,
                            symbol.name,
                            end,
                            symbol.address + symbol.size
                        );
                    }
                }
                None => {
                    log::warn!(
                        "Function {:#010X} ({}) not discovered!",
                        symbol.address,
                        symbol.name
                    );
                }
            }
        }
    }
    for (&start, &end) in &state.function_bounds {
        if end == 0 {
            continue;
        }
        if !real_functions.contains_key(&start) {
            let (real_addr, real_name) = real_functions.range(..start).last().unwrap();
            log::warn!(
                "Function {:#010X} not real (actually a part of {} @ {:#010X})",
                start,
                real_name,
                real_addr
            );
        }
    }
    // return Ok(()); // TODO

    for real_section in &real_obj.sections {
        let obj_section = match obj.sections.get(real_section.index) {
            Some(v) => v,
            None => continue,
        };
        let real_map = real_section.build_relocation_map()?;
        let obj_map = obj_section.build_relocation_map()?;
        for (&real_addr, &real_reloc_idx) in &real_map {
            let real_reloc = &real_section.relocations[real_reloc_idx];
            let real_symbol = real_obj.symbols.at(real_reloc.target_symbol);
            let obj_reloc = match obj_map.get(&real_addr) {
                Some(v) => &obj_section.relocations[*v],
                None => {
                    // Ignore GCC local jump branches
                    if real_symbol.kind == ObjSymbolKind::Section
                        && real_section.kind == ObjSectionKind::Code
                        && real_reloc.addend != 0
                        && matches!(
                            real_reloc.kind,
                            ObjRelocKind::PpcRel14 | ObjRelocKind::PpcRel24
                        )
                    {
                        continue;
                    }
                    log::warn!(
                        "Relocation not found @ {:#010X} {:?} to {:#010X}+{:X} ({})",
                        real_addr,
                        real_reloc.kind,
                        real_symbol.address,
                        real_reloc.addend,
                        real_symbol.demangled_name.as_ref().unwrap_or(&real_symbol.name)
                    );
                    continue;
                }
            };
            let obj_symbol = obj.symbols.at(obj_reloc.target_symbol);
            if real_reloc.kind != obj_reloc.kind {
                log::warn!(
                    "Relocation type mismatch @ {:#010X}: {:?} != {:?}",
                    real_addr,
                    obj_reloc.kind,
                    real_reloc.kind
                );
                continue;
            }
            if real_symbol.address as i64 + real_reloc.addend
                != obj_symbol.address as i64 + obj_reloc.addend
            {
                log::warn!(
                    "Relocation target mismatch @ {:#010X} {:?}: {:#010X}+{:X} != {:#010X}+{:X} ({})",
                    real_addr,
                    real_reloc.kind,
                    obj_symbol.address,
                    obj_reloc.addend,
                    real_symbol.address,
                    real_reloc.addend,
                    real_symbol.demangled_name.as_ref().unwrap_or(&real_symbol.name)
                );
                continue;
            }
        }
        for (&obj_addr, &obj_reloc_idx) in &obj_map {
            let obj_reloc = &obj_section.relocations[obj_reloc_idx];
            let obj_symbol = obj.symbols.at(obj_reloc.target_symbol);
            if !real_map.contains_key(&obj_addr) {
                log::warn!(
                    "Relocation not real @ {:#010X} {:?} to {:#010X}+{:X} ({})",
                    obj_addr,
                    obj_reloc.kind,
                    obj_symbol.address,
                    obj_reloc.addend,
                    obj_symbol.demangled_name.as_ref().unwrap_or(&obj_symbol.name)
                );
                continue;
            }
        }
    }
    Ok(())
}
