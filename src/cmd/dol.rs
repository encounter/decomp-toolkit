use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, BufWriter},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use argh::FromArgs;

use crate::util::{
    cfa::{
        locate_sda_bases, AnalysisPass, AnalyzerState, FindSaveRestSleds,
        FindTRKInterruptVectorTable,
    },
    config::{parse_symbol_line, write_symbols},
    dol::process_dol,
    elf::process_elf,
    executor::read_u32,
    map::process_map,
    obj::{
        ObjInfo, ObjRelocKind, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind,
    },
    sigs::check_signatures,
    tracker::Tracker,
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
    Disasm(DisasmArgs),
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles a DOL file.
#[argh(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argh(option, short = 'm')]
    /// path to input map
    map_file: Option<PathBuf>,
    #[argh(option, short = 's')]
    /// path to symbols file
    symbols_file: Option<PathBuf>,
    #[argh(option, short = 'e')]
    /// ELF file to validate against (debugging only)
    elf_file: Option<PathBuf>,
    #[argh(positional)]
    /// DOL file
    dol_file: PathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Views DOL file information.
#[argh(subcommand, name = "info")]
pub struct InfoArgs {
    #[argh(positional)]
    /// DOL file
    dol_file: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Info(c_args) => info(c_args),
    }
}

const SIGNATURES: &[(&str, &str)] = &[
    ("__init_registers", include_str!("../../assets/__init_registers.yml")),
    ("__init_hardware", include_str!("../../assets/__init_hardware.yml")),
    ("__init_data", include_str!("../../assets/__init_data.yml")),
    ("__set_debug_bba", include_str!("../../assets/__set_debug_bba.yml")),
    ("__OSPSInit", include_str!("../../assets/__OSPSInit.yml")),
    ("__OSFPRInit", include_str!("../../assets/__OSFPRInit.yml")),
    ("__OSCacheInit", include_str!("../../assets/__OSCacheInit.yml")),
    ("DMAErrorHandler", include_str!("../../assets/DMAErrorHandler.yml")),
    ("DBInit", include_str!("../../assets/DBInit.yml")),
    ("OSInit", include_str!("../../assets/OSInit.yml")),
    ("__OSThreadInit", include_str!("../../assets/__OSThreadInit.yml")),
    ("__OSInitIPCBuffer", include_str!("../../assets/__OSInitIPCBuffer.yml")),
    ("EXIInit", include_str!("../../assets/EXIInit.yml")),
    ("EXIGetID", include_str!("../../assets/EXIGetID.yml")),
    ("exit", include_str!("../../assets/exit.yml")),
    ("_ExitProcess", include_str!("../../assets/_ExitProcess.yml")),
    ("__fini_cpp", include_str!("../../assets/__fini_cpp.yml")),
    ("__destroy_global_chain", include_str!("../../assets/__destroy_global_chain.yml")),
    ("InitMetroTRK", include_str!("../../assets/InitMetroTRK.yml")),
    ("InitMetroTRKCommTable", include_str!("../../assets/InitMetroTRKCommTable.yml")),
    ("OSExceptionInit", include_str!("../../assets/OSExceptionInit.yml")),
    ("OSDefaultExceptionHandler", include_str!("../../assets/OSDefaultExceptionHandler.yml")),
    ("__OSUnhandledException", include_str!("../../assets/__OSUnhandledException.yml")),
    ("OSDisableScheduler", include_str!("../../assets/OSDisableScheduler.yml")),
    ("__OSReschedule", include_str!("../../assets/__OSReschedule.yml")),
    ("__OSInitSystemCall", include_str!("../../assets/__OSInitSystemCall.yml")),
    ("OSInitAlarm", include_str!("../../assets/OSInitAlarm.yml")),
    ("__OSInitAlarm", include_str!("../../assets/__OSInitAlarm.yml")),
    ("__OSEVStart", include_str!("../../assets/OSExceptionVector.yml")),
    ("__OSDBINTSTART", include_str!("../../assets/__OSDBIntegrator.yml")),
    ("__OSDBJUMPSTART", include_str!("../../assets/__OSDBJump.yml")),
    ("SIInit", include_str!("../../assets/SIInit.yml")),
    ("SIGetType", include_str!("../../assets/SIGetType.yml")),
    ("SISetSamplingRate", include_str!("../../assets/SISetSamplingRate.yml")),
    ("SISetXY", include_str!("../../assets/SISetXY.yml")),
    ("VIGetTvFormat", include_str!("../../assets/VIGetTvFormat.yml")),
    ("DVDInit", include_str!("../../assets/DVDInit.yml")),
    ("DVDSetAutoFatalMessaging", include_str!("../../assets/DVDSetAutoFatalMessaging.yml")),
    ("OSSetArenaLo", include_str!("../../assets/OSSetArenaLo.yml")),
    ("OSSetArenaHi", include_str!("../../assets/OSSetArenaHi.yml")),
    ("OSSetMEM1ArenaLo", include_str!("../../assets/OSSetMEM1ArenaLo.yml")),
    ("OSSetMEM1ArenaHi", include_str!("../../assets/OSSetMEM1ArenaHi.yml")),
    ("OSSetMEM2ArenaLo", include_str!("../../assets/OSSetMEM2ArenaLo.yml")),
    ("OSSetMEM2ArenaHi", include_str!("../../assets/OSSetMEM2ArenaHi.yml")),
    ("__OSInitAudioSystem", include_str!("../../assets/__OSInitAudioSystem.yml")),
    ("__OSInitMemoryProtection", include_str!("../../assets/__OSInitMemoryProtection.yml")),
    // ("BATConfig", include_str!("../../assets/BATConfig.yml")), TODO
    ("ReportOSInfo", include_str!("../../assets/ReportOSInfo.yml")),
    ("__check_pad3", include_str!("../../assets/__check_pad3.yml")),
    ("OSResetSystem", include_str!("../../assets/OSResetSystem.yml")),
    ("OSReturnToMenu", include_str!("../../assets/OSReturnToMenu.yml")),
    ("__OSReturnToMenu", include_str!("../../assets/__OSReturnToMenu.yml")),
    ("__OSShutdownDevices", include_str!("../../assets/__OSShutdownDevices.yml")),
    ("__OSInitSram", include_str!("../../assets/__OSInitSram.yml")),
    ("__OSSyncSram", include_str!("../../assets/__OSSyncSram.yml")),
    ("__OSGetExceptionHandler", include_str!("../../assets/__OSGetExceptionHandler.yml")),
    ("OSRegisterResetFunction", include_str!("../../assets/OSRegisterResetFunction.yml")),
    ("OSRegisterShutdownFunction", include_str!("../../assets/OSRegisterShutdownFunction.yml")),
    ("DecrementerExceptionHandler", include_str!("../../assets/DecrementerExceptionHandler.yml")),
    ("DecrementerExceptionCallback", include_str!("../../assets/DecrementerExceptionCallback.yml")),
    ("__OSInterruptInit", include_str!("../../assets/__OSInterruptInit.yml")),
    ("__OSContextInit", include_str!("../../assets/__OSContextInit.yml")),
    ("OSSwitchFPUContext", include_str!("../../assets/OSSwitchFPUContext.yml")),
    ("OSReport", include_str!("../../assets/OSReport.yml")),
    ("TRK_main", include_str!("../../assets/TRK_main.yml")),
    ("TRKNubWelcome", include_str!("../../assets/TRKNubWelcome.yml")),
    ("TRKInitializeNub", include_str!("../../assets/TRKInitializeNub.yml")),
    ("TRKInitializeIntDrivenUART", include_str!("../../assets/TRKInitializeIntDrivenUART.yml")),
    ("TRKEXICallBack", include_str!("../../assets/TRKEXICallBack.yml")),
    ("TRKLoadContext", include_str!("../../assets/TRKLoadContext.yml")),
    ("TRKInterruptHandler", include_str!("../../assets/TRKInterruptHandler.yml")),
    ("TRKExceptionHandler", include_str!("../../assets/TRKExceptionHandler.yml")),
    ("TRKSaveExtended1Block", include_str!("../../assets/TRKSaveExtended1Block.yml")),
    ("TRKNubMainLoop", include_str!("../../assets/TRKNubMainLoop.yml")),
    ("TRKTargetContinue", include_str!("../../assets/TRKTargetContinue.yml")),
    ("TRKSwapAndGo", include_str!("../../assets/TRKSwapAndGo.yml")),
    ("TRKRestoreExtended1Block", include_str!("../../assets/TRKRestoreExtended1Block.yml")),
    (
        "TRKInterruptHandlerEnableInterrupts",
        include_str!("../../assets/TRKInterruptHandlerEnableInterrupts.yml"),
    ),
    ("memset", include_str!("../../assets/memset.yml")),
    (
        "__msl_runtime_constraint_violation_s",
        include_str!("../../assets/__msl_runtime_constraint_violation_s.yml"),
    ),
    ("ClearArena", include_str!("../../assets/ClearArena.yml")),
    ("IPCCltInit", include_str!("../../assets/IPCCltInit.yml")),
    ("__OSInitSTM", include_str!("../../assets/__OSInitSTM.yml")),
    ("IOS_Open", include_str!("../../assets/IOS_Open.yml")),
    ("__ios_Ipc2", include_str!("../../assets/__ios_Ipc2.yml")),
    ("IPCiProfQueueReq", include_str!("../../assets/IPCiProfQueueReq.yml")),
    ("SCInit", include_str!("../../assets/SCInit.yml")),
    ("SCReloadConfFileAsync", include_str!("../../assets/SCReloadConfFileAsync.yml")),
    ("NANDPrivateOpenAsync", include_str!("../../assets/NANDPrivateOpenAsync.yml")),
    ("nandIsInitialized", include_str!("../../assets/nandIsInitialized.yml")),
    ("nandOpen", include_str!("../../assets/nandOpen.yml")),
    ("nandGenerateAbsPath", include_str!("../../assets/nandGenerateAbsPath.yml")),
    ("nandGetHeadToken", include_str!("../../assets/nandGetHeadToken.yml")),
    ("ISFS_OpenAsync", include_str!("../../assets/ISFS_OpenAsync.yml")),
    ("nandConvertErrorCode", include_str!("../../assets/nandConvertErrorCode.yml")),
    ("NANDLoggingAddMessageAsync", include_str!("../../assets/NANDLoggingAddMessageAsync.yml")),
    ("__NANDPrintErrorMessage", include_str!("../../assets/__NANDPrintErrorMessage.yml")),
    ("__OSInitNet", include_str!("../../assets/__OSInitNet.yml")),
    ("__DVDCheckDevice", include_str!("../../assets/__DVDCheckDevice.yml")),
    ("__OSInitPlayTime", include_str!("../../assets/__OSInitPlayTime.yml")),
    ("__OSStartPlayRecord", include_str!("../../assets/__OSStartPlayRecord.yml")),
    ("NANDInit", include_str!("../../assets/NANDInit.yml")),
    ("ISFS_OpenLib", include_str!("../../assets/ISFS_OpenLib.yml")),
    ("ESP_GetTitleId", include_str!("../../assets/ESP_GetTitleId.yml")),
    ("NANDSetAutoErrorMessaging", include_str!("../../assets/NANDSetAutoErrorMessaging.yml")),
    ("__DVDFSInit", include_str!("../../assets/__DVDFSInit.yml")),
    ("__DVDClearWaitingQueue", include_str!("../../assets/__DVDClearWaitingQueue.yml")),
    ("__DVDInitWA", include_str!("../../assets/__DVDInitWA.yml")),
    ("__DVDLowSetWAType", include_str!("../../assets/__DVDLowSetWAType.yml")),
    ("__fstLoad", include_str!("../../assets/__fstLoad.yml")),
    ("DVDReset", include_str!("../../assets/DVDReset.yml")),
    ("DVDLowReset", include_str!("../../assets/DVDLowReset.yml")),
    ("DVDReadDiskID", include_str!("../../assets/DVDReadDiskID.yml")),
    ("stateReady", include_str!("../../assets/stateReady.yml")),
    ("DVDLowWaitCoverClose", include_str!("../../assets/DVDLowWaitCoverClose.yml")),
    ("__DVDStoreErrorCode", include_str!("../../assets/__DVDStoreErrorCode.yml")),
    ("DVDLowStopMotor", include_str!("../../assets/DVDLowStopMotor.yml")),
    ("DVDGetDriveStatus", include_str!("../../assets/DVDGetDriveStatus.yml")),
    ("printf", include_str!("../../assets/printf.yml")),
    ("sprintf", include_str!("../../assets/sprintf.yml")),
    ("vprintf", include_str!("../../assets/vprintf.yml")),
    ("vsprintf", include_str!("../../assets/vsprintf.yml")),
    ("vsnprintf", include_str!("../../assets/vsnprintf.yml")),
    ("__pformatter", include_str!("../../assets/__pformatter.yml")),
    ("longlong2str", include_str!("../../assets/longlong2str.yml")),
    ("__mod2u", include_str!("../../assets/__mod2u.yml")),
    ("__FileWrite", include_str!("../../assets/__FileWrite.yml")),
    ("fwrite", include_str!("../../assets/fwrite.yml")),
    ("__fwrite", include_str!("../../assets/__fwrite.yml")),
    ("__stdio_atexit", include_str!("../../assets/__stdio_atexit.yml")),
    ("__StringWrite", include_str!("../../assets/__StringWrite.yml")),
];

pub fn apply_signatures(obj: &mut ObjInfo) -> Result<()> {
    let entry = obj.entry as u32;
    check_signatures(obj, entry, include_str!("../../assets/__start.yml"))?;
    for &(name, sig_str) in SIGNATURES {
        if let Some(symbol) = obj.symbols.iter().find(|symbol| symbol.name == name) {
            let addr = symbol.address as u32;
            check_signatures(obj, addr, sig_str)?;
        }
    }
    if let Some(symbol) = obj.symbols.iter().find(|symbol| symbol.name == "__init_user") {
        // __init_user can be overridden, but we can still look for __init_cpp from it
        let mut analyzer = AnalyzerState::default();
        analyzer.process_function_at(&obj, symbol.address as u32)?;
        for addr in analyzer.function_entries {
            if check_signatures(obj, addr, include_str!("../../assets/__init_cpp.yml"))? {
                break;
            }
        }
    }
    if let Some(symbol) = obj.symbols.iter().find(|symbol| symbol.name == "_ctors") {
        // First entry of ctors is __init_cpp_exceptions
        let section = obj.section_at(symbol.address as u32)?;
        let target = read_u32(&section.data, symbol.address as u32, section.address as u32)
            .ok_or_else(|| anyhow!("Failed to read _ctors data"))?;
        if target != 0 {
            check_signatures(obj, target, include_str!("../../assets/__init_cpp_exceptions.yml"))?;
        }
    }
    if let Some(symbol) = obj.symbols.iter().find(|symbol| symbol.name == "_dtors") {
        // Second entry of dtors is __fini_cpp_exceptions
        let section = obj.section_at(symbol.address as u32)?;
        let target = read_u32(&section.data, symbol.address as u32 + 4, section.address as u32)
            .ok_or_else(|| anyhow!("Failed to read _dtors data"))?;
        if target != 0 {
            check_signatures(obj, target, include_str!("../../assets/__fini_cpp_exceptions.yml"))?;
        }
    }
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let mut obj = process_dol(&args.dol_file)?;
    apply_signatures(&mut obj)?;
    // Apply known functions from extab
    let mut state = AnalyzerState::default();
    for (&addr, &size) in &obj.known_functions {
        state.function_entries.insert(addr);
        state.function_bounds.insert(addr, addr + size);
    }
    for symbol in &obj.symbols {
        if symbol.kind != ObjSymbolKind::Function {
            continue;
        }
        state.function_entries.insert(symbol.address as u32);
        if !symbol.size_known {
            continue;
        }
        state.function_bounds.insert(symbol.address as u32, (symbol.address + symbol.size) as u32);
    }
    // Also check the start of each code section
    for section in &obj.sections {
        if section.kind == ObjSectionKind::Code {
            state.function_entries.insert(section.address as u32);
        }
    }

    state.detect_functions(&obj)?;
    log::info!("Discovered {} functions", state.function_slices.len());

    FindTRKInterruptVectorTable::execute(&mut state, &obj)?;
    FindSaveRestSleds::execute(&mut state, &obj)?;
    state.apply(&mut obj)?;

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
    let mut symbols = obj.symbols.clone();
    symbols.sort_by_key(|sym| sym.address);
    for symbol in symbols {
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

fn disasm(args: DisasmArgs) -> Result<()> {
    let mut obj = process_dol(&args.dol_file)?;
    log::info!("Performing initial control flow analysis");

    // if detect_sda_bases(&mut obj).context("Failed to locate SDA bases")? {
    //     let (sda2_base, sda_base) = obj.sda_bases.unwrap();
    //     log::info!("Found _SDA2_BASE_ @ {:#010X}, _SDA_BASE_ @ {:#010X}", sda2_base, sda_base);
    // } else {
    //     bail!("Unable to locate SDA bases");
    // }

    if let Some(map) = &args.map_file {
        let mut reader = BufReader::new(
            File::open(map)
                .with_context(|| format!("Failed to open map file '{}'", map.display()))?,
        );
        let _entries = process_map(&mut reader)?;
    }

    let mut state = AnalyzerState::default();

    if let Some(symbols_path) = &args.symbols_file {
        let mut reader = BufReader::new(File::open(symbols_path).with_context(|| {
            format!("Failed to open symbols file '{}'", symbols_path.display())
        })?);
        for result in reader.lines() {
            let line = match result {
                Ok(line) => line,
                Err(e) => bail!("Failed to process symbols file: {e:?}"),
            };
            if let Some(symbol) = parse_symbol_line(&line, &obj)? {
                // if symbol.kind == ObjSymbolKind::Function {
                //     state.function_entries.insert(symbol.address as u32);
                //     if symbol.size_known {
                //         state
                //             .function_bounds
                //             .insert(symbol.address as u32, (symbol.address + symbol.size) as u32);
                //     }
                // }
                if let Some(existing_symbol) = obj
                    .symbols
                    .iter_mut()
                    .find(|e| e.address == symbol.address && e.kind == symbol.kind)
                {
                    *existing_symbol = symbol;
                } else {
                    obj.symbols.push(symbol);
                }
            }
        }
    }

    // TODO move before symbols?
    apply_signatures(&mut obj)?;

    // Apply known functions from extab
    for (&addr, &size) in &obj.known_functions {
        state.function_entries.insert(addr);
        state.function_bounds.insert(addr, addr + size);
    }
    for symbol in &obj.symbols {
        if symbol.kind != ObjSymbolKind::Function {
            continue;
        }
        state.function_entries.insert(symbol.address as u32);
        if !symbol.size_known {
            continue;
        }
        state.function_bounds.insert(symbol.address as u32, (symbol.address + symbol.size) as u32);
    }
    // Also check the start of each code section
    for section in &obj.sections {
        if section.kind == ObjSectionKind::Code {
            state.function_entries.insert(section.address as u32);
        }
    }

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
    //
    // log::info!("Writing disassembly");
    // let mut w = BufWriter::new(File::create("out.s")?);
    // write_asm(&mut w, &obj)?;

    if let Some(symbols_path) = &args.symbols_file {
        let mut symbols_writer = BufWriter::new(
            File::create(&symbols_path)
                .with_context(|| format!("Failed to create '{}'", symbols_path.display()))?,
        );
        write_symbols(&mut symbols_writer, &obj)?;
    }

    // (debugging) validate against ELF
    if let Some(file) = args.elf_file {
        validate(&obj, &file, &state)?;
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
        for (_symbol_idx, symbol) in real_obj.symbols_for_section(section.index) {
            // if symbol.name.starts_with("switch_") {
            //     continue;
            // }
            // if symbol.kind == ObjSymbolKind::Function {
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
            // }
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
    for real_section in &real_obj.sections {
        let obj_section = match obj.sections.get(real_section.index) {
            Some(v) => v,
            None => continue,
        };
        let real_map = real_section.build_relocation_map()?;
        let obj_map = obj_section.build_relocation_map()?;
        for (&real_addr, real_reloc) in &real_map {
            let real_symbol = &real_obj.symbols[real_reloc.target_symbol];
            let obj_reloc = match obj_map.get(&real_addr) {
                Some(v) => v,
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
            let obj_symbol = &obj.symbols[obj_reloc.target_symbol];
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
        for (&obj_addr, obj_reloc) in &obj_map {
            let obj_symbol = &obj.symbols[obj_reloc.target_symbol];
            let real_reloc = match real_map.get(&obj_addr) {
                Some(v) => v,
                None => {
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
            };
        }
    }
    Ok(())
}
