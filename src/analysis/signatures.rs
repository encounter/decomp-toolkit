use anyhow::{anyhow, Result};

use crate::{
    analysis::{cfa::AnalyzerState, read_u32},
    obj::{
        signatures::{
            apply_signature, check_signatures, check_signatures_str, parse_signatures,
            FunctionSignature,
        },
        ObjInfo, ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
};

const SIGNATURES: &[(&str, &str)] = &[
    ("__init_registers", include_str!("../../assets/signatures/__init_registers.yml")),
    ("__init_hardware", include_str!("../../assets/signatures/__init_hardware.yml")),
    ("__init_data", include_str!("../../assets/signatures/__init_data.yml")),
    ("__set_debug_bba", include_str!("../../assets/signatures/__set_debug_bba.yml")),
    ("__OSPSInit", include_str!("../../assets/signatures/__OSPSInit.yml")),
    ("__OSFPRInit", include_str!("../../assets/signatures/__OSFPRInit.yml")),
    ("__OSCacheInit", include_str!("../../assets/signatures/__OSCacheInit.yml")),
    ("DMAErrorHandler", include_str!("../../assets/signatures/DMAErrorHandler.yml")),
    ("DBInit", include_str!("../../assets/signatures/DBInit.yml")),
    ("OSInit", include_str!("../../assets/signatures/OSInit.yml")),
    ("__OSThreadInit", include_str!("../../assets/signatures/__OSThreadInit.yml")),
    ("__OSInitIPCBuffer", include_str!("../../assets/signatures/__OSInitIPCBuffer.yml")),
    ("EXIInit", include_str!("../../assets/signatures/EXIInit.yml")),
    ("EXIGetID", include_str!("../../assets/signatures/EXIGetID.yml")),
    ("exit", include_str!("../../assets/signatures/exit.yml")),
    ("_ExitProcess", include_str!("../../assets/signatures/_ExitProcess.yml")),
    ("__fini_cpp", include_str!("../../assets/signatures/__fini_cpp.yml")),
    // ("__destroy_global_chain", include_str!("../../assets/signatures/__destroy_global_chain.yml")),
    ("InitMetroTRK", include_str!("../../assets/signatures/InitMetroTRK.yml")),
    ("InitMetroTRKCommTable", include_str!("../../assets/signatures/InitMetroTRKCommTable.yml")),
    ("OSExceptionInit", include_str!("../../assets/signatures/OSExceptionInit.yml")),
    (
        "OSDefaultExceptionHandler",
        include_str!("../../assets/signatures/OSDefaultExceptionHandler.yml"),
    ),
    ("__OSUnhandledException", include_str!("../../assets/signatures/__OSUnhandledException.yml")),
    ("OSDisableScheduler", include_str!("../../assets/signatures/OSDisableScheduler.yml")),
    ("__OSReschedule", include_str!("../../assets/signatures/__OSReschedule.yml")),
    ("__OSInitSystemCall", include_str!("../../assets/signatures/__OSInitSystemCall.yml")),
    ("OSInitAlarm", include_str!("../../assets/signatures/OSInitAlarm.yml")),
    ("__OSInitAlarm", include_str!("../../assets/signatures/__OSInitAlarm.yml")),
    ("__OSEVStart", include_str!("../../assets/signatures/OSExceptionVector.yml")),
    ("__OSDBINTSTART", include_str!("../../assets/signatures/__OSDBIntegrator.yml")),
    ("__OSDBJUMPSTART", include_str!("../../assets/signatures/__OSDBJump.yml")),
    ("SIInit", include_str!("../../assets/signatures/SIInit.yml")),
    ("SIGetType", include_str!("../../assets/signatures/SIGetType.yml")),
    ("SISetSamplingRate", include_str!("../../assets/signatures/SISetSamplingRate.yml")),
    ("SISetXY", include_str!("../../assets/signatures/SISetXY.yml")),
    ("VIGetTvFormat", include_str!("../../assets/signatures/VIGetTvFormat.yml")),
    ("DVDInit", include_str!("../../assets/signatures/DVDInit.yml")),
    (
        "DVDSetAutoFatalMessaging",
        include_str!("../../assets/signatures/DVDSetAutoFatalMessaging.yml"),
    ),
    ("OSSetArenaLo", include_str!("../../assets/signatures/OSSetArenaLo.yml")),
    ("OSSetArenaHi", include_str!("../../assets/signatures/OSSetArenaHi.yml")),
    ("OSSetMEM1ArenaLo", include_str!("../../assets/signatures/OSSetMEM1ArenaLo.yml")),
    ("OSSetMEM1ArenaHi", include_str!("../../assets/signatures/OSSetMEM1ArenaHi.yml")),
    ("OSSetMEM2ArenaLo", include_str!("../../assets/signatures/OSSetMEM2ArenaLo.yml")),
    ("OSSetMEM2ArenaHi", include_str!("../../assets/signatures/OSSetMEM2ArenaHi.yml")),
    ("__OSInitAudioSystem", include_str!("../../assets/signatures/__OSInitAudioSystem.yml")),
    (
        "__OSInitMemoryProtection",
        include_str!("../../assets/signatures/__OSInitMemoryProtection.yml"),
    ),
    // ("BATConfig", include_str!("../../assets/signatures/BATConfig.yml")), TODO
    ("ReportOSInfo", include_str!("../../assets/signatures/ReportOSInfo.yml")),
    ("__check_pad3", include_str!("../../assets/signatures/__check_pad3.yml")),
    ("OSResetSystem", include_str!("../../assets/signatures/OSResetSystem.yml")),
    ("OSReturnToMenu", include_str!("../../assets/signatures/OSReturnToMenu.yml")),
    ("__OSReturnToMenu", include_str!("../../assets/signatures/__OSReturnToMenu.yml")),
    ("__OSShutdownDevices", include_str!("../../assets/signatures/__OSShutdownDevices.yml")),
    ("__OSInitSram", include_str!("../../assets/signatures/__OSInitSram.yml")),
    ("__OSSyncSram", include_str!("../../assets/signatures/__OSSyncSram.yml")),
    (
        "__OSGetExceptionHandler",
        include_str!("../../assets/signatures/__OSGetExceptionHandler.yml"),
    ),
    (
        "OSRegisterResetFunction",
        include_str!("../../assets/signatures/OSRegisterResetFunction.yml"),
    ),
    (
        "OSRegisterShutdownFunction",
        include_str!("../../assets/signatures/OSRegisterShutdownFunction.yml"),
    ),
    (
        "DecrementerExceptionHandler",
        include_str!("../../assets/signatures/DecrementerExceptionHandler.yml"),
    ),
    (
        "DecrementerExceptionCallback",
        include_str!("../../assets/signatures/DecrementerExceptionCallback.yml"),
    ),
    ("__OSInterruptInit", include_str!("../../assets/signatures/__OSInterruptInit.yml")),
    ("__OSContextInit", include_str!("../../assets/signatures/__OSContextInit.yml")),
    ("OSSwitchFPUContext", include_str!("../../assets/signatures/OSSwitchFPUContext.yml")),
    ("OSReport", include_str!("../../assets/signatures/OSReport.yml")),
    ("TRK_main", include_str!("../../assets/signatures/TRK_main.yml")),
    ("TRKNubWelcome", include_str!("../../assets/signatures/TRKNubWelcome.yml")),
    ("TRKInitializeNub", include_str!("../../assets/signatures/TRKInitializeNub.yml")),
    (
        "TRKInitializeIntDrivenUART",
        include_str!("../../assets/signatures/TRKInitializeIntDrivenUART.yml"),
    ),
    ("TRKEXICallBack", include_str!("../../assets/signatures/TRKEXICallBack.yml")),
    ("TRKLoadContext", include_str!("../../assets/signatures/TRKLoadContext.yml")),
    ("TRKInterruptHandler", include_str!("../../assets/signatures/TRKInterruptHandler.yml")),
    ("TRKExceptionHandler", include_str!("../../assets/signatures/TRKExceptionHandler.yml")),
    ("TRKSaveExtended1Block", include_str!("../../assets/signatures/TRKSaveExtended1Block.yml")),
    ("TRKNubMainLoop", include_str!("../../assets/signatures/TRKNubMainLoop.yml")),
    ("TRKTargetContinue", include_str!("../../assets/signatures/TRKTargetContinue.yml")),
    ("TRKSwapAndGo", include_str!("../../assets/signatures/TRKSwapAndGo.yml")),
    (
        "TRKRestoreExtended1Block",
        include_str!("../../assets/signatures/TRKRestoreExtended1Block.yml"),
    ),
    (
        "TRKInterruptHandlerEnableInterrupts",
        include_str!("../../assets/signatures/TRKInterruptHandlerEnableInterrupts.yml"),
    ),
    ("memset", include_str!("../../assets/signatures/memset.yml")),
    (
        "__msl_runtime_constraint_violation_s",
        include_str!("../../assets/signatures/__msl_runtime_constraint_violation_s.yml"),
    ),
    ("ClearArena", include_str!("../../assets/signatures/ClearArena.yml")),
    ("IPCCltInit", include_str!("../../assets/signatures/IPCCltInit.yml")),
    ("__OSInitSTM", include_str!("../../assets/signatures/__OSInitSTM.yml")),
    ("IOS_Open", include_str!("../../assets/signatures/IOS_Open.yml")),
    ("__ios_Ipc2", include_str!("../../assets/signatures/__ios_Ipc2.yml")),
    ("IPCiProfQueueReq", include_str!("../../assets/signatures/IPCiProfQueueReq.yml")),
    ("SCInit", include_str!("../../assets/signatures/SCInit.yml")),
    ("SCReloadConfFileAsync", include_str!("../../assets/signatures/SCReloadConfFileAsync.yml")),
    ("NANDPrivateOpenAsync", include_str!("../../assets/signatures/NANDPrivateOpenAsync.yml")),
    ("nandIsInitialized", include_str!("../../assets/signatures/nandIsInitialized.yml")),
    ("nandOpen", include_str!("../../assets/signatures/nandOpen.yml")),
    ("nandGenerateAbsPath", include_str!("../../assets/signatures/nandGenerateAbsPath.yml")),
    ("nandGetHeadToken", include_str!("../../assets/signatures/nandGetHeadToken.yml")),
    ("ISFS_OpenAsync", include_str!("../../assets/signatures/ISFS_OpenAsync.yml")),
    ("nandConvertErrorCode", include_str!("../../assets/signatures/nandConvertErrorCode.yml")),
    (
        "NANDLoggingAddMessageAsync",
        include_str!("../../assets/signatures/NANDLoggingAddMessageAsync.yml"),
    ),
    (
        "__NANDPrintErrorMessage",
        include_str!("../../assets/signatures/__NANDPrintErrorMessage.yml"),
    ),
    ("__OSInitNet", include_str!("../../assets/signatures/__OSInitNet.yml")),
    ("__DVDCheckDevice", include_str!("../../assets/signatures/__DVDCheckDevice.yml")),
    ("__OSInitPlayTime", include_str!("../../assets/signatures/__OSInitPlayTime.yml")),
    ("__OSStartPlayRecord", include_str!("../../assets/signatures/__OSStartPlayRecord.yml")),
    ("NANDInit", include_str!("../../assets/signatures/NANDInit.yml")),
    ("ISFS_OpenLib", include_str!("../../assets/signatures/ISFS_OpenLib.yml")),
    ("ESP_GetTitleId", include_str!("../../assets/signatures/ESP_GetTitleId.yml")),
    (
        "NANDSetAutoErrorMessaging",
        include_str!("../../assets/signatures/NANDSetAutoErrorMessaging.yml"),
    ),
    ("__DVDFSInit", include_str!("../../assets/signatures/__DVDFSInit.yml")),
    ("__DVDClearWaitingQueue", include_str!("../../assets/signatures/__DVDClearWaitingQueue.yml")),
    ("__DVDInitWA", include_str!("../../assets/signatures/__DVDInitWA.yml")),
    ("__DVDLowSetWAType", include_str!("../../assets/signatures/__DVDLowSetWAType.yml")),
    ("__fstLoad", include_str!("../../assets/signatures/__fstLoad.yml")),
    ("DVDReset", include_str!("../../assets/signatures/DVDReset.yml")),
    ("DVDLowReset", include_str!("../../assets/signatures/DVDLowReset.yml")),
    ("DVDReadDiskID", include_str!("../../assets/signatures/DVDReadDiskID.yml")),
    ("stateReady", include_str!("../../assets/signatures/stateReady.yml")),
    ("DVDLowWaitCoverClose", include_str!("../../assets/signatures/DVDLowWaitCoverClose.yml")),
    ("__DVDStoreErrorCode", include_str!("../../assets/signatures/__DVDStoreErrorCode.yml")),
    ("DVDLowStopMotor", include_str!("../../assets/signatures/DVDLowStopMotor.yml")),
    ("DVDGetDriveStatus", include_str!("../../assets/signatures/DVDGetDriveStatus.yml")),
    ("printf", include_str!("../../assets/signatures/printf.yml")),
    ("sprintf", include_str!("../../assets/signatures/sprintf.yml")),
    ("vprintf", include_str!("../../assets/signatures/vprintf.yml")),
    ("vsprintf", include_str!("../../assets/signatures/vsprintf.yml")),
    ("vsnprintf", include_str!("../../assets/signatures/vsnprintf.yml")),
    ("__pformatter", include_str!("../../assets/signatures/__pformatter.yml")),
    ("longlong2str", include_str!("../../assets/signatures/longlong2str.yml")),
    ("__mod2u", include_str!("../../assets/signatures/__mod2u.yml")),
    ("__FileWrite", include_str!("../../assets/signatures/__FileWrite.yml")),
    ("fwrite", include_str!("../../assets/signatures/fwrite.yml")),
    ("__fwrite", include_str!("../../assets/signatures/__fwrite.yml")),
    ("__stdio_atexit", include_str!("../../assets/signatures/__stdio_atexit.yml")),
    ("__StringWrite", include_str!("../../assets/signatures/__StringWrite.yml")),
];
const POST_SIGNATURES: &[(&str, &str)] = &[
    ("RSOStaticLocateObject", include_str!("../../assets/signatures/RSOStaticLocateObject.yml")),
    // ("GXInit", include_str!("../../assets/signatures/GXInit.yml")),
    ("__register_fragment", include_str!("../../assets/signatures/__register_fragment.yml")),
];

pub fn apply_signatures(obj: &mut ObjInfo) -> Result<()> {
    let entry = obj.entry as u32;
    if let Some(signature) =
        check_signatures_str(obj, entry, include_str!("../../assets/signatures/__start.yml"))?
    {
        apply_signature(obj, entry, &signature)?;
    }
    for &(name, sig_str) in SIGNATURES {
        if let Some((_, symbol)) = obj.symbols.by_name(name)? {
            let addr = symbol.address as u32;
            if let Some(signature) = check_signatures_str(obj, addr, sig_str)? {
                apply_signature(obj, addr, &signature)?;
            }
        }
    }
    if let Some((_, symbol)) = obj.symbols.by_name("__init_user")? {
        // __init_user can be overridden, but we can still look for __init_cpp from it
        let mut analyzer = AnalyzerState::default();
        analyzer.process_function_at(obj, symbol.address as u32)?;
        for addr in analyzer.function_entries {
            if let Some(signature) = check_signatures_str(
                obj,
                addr,
                include_str!("../../assets/signatures/__init_cpp.yml"),
            )? {
                apply_signature(obj, addr, &signature)?;
                break;
            }
        }
    }
    if let Some((_, symbol)) = obj.symbols.by_name("_ctors")? {
        // First entry of ctors is __init_cpp_exceptions
        let section = obj.section_at(symbol.address as u32)?;
        let target = read_u32(&section.data, symbol.address as u32, section.address as u32)
            .ok_or_else(|| anyhow!("Failed to read _ctors data"))?;
        if target != 0 {
            if let Some(signature) = check_signatures_str(
                obj,
                target,
                include_str!("../../assets/signatures/__init_cpp_exceptions.yml"),
            )? {
                let address = symbol.address;
                let section_index = section.index;
                apply_signature(obj, target, &signature)?;
                obj.add_symbol(
                    ObjSymbol {
                        name: "__init_cpp_exceptions_reference".to_string(),
                        demangled_name: None,
                        address,
                        section: Some(section_index),
                        size: 4,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                        kind: ObjSymbolKind::Object,
                        align: None,
                        data_kind: Default::default(),
                    },
                    true,
                )?;
                if obj.split_for(address as u32).is_none() {
                    obj.add_split(address as u32, ObjSplit {
                        unit: "__init_cpp_exceptions.cpp".to_string(),
                        end: address as u32 + 4,
                        align: None,
                        common: false,
                    });
                }
            }
        }
    }
    if let Some((_, symbol)) = obj.symbols.by_name("_dtors")? {
        let section = obj.section_at(symbol.address as u32)?;
        let address = symbol.address;
        let section_address = section.address;
        let section_index = section.index;
        // First entry of dtors is __destroy_global_chain
        let target = read_u32(&section.data, address as u32, section_address as u32)
            .ok_or_else(|| anyhow!("Failed to read _dtors data"))?;
        let target2 = read_u32(&section.data, address as u32 + 4, section_address as u32)
            .ok_or_else(|| anyhow!("Failed to read _dtors data"))?;
        let mut target_ok = false;
        let mut target2_ok = false;
        if target != 0 {
            if let Some(signature) = check_signatures_str(
                obj,
                target,
                include_str!("../../assets/signatures/__destroy_global_chain.yml"),
            )? {
                apply_signature(obj, target, &signature)?;
                obj.add_symbol(
                    ObjSymbol {
                        name: "__destroy_global_chain_reference".to_string(),
                        demangled_name: None,
                        address,
                        section: Some(section_index),
                        size: 4,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                        kind: ObjSymbolKind::Object,
                        align: None,
                        data_kind: Default::default(),
                    },
                    true,
                )?;
                target_ok = true;
            }
        }
        // Second entry of dtors is __fini_cpp_exceptions
        if target2 != 0 {
            if let Some(signature) = check_signatures_str(
                obj,
                target2,
                include_str!("../../assets/signatures/__fini_cpp_exceptions.yml"),
            )? {
                apply_signature(obj, target2, &signature)?;
                obj.add_symbol(
                    ObjSymbol {
                        name: "__fini_cpp_exceptions_reference".to_string(),
                        demangled_name: None,
                        address: address + 4,
                        section: Some(section_index),
                        size: 4,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                        kind: ObjSymbolKind::Object,
                        align: None,
                        data_kind: Default::default(),
                    },
                    true,
                )?;
                target2_ok = true;
            }
        }

        if target_ok && target2_ok && obj.split_for(address as u32).is_none() {
            obj.add_split(address as u32, ObjSplit {
                unit: "__init_cpp_exceptions.cpp".to_string(),
                end: address as u32 + 8,
                align: None,
                common: false,
            });
        }
    }
    Ok(())
}

pub fn apply_signatures_post(obj: &mut ObjInfo) -> Result<()> {
    log::info!("Checking post CFA signatures...");
    for &(_name, sig_str) in POST_SIGNATURES {
        let signatures = parse_signatures(sig_str)?;
        let mut iter = obj.symbols.by_kind(ObjSymbolKind::Function);
        let opt = loop {
            let Some((_, symbol)) = iter.next() else {
                break Option::<(u32, FunctionSignature)>::None;
            };
            if let Some(signature) = check_signatures(obj, symbol.address as u32, &signatures)? {
                break Some((symbol.address as u32, signature));
            }
        };
        if let Some((addr, signature)) = opt {
            drop(iter);
            apply_signature(obj, addr, &signature)?;
            break;
        }
    }
    log::info!("Done!");
    Ok(())
}
