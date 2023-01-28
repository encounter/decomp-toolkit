use std::{collections::HashMap, env, fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use flagset::{flags, FlagSet};
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

flags! {
    #[repr(u8)]
    #[derive(Deserialize_repr, Serialize_repr)]
    pub enum ObjSymbolFlags: u8 {
        Global,
        Local,
        Weak,
        Common,
        Hidden,
    }
}
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjSymbolFlagSet(pub FlagSet<ObjSymbolFlags>);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObjSymbolKind {
    Unknown,
    Function,
    Object,
    Section,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObjRelocKind {
    Absolute,
    PpcAddr16Hi,
    PpcAddr16Ha,
    PpcAddr16Lo,
    PpcRel24,
    PpcRel14,
    PpcEmbSda21,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutSymbol {
    pub kind: ObjSymbolKind,
    pub name: String,
    pub size: u32,
    pub flags: ObjSymbolFlagSet,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutReloc {
    pub offset: u32,
    pub kind: ObjRelocKind,
    pub symbol: usize,
    pub addend: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub symbol: usize,
    pub hash: String,
    pub signature: String,
    pub symbols: Vec<OutSymbol>,
    pub relocations: Vec<OutReloc>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum SigSymbolKind {
    Unknown = 0,
    Function = 1,
    Object = 2,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum SigSection {
    Init = 0,
    Extab = 1,
    Extabindex = 2,
    Text = 3,
    Ctors = 4,
    Dtors = 5,
    Rodata = 6,
    Data = 7,
    Bss = 8,
    Sdata = 9,
    Sbss = 10,
    Sdata2 = 11,
    Sbss2 = 12,
    Dbgtext = 13,
    Unknown = 255,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum SigSymbolFlag {
    Global = 1 << 0,
    Local = 1 << 1,
    Weak = 1 << 2,
    Common = 1 << 3,
    Hidden = 1 << 4,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SigSymbol {
    pub kind: SigSymbolKind,
    pub name: String,
    pub size: u32,
    pub flags: u8, // SigSymbolFlag
    pub section: SigSection,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
pub enum SigRelocKind {
    Absolute = 0,
    PpcAddr16Hi = 1,
    PpcAddr16Ha = 2,
    PpcAddr16Lo = 3,
    PpcRel24 = 4,
    PpcRel14 = 5,
    PpcEmbSda21 = 6,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SigReloc {
    pub offset: u32,
    pub symbol: usize,
    pub kind: SigRelocKind,
    pub addend: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sig {
    pub symbol: usize,
    pub data: Vec<u8>,
    pub relocations: Vec<SigReloc>,
    pub search: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Output {
    pub symbols: Vec<SigSymbol>,
    pub signatures: HashMap<String, Sig>,
}

pub fn parse_yml(sig_str: &str) -> Result<Vec<FunctionSignature>> {
    Ok(serde_yaml::from_str(sig_str)?)
}

const SIGNATURES: &[(&str, bool)] = &[
    ("__start", false),
    ("__init_registers", false),
    ("__init_hardware", false),
    ("__init_data", false),
    ("__set_debug_bba", false),
    ("__OSPSInit", false),
    ("__OSFPRInit", false),
    ("__OSCacheInit", false),
    ("DMAErrorHandler", false),
    ("DBInit", false),
    ("OSInit", false),
    ("__OSThreadInit", false),
    ("__OSInitIPCBuffer", false),
    ("EXIInit", false),
    ("EXIGetID", false),
    ("exit", false),
    ("_ExitProcess", false),
    ("__fini_cpp", false),
    ("__fini_cpp_exceptions", false),
    ("__destroy_global_chain", false),
    ("__init_cpp", false),
    ("__init_cpp_exceptions", false),
    ("InitMetroTRK", false),
    ("InitMetroTRKCommTable", false),
    ("OSExceptionInit", false),
    ("OSDefaultExceptionHandler", false),
    ("__OSUnhandledException", false),
    ("OSDisableScheduler", false),
    ("__OSReschedule", false),
    ("__OSInitSystemCall", false),
    ("OSInitAlarm", false),
    ("__OSInitAlarm", false),
    // TODO aliases
    // ("__OSEVStart", false),
    // ("__OSDBINTSTART", false),
    // ("__OSDBJUMPSTART", false),
    ("SIInit", false),
    ("SIGetType", false),
    ("SISetSamplingRate", false),
    ("SISetXY", false),
    ("VIGetTvFormat", false),
    ("DVDInit", false),
    ("DVDSetAutoFatalMessaging", false),
    ("OSSetArenaLo", false),
    ("OSSetArenaHi", false),
    ("OSSetMEM1ArenaLo", false),
    ("OSSetMEM1ArenaHi", false),
    ("OSSetMEM2ArenaLo", false),
    ("OSSetMEM2ArenaHi", false),
    ("__OSInitAudioSystem", false),
    ("__OSInitMemoryProtection", false),
    // ("BATConfig", false), TODO
    ("ReportOSInfo", false),
    ("__check_pad3", false),
    ("OSResetSystem", false),
    ("OSReturnToMenu", false),
    ("__OSReturnToMenu", false),
    ("__OSShutdownDevices", false),
    ("__OSInitSram", false),
    ("__OSSyncSram", false),
    ("__OSGetExceptionHandler", false),
    ("OSRegisterResetFunction", false),
    ("OSRegisterShutdownFunction", false),
    ("DecrementerExceptionHandler", false),
    ("DecrementerExceptionCallback", false),
    ("__OSInterruptInit", false),
    ("__OSContextInit", false),
    ("OSSwitchFPUContext", false),
    ("OSReport", false),
    ("TRK_main", false),
    ("TRKNubWelcome", false),
    ("TRKInitializeNub", false),
    ("TRKInitializeIntDrivenUART", false),
    ("TRKEXICallBack", false),
    ("TRKLoadContext", false),
    ("TRKInterruptHandler", false),
    ("TRKExceptionHandler", false),
    ("TRKSaveExtended1Block", false),
    ("TRKNubMainLoop", false),
    ("TRKTargetContinue", false),
    ("TRKSwapAndGo", false),
    ("TRKRestoreExtended1Block", false),
    ("TRKInterruptHandlerEnableInterrupts", false),
    ("memset", false),
    ("__msl_runtime_constraint_violation_s", false),
    ("ClearArena", false),
    ("IPCCltInit", false),
    ("__OSInitSTM", false),
    ("IOS_Open", false),
    ("__ios_Ipc2", false),
    ("IPCiProfQueueReq", false),
    ("SCInit", false),
    ("SCReloadConfFileAsync", false),
    ("NANDPrivateOpenAsync", false),
    ("nandIsInitialized", false),
    ("nandOpen", false),
    ("nandGenerateAbsPath", false),
    ("nandGetHeadToken", false),
    ("ISFS_OpenAsync", false),
    ("nandConvertErrorCode", false),
    ("NANDLoggingAddMessageAsync", false),
    ("__NANDPrintErrorMessage", false),
    ("__OSInitNet", false),
    ("__DVDCheckDevice", false),
    ("__OSInitPlayTime", false),
    ("__OSStartPlayRecord", false),
    ("NANDInit", false),
    ("ISFS_OpenLib", false),
    ("ESP_GetTitleId", false),
    ("NANDSetAutoErrorMessaging", false),
    ("__DVDFSInit", false),
    ("__DVDClearWaitingQueue", false),
    ("__DVDInitWA", false),
    ("__DVDLowSetWAType", false),
    ("__fstLoad", false),
    ("DVDReset", false),
    ("DVDLowReset", false),
    ("DVDReadDiskID", false),
    ("stateReady", false),
    ("DVDLowWaitCoverClose", false),
    ("__DVDStoreErrorCode", false),
    ("DVDLowStopMotor", false),
    ("DVDGetDriveStatus", false),
    ("printf", false),
    ("sprintf", false),
    ("vprintf", false),
    ("vsprintf", false),
    ("vsnprintf", false),
    ("__pformatter", false),
    ("longlong2str", false),
    ("__mod2u", false),
    ("__FileWrite", false),
    ("fwrite", false),
    ("__fwrite", false),
    ("__stdio_atexit", false),
    ("__StringWrite", false),
    ("RSOStaticLocateObject", true),
];

fn main() -> Result<()> {
    let output = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    let rev = String::from_utf8(output.stdout)?;
    println!("cargo:rustc-env=GIT_COMMIT_SHA={rev}");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");

    let mut symbols = Vec::<SigSymbol>::new();
    let mut out = HashMap::<String, Sig>::new();
    let in_dir = PathBuf::from("assets/signatures");
    for &(name, search) in SIGNATURES {
        let path = in_dir.join(format!("{name}.yml"));
        println!("cargo:rustc-rerun-if-changed={}", path.display());
        let str = fs::read_to_string(&path)
            .with_context(|| format!("Failed to open '{}'", path.display()))?;
        apply_sig(&str, &mut symbols, &mut out, search)?;
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    rmp_serde::encode::write(&mut encoder, &Output { symbols, signatures: out })?;
    let compressed = encoder.finish()?;
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("signatures.bin"), &compressed)?;

    Ok(())
}

fn apply_sig(
    sig_str: &str,
    symbols: &mut Vec<SigSymbol>,
    out: &mut HashMap<String, Sig>,
    search: bool,
) -> Result<()> {
    let data = parse_yml(sig_str)?;
    for in_sig in data {
        let in_sym = &in_sig.symbols[in_sig.symbol];
        let mut out_sig = Sig {
            symbol: add_symbol(symbols, in_sym)?,
            data: STANDARD.decode(&in_sig.signature)?,
            relocations: vec![],
            search,
        };
        for in_reloc in &in_sig.relocations {
            out_sig.relocations.push(SigReloc {
                offset: in_reloc.offset,
                symbol: add_symbol(symbols, &in_sig.symbols[in_reloc.symbol])?,
                kind: to_sig_reloc_kind(in_reloc.kind)?,
                addend: in_reloc.addend,
            });
        }
        out.insert(in_sym.name.clone(), out_sig);
    }
    Ok(())
}

fn to_sym_section(s: Option<&str>) -> Result<SigSection> {
    match s {
        None => Ok(SigSection::Unknown),
        Some(".init") => Ok(SigSection::Init),
        Some("extab") => Ok(SigSection::Extab),
        Some("extabindex") => Ok(SigSection::Extabindex),
        Some(".text") => Ok(SigSection::Text),
        Some(".ctors") => Ok(SigSection::Ctors),
        Some(".dtors") => Ok(SigSection::Dtors),
        Some(".rodata") => Ok(SigSection::Rodata),
        Some(".data") => Ok(SigSection::Data),
        Some(".bss") => Ok(SigSection::Bss),
        Some(".sdata") => Ok(SigSection::Sdata),
        Some(".sbss") => Ok(SigSection::Sbss),
        Some(".sdata2") => Ok(SigSection::Sdata2),
        Some(".sbss2") => Ok(SigSection::Sbss2),
        Some(".dbgtext") => Ok(SigSection::Dbgtext),
        Some(section) => Err(anyhow!("Unknown section {}", section)),
    }
}

fn to_sig_symbol_kind(kind: ObjSymbolKind) -> Result<SigSymbolKind> {
    match kind {
        ObjSymbolKind::Unknown => Ok(SigSymbolKind::Unknown),
        ObjSymbolKind::Function => Ok(SigSymbolKind::Function),
        ObjSymbolKind::Object => Ok(SigSymbolKind::Object),
        ObjSymbolKind::Section => Err(anyhow!("Section symbols unsupported")),
    }
}

fn to_sig_symbol_flags(flags: ObjSymbolFlagSet) -> Result<u8> {
    let mut out = 0;
    for flag in flags.0 {
        match flag {
            ObjSymbolFlags::Global => {
                out |= SigSymbolFlag::Global as u8;
            }
            ObjSymbolFlags::Local => {
                out |= SigSymbolFlag::Local as u8;
            }
            ObjSymbolFlags::Weak => {
                out |= SigSymbolFlag::Weak as u8;
            }
            ObjSymbolFlags::Common => {
                out |= SigSymbolFlag::Common as u8;
            }
            ObjSymbolFlags::Hidden => {
                out |= SigSymbolFlag::Hidden as u8;
            }
        }
    }
    Ok(out)
}

fn to_sig_reloc_kind(kind: ObjRelocKind) -> Result<SigRelocKind> {
    match kind {
        ObjRelocKind::Absolute => Ok(SigRelocKind::Absolute),
        ObjRelocKind::PpcAddr16Hi => Ok(SigRelocKind::PpcAddr16Hi),
        ObjRelocKind::PpcAddr16Ha => Ok(SigRelocKind::PpcAddr16Ha),
        ObjRelocKind::PpcAddr16Lo => Ok(SigRelocKind::PpcAddr16Lo),
        ObjRelocKind::PpcRel24 => Ok(SigRelocKind::PpcRel24),
        ObjRelocKind::PpcRel14 => Ok(SigRelocKind::PpcRel14),
        ObjRelocKind::PpcEmbSda21 => Ok(SigRelocKind::PpcEmbSda21),
    }
}

fn add_symbol(symbols: &mut Vec<SigSymbol>, in_sym: &OutSymbol) -> Result<usize> {
    let sig_section = to_sym_section(in_sym.section.as_deref())?;
    let sig_symbol_kind = to_sig_symbol_kind(in_sym.kind)?;
    let sig_symbol_flags = to_sig_symbol_flags(in_sym.flags)?;
    if let Some((idx, existing)) = symbols.iter_mut().enumerate().find(|(_, sym)| {
        sym.kind == sig_symbol_kind && sym.size == in_sym.size && sym.name == in_sym.name
    }) {
        if existing.kind != sig_symbol_kind {
            bail!(
                "Mismatched types for {}: {:?} != {:?}",
                in_sym.name,
                sig_symbol_kind,
                existing.kind
            );
        }
        if existing.section != sig_section {
            if existing.section == SigSection::Unknown || sig_section == SigSection::Unknown {
                existing.section = SigSection::Unknown;
            } else {
                eprintln!(
                    "Mismatched sections for {}: {:?} != {:?}",
                    in_sym.name, sig_section, existing.section
                );
                existing.section = SigSection::Unknown;
            }
        }
        if existing.size != in_sym.size {
            bail!("Mismatched size for {}: {} != {}", in_sym.name, in_sym.size, existing.size);
        }
        if existing.flags != sig_symbol_flags {
            if (existing.flags & (SigSymbolFlag::Weak as u8) != 0
                && sig_symbol_flags & (SigSymbolFlag::Weak as u8) == 0)
                || (sig_symbol_flags & (SigSymbolFlag::Weak as u8) != 0
                    && existing.flags & (SigSymbolFlag::Weak as u8) == 0)
            {
                existing.flags |= SigSymbolFlag::Weak as u8;
            } else {
                eprintln!(
                    "Mismatched flags for {}: {} != {}",
                    in_sym.name, sig_symbol_flags, existing.flags
                );
            }
        }
        return Ok(idx);
    }
    let idx = symbols.len();
    symbols.push(SigSymbol {
        kind: sig_symbol_kind,
        name: in_sym.name.clone(),
        size: in_sym.size,
        flags: sig_symbol_flags,
        section: sig_section,
    });
    Ok(idx)
}
