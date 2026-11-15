use std::io::{BufRead, Cursor, Write};

use anyhow::{Context, Result, bail, ensure};
use argp::FromArgs;
use itertools::Itertools;
use object::{
    Architecture, Endianness, Object, ObjectKind, ObjectSection, ObjectSymbol, SectionKind,
    SymbolIndex, SymbolSection,
    elf::{R_PPC_NONE, R_PPC_REL24},
};
use rustc_hash::FxHashMap;
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    cmd::dol::{ModuleKind, ProjectConfig, find_object_base},
    util::{
        file::{buf_writer, verify_hash},
        path::native_path,
        rso::{
            DOL_SECTION_ABS, DOL_SECTION_ETI, DOL_SECTION_NAMES, RSO_SECTION_NAMES, RsoExport,
            RsoModule, RsoRelocation, RsoSection, msvc_qsort, sort_exports,
        },
    },
    vfs::open_file,
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
    #[argp(positional, from_str_fn(native_path))]
    /// RSO file
    rso_file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Creates an RSO from a relocatable ELF (PLF), or a SEL from an executable ELF.
#[argp(subcommand, name = "make")]
pub struct MakeArgs {
    #[argp(positional, arg_name = "ELF File", from_str_fn(native_path))]
    /// elf file
    input: Utf8NativePathBuf,

    #[argp(option, short = 'o', arg_name = "File", from_str_fn(native_path))]
    /// output file path
    output: Utf8NativePathBuf,

    #[argp(option, short = 'm', arg_name = "Name")]
    /// module name (or path). Default: name of the original module, or input name
    module_name: Option<String>,

    #[argp(option, short = 'e', arg_name = "File", from_str_fn(native_path))]
    /// file containing exported symbol names (newline separated)
    export: Option<Utf8NativePathBuf>,

    #[argp(option, short = 'c', from_str_fn(native_path))]
    /// (optional) project configuration file. The original module is loaded from it and used
    /// to match its section indices, module name, exports and symbol order.
    config: Option<Utf8NativePathBuf>,

    #[argp(option, short = 'n', arg_name = "Name")]
    /// (optional) name of the module in the project configuration (for RSOs; required with -c)
    name: Option<String>,

    #[argp(switch)]
    /// patch calls to imported functions to branch to `_unresolved`
    patch_unresolved: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Make(c_args) => make(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let module = {
        let mut file = open_file(&args.rso_file, true)?;
        RsoModule::read(file.as_mut())?
    };
    println!("{} module: {}", if module.is_sel { "SEL" } else { "RSO" }, module.name);
    println!("Version: {}", module.version);
    for (name, entry) in
        [("_prolog", module.prolog), ("_epilog", module.epilog), ("_unresolved", module.unresolved)]
    {
        if let Some((section, offset)) = entry {
            println!("{name}: {section}:{offset:#X}");
        }
    }

    println!("\nSections ({}):", module.sections.len());
    println!("\t{: >5} | {: <10} | {: <10} | {: <5}", "Index", "Offset", "Size", "Kind");
    for (idx, section) in module.sections.iter().enumerate() {
        if section.size == 0 {
            continue;
        }
        let kind = match (section.offset, section.exec) {
            (0, _) => "bss",
            (_, true) => "code",
            (_, false) => "data",
        };
        println!(
            "\t{: >5} | {: <#10X} | {: <#10X} | {: <5}",
            idx, section.offset, section.size, kind
        );
    }

    println!("\nExports ({}):", module.exports.len());
    for export in &module.exports {
        println!("\t{}:{:#X} {}", export.section, export.offset, export.name);
    }

    println!("\nImports ({}):", module.imports.len());
    for (idx, name) in module.imports.iter().enumerate() {
        let count = module.external_relocations.iter().filter(|r| r.id() as usize == idx).count();
        println!("\t{name} ({count} relocations)");
    }

    println!("\nInternal relocations: {}", module.internal_relocations.len());
    println!("External relocations: {}", module.external_relocations.len());
    Ok(())
}

fn make(args: MakeArgs) -> Result<()> {
    let mut file = open_file(&args.input, true)?;
    let obj_file = object::read::File::parse(file.map()?)?;
    match obj_file.architecture() {
        Architecture::PowerPc => {}
        arch => bail!("Unexpected architecture: {arch:?}"),
    };
    ensure!(obj_file.endianness() == Endianness::Big, "Expected big endian");
    let is_sel = match obj_file.kind() {
        ObjectKind::Executable => true,
        ObjectKind::Relocatable => false,
        kind => bail!("Unexpected ELF type: {kind:?}"),
    };

    // Load the original module (if specified) to match its layout
    let reference = match &args.config {
        Some(config_path) => Some(
            load_reference(config_path, is_sel, args.name.as_deref())
                .with_context(|| format!("While loading original module from '{config_path}'"))?,
        ),
        None => None,
    };

    let mut exports = match &args.export {
        Some(export_file_path) => {
            let export_file_reader = open_file(export_file_path, true)?;
            export_file_reader.lines().map_while(Result::ok).collect()
        }
        None => vec![],
    };
    exports.retain(|s: &String| !s.is_empty());

    let name = match (&args.module_name, &reference) {
        (Some(name), _) => name.clone(),
        (None, Some(reference)) => reference.name.clone(),
        (None, None) => args.input.to_string(),
    };
    let module = if is_sel {
        build_sel(&obj_file, reference.as_ref(), name, exports)?
    } else {
        build_rso(&obj_file, reference.as_ref(), name, exports, args.patch_unresolved)?
    };

    let mut out = buf_writer(&args.output)?;
    module.write(&mut out)?;
    out.flush()?;
    Ok(())
}

/// Loads the original RSO (or SEL) from a project config.
fn load_reference(
    config_path: &Utf8NativePath,
    is_sel: bool,
    name: Option<&str>,
) -> Result<RsoModule> {
    let config: ProjectConfig = {
        let mut file = open_file(config_path, true)?;
        serde_yaml::from_reader(file.as_mut())?
    };
    let object_base = find_object_base(&config)?;
    let (path, hash) = if is_sel {
        let path = config.selfile.as_ref().context("Project config has no selfile")?;
        (path, config.selfile_hash.as_deref())
    } else {
        let name = name.context("Module name (-n) is required with a project config")?;
        let module_config = config
            .modules
            .iter()
            .find(|m| m.name() == name)
            .with_context(|| format!("Module '{name}' not found in project config"))?;
        ensure!(module_config.kind() == ModuleKind::Rso, "Module '{name}' is not an RSO");
        (&module_config.object, module_config.hash.as_deref())
    };
    let mut file = object_base.open(path)?;
    let data = file.map()?;
    if let Some(hash_str) = hash {
        verify_hash(data, hash_str)?;
    }
    RsoModule::read(&mut Cursor::new(data))
        .with_context(|| format!("While reading '{}'", object_base.join(path)))
}

/// Orders `names` to match `reference`, with any names not present in it appended in their
/// existing order. Returns indices into `names`.
fn order_by_reference<'a, I>(names: &[&str], reference: Option<I>) -> Vec<usize>
where I: Iterator<Item = &'a str> {
    let Some(reference) = reference else {
        return (0..names.len()).collect();
    };
    let mut by_name = FxHashMap::<&str, usize>::default();
    for (idx, &name) in names.iter().enumerate() {
        by_name.entry(name).or_insert(idx);
    }
    let mut used = vec![false; names.len()];
    let mut order = Vec::with_capacity(names.len());
    for name in reference {
        if let Some(&idx) = by_name.get(name) {
            if !used[idx] {
                used[idx] = true;
                order.push(idx);
            }
        }
    }
    order.extend((0..names.len()).filter(|&idx| !used[idx]));
    order
}

/// Builds the export table, sorted by name hash, along with the string table order.
/// `exports` must be in string table order.
fn finish_exports(exports: Vec<RsoExport>) -> (Vec<RsoExport>, Vec<usize>) {
    let mut sorted = exports.clone();
    sort_exports(&mut sorted);
    let mut index = FxHashMap::<&str, usize>::default();
    for (idx, export) in sorted.iter().enumerate() {
        index.insert(export.name.as_str(), idx);
    }
    let name_order = exports.iter().map(|e| index[e.name.as_str()]).collect();
    (sorted, name_order)
}

/// Collects the names of symbols to export: those of the original module (if any), followed
/// by any additional names specified by the user.
fn export_names(reference: Option<&RsoModule>, extra: Vec<String>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(reference) = reference {
        names.extend(
            reference.export_name_order.iter().map(|&idx| reference.exports[idx].name.clone()),
        );
    }
    for name in extra {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn build_sel(
    file: &object::File,
    reference: Option<&RsoModule>,
    name: String,
    exports: Vec<String>,
) -> Result<RsoModule> {
    let mut symbols = FxHashMap::<&str, object::Symbol>::default();
    for symbol in file.symbols() {
        if symbol.is_undefined() || symbol.is_local() {
            continue;
        }
        if let Ok(name) = symbol.name() {
            symbols.entry(name).or_insert(symbol);
        }
    }

    let mut out = Vec::new();
    for name in export_names(reference, exports) {
        let symbol =
            symbols.get(name.as_str()).with_context(|| format!("Symbol '{name}' not found"))?;
        let (section, offset) = match symbol.section() {
            SymbolSection::Absolute => (DOL_SECTION_ABS, symbol.address() as u32),
            SymbolSection::Section(section_index) => {
                let section = file.section_by_index(section_index)?;
                let section_name = section.name()?;
                let index = if section_name == "extabindex" {
                    DOL_SECTION_ETI
                } else {
                    DOL_SECTION_NAMES.iter().position(|&n| n == Some(section_name)).with_context(
                        || format!("Can't export symbol '{name}' in section {section_name}"),
                    )? as u32
                };
                (index, (symbol.address() - section.address()) as u32)
            }
            section => bail!("Can't export symbol '{name}' with section {section:?}"),
        };
        out.push(RsoExport { name, section, offset });
    }
    let (exports, export_name_order) = finish_exports(out);

    let num_sections =
        reference.map_or(file.sections().count() + 1, |reference| reference.sections.len());
    Ok(RsoModule {
        is_sel: true,
        version: 1,
        name,
        sections: vec![Default::default(); num_sections],
        exports,
        export_name_order,
        ..Default::default()
    })
}

fn build_rso(
    file: &object::File,
    reference: Option<&RsoModule>,
    name: String,
    exports: Vec<String>,
    patch_unresolved: bool,
) -> Result<RsoModule> {
    // Sections to include, in order
    let elf_sections = file
        .sections()
        .filter(|s| s.size() != 0 && s.name().is_ok_and(|n| RSO_SECTION_NAMES.contains(&n)))
        .collect::<Vec<_>>();

    // Determine the RSO section index for each. By default, RSO sections share the section
    // indices of the ELF. However, the original ELF had a different set of sections, so if we
    // have the original module, match up the non-empty sections in order instead.
    let (num_sections, indices) = match reference {
        Some(reference) => {
            let indices = reference
                .sections
                .iter()
                .enumerate()
                .filter(|(_, s)| s.size != 0)
                .map(|(idx, _)| idx)
                .collect::<Vec<_>>();
            ensure!(
                indices.len() == elf_sections.len(),
                "Section count mismatch: original module has {} sections, but ELF has {} ({})",
                indices.len(),
                elf_sections.len(),
                elf_sections.iter().filter_map(|s| s.name().ok()).join(", ")
            );
            (reference.sections.len(), indices)
        }
        None => (file.sections().count() + 1, elf_sections.iter().map(|s| s.index().0).collect()),
    };
    let section_map = elf_sections
        .iter()
        .zip(&indices)
        .map(|(section, &idx)| (section.index(), idx))
        .collect::<FxHashMap<_, _>>();

    let mut sections = vec![RsoSection::default(); num_sections];
    let mut align = vec![0u32; num_sections];
    for (section, &idx) in elf_sections.iter().zip(&indices) {
        let out = sections.get_mut(idx).context("Section index out of range")?;
        out.size = section.size() as u32;
        if section.kind() != SectionKind::UninitializedData {
            out.data = section.data()?.to_vec();
            ensure!(out.data.len() as u64 == section.size(), "Section data size mismatch");
        }
        align[idx] = section.align() as u32;
    }

    let mut module = RsoModule { is_sel: false, version: 1, name, sections, ..Default::default() };
    module.layout_sections(&align);

    // Locates a defined symbol's RSO section index and section-relative offset
    let locate = |symbol: &object::Symbol| -> Result<(u32, u32)> {
        match symbol.section() {
            SymbolSection::Section(section_index) => {
                let &idx = section_map.get(&section_index).with_context(|| {
                    format!(
                        "Symbol '{}' is in section '{}', which is not part of the RSO",
                        symbol.name().unwrap_or("[invalid]"),
                        file.section_by_index(section_index)
                            .and_then(|s| s.name())
                            .unwrap_or("[invalid]")
                    )
                })?;
                Ok((idx as u32, symbol.address() as u32))
            }
            section => bail!(
                "Unsupported section {:?} for symbol '{}'",
                section,
                symbol.name().unwrap_or("[invalid]")
            ),
        }
    };

    let mut defined = FxHashMap::<&str, object::Symbol>::default();
    for symbol in file.symbols() {
        if symbol.is_undefined() || symbol.is_local() {
            continue;
        }
        if let Ok(name) = symbol.name() {
            defined.entry(name).or_insert(symbol);
        }
    }
    let entry = |name: &str| -> Result<Option<(u8, u32)>> {
        defined
            .get(name)
            .map(|symbol| locate(symbol).map(|(section, offset)| (section as u8, offset)))
            .transpose()
    };
    module.prolog = entry("_prolog")?;
    module.epilog = entry("_epilog")?;
    module.unresolved = entry("_unresolved")?;

    // Exports
    let mut out_exports = Vec::new();
    for name in export_names(reference, exports) {
        let symbol =
            defined.get(name.as_str()).with_context(|| format!("Symbol '{name}' not found"))?;
        let (section, offset) = if symbol.section() == SymbolSection::Absolute {
            (DOL_SECTION_ABS, symbol.address() as u32)
        } else {
            locate(symbol)?
        };
        out_exports.push(RsoExport { name, section, offset });
    }
    (module.exports, module.export_name_order) = finish_exports(out_exports);

    // Relocations. External relocations reference the ELF symbol index until imports are
    // finalized below.
    let mut internal = Vec::<RsoRelocation>::new();
    let mut external = Vec::<(u32, u8, SymbolIndex)>::new();
    for (section, &idx) in elf_sections.iter().zip(&indices) {
        let section_offset = module.sections[idx].offset;
        for (address, reloc) in section.relocations() {
            let object::RelocationTarget::Symbol(symbol_index) = reloc.target() else {
                bail!("Unsupported relocation target at {}:{:#X}", section.name()?, address);
            };
            let object::RelocationFlags::Elf { r_type } = reloc.flags() else {
                bail!("Unsupported relocation flags at {}:{:#X}", section.name()?, address);
            };
            if r_type == R_PPC_NONE {
                continue;
            }
            ensure!(
                section.kind() != SectionKind::UninitializedData,
                "Relocation in uninitialized section {}",
                section.name()?
            );
            let r_type = u8::try_from(r_type)
                .ok()
                .with_context(|| format!("Unsupported relocation type {r_type}"))?;
            let offset = section_offset + address as u32;
            let symbol = file.symbol_by_index(symbol_index)?;
            if symbol.is_undefined() {
                external.push((offset, r_type, symbol_index));
            } else {
                let (target_section, symbol_offset) = locate(&symbol)?;
                internal.push(RsoRelocation::new(
                    offset,
                    target_section,
                    r_type,
                    (symbol_offset as i64 + reloc.addend()) as u32,
                ));
            }
        }
    }

    // Imports: every undefined symbol that's referenced by a relocation. They're ordered to
    // match the original module (if any), then by ELF symbol index.
    let mut import_symbols = external.iter().map(|&(_, _, idx)| idx).collect::<Vec<_>>();
    import_symbols.sort_unstable_by_key(|idx| idx.0);
    import_symbols.dedup();
    let import_names = import_symbols
        .iter()
        .map(|&idx| Ok(file.symbol_by_index(idx)?.name()?))
        .collect::<Result<Vec<&str>>>()?;
    let import_order =
        order_by_reference(&import_names, reference.map(|r| r.imports.iter().map(|s| s.as_str())));
    let mut import_index = FxHashMap::<SymbolIndex, u32>::default();
    for (new_idx, &old_idx) in import_order.iter().enumerate() {
        import_index.insert(import_symbols[old_idx], new_idx as u32);
        module.imports.push(import_names[old_idx].to_string());
    }

    internal.sort_by_key(|r| r.offset());
    external.sort_by_key(|&(offset, _, _)| offset);
    let mut external = external
        .into_iter()
        .map(|(offset, r_type, symbol)| {
            RsoRelocation::new(offset, import_index[&symbol], r_type, 0)
        })
        .collect::<Vec<_>>();
    // Match the (unstable) sort used by the official tooling
    msvc_qsort(&mut external, |a, b| a.id().cmp(&b.id()));

    if patch_unresolved {
        // Point unresolved calls at the `_unresolved` function
        if let Some((unresolved_section, unresolved_offset)) = module.unresolved {
            let section = &mut module.sections[unresolved_section as usize];
            let range = section.offset..section.offset + section.size;
            for reloc in &external {
                if reloc.rel_type() as u32 != R_PPC_REL24 || !range.contains(&reloc.offset()) {
                    continue;
                }
                let address = reloc.offset() - section.offset;
                let data = &mut section.data[address as usize..address as usize + 4];
                let ins = u32::from_be_bytes(data.try_into().unwrap());
                let diff = unresolved_offset.wrapping_sub(address);
                data.copy_from_slice(&((diff & 0x3fffffc) | (ins & 0xfc000003)).to_be_bytes());
            }
        }
    }

    module.internal_relocations = internal;
    module.external_relocations = external;
    Ok(module)
}
