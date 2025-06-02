use std::{
    collections::{hash_map, HashMap},
    io::Cursor,
    num::NonZeroU64,
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use cwdemangle::demangle;
use flagset::Flags;
use indexmap::IndexMap;
use objdiff_core::obj::split_meta::{SplitMeta, SHT_SPLITMETA, SPLITMETA_SECTION};
use object::{
    elf,
    elf::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_LOUSER, SHT_NOBITS, SHT_PROGBITS},
    write::{
        elf::{ProgramHeader, Rel, SectionHeader, SectionIndex, SymbolIndex, Writer},
        StringId,
    },
    Architecture, Endianness, File, Object, ObjectKind, ObjectSection, ObjectSymbol, Relocation,
    RelocationFlags, RelocationTarget, SectionKind, Symbol, SymbolKind, SymbolScope, SymbolSection,
};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::{
    array_ref,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSplit, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
        SectionIndex as ObjSectionIndex, SymbolIndex as ObjSymbolIndex,
    },
    util::{
        comment::{CommentSym, MWComment},
        reader::{Endian, FromReader, ToWriter},
    },
    vfs::open_file,
};

pub const SHT_MWCATS: u32 = SHT_LOUSER + 0x4A2A82C2;

enum BoundaryState {
    /// Looking for a file symbol, any section symbols are queued
    LookForFile(Vec<(u64, String)>),
    /// Looking for section symbols
    LookForSections(String),
    /// Done with files and sections
    FilesEnded,
}

pub fn process_elf(path: &Utf8NativePath) -> Result<ObjInfo> {
    let mut file = open_file(path, true)?;
    let obj_file = File::parse(file.map()?)?;
    let architecture = match obj_file.architecture() {
        Architecture::PowerPc => ObjArchitecture::PowerPc,
        arch => bail!("Unexpected architecture: {arch:?}"),
    };
    ensure!(obj_file.endianness() == Endianness::Big, "Expected big endian");
    let kind = match obj_file.kind() {
        ObjectKind::Executable => ObjKind::Executable,
        ObjectKind::Relocatable => ObjKind::Relocatable,
        kind => bail!("Unexpected ELF type: {kind:?}"),
    };

    let mut obj_name = String::new();
    let mut stack_address: Option<u32> = None;
    let mut stack_end: Option<u32> = None;
    let mut db_stack_addr: Option<u32> = None;
    let mut arena_lo: Option<u32> = None;
    let mut arena_hi: Option<u32> = None;
    let mut sda_base: Option<u32> = None;
    let mut sda2_base: Option<u32> = None;

    let mut sections: Vec<ObjSection> = vec![];
    let mut section_indexes: Vec<Option<usize>> = vec![None /* ELF null section */];
    for section in obj_file.sections() {
        if section.size() == 0 {
            section_indexes.push(None);
            continue;
        }
        let section_name = section.name()?;
        let section_kind = match section.kind() {
            SectionKind::Text => ObjSectionKind::Code,
            SectionKind::Data => ObjSectionKind::Data,
            SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
            SectionKind::UninitializedData => ObjSectionKind::Bss,
            // SectionKind::Other if section_name == ".comment" => ObjSectionKind::Comment,
            _ => {
                section_indexes.push(None);
                continue;
            }
        };
        section_indexes.push(Some(sections.len()));
        sections.push(ObjSection {
            name: section_name.to_string(),
            kind: section_kind,
            address: section.address(),
            size: section.size(),
            data: section.uncompressed_data()?.to_vec(),
            align: section.align(),
            elf_index: section.index().0 as ObjSectionIndex,
            relocations: Default::default(),
            virtual_address: None, // Loaded from section symbol
            file_offset: section.file_range().map(|(v, _)| v).unwrap_or_default(),
            section_known: true,
            splits: Default::default(),
        });
    }

    let mw_comment = load_comment(&obj_file).unwrap_or_else(|e| {
        log::warn!("Failed to read .comment section: {e:#}");
        None
    });
    let split_meta = load_split_meta(&obj_file).unwrap_or_else(|e| {
        log::warn!("Failed to read .note.split section: {e:#}");
        None
    });

    let mut symbols: Vec<ObjSymbol> = vec![];
    let mut symbol_indexes: Vec<Option<ObjSymbolIndex>> = vec![None /* ELF null symbol */];
    let mut section_starts = IndexMap::<String, Vec<(u64, String)>>::new();
    let mut name_to_index = HashMap::<String, usize>::new(); // for resolving duplicate names
    let mut boundary_state = BoundaryState::LookForFile(Default::default());

    for symbol in obj_file.symbols() {
        // Locate linker-generated symbols
        let symbol_name = symbol.name()?;
        match symbol_name {
            "_stack_addr" => stack_address = Some(symbol.address() as u32),
            "_stack_end" => stack_end = Some(symbol.address() as u32),
            "_db_stack_addr" => db_stack_addr = Some(symbol.address() as u32),
            "__ArenaLo" => arena_lo = Some(symbol.address() as u32),
            "__ArenaHi" => arena_hi = Some(symbol.address() as u32),
            "_SDA_BASE_" => sda_base = Some(symbol.address() as u32),
            "_SDA2_BASE_" => sda2_base = Some(symbol.address() as u32),
            _ => {}
        };

        // MWCC has file symbol first, then sections
        // GCC has section symbols first, then file
        match symbol.kind() {
            SymbolKind::File => {
                let mut file_name = symbol_name.to_string();
                // Try to exclude precompiled header symbols
                // Make configurable eventually
                if file_name == "Precompiled.cpp"
                    || file_name == "stdafx.cpp"
                    || file_name.ends_with(".h")
                    || file_name.starts_with("Pch.")
                    || file_name.contains("precompiled_")
                    || file_name.contains("Precompiled")
                    || file_name.contains(".pch")
                    || file_name.contains("_PCH.")
                {
                    symbol_indexes.push(None);
                    continue;
                }
                if kind == ObjKind::Relocatable {
                    obj_name.clone_from(&file_name);
                }
                let sections = match section_starts.entry(file_name.clone()) {
                    indexmap::map::Entry::Occupied(_) => {
                        let index = match name_to_index.entry(file_name.clone()) {
                            hash_map::Entry::Occupied(e) => e.into_mut(),
                            hash_map::Entry::Vacant(e) => e.insert(0),
                        };
                        *index += 1;
                        let new_name = format!("{file_name}_{index}");
                        // log::info!("Renaming {} to {}", file_name, new_name);
                        file_name.clone_from(&new_name);
                        match section_starts.entry(new_name.clone()) {
                            indexmap::map::Entry::Occupied(_) => {
                                bail!("Duplicate filename '{}'", new_name)
                            }
                            indexmap::map::Entry::Vacant(e) => e.insert(Default::default()),
                        }
                    }
                    indexmap::map::Entry::Vacant(e) => e.insert(Default::default()),
                };
                match &mut boundary_state {
                    BoundaryState::LookForFile(queue) => {
                        if queue.is_empty() {
                            boundary_state = BoundaryState::LookForSections(file_name);
                        } else {
                            // Clears queue
                            sections.append(queue);
                        }
                    }
                    BoundaryState::LookForSections(_) => {
                        boundary_state = BoundaryState::LookForSections(file_name);
                    }
                    BoundaryState::FilesEnded => {
                        log::warn!("File symbol after files ended: '{}'", file_name);
                    }
                }
            }
            SymbolKind::Section => {
                let section_index = symbol
                    .section_index()
                    .ok_or_else(|| anyhow!("Section symbol without section"))?;

                // Resolve original address from split metadata
                if let Some(addr) = split_meta
                    .as_ref()
                    .and_then(|m| m.virtual_addresses.as_ref())
                    .and_then(|v| v.get(symbol.index().0).cloned())
                {
                    if let Some(section_index) = section_indexes[section_index.0] {
                        sections[section_index].virtual_address = Some(addr);
                    }
                }

                let section = obj_file.section_by_index(section_index)?;
                let section_name = section.name()?.to_string();
                match &mut boundary_state {
                    BoundaryState::LookForFile(queue) => {
                        queue.push((symbol.address(), section_name));
                    }
                    BoundaryState::LookForSections(file_name) => {
                        if section_indexes[section_index.0].is_some() {
                            let sections = section_starts
                                .get_mut(file_name)
                                .ok_or_else(|| anyhow!("Failed to create entry"))?;
                            sections.push((symbol.address(), section_name));
                        }
                    }
                    BoundaryState::FilesEnded => {
                        log::warn!(
                            "Section symbol after files ended: {} @ {:#010X}",
                            section_name,
                            symbol.address()
                        );
                    }
                }
            }
            _ => match symbol.section() {
                // Linker generated symbols indicate the end
                SymbolSection::Absolute => {
                    boundary_state = BoundaryState::FilesEnded;
                }
                SymbolSection::Section(section_index) => match &mut boundary_state {
                    BoundaryState::LookForFile(_) => {}
                    BoundaryState::LookForSections(file_name) => {
                        if section_indexes[section_index.0].is_some() {
                            let sections = section_starts
                                .get_mut(file_name)
                                .ok_or_else(|| anyhow!("Failed to create entry"))?;
                            let section = obj_file.section_by_index(section_index)?;
                            let section_name = section.name()?;
                            if let Some((addr, _)) = sections
                                .iter_mut()
                                .find(|(addr, name)| *addr == 0 && name == section_name)
                            {
                                // If the section symbol had address 0, determine address
                                // from first symbol within that section.
                                *addr = symbol.address();
                            } else if !sections.iter().any(|(_, name)| name == section_name) {
                                // Otherwise, if there was no section symbol, assume this
                                // symbol indicates the section address.
                                sections.push((symbol.address(), section_name.to_string()));
                            }
                        }
                    }
                    BoundaryState::FilesEnded => {}
                },
                SymbolSection::Common | SymbolSection::Undefined => {}
                _ => bail!("Unsupported symbol section type {symbol:?}"),
            },
        }

        // Generate symbols
        if matches!(symbol.kind(), SymbolKind::File)
            || matches!(symbol.section_index(), Some(idx) if section_indexes[idx.0].is_none())
        {
            symbol_indexes.push(None);
            continue;
        }
        symbol_indexes.push(Some(symbols.len() as ObjSymbolIndex));
        let comment_sym = mw_comment.as_ref().map(|(_, vec)| &vec[symbol.index().0 - 1]);
        symbols.push(to_obj_symbol(&obj_file, &symbol, &section_indexes, comment_sym)?);
    }

    let mut link_order = Vec::<ObjUnit>::new();
    if kind == ObjKind::Executable {
        // Link order is trivially deduced
        for file_name in section_starts.keys() {
            link_order.push(ObjUnit {
                name: file_name.clone(),
                autogenerated: false,
                comment_version: None,
                order: None,
            });
        }

        // Create a map of address -> file splits
        for (file_name, section_addrs) in section_starts {
            for (address, _) in section_addrs {
                let Some(section) = sections.iter_mut().find(|s| s.contains(address as u32)) else {
                    log::warn!(
                        "Failed to find section containing address {:#010X} in file {}",
                        address,
                        file_name
                    );
                    continue;
                };
                section.splits.push(address as u32, ObjSplit {
                    unit: file_name.clone(),
                    end: 0, // TODO
                    align: None,
                    common: false, // TODO
                    autogenerated: false,
                    skip: false,
                    rename: None,
                });
            }
        }

        // TODO rebuild common symbols
    }

    for section in obj_file.sections() {
        let out_section =
            match section_indexes[section.index().0].and_then(|idx| sections.get_mut(idx)) {
                Some(s) => s,
                None => continue,
            };
        // Generate relocations
        for (address, reloc) in section.relocations() {
            let Some(reloc) =
                to_obj_reloc(&obj_file, &symbol_indexes, &out_section.data, address, reloc)?
            else {
                continue;
            };
            out_section.relocations.insert(address as u32, reloc)?;
        }
    }

    let mut obj = ObjInfo::new(kind, architecture, obj_name, symbols, sections);
    obj.entry = NonZeroU64::new(obj_file.entry()).map(|n| n.get());
    obj.mw_comment = mw_comment.map(|(header, _)| header);
    obj.split_meta = split_meta;
    obj.sda2_base = sda2_base;
    obj.sda_base = sda_base;
    obj.stack_address = stack_address;
    obj.stack_end = stack_end;
    obj.db_stack_addr = db_stack_addr;
    obj.arena_lo = arena_lo;
    obj.arena_hi = arena_hi;
    obj.link_order = link_order;
    Ok(obj)
}

fn load_split_meta(obj_file: &File) -> Result<Option<SplitMeta>> {
    let Some(split_meta_section) = obj_file.section_by_name(SPLITMETA_SECTION) else {
        return Ok(None);
    };
    let data = split_meta_section.uncompressed_data()?;
    if data.is_empty() {
        return Ok(None);
    }
    let metadata =
        SplitMeta::from_section(split_meta_section, obj_file.endianness(), obj_file.is_64())?;
    log::debug!("Loaded .note.split section");
    Ok(Some(metadata))
}

fn load_comment(obj_file: &File) -> Result<Option<(MWComment, Vec<CommentSym>)>> {
    let Some(comment_section) = obj_file.section_by_name(".comment") else {
        return Ok(None);
    };
    let data = comment_section.uncompressed_data()?;
    if data.is_empty() {
        return Ok(None);
    }
    let mut reader = Cursor::new(&*data);
    let header = MWComment::from_reader(&mut reader, Endian::Big)?;
    log::debug!("Loaded .comment section header {:?}", header);
    CommentSym::from_reader(&mut reader, Endian::Big)?; // Null symbol
    let mut comment_syms = Vec::with_capacity(obj_file.symbols().count());
    for symbol in obj_file.symbols() {
        let comment_sym = CommentSym::from_reader(&mut reader, Endian::Big)?;
        log::debug!("Symbol {:?} -> Comment {:?}", symbol, comment_sym);
        comment_syms.push(comment_sym);
    }
    ensure!(data.len() == reader.position() as usize, "Section data not fully read");
    Ok(Some((header, comment_syms)))
}

pub fn write_elf(obj: &ObjInfo, export_all: bool) -> Result<Vec<u8>> {
    let mut out_data = Vec::new();
    let mut writer = Writer::new(Endianness::Big, false, &mut out_data);

    struct OutSection {
        index: SectionIndex,
        rela_index: Option<SectionIndex>,
        offset: usize,
        rela_offset: usize,
        name: StringId,
        rela_name: Option<StringId>,
        virtual_address: Option<u64>,
    }
    struct OutSymbol {
        #[allow(dead_code)]
        index: SymbolIndex,
        sym: object::write::elf::Sym,
    }

    writer.reserve_null_section_index();
    let mut out_sections: Vec<OutSection> = Vec::with_capacity(obj.sections.len() as usize);
    for (_, section) in obj.sections.iter() {
        let name = writer.add_section_name(section.name.as_bytes());
        let index = writer.reserve_section_index();
        out_sections.push(OutSection {
            index,
            rela_index: None,
            offset: 0,
            rela_offset: 0,
            name,
            rela_name: None,
            virtual_address: section.virtual_address,
        });
    }

    let mut rela_names: Vec<String> = vec![Default::default(); obj.sections.len() as usize];
    for (((_, section), out_section), rela_name) in
        obj.sections.iter().zip(&mut out_sections).zip(&mut rela_names)
    {
        if section.relocations.is_empty() {
            continue;
        }
        *rela_name = format!(".rela{}", section.name);
        out_section.rela_name = Some(writer.add_section_name(rela_name.as_bytes()));
        out_section.rela_index = Some(writer.reserve_section_index());
    }

    let symtab = writer.reserve_symtab_section_index();
    writer.reserve_strtab_section_index();
    writer.reserve_shstrtab_section_index();

    // Generate .comment section
    let mut comment_data = if let Some(mw_comment) = &obj.mw_comment {
        // Reserve section
        let name = writer.add_section_name(".comment".as_bytes());
        let index = writer.reserve_section_index();
        let out_section_idx = out_sections.len();
        out_sections.push(OutSection {
            index,
            rela_index: None,
            offset: 0,
            rela_offset: 0,
            name,
            rela_name: None,
            virtual_address: None,
        });

        // Generate .comment data
        let mut comment_data = Vec::<u8>::with_capacity(0x2C + obj.symbols.count() as usize * 8);
        mw_comment.to_writer_static(&mut comment_data, Endian::Big)?;
        // Null symbol
        CommentSym { align: 0, vis_flags: 0, active_flags: 0 }
            .to_writer_static(&mut comment_data, Endian::Big)?;
        Some((comment_data, out_section_idx))
    } else {
        None
    };

    // Generate .note.split section
    let mut split_meta = if let (Some(metadata), Some(_)) = (&obj.split_meta, &obj.mw_comment) {
        // Reserve section
        let name = writer.add_section_name(SPLITMETA_SECTION.as_bytes());
        let index = writer.reserve_section_index();
        let out_section_idx = out_sections.len();
        out_sections.push(OutSection {
            index,
            rela_index: None,
            offset: 0,
            rela_offset: 0,
            name,
            rela_name: None,
            virtual_address: None,
        });

        // Generate .note.split data
        let mut out = metadata.clone();
        out.virtual_addresses = Some(vec![
            0, // Null symbol
        ]);
        Some((out, out_section_idx))
    } else {
        None
    };

    let mut out_symbols: Vec<OutSymbol> = Vec::with_capacity(obj.symbols.count() as usize);
    let mut symbol_map = vec![None; obj.symbols.count() as usize];
    let mut section_symbol_offset = 0;
    let mut num_local = 0;

    // Add file symbol
    let obj_name;
    if !obj.name.is_empty() {
        // Only write filename
        obj_name = Path::new(&obj.name)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| obj.name.clone());

        let name_index = writer.add_string(obj_name.as_bytes());
        let index = writer.reserve_symbol_index(None);
        out_symbols.push(OutSymbol {
            index,
            sym: object::write::elf::Sym {
                name: Some(name_index),
                section: None,
                st_info: {
                    let st_type = elf::STT_FILE;
                    let st_bind = elf::STB_LOCAL;
                    (st_bind << 4) + st_type
                },
                st_other: elf::STV_DEFAULT,
                st_shndx: elf::SHN_ABS,
                st_value: 0,
                st_size: 0,
            },
        });
        if let Some((comment_data, _)) = &mut comment_data {
            CommentSym { align: 1, vis_flags: 0, active_flags: 0 }
                .to_writer_static(comment_data, Endian::Big)?;
        }
        if let Some(virtual_addresses) =
            split_meta.as_mut().and_then(|(m, _)| m.virtual_addresses.as_mut())
        {
            virtual_addresses.push(0);
        }
        section_symbol_offset += 1;
    }

    // Add section symbols for relocatable objects
    if obj.kind == ObjKind::Relocatable {
        for (section_index, section) in obj.sections.iter() {
            let out_section_index = out_sections.get(section_index as usize).map(|s| s.index);
            let index = writer.reserve_symbol_index(out_section_index);
            let sym = object::write::elf::Sym {
                name: None,
                section: out_section_index,
                st_info: (elf::STB_LOCAL << 4) + elf::STT_SECTION,
                st_other: elf::STV_DEFAULT,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            };
            num_local = writer.symbol_count();
            out_symbols.push(OutSymbol { index, sym });
            if let Some((comment_data, _)) = &mut comment_data {
                CommentSym { align: section.align as u32, vis_flags: 0, active_flags: 0 }
                    .to_writer_static(comment_data, Endian::Big)?;
            }
            if let Some(virtual_addresses) =
                split_meta.as_mut().and_then(|(m, _)| m.virtual_addresses.as_mut())
            {
                virtual_addresses.push(section.virtual_address.unwrap_or(0));
            }
        }
    }

    // Add symbols, starting with local symbols
    for (symbol_index, symbol) in obj
        .symbols
        .iter()
        .filter(|&(_, s)| s.flags.is_local())
        .chain(obj.symbols.iter().filter(|&(_, s)| !s.flags.is_local()))
    {
        if obj.kind == ObjKind::Relocatable && symbol.kind == ObjSymbolKind::Section {
            // We wrote section symbols above, so skip them here
            let section_index =
                symbol.section.ok_or_else(|| anyhow!("section symbol without section index"))?;
            symbol_map[symbol_index as usize] =
                Some(section_symbol_offset as ObjSectionIndex + section_index);
            continue;
        }

        let section = symbol.section.and_then(|idx| out_sections.get(idx as usize));
        let section_index = section.map(|s| s.index);
        let index = writer.reserve_symbol_index(section_index);
        let name_index = if symbol.name.is_empty() {
            None
        } else {
            Some(writer.add_string(symbol.name.as_bytes()))
        };
        let sym = object::write::elf::Sym {
            name: name_index,
            section: section_index,
            st_info: {
                let st_type = match symbol.kind {
                    ObjSymbolKind::Unknown => elf::STT_NOTYPE,
                    ObjSymbolKind::Function => elf::STT_FUNC,
                    ObjSymbolKind::Object => elf::STT_OBJECT,
                    ObjSymbolKind::Section => elf::STT_SECTION,
                };
                let st_bind = if symbol.flags.is_weak() {
                    elf::STB_WEAK
                } else if symbol.flags.is_local() {
                    elf::STB_LOCAL
                } else {
                    elf::STB_GLOBAL
                };
                (st_bind << 4) + st_type
            },
            st_other: if symbol.flags.is_hidden() { elf::STV_HIDDEN } else { elf::STV_DEFAULT },
            st_shndx: if section_index.is_some() {
                0
            } else if symbol.flags.is_common() {
                elf::SHN_COMMON
            } else if symbol.address != 0 {
                elf::SHN_ABS
            } else {
                elf::SHN_UNDEF
            },
            st_value: symbol.address,
            st_size: symbol.size,
        };
        if sym.st_info >> 4 == elf::STB_LOCAL {
            num_local = writer.symbol_count();
        }
        out_symbols.push(OutSymbol { index, sym });
        symbol_map[symbol_index as usize] = Some(index.0);
        if let Some((comment_data, _)) = &mut comment_data {
            CommentSym::from(symbol, export_all).to_writer_static(comment_data, Endian::Big)?;
        }
        if let Some(virtual_addresses) =
            split_meta.as_mut().and_then(|(m, _)| m.virtual_addresses.as_mut())
        {
            if let Some(section_vaddr) = section.and_then(|s| s.virtual_address) {
                virtual_addresses.push(section_vaddr + symbol.address);
            } else {
                virtual_addresses.push(0);
            }
        }
    }

    writer.reserve_file_header();

    if obj.kind == ObjKind::Executable {
        writer.reserve_program_headers(obj.sections.len());
    }

    for ((_, section), out_section) in obj.sections.iter().zip(&mut out_sections) {
        if section.kind == ObjSectionKind::Bss {
            continue;
        }
        ensure!(section.data.len() as u64 == section.size);
        if section.size == 0 {
            // Bug in Writer::reserve doesn't align when len is 0
            let offset = (writer.reserved_len() + 31) & !31;
            writer.reserve_until(offset);
            out_section.offset = offset;
        } else {
            out_section.offset = writer.reserve(section.data.len(), 32);
        }
    }

    for ((_, section), out_section) in obj.sections.iter().zip(&mut out_sections) {
        if section.relocations.is_empty() {
            continue;
        }
        out_section.rela_offset = writer.reserve_relocations(section.relocations.len(), true);
    }

    writer.reserve_symtab();
    writer.reserve_strtab();
    writer.reserve_shstrtab();

    // Reserve .comment section
    if let Some((comment_data, idx)) = &comment_data {
        let out_section = &mut out_sections[*idx];
        out_section.offset = writer.reserve(comment_data.len(), 32);
    }

    // Reserve .note.split section
    if let Some((metadata, idx)) = &split_meta {
        let out_section = &mut out_sections[*idx];
        out_section.offset = writer.reserve(metadata.write_size(false), 32);
    }

    writer.reserve_section_headers();

    writer.write_file_header(&object::write::elf::FileHeader {
        os_abi: elf::ELFOSABI_SYSV,
        abi_version: 0,
        e_type: match obj.kind {
            ObjKind::Executable => elf::ET_EXEC,
            ObjKind::Relocatable => elf::ET_REL,
        },
        e_machine: elf::EM_PPC,
        e_entry: obj.entry.unwrap_or(0),
        e_flags: elf::EF_PPC_EMB,
    })?;

    if obj.kind == ObjKind::Executable {
        writer.write_align_program_headers();
        for ((_, section), out_section) in obj.sections.iter().zip(&out_sections) {
            writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: match section.kind {
                    ObjSectionKind::Code => elf::PF_R | elf::PF_X,
                    ObjSectionKind::Data | ObjSectionKind::Bss => elf::PF_R | elf::PF_W,
                    ObjSectionKind::ReadOnlyData => elf::PF_R,
                },
                p_offset: out_section.offset as u64,
                p_vaddr: section.address,
                p_paddr: 0,
                p_filesz: match section.kind {
                    ObjSectionKind::Bss => 0,
                    _ => section.size,
                },
                p_memsz: section.size,
                p_align: 32,
            });
        }
    }

    for ((_, section), out_section) in obj.sections.iter().zip(&out_sections) {
        if section.kind == ObjSectionKind::Bss {
            continue;
        }
        writer.write_align(32);
        ensure!(writer.len() == out_section.offset);
        if obj.kind == ObjKind::Relocatable {
            write_relocatable_section_data(&mut writer, section)?;
        } else {
            writer.write(&section.data);
        }
    }

    for ((_, section), out_section) in obj.sections.iter().zip(&out_sections) {
        if section.relocations.is_empty() {
            continue;
        }
        writer.write_align_relocation();
        ensure!(writer.len() == out_section.rela_offset);
        for (addr, reloc) in section.relocations.iter() {
            let (r_offset, r_type) = reloc.to_elf(addr);
            let r_sym = symbol_map[reloc.target_symbol as usize]
                .ok_or_else(|| anyhow!("Relocation against stripped symbol"))?;
            writer.write_relocation(true, &Rel { r_offset, r_sym, r_type, r_addend: reloc.addend });
        }
    }

    writer.write_null_symbol();
    for out_symbol in &out_symbols {
        writer.write_symbol(&out_symbol.sym);
    }

    writer.write_strtab();
    writer.write_shstrtab();

    // Write comment section
    if let Some((comment_data, idx)) = &comment_data {
        let out_section = &out_sections[*idx];
        writer.write_align(32);
        ensure!(writer.len() == out_section.offset);
        writer.write(comment_data);
    }

    // Write .note.split section
    if let Some((metadata, idx)) = &split_meta {
        let out_section = &out_sections[*idx];
        writer.write_align(32);
        ensure!(writer.len() == out_section.offset);
        // object::write::elf::Writer doesn't implement std::io::Write...
        let mut data = Vec::with_capacity(metadata.write_size(false));
        metadata.to_writer(&mut data, object::BigEndian, false)?;
        writer.write(&data);
    }

    writer.write_null_section_header();
    for ((_, section), out_section) in obj.sections.iter().zip(&out_sections) {
        writer.write_section_header(&SectionHeader {
            name: Some(out_section.name),
            sh_type: match section.kind {
                ObjSectionKind::Code | ObjSectionKind::Data | ObjSectionKind::ReadOnlyData => {
                    SHT_PROGBITS
                }
                ObjSectionKind::Bss => SHT_NOBITS,
            },
            sh_flags: match section.kind {
                ObjSectionKind::Code => SHF_ALLOC | SHF_EXECINSTR,
                ObjSectionKind::Data | ObjSectionKind::Bss => SHF_ALLOC | SHF_WRITE,
                ObjSectionKind::ReadOnlyData => SHF_ALLOC,
            } as u64,
            sh_addr: section.address,
            sh_offset: out_section.offset as u64,
            sh_size: section.size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: section.align,
            sh_entsize: 0, // TODO?
        });
    }
    for ((_, section), out_section) in obj.sections.iter().zip(&out_sections) {
        let Some(rela_name) = out_section.rela_name else {
            continue;
        };
        writer.write_relocation_section_header(
            rela_name,
            out_section.index,
            symtab,
            out_section.rela_offset,
            section.relocations.len(),
            true,
        );
    }

    writer.write_symtab_section_header(num_local);
    writer.write_strtab_section_header();
    writer.write_shstrtab_section_header();

    // Write .comment section header
    if let Some((comment_data, idx)) = &comment_data {
        let out_section = &out_sections[*idx];
        writer.write_section_header(&SectionHeader {
            name: Some(out_section.name),
            sh_type: SHT_PROGBITS,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: out_section.offset as u64,
            sh_size: comment_data.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 1,
        });
    }

    // Write .note.split section header
    if let Some((metadata, idx)) = &split_meta {
        let out_section = &out_sections[*idx];
        let mut sh_type = SHT_SPLITMETA;
        if matches!(&obj.mw_comment, Some(comment) if comment.version < 14) {
            // Prior to mwld GC 3.0a3, the linker doesn't support ELF .note sections
            // properly. With GC 2.7, it crashes if the section type is SHT_NOTE.
            // Use the same section type as .mwcats.* so the linker ignores it.
            sh_type = SHT_MWCATS;
        }
        writer.write_section_header(&SectionHeader {
            name: Some(out_section.name),
            sh_type,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: out_section.offset as u64,
            sh_size: metadata.write_size(false) as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 4,
            sh_entsize: 0,
        });
    }

    ensure!(writer.reserved_len() == writer.len());
    Ok(out_data)
}

fn to_obj_symbol(
    obj_file: &object::File<'_>,
    symbol: &Symbol<'_, '_>,
    section_indexes: &[Option<usize>],
    comment_sym: Option<&CommentSym>,
) -> Result<ObjSymbol> {
    let section = match symbol.section_index() {
        Some(idx) => Some(obj_file.section_by_index(idx)?),
        None => None,
    };
    let name = match symbol.kind() {
        SymbolKind::Section => match &section {
            Some(section) => section.name()?,
            _ => bail!("Section symbol without section"),
        },
        _ => symbol.name()?,
    };
    ensure!(!name.is_empty(), "Empty symbol name");
    let mut flags = ObjSymbolFlagSet(ObjSymbolFlags::none());
    if symbol.is_global() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Global);
    }
    if symbol.is_local() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Local);
    }
    if symbol.is_common() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Common);
    }
    if symbol.is_weak() {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Weak);
    }
    if symbol.scope() == SymbolScope::Linkage {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Hidden);
    }
    if comment_sym.is_some_and(|c| c.active_flags & 0x8 != 0) {
        flags = ObjSymbolFlagSet(flags.0 | ObjSymbolFlags::Exported);
    }
    let section_idx = section.as_ref().and_then(|section| section_indexes[section.index().0]);
    Ok(ObjSymbol {
        name: name.to_string(),
        demangled_name: demangle(name, &Default::default()),
        address: symbol.address(),
        section: section_idx.map(|s| s as ObjSectionIndex),
        size: symbol.size(),
        size_known: true,
        flags,
        kind: match symbol.kind() {
            SymbolKind::Text => ObjSymbolKind::Function,
            SymbolKind::Data => ObjSymbolKind::Object,
            SymbolKind::Unknown | SymbolKind::Label => ObjSymbolKind::Unknown,
            SymbolKind::Section => ObjSymbolKind::Section,
            _ => bail!("Unsupported symbol kind: {:?}", symbol),
        },
        align: comment_sym.map(|c| c.align),
        ..Default::default()
    })
}

pub fn to_obj_reloc_kind(flags: RelocationFlags) -> Result<ObjRelocKind> {
    Ok(match flags {
        RelocationFlags::Elf { r_type } => match r_type {
            elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 => ObjRelocKind::Absolute,
            elf::R_PPC_ADDR16_LO => ObjRelocKind::PpcAddr16Lo,
            elf::R_PPC_ADDR16_HI => ObjRelocKind::PpcAddr16Hi,
            elf::R_PPC_ADDR16_HA => ObjRelocKind::PpcAddr16Ha,
            elf::R_PPC_REL24 => ObjRelocKind::PpcRel24,
            elf::R_PPC_REL14 => ObjRelocKind::PpcRel14,
            elf::R_PPC_EMB_SDA21 => ObjRelocKind::PpcEmbSda21,
            kind => bail!("Unhandled ELF relocation type: {kind}"),
        },
        flags => bail!("Unhandled relocation type: {:?}", flags),
    })
}

fn to_obj_reloc(
    obj_file: &object::File<'_>,
    symbol_indexes: &[Option<ObjSymbolIndex>],
    section_data: &[u8],
    address: u64,
    reloc: Relocation,
) -> Result<Option<ObjReloc>> {
    let reloc_kind = to_obj_reloc_kind(reloc.flags())?;
    let symbol = match reloc.target() {
        RelocationTarget::Symbol(idx) => {
            obj_file.symbol_by_index(idx).context("Failed to locate relocation target symbol")?
        }
        RelocationTarget::Absolute => {
            log::debug!("Skipping absolute relocation at {:#010X}", address);
            return Ok(None);
        }
        _ => {
            bail!("Unhandled relocation target: {:?} (address: {:#010X})", reloc.target(), address)
        }
    };
    let target_symbol = symbol_indexes[symbol.index().0]
        .ok_or_else(|| anyhow!("Relocation against stripped symbol: {symbol:?}"))?;
    let addend = match symbol.kind() {
        SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown | SymbolKind::Label => {
            Ok(reloc.addend())
        }
        SymbolKind::Section => {
            let addend = if reloc.has_implicit_addend() {
                let addend = u32::from_be_bytes(
                    section_data[address as usize..address as usize + 4].try_into()?,
                ) as i64;
                match reloc_kind {
                    ObjRelocKind::Absolute => addend,
                    _ => bail!("Unsupported implicit relocation type {reloc_kind:?}"),
                }
            } else {
                reloc.addend()
            };
            ensure!(addend >= 0, "Negative addend in section reloc: {addend}");
            Ok(addend)
        }
        _ => Err(anyhow!("Unhandled relocation symbol type {:?}", symbol.kind())),
    }?;
    Ok(Some(ObjReloc { kind: reloc_kind, target_symbol, addend, module: None }))
}

/// Writes section data while zeroing out relocations.
fn write_relocatable_section_data(w: &mut Writer, section: &ObjSection) -> Result<()> {
    ensure!(section.address == 0);
    let mut current_address = 0;
    for (addr, reloc) in section.relocations.iter() {
        w.write(&section.data[current_address..addr as usize]);
        let mut ins = u32::from_be_bytes(*array_ref!(section.data, addr as usize, 4));
        match reloc.kind {
            ObjRelocKind::Absolute => {
                ins = 0;
            }
            ObjRelocKind::PpcAddr16Hi | ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo => {
                ins &= !0xFFFF;
            }
            ObjRelocKind::PpcRel24 => {
                ins &= !0x3FFFFFC;
            }
            ObjRelocKind::PpcRel14 => {
                ins &= !0xFFFC;
            }
            ObjRelocKind::PpcEmbSda21 => {
                ins &= !0x1FFFFF;
            }
        }
        w.write(&ins.to_be_bytes());
        current_address = addr as usize + 4;
    }
    // Write remaining data
    w.write(&section.data[current_address..]);
    Ok(())
}

pub fn is_elf_file(path: &Utf8NativePathBuf) -> Result<bool> {
    let mut file = open_file(path, true)?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic)?;
    Ok(magic == elf::ELFMAG)
}
