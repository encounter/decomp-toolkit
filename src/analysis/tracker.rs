use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    mem::take,
};

use anyhow::{bail, Result};
use ppc750cl::Opcode;

use crate::{
    analysis::{
        executor::{ExecCbData, ExecCbResult, Executor},
        uniq_jump_table_entries,
        vm::{is_store_op, BranchTarget, GprValue, StepResult, VM},
    },
    obj::{
        ObjDataKind, ObjInfo, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
};

#[derive(Debug, Copy, Clone)]
pub enum Relocation {
    Ha(u32),
    Hi(u32),
    Lo(u32),
    Sda21(u32),
    Rel14(u32),
    Rel24(u32),
    Absolute(u32),
}

#[derive(Debug)]
pub enum DataKind {
    Unknown = -1,
    Word,
    Half,
    Byte,
    Float,
    Double,
    // String,
    // String16,
}

pub struct Tracker {
    processed_functions: BTreeSet<u32>,
    sda2_base: u32, // r2
    sda_base: u32,  // r13
    pub relocations: BTreeMap<u32, Relocation>,
    data_types: BTreeMap<u32, DataKind>,
    stack_address: Option<u32>,
    stack_end: Option<u32>,
    db_stack_addr: Option<u32>,
    arena_lo: Option<u32>,
    arena_hi: Option<u32>,
    pub ignore_addresses: BTreeSet<u32>,
    pub known_relocations: BTreeSet<u32>,

    stores_to: BTreeSet<u32>, // for determining data vs rodata, sdata(2)/sbss(2)
    sda_to: BTreeSet<u32>,    // for determining data vs sdata
    hal_to: BTreeSet<u32>,    // for determining data vs sdata
}

impl Tracker {
    pub fn new(obj: &ObjInfo) -> Tracker {
        Self {
            processed_functions: Default::default(),
            sda2_base: obj.sda2_base.unwrap(),
            sda_base: obj.sda_base.unwrap(),
            relocations: Default::default(),
            data_types: Default::default(),
            stack_address: obj.stack_address,
            stack_end: obj.stack_end.or_else(|| {
                // Stack ends after all BSS sections
                obj.sections
                    .iter()
                    .rfind(|s| s.kind == ObjSectionKind::Bss)
                    .map(|s| (s.address + s.size) as u32)
            }),
            db_stack_addr: obj.db_stack_addr,
            arena_lo: obj
                .arena_lo
                .or_else(|| obj.db_stack_addr.map(|db_stack_addr| (db_stack_addr + 0x1F) & !0x1F)),
            arena_hi: Some(obj.arena_hi.unwrap_or(0x81700000)),
            ignore_addresses: Default::default(),
            known_relocations: Default::default(),
            stores_to: Default::default(),
            sda_to: Default::default(),
            hal_to: Default::default(),
        }
    }

    pub fn process(&mut self, obj: &ObjInfo) -> Result<()> {
        log::debug!("Processing code sections");
        self.process_code(obj)?;
        for section in &obj.sections {
            if matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData) {
                log::debug!("Processing section {}, address {:#X}", section.index, section.address);
                self.process_data(obj, section)?;
            }
        }
        Ok(())
    }

    fn process_code(&mut self, obj: &ObjInfo) -> Result<()> {
        self.process_function_by_address(obj, obj.entry as u32)?;
        for section in obj.sections.iter().filter(|s| s.kind == ObjSectionKind::Code) {
            for (_, symbol) in obj
                .symbols
                .for_range(section.address as u32..(section.address + section.size) as u32)
                .filter(|(_, symbol)| symbol.kind == ObjSymbolKind::Function && symbol.size_known)
            {
                let addr = symbol.address as u32;
                if !self.processed_functions.insert(addr) {
                    continue;
                }
                self.process_function(obj, symbol)?;
            }
        }
        Ok(())
    }

    fn process_function_by_address(&mut self, obj: &ObjInfo, addr: u32) -> Result<()> {
        if self.processed_functions.contains(&addr) {
            return Ok(());
        }
        self.processed_functions.insert(addr);
        if let Some((_, symbol)) = obj
            .symbols
            .at_address(addr)
            .find(|(_, symbol)| symbol.kind == ObjSymbolKind::Function && symbol.size_known)
        {
            self.process_function(obj, symbol)?;
        } else {
            log::warn!("Failed to locate function symbol @ {:#010X}", addr);
        }
        Ok(())
    }

    fn instruction_callback(
        &mut self,
        data: ExecCbData,
        obj: &ObjInfo,
        function_start: u32,
        function_end: u32,
        possible_missed_branches: &mut BTreeMap<u32, Box<VM>>,
    ) -> Result<ExecCbResult<()>> {
        let ExecCbData { executor, vm, result, section: _, ins, block_start: _ } = data;
        let is_function_addr = |addr: u32| addr >= function_start && addr < function_end;

        match result {
            StepResult::Continue => {
                match ins.op {
                    // addi rD, rA, SIMM
                    Opcode::Addi | Opcode::Addic | Opcode::Addic_ => {
                        let source = ins.field_rA();
                        let target = ins.field_rD();
                        if let GprValue::Constant(value) = vm.gpr[target].value {
                            if self.is_valid_address(obj, ins.addr, value) {
                                if (source == 2
                                    && vm.gpr[2].value == GprValue::Constant(self.sda2_base))
                                    || (source == 13
                                        && vm.gpr[13].value == GprValue::Constant(self.sda_base))
                                {
                                    self.relocations.insert(ins.addr, Relocation::Sda21(value));
                                    self.sda_to.insert(value);
                                } else if let (Some(hi_addr), Some(lo_addr)) =
                                    (vm.gpr[target].hi_addr, vm.gpr[target].lo_addr)
                                {
                                    let hi_reloc = self.relocations.get(&hi_addr.get()).cloned();
                                    if hi_reloc.is_none() {
                                        self.relocations
                                            .insert(hi_addr.get(), Relocation::Ha(value));
                                    }
                                    let lo_reloc = self.relocations.get(&lo_addr.get()).cloned();
                                    if lo_reloc.is_none() {
                                        self.relocations
                                            .insert(lo_addr.get(), Relocation::Lo(value));
                                    }
                                    self.hal_to.insert(value);
                                }
                            }
                        }
                    }
                    // ori rA, rS, UIMM
                    Opcode::Ori => {
                        let target = ins.field_rA();
                        if let GprValue::Constant(value) = vm.gpr[target].value {
                            if self.is_valid_address(obj, ins.addr, value) {
                                if let (Some(hi_addr), Some(lo_addr)) =
                                    (vm.gpr[target].hi_addr, vm.gpr[target].lo_addr)
                                {
                                    let hi_reloc = self.relocations.get(&hi_addr.get()).cloned();
                                    if hi_reloc.is_none() {
                                        self.relocations
                                            .insert(hi_addr.get(), Relocation::Hi(value));
                                    }
                                    let lo_reloc = self.relocations.get(&lo_addr.get()).cloned();
                                    if lo_reloc.is_none() {
                                        self.relocations
                                            .insert(lo_addr.get(), Relocation::Lo(value));
                                    }
                                    self.hal_to.insert(value);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                Ok(ExecCbResult::Continue)
            }
            StepResult::LoadStore { address, source, source_reg } => {
                if self.is_valid_address(obj, ins.addr, address) {
                    if (source_reg == 2 && source.value == GprValue::Constant(self.sda2_base))
                        || (source_reg == 13 && source.value == GprValue::Constant(self.sda_base))
                    {
                        self.relocations.insert(ins.addr, Relocation::Sda21(address));
                        self.sda_to.insert(address);
                    } else {
                        match (source.hi_addr, source.lo_addr) {
                            (Some(hi_addr), None) => {
                                let hi_reloc = self.relocations.get(&hi_addr.get()).cloned();
                                if hi_reloc.is_none() {
                                    self.relocations.insert(hi_addr.get(), Relocation::Ha(address));
                                }
                                if hi_reloc.is_none()
                                    || matches!(hi_reloc, Some(Relocation::Ha(v)) if v == address)
                                {
                                    self.relocations.insert(ins.addr, Relocation::Lo(address));
                                }
                                self.hal_to.insert(address);
                            }
                            (Some(hi_addr), Some(lo_addr)) => {
                                let hi_reloc = self.relocations.get(&hi_addr.get()).cloned();
                                if hi_reloc.is_none() {
                                    self.relocations.insert(hi_addr.get(), Relocation::Ha(address));
                                }
                                let lo_reloc = self.relocations.get(&lo_addr.get()).cloned();
                                if lo_reloc.is_none() {
                                    self.relocations.insert(lo_addr.get(), Relocation::Lo(address));
                                }
                                self.hal_to.insert(address);
                            }
                            _ => {}
                        }
                    }
                    self.data_types.insert(address, data_kind_from_op(ins.op));
                    if is_store_op(ins.op) {
                        self.stores_to.insert(address);
                    }
                }
                Ok(ExecCbResult::Continue)
            }
            StepResult::Illegal => bail!(
                "Illegal instruction hit @ {:#010X} (function {:#010X}-{:#010X})",
                ins.addr,
                function_start,
                function_end
            ),
            StepResult::Jump(target) => match target {
                BranchTarget::Unknown | BranchTarget::Return => Ok(ExecCbResult::EndBlock),
                BranchTarget::Address(addr) => {
                    let next_addr = ins.addr + 4;
                    if next_addr < function_end {
                        possible_missed_branches.insert(ins.addr + 4, vm.clone_all());
                    }
                    if is_function_addr(addr) {
                        Ok(ExecCbResult::Jump(addr))
                    } else {
                        self.relocations.insert(ins.addr, Relocation::Rel24(addr));
                        Ok(ExecCbResult::EndBlock)
                    }
                }
                BranchTarget::JumpTable { address, size } => {
                    let (entries, _) = uniq_jump_table_entries(
                        obj,
                        address,
                        size,
                        ins.addr,
                        function_start,
                        function_end,
                    )?;
                    for target in entries {
                        if is_function_addr(target) {
                            executor.push(target, vm.clone_all(), true);
                        }
                    }
                    Ok(ExecCbResult::EndBlock)
                }
            },
            StepResult::Branch(branches) => {
                for branch in branches {
                    match branch.target {
                        BranchTarget::Unknown | BranchTarget::Return => {}
                        BranchTarget::Address(addr) => {
                            if branch.link || !is_function_addr(addr) {
                                self.relocations.insert(ins.addr, match ins.op {
                                    Opcode::B => Relocation::Rel24(addr),
                                    _ => Relocation::Rel14(addr),
                                });
                            } else if is_function_addr(addr) {
                                executor.push(addr, branch.vm, true);
                            }
                        }
                        BranchTarget::JumpTable { .. } => {
                            bail!("Conditional jump table unsupported @ {:#010X}", ins.addr)
                        }
                    }
                }
                Ok(ExecCbResult::EndBlock)
            }
        }
    }

    pub fn process_function(&mut self, obj: &ObjInfo, symbol: &ObjSymbol) -> Result<()> {
        let function_start = symbol.address as u32;
        let function_end = (symbol.address + symbol.size) as u32;

        // The compiler can sometimes create impossible-to-reach branches,
        // but we still want to track them.
        let mut possible_missed_branches = BTreeMap::new();

        let mut executor = Executor::new(obj);
        executor.push(
            symbol.address as u32,
            VM::new_with_base(self.sda2_base, self.sda_base),
            false,
        );
        loop {
            executor.run(obj, |data| -> Result<ExecCbResult<()>> {
                self.instruction_callback(
                    data,
                    obj,
                    function_start,
                    function_end,
                    &mut possible_missed_branches,
                )
            })?;

            if possible_missed_branches.is_empty() {
                break;
            }
            let mut added = false;
            for (addr, vm) in take(&mut possible_missed_branches) {
                let section = match obj.section_at(addr) {
                    Ok(section) => section,
                    Err(_) => continue,
                };
                if !executor.visited(section, addr) {
                    executor.push(addr, vm, true);
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        Ok(())
    }

    fn process_data(&mut self, obj: &ObjInfo, section: &ObjSection) -> Result<()> {
        let mut addr = section.address as u32;
        for chunk in section.data.chunks_exact(4) {
            let value = u32::from_be_bytes(chunk.try_into()?);
            if self.is_valid_address(obj, addr, value) {
                self.relocations.insert(addr, Relocation::Absolute(value));
            }
            addr += 4;
        }
        Ok(())
    }

    fn is_valid_address(&self, obj: &ObjInfo, from: u32, addr: u32) -> bool {
        if self.ignore_addresses.contains(&addr) {
            return false;
        }
        if let Some((&start, &end)) = obj.blocked_ranges.range(..=from).last() {
            if from >= start && from < end {
                return false;
            }
        }
        if self.known_relocations.contains(&from) {
            return true;
        }
        if self.stack_address == Some(addr)
            || self.stack_end == Some(addr)
            || self.db_stack_addr == Some(addr)
            || self.arena_lo == Some(addr)
            || self.arena_hi == Some(addr)
            || self.sda2_base == addr
            || self.sda_base == addr
        {
            return true;
        }
        // if addr > 0x80000000 && addr < 0x80003100 {
        //     return true;
        // }
        if let Ok(section) = obj.section_at(addr) {
            // References to code sections will never be unaligned
            return section.kind != ObjSectionKind::Code || addr & 3 == 0;
        }
        false
    }

    fn special_symbol(
        &self,
        obj: &mut ObjInfo,
        addr: u32,
        reloc_kind: ObjRelocKind,
    ) -> Option<usize> {
        if !matches!(reloc_kind, ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo) {
            return None;
        }
        // HACK for RSOStaticLocateObject
        // for section in &obj.sections {
        //     if addr == section.address as u32 {
        //         let name = format!("_f_{}", section.name.trim_start_matches('.'));
        //         return generate_special_symbol(obj, addr, &name).ok();
        //     }
        // }
        let mut check_symbol = |opt: Option<u32>, name: &str| -> Option<usize> {
            if let Some(value) = opt {
                if addr == value {
                    return generate_special_symbol(obj, value, name).ok();
                }
            }
            None
        };
        check_symbol(self.stack_address, "_stack_addr")
            .or_else(|| check_symbol(self.stack_end, "_stack_end"))
            .or_else(|| check_symbol(self.arena_lo, "__ArenaLo"))
            .or_else(|| check_symbol(self.arena_hi, "__ArenaHi"))
            .or_else(|| check_symbol(self.db_stack_addr, "_db_stack_addr"))
            .or_else(|| check_symbol(Some(self.sda2_base), "_SDA2_BASE_"))
            .or_else(|| check_symbol(Some(self.sda_base), "_SDA_BASE_"))
    }

    pub fn apply(&self, obj: &mut ObjInfo, replace: bool) -> Result<()> {
        fn apply_section_name(section: &mut ObjSection, name: &str) {
            let module_id = if let Some((_, b)) = section.name.split_once(':') {
                b.parse::<u32>().unwrap_or(0)
            } else {
                0
            };
            let new_name =
                if module_id == 0 { name.to_string() } else { format!("{}:{}", name, module_id) };
            log::debug!("Renaming {} to {}", section.name, new_name);
            section.name = new_name;
        }

        for section in &mut obj.sections {
            if !section.section_known {
                if section.kind == ObjSectionKind::Code {
                    apply_section_name(section, ".text");
                    continue;
                }
                let start = section.address as u32;
                let end = (section.address + section.size) as u32;
                if self.sda_to.range(start..end).next().is_some() {
                    if self.stores_to.range(start..end).next().is_some() {
                        if section.kind == ObjSectionKind::Bss {
                            apply_section_name(section, ".sbss");
                        } else {
                            apply_section_name(section, ".sdata");
                        }
                    } else if section.kind == ObjSectionKind::Bss {
                        apply_section_name(section, ".sbss2");
                    } else {
                        apply_section_name(section, ".sdata2");
                        section.kind = ObjSectionKind::ReadOnlyData;
                    }
                } else if self.hal_to.range(start..end).next().is_some() {
                    if section.kind == ObjSectionKind::Bss {
                        apply_section_name(section, ".bss");
                    } else if self.stores_to.range(start..end).next().is_some() {
                        apply_section_name(section, ".data");
                    } else {
                        apply_section_name(section, ".rodata");
                        section.kind = ObjSectionKind::ReadOnlyData;
                    }
                }
            }
        }

        let mut relocation_maps = Vec::new();
        for section in &obj.sections {
            relocation_maps.push(section.build_relocation_map()?);
        }

        for (addr, reloc) in &self.relocations {
            let addr = *addr;
            let (reloc_kind, target) = match *reloc {
                Relocation::Ha(v) => (ObjRelocKind::PpcAddr16Ha, v),
                Relocation::Hi(v) => (ObjRelocKind::PpcAddr16Hi, v),
                Relocation::Lo(v) => (ObjRelocKind::PpcAddr16Lo, v),
                Relocation::Sda21(v) => (ObjRelocKind::PpcEmbSda21, v),
                Relocation::Rel14(v) => (ObjRelocKind::PpcRel14, v),
                Relocation::Rel24(v) => (ObjRelocKind::PpcRel24, v),
                Relocation::Absolute(v) => (ObjRelocKind::Absolute, v),
            };
            let data_kind = self
                .data_types
                .get(&target)
                .map(|dt| match dt {
                    DataKind::Unknown => ObjDataKind::Unknown,
                    DataKind::Word => ObjDataKind::Byte4,
                    DataKind::Half => ObjDataKind::Byte2,
                    DataKind::Byte => ObjDataKind::Byte,
                    DataKind::Float => ObjDataKind::Float,
                    DataKind::Double => ObjDataKind::Double,
                })
                .unwrap_or_default();
            let (target_symbol, addend) =
                if let Some(symbol) = self.special_symbol(obj, target, reloc_kind) {
                    (symbol, 0)
                } else {
                    let target_section = match obj.sections.iter().find(|s| {
                        target >= s.address as u32 && target < (s.address + s.size) as u32
                    }) {
                        Some(v) => v,
                        None => continue,
                    };
                    if let Some((symbol_idx, symbol)) =
                        obj.symbols.for_relocation(target, reloc_kind)?
                    {
                        let symbol_address = symbol.address;
                        // TODO meh
                        if data_kind != ObjDataKind::Unknown
                            && symbol.data_kind == ObjDataKind::Unknown
                            && symbol_address as u32 == target
                        {
                            obj.symbols
                                .replace(symbol_idx, ObjSymbol { data_kind, ..symbol.clone() })?;
                        }
                        (symbol_idx, target as i64 - symbol_address as i64)
                    } else {
                        // Create a new label
                        let symbol_idx = obj.symbols.add_direct(ObjSymbol {
                            name: format!("lbl_{:08X}", target),
                            demangled_name: None,
                            address: target as u64,
                            section: Some(target_section.index),
                            size: 0,
                            size_known: false,
                            flags: Default::default(),
                            kind: Default::default(),
                            align: None,
                            data_kind,
                        })?;
                        (symbol_idx, 0)
                    }
                };
            let reloc = ObjReloc { kind: reloc_kind, address: addr as u64, target_symbol, addend };
            let section = match obj
                .sections
                .iter_mut()
                .find(|s| addr >= s.address as u32 && addr < (s.address + s.size) as u32)
            {
                Some(v) => v,
                None => bail!(
                    "Failed to locate source section for relocation @ {:#010X} {:#010X?}",
                    addr,
                    reloc
                ),
            };

            let reloc_map = &mut relocation_maps[section.index];
            match reloc_map.entry(addr) {
                Entry::Vacant(e) => {
                    e.insert(section.relocations.len());
                    section.relocations.push(reloc);
                }
                Entry::Occupied(e) => {
                    let reloc_symbol = obj.symbols.at(reloc.target_symbol);
                    if reloc_symbol.name != "_unresolved" {
                        let v = &mut section.relocations[*e.get()];
                        let iter_symbol = obj.symbols.at(v.target_symbol);
                        if iter_symbol.address as i64 + v.addend
                            != reloc_symbol.address as i64 + reloc.addend
                        {
                            bail!(
                                "Conflicting relocations (target {:#010X}): {:#010X?} ({}) != {:#010X?} ({})",
                                target,
                                v,
                                iter_symbol.name,
                                reloc,
                                reloc_symbol.name
                            );
                        }
                        if replace {
                            *v = reloc;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn data_kind_from_op(op: Opcode) -> DataKind {
    match op {
        Opcode::Lbz => DataKind::Byte,
        Opcode::Lbzu => DataKind::Byte,
        Opcode::Lbzux => DataKind::Byte,
        Opcode::Lbzx => DataKind::Byte,
        Opcode::Lfd => DataKind::Double,
        Opcode::Lfdu => DataKind::Double,
        Opcode::Lfdux => DataKind::Double,
        Opcode::Lfdx => DataKind::Double,
        Opcode::Lfs => DataKind::Float,
        Opcode::Lfsu => DataKind::Float,
        Opcode::Lfsux => DataKind::Float,
        Opcode::Lfsx => DataKind::Float,
        Opcode::Lha => DataKind::Half,
        Opcode::Lhau => DataKind::Half,
        Opcode::Lhaux => DataKind::Half,
        Opcode::Lhax => DataKind::Half,
        Opcode::Lhbrx => DataKind::Half,
        Opcode::Lhz => DataKind::Half,
        Opcode::Lhzu => DataKind::Half,
        Opcode::Lhzux => DataKind::Half,
        Opcode::Lhzx => DataKind::Half,
        Opcode::Lwz => DataKind::Word,
        Opcode::Lwzu => DataKind::Word,
        Opcode::Lwzux => DataKind::Word,
        Opcode::Lwzx => DataKind::Word,
        Opcode::Stb => DataKind::Byte,
        Opcode::Stbu => DataKind::Byte,
        Opcode::Stbux => DataKind::Byte,
        Opcode::Stbx => DataKind::Byte,
        Opcode::Stfd => DataKind::Double,
        Opcode::Stfdu => DataKind::Double,
        Opcode::Stfdux => DataKind::Double,
        Opcode::Stfdx => DataKind::Double,
        Opcode::Stfiwx => DataKind::Float,
        Opcode::Stfs => DataKind::Float,
        Opcode::Stfsu => DataKind::Float,
        Opcode::Stfsux => DataKind::Float,
        Opcode::Stfsx => DataKind::Float,
        Opcode::Sth => DataKind::Half,
        Opcode::Sthbrx => DataKind::Half,
        Opcode::Sthu => DataKind::Half,
        Opcode::Sthux => DataKind::Half,
        Opcode::Sthx => DataKind::Half,
        Opcode::Stw => DataKind::Word,
        Opcode::Stwbrx => DataKind::Word,
        Opcode::Stwcx_ => DataKind::Word,
        Opcode::Stwu => DataKind::Word,
        Opcode::Stwux => DataKind::Word,
        Opcode::Stwx => DataKind::Word,
        _ => DataKind::Unknown,
    }
}

fn generate_special_symbol(obj: &mut ObjInfo, addr: u32, name: &str) -> Result<usize> {
    obj.add_symbol(
        ObjSymbol {
            name: name.to_string(),
            address: addr as u64,
            size: 0,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        },
        true,
    )
}
