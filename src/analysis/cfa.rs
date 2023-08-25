use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display, Formatter, UpperHex},
    ops::{Add, AddAssign, BitAnd, Sub},
};

use anyhow::{bail, ensure, Context, Result};

use crate::{
    analysis::{
        executor::{ExecCbData, ExecCbResult, Executor},
        skip_alignment,
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, GprValue, StepResult, VM},
    },
    obj::{ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionAddress {
    pub section: usize,
    pub address: u32,
}

impl Debug for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#X}", self.section as isize, self.address)
    }
}

impl Display for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#X}", self.section as isize, self.address)
    }
}

impl SectionAddress {
    pub fn new(section: usize, address: u32) -> Self { Self { section, address } }
}

impl Add<u32> for SectionAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self { section: self.section, address: self.address + rhs }
    }
}

impl Sub<u32> for SectionAddress {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        Self { section: self.section, address: self.address - rhs }
    }
}

impl AddAssign<u32> for SectionAddress {
    fn add_assign(&mut self, rhs: u32) { self.address += rhs; }
}

impl UpperHex for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#010X}", self.section as isize, self.address)
    }
}

impl BitAnd<u32> for SectionAddress {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output { self.address & rhs }
}

#[derive(Debug, Default)]
pub struct AnalyzerState {
    pub sda_bases: Option<(u32, u32)>,
    pub function_entries: BTreeSet<SectionAddress>,
    pub function_bounds: BTreeMap<SectionAddress, Option<SectionAddress>>,
    pub function_slices: BTreeMap<SectionAddress, FunctionSlices>,
    pub jump_tables: BTreeMap<SectionAddress, u32>,
    pub known_symbols: BTreeMap<SectionAddress, ObjSymbol>,
    pub known_sections: BTreeMap<usize, String>,
    pub non_finalized_functions: BTreeMap<SectionAddress, FunctionSlices>,
}

impl AnalyzerState {
    pub fn apply(&self, obj: &mut ObjInfo) -> Result<()> {
        for (&section_index, section_name) in &self.known_sections {
            obj.sections[section_index].rename(section_name.clone())?;
        }
        for (&start, &end) in &self.function_bounds {
            let Some(end) = end else { continue };
            let section = &obj.sections[start.section];
            ensure!(
                section.contains_range(start.address..end.address),
                "Function {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
                start.address,
                end,
                section.name,
                section.address,
                section.address + section.size
            );
            let name = if obj.module_id == 0 {
                format!("fn_{:08X}", start.address)
            } else {
                format!("fn_{}_{:X}", obj.module_id, start.address)
            };
            obj.add_symbol(
                ObjSymbol {
                    name,
                    demangled_name: None,
                    address: start.address as u64,
                    section: Some(start.section),
                    size: (end.address - start.address) as u64,
                    size_known: true,
                    flags: Default::default(),
                    kind: ObjSymbolKind::Function,
                    align: None,
                    data_kind: Default::default(),
                },
                false,
            )?;
        }
        for (&addr, &size) in &self.jump_tables {
            let section = &obj.sections[addr.section];
            ensure!(
                section.contains_range(addr.address..addr.address + size),
                "Jump table {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
                addr.address,
                addr.address + size,
                section.name,
                section.address,
                section.address + section.size
            );
            let address_str = if obj.module_id == 0 {
                format!("{:08X}", addr.address)
            } else {
                format!(
                    "{}_{}_{:X}",
                    obj.module_id,
                    section.name.trim_start_matches('.'),
                    addr.address
                )
            };
            obj.add_symbol(
                ObjSymbol {
                    name: format!("jumptable_{}", address_str),
                    demangled_name: None,
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size: size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                    kind: ObjSymbolKind::Object,
                    align: None,
                    data_kind: Default::default(),
                },
                false,
            )?;
        }
        for (&_addr, symbol) in &self.known_symbols {
            obj.add_symbol(symbol.clone(), true)?;
        }
        Ok(())
    }

    pub fn detect_functions(&mut self, obj: &ObjInfo) -> Result<()> {
        // Apply known functions from extab
        for (&addr, &size) in &obj.known_functions {
            let (section_index, _) = obj
                .sections
                .at_address(addr)
                .context(format!("Function {:#010X} outside of any section", addr))?;
            let addr_ref = SectionAddress::new(section_index, addr);
            self.function_entries.insert(addr_ref);
            self.function_bounds.insert(addr_ref, Some(addr_ref + size));
        }
        // Apply known functions from symbols
        for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
            let Some(section_index) = symbol.section else { continue };
            let addr_ref = SectionAddress::new(section_index, symbol.address as u32);
            self.function_entries.insert(addr_ref);
            if symbol.size_known {
                self.function_bounds.insert(addr_ref, Some(addr_ref + symbol.size as u32));
            }
        }
        // Also check the beginning of every code section
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            self.function_entries
                .insert(SectionAddress::new(section_index, section.address as u32));
        }

        // Process known functions first
        let known_functions = self.function_entries.clone();
        for addr in known_functions {
            self.process_function_at(obj, addr)?;
        }
        if let Some(entry) = obj.entry.map(|n| n as u32) {
            // Locate entry function bounds
            let (section_index, _) = obj
                .sections
                .at_address(entry)
                .context(format!("Entry point {:#010X} outside of any section", entry))?;
            self.process_function_at(obj, SectionAddress::new(section_index, entry))?;
        }
        // Locate bounds for referenced functions until none are left
        self.process_functions(obj)?;
        // Final pass(es)
        while self.finalize_functions(obj, true)? {
            self.process_functions(obj)?;
        }
        Ok(())
    }

    fn finalize_functions(&mut self, obj: &ObjInfo, finalize: bool) -> Result<bool> {
        let mut finalized = Vec::new();
        for (&addr, slices) in &mut self.non_finalized_functions {
            // log::info!("Trying to finalize {:#010X}", addr);
            let Some(function_start) = slices.start() else {
                bail!("Function slice without start @ {:#010X}", addr);
            };
            let function_end = slices.end();
            let mut current = SectionAddress::new(addr.section, 0);
            while let Some(&block) = slices.possible_blocks.range(current + 4..).next() {
                current = block;
                match slices.check_tail_call(
                    obj,
                    block,
                    function_start,
                    function_end,
                    &self.function_entries,
                ) {
                    TailCallResult::Not => {
                        log::trace!("Finalized block @ {:#010X}", block);
                        slices.possible_blocks.remove(&block);
                        slices.analyze(
                            obj,
                            block,
                            function_start,
                            function_end,
                            &self.function_entries,
                        )?;
                    }
                    TailCallResult::Is => {
                        log::trace!("Finalized tail call @ {:#010X}", block);
                        slices.possible_blocks.remove(&block);
                        slices.function_references.insert(block);
                    }
                    TailCallResult::Possible => {
                        if finalize {
                            log::trace!(
                                "Still couldn't determine {:#010X}, assuming non-tail-call",
                                block
                            );
                            slices.possible_blocks.remove(&block);
                            slices.analyze(
                                obj,
                                block,
                                function_start,
                                function_end,
                                &self.function_entries,
                            )?;
                        }
                    }
                    TailCallResult::Error(e) => return Err(e),
                }
            }
            if slices.can_finalize() {
                log::trace!("Finalizing {:#010X}", addr);
                slices.finalize(obj, &self.function_entries)?;
                self.function_entries.append(&mut slices.function_references.clone());
                self.jump_tables.append(&mut slices.jump_table_references.clone());
                let end = slices.end();
                self.function_bounds.insert(addr, end);
                self.function_slices.insert(addr, slices.clone());
                finalized.push(addr);
            }
        }
        let finalized_new = !finalized.is_empty();
        for addr in finalized {
            self.non_finalized_functions.remove(&addr);
        }
        Ok(finalized_new)
    }

    fn first_unbounded_function(&self) -> Option<SectionAddress> {
        let mut entries_iter = self.function_entries.iter().cloned();
        let mut bounds_iter = self.function_bounds.keys().cloned();
        let mut entry = entries_iter.next();
        let mut bound = bounds_iter.next();
        loop {
            match (entry, bound) {
                (Some(a), Some(b)) => {
                    if b < a {
                        bound = bounds_iter.next();
                        continue;
                    } else if a != b {
                        if self.non_finalized_functions.contains_key(&a) {
                            entry = entries_iter.next();
                            continue;
                        } else {
                            break Some(a);
                        }
                    }
                }
                (Some(a), None) => {
                    if self.non_finalized_functions.contains_key(&a) {
                        entry = entries_iter.next();
                        continue;
                    } else {
                        break Some(a);
                    }
                }
                _ => break None,
            }
            entry = entries_iter.next();
            bound = bounds_iter.next();
        }
    }

    fn process_functions(&mut self, obj: &ObjInfo) -> Result<()> {
        loop {
            match self.first_unbounded_function() {
                Some(addr) => {
                    log::trace!("Processing {:#010X}", addr);
                    self.process_function_at(obj, addr)?;
                }
                None => {
                    if !self.finalize_functions(obj, false)? && !self.detect_new_functions(obj)? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn process_function_at(&mut self, obj: &ObjInfo, addr: SectionAddress) -> Result<bool> {
        // if addr == 0 || addr == 0xFFFFFFFF {
        //     log::warn!("Tried to detect @ {:#010X}", addr);
        //     self.function_bounds.insert(addr, 0);
        //     return Ok(false);
        // }
        Ok(if let Some(mut slices) = self.process_function(obj, addr)? {
            self.function_entries.insert(addr);
            self.function_entries.append(&mut slices.function_references.clone());
            self.jump_tables.append(&mut slices.jump_table_references.clone());
            if slices.can_finalize() {
                slices.finalize(obj, &self.function_entries)?;
                self.function_bounds.insert(addr, slices.end());
                self.function_slices.insert(addr, slices);
            } else {
                self.non_finalized_functions.insert(addr, slices);
            }
            true
        } else {
            log::debug!("Not a function @ {:#010X}", addr);
            self.function_bounds.insert(addr, None);
            false
        })
    }

    fn process_function(
        &mut self,
        obj: &ObjInfo,
        start: SectionAddress,
    ) -> Result<Option<FunctionSlices>> {
        let mut slices = FunctionSlices::default();
        let function_end = self.function_bounds.get(&start).cloned().flatten();
        Ok(match slices.analyze(obj, start, start, function_end, &self.function_entries)? {
            true => Some(slices),
            false => None,
        })
    }

    fn detect_new_functions(&mut self, obj: &ObjInfo) -> Result<bool> {
        let mut found_new = false;
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            let section_start = SectionAddress::new(section_index, section.address as u32);
            let section_end = section_start + section.size as u32;
            let mut iter = self.function_bounds.range(section_start..section_end).peekable();
            loop {
                match (iter.next(), iter.peek()) {
                    (Some((&first_begin, &first_end)), Some(&(&second_begin, &second_end))) => {
                        let Some(first_end) = first_end else { continue };
                        if first_end > second_begin {
                            continue;
                        }
                        let addr = match skip_alignment(section, first_end, second_begin) {
                            Some(addr) => addr,
                            None => continue,
                        };
                        if second_begin > addr && self.function_entries.insert(addr) {
                            log::trace!(
                                "Trying function @ {:#010X} (from {:#010X}-{:#010X} <-> {:#010X}-{:#010X?})",
                                addr,
                                first_begin,
                                first_end,
                                second_begin,
                                second_end,
                            );
                            found_new = true;
                        }
                    }
                    (Some((&last_begin, &last_end)), None) => {
                        let Some(last_end) = last_end else { continue };
                        if last_end < section_end {
                            let addr = match skip_alignment(section, last_end, section_end) {
                                Some(addr) => addr,
                                None => continue,
                            };
                            if addr < section_end && self.function_entries.insert(addr) {
                                log::debug!(
                                    "Trying function @ {:#010X} (from {:#010X}-{:#010X} <-> {:#010X})",
                                    addr,
                                    last_begin,
                                    last_end,
                                    section_end,
                                );
                                found_new = true;
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
        Ok(found_new)
    }
}

/// Execute VM from entry point following branches and function calls
/// until SDA bases are initialized (__init_registers)
pub fn locate_sda_bases(obj: &mut ObjInfo) -> Result<bool> {
    let Some(entry) = obj.entry else {
        return Ok(false);
    };
    let (section_index, _) = obj
        .sections
        .at_address(entry as u32)
        .context(format!("Entry point {:#010X} outside of any section", entry))?;
    let entry_addr = SectionAddress::new(section_index, entry as u32);

    let mut executor = Executor::new(obj);
    executor.push(entry_addr, VM::new(), false);
    let result = executor.run(
        obj,
        |ExecCbData { executor, vm, result, ins_addr: _, section: _, ins, block_start: _ }| {
            match result {
                StepResult::Continue | StepResult::LoadStore { .. } => {
                    return Ok(ExecCbResult::Continue);
                }
                StepResult::Illegal => bail!("Illegal instruction @ {:#010X}", ins.addr),
                StepResult::Jump(target) => {
                    if let BranchTarget::Address(addr) = target {
                        return Ok(ExecCbResult::Jump(addr));
                    }
                }
                StepResult::Branch(branches) => {
                    for branch in branches {
                        if let BranchTarget::Address(addr) = branch.target {
                            executor.push(addr, branch.vm, false);
                        }
                    }
                }
            }

            if let (GprValue::Constant(sda2_base), GprValue::Constant(sda_base)) =
                (vm.gpr_value(2), vm.gpr_value(13))
            {
                return Ok(ExecCbResult::End((sda2_base, sda_base)));
            }

            Ok(ExecCbResult::EndBlock)
        },
    )?;
    match result {
        Some((sda2_base, sda_base)) => {
            obj.sda2_base = Some(sda2_base);
            obj.sda_base = Some(sda_base);
            Ok(true)
        }
        None => Ok(false),
    }
}
