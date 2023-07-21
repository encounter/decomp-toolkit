use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};

use crate::{
    analysis::{
        executor::{ExecCbData, ExecCbResult, Executor},
        skip_alignment,
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, GprValue, StepResult, VM},
    },
    obj::{ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
};

#[derive(Debug, Default)]
pub struct AnalyzerState {
    pub sda_bases: Option<(u32, u32)>,
    pub function_entries: BTreeSet<u32>,
    pub function_bounds: BTreeMap<u32, u32>,
    pub function_slices: BTreeMap<u32, FunctionSlices>,
    pub jump_tables: BTreeMap<u32, u32>,
    pub known_symbols: BTreeMap<u32, ObjSymbol>,
    pub non_finalized_functions: BTreeMap<u32, FunctionSlices>,
}

impl AnalyzerState {
    pub fn apply(&self, obj: &mut ObjInfo) -> Result<()> {
        for (&start, &end) in &self.function_bounds {
            if end == 0 {
                continue;
            }
            let section_index =
                obj.section_for(start..end).context("Failed to locate section for function")?.index;
            obj.add_symbol(
                ObjSymbol {
                    name: format!("fn_{:08X}", start),
                    demangled_name: None,
                    address: start as u64,
                    section: Some(section_index),
                    size: (end - start) as u64,
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
            let section_index = obj
                .section_for(addr..addr + size)
                .context("Failed to locate section for jump table")?
                .index;
            obj.add_symbol(
                ObjSymbol {
                    name: format!("jumptable_{:08X}", addr),
                    demangled_name: None,
                    address: addr as u64,
                    section: Some(section_index),
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
            self.function_entries.insert(addr);
            self.function_bounds.insert(addr, addr + size);
        }
        // Apply known functions from symbols
        for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
            self.function_entries.insert(symbol.address as u32);
            if symbol.size_known {
                self.function_bounds
                    .insert(symbol.address as u32, (symbol.address + symbol.size) as u32);
            }
        }

        // Process known functions first
        let known_functions = self.function_entries.clone();
        for addr in known_functions {
            self.process_function_at(obj, addr)?;
        }
        // Locate entry function bounds
        self.process_function_at(obj, obj.entry as u32)?;
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
            let function_start = slices.start();
            let function_end = slices.end();
            let mut current = 0;
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
                            Some(function_end),
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
                                Some(function_end),
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

    fn first_unbounded_function(&self) -> Option<u32> {
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

    pub fn process_function_at(&mut self, obj: &ObjInfo, addr: u32) -> Result<bool> {
        if addr == 0 || addr == 0xFFFFFFFF {
            log::warn!("Tried to detect @ {:#010X}", addr);
            self.function_bounds.insert(addr, 0);
            return Ok(false);
        }
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
            self.function_bounds.insert(addr, 0);
            false
        })
    }

    fn process_function(&mut self, obj: &ObjInfo, start: u32) -> Result<Option<FunctionSlices>> {
        let mut slices = FunctionSlices::default();
        let function_end = self.function_bounds.get(&start).cloned();
        Ok(match slices.analyze(obj, start, start, function_end, &self.function_entries)? {
            true => Some(slices),
            false => None,
        })
    }

    fn detect_new_functions(&mut self, obj: &ObjInfo) -> Result<bool> {
        let mut found_new = false;
        for section in &obj.sections {
            if section.kind != ObjSectionKind::Code {
                continue;
            }

            let section_start = section.address as u32;
            let section_end = (section.address + section.size) as u32;
            let mut iter = self.function_bounds.range(section_start..section_end).peekable();
            loop {
                match (iter.next(), iter.peek()) {
                    (Some((&first_begin, &first_end)), Some(&(&second_begin, &second_end))) => {
                        if first_end == 0 || first_end > second_begin {
                            continue;
                        }
                        let addr = match skip_alignment(obj, first_end, second_begin) {
                            Some(addr) => addr,
                            None => continue,
                        };
                        if second_begin > addr && self.function_entries.insert(addr) {
                            log::trace!(
                                "Trying function @ {:#010X} (from {:#010X}-{:#010X} <-> {:#010X}-{:#010X})",
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
                        if last_end > 0 && last_end < section_end {
                            let addr = match skip_alignment(obj, last_end, section_end) {
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
    let mut executor = Executor::new(obj);
    executor.push(obj.entry as u32, VM::new(), false);
    let result = executor.run(
        obj,
        |ExecCbData { executor, vm, result, section: _, ins, block_start: _ }| {
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
