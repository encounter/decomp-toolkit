use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};

use crate::{
    analysis::{
        executor::{ExecCbData, ExecCbResult, Executor},
        skip_alignment,
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, GprValue, StepResult, VM},
    },
    obj::{ObjInfo, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
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
            if let Some(existing_symbol) = obj
                .symbols
                .iter_mut()
                .find(|sym| sym.address == start as u64 && sym.kind == ObjSymbolKind::Function)
            {
                let new_size = (end - start) as u64;
                if !existing_symbol.size_known || existing_symbol.size == 0 {
                    existing_symbol.size = new_size;
                    existing_symbol.size_known = true;
                } else if existing_symbol.size != new_size {
                    log::warn!(
                        "Conflicting size for {}: was {:#X}, now {:#X}",
                        existing_symbol.name,
                        existing_symbol.size,
                        new_size
                    );
                }
                continue;
            }
            let section = obj
                .sections
                .iter()
                .find(|section| {
                    (start as u64) >= section.address
                        && (end as u64) <= section.address + section.size
                })
                .ok_or_else(|| {
                    anyhow!("Failed to locate section for function {:#010X}-{:#010X}", start, end)
                })?;
            obj.symbols.push(ObjSymbol {
                name: format!("fn_{:08X}", start),
                demangled_name: None,
                address: start as u64,
                section: Some(section.index),
                size: (end - start) as u64,
                size_known: true,
                flags: Default::default(),
                kind: ObjSymbolKind::Function,
            });
        }
        for (&addr, &size) in &self.jump_tables {
            let section = obj
                .sections
                .iter()
                .find(|section| {
                    (addr as u64) >= section.address
                        && ((addr + size) as u64) <= section.address + section.size
                })
                .ok_or_else(|| anyhow!("Failed to locate section for jump table"))?;
            if let Some(existing_symbol) = obj
                .symbols
                .iter_mut()
                .find(|sym| sym.address == addr as u64 && sym.kind == ObjSymbolKind::Object)
            {
                let new_size = size as u64;
                if !existing_symbol.size_known || existing_symbol.size == 0 {
                    existing_symbol.size = new_size;
                    existing_symbol.size_known = true;
                    // existing_symbol.flags.0 &= ObjSymbolFlags::Global;
                    // existing_symbol.flags.0 |= ObjSymbolFlags::Local;
                } else if existing_symbol.size != new_size {
                    log::warn!(
                        "Conflicting size for {}: was {:#X}, now {:#X}",
                        existing_symbol.name,
                        existing_symbol.size,
                        new_size
                    );
                }
                continue;
            }
            obj.symbols.push(ObjSymbol {
                name: format!("jumptable_{:08X}", addr),
                demangled_name: None,
                address: addr as u64,
                section: Some(section.index),
                size: size as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                kind: ObjSymbolKind::Object,
            });
        }
        for (&_addr, symbol) in &self.known_symbols {
            if let Some(existing_symbol) = obj
                .symbols
                .iter_mut()
                .find(|e| symbol.address == e.address && symbol.kind == e.kind)
            {
                *existing_symbol = symbol.clone();
                continue;
            }
            obj.symbols.push(symbol.clone());
        }
        Ok(())
    }

    pub fn detect_functions(&mut self, obj: &ObjInfo) -> Result<()> {
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
                    self.process_function_at(&obj, addr)?;
                }
                None => {
                    if !self.finalize_functions(obj, false)? {
                        if !self.detect_new_functions(obj)? {
                            break;
                        }
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
        if start == 0x801FC300 {
            log::info!("Processing TRKExceptionHandler");
        }
        Ok(match slices.analyze(obj, start, start, function_end, &self.function_entries)? {
            true => Some(slices),
            false => None,
        })
    }

    fn detect_new_functions(&mut self, obj: &ObjInfo) -> Result<bool> {
        let mut found_new = false;
        let mut iter = self.function_bounds.iter().peekable();
        while let (Some((&first_begin, &first_end)), Some(&(&second_begin, &second_end))) =
            (iter.next(), iter.peek())
        {
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
                StepResult::Jump(target) => match target {
                    BranchTarget::Address(addr) => {
                        return Ok(ExecCbResult::Jump(addr));
                    }
                    _ => {}
                },
                StepResult::Branch(branches) => {
                    for branch in branches {
                        match branch.target {
                            BranchTarget::Address(addr) => {
                                executor.push(addr, branch.vm, false);
                            }
                            _ => {}
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
