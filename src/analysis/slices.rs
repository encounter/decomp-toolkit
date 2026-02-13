use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{bail, ensure, Context, Result};
use powerpc::{Ins, Opcode};

use crate::{
    analysis::{
        cfa::{FunctionInfo, SectionAddress},
        disassemble,
        executor::{ExecCbData, ExecCbResult, Executor},
        uniq_jump_table_entries,
        vm::{section_address_for, BranchTarget, JumpTableType, StepResult, VM},
        RelocationTarget,
    },
    obj::{ObjInfo, ObjKind, ObjSection, ObjSymbolKind},
};

#[derive(Debug, Default, Clone)]
pub struct FunctionSlices {
    pub blocks: BTreeMap<SectionAddress, Option<SectionAddress>>,
    pub branches: BTreeMap<SectionAddress, Vec<SectionAddress>>,
    pub function_references: BTreeSet<SectionAddress>,
    pub jump_table_references: BTreeMap<SectionAddress, u32>,
    pub prologue: Option<SectionAddress>,
    pub epilogue: Option<SectionAddress>,
    // Either a block or tail call
    pub possible_blocks: BTreeMap<SectionAddress, Box<VM>>,
    pub has_conditional_blr: bool,
    pub has_rfi: bool,
    pub finalized: bool,
    pub has_r1_load: bool, // Possibly instead of a prologue
}

pub enum TailCallResult {
    Not,
    Is,
    Possible,
    Error(anyhow::Error),
}

type BlockRange = Range<SectionAddress>;

type InsCheck = dyn Fn(Ins) -> bool;

/// Stop searching for prologue/epilogue sequences if the next instruction
/// is a branch or uses r0 or r1.
fn is_end_of_seq(next: &Ins) -> bool {
    next.is_branch()
        || next
            .defs()
            .iter()
            .chain(next.uses().iter())
            .any(|a| matches!(a, powerpc::Argument::GPR(powerpc::GPR(0 | 1))))
}

#[inline(always)]
fn check_sequence(
    section: &ObjSection,
    addr: SectionAddress,
    ins: Option<Ins>,
    sequence: &[(&InsCheck, &InsCheck)],
) -> Result<bool> {
    let ins = ins
        .or_else(|| disassemble(section, addr.address))
        .with_context(|| format!("Failed to disassemble instruction at {addr:#010X}"))?;
    for &(first, second) in sequence {
        if !first(ins) {
            continue;
        }
        let mut current_addr = addr.address + 4;
        while let Some(next) = disassemble(section, current_addr) {
            if second(next) {
                return Ok(true);
            }
            if is_end_of_seq(&next) {
                // If we hit a branch or an instruction that uses r0 or r1, stop searching.
                break;
            }
            current_addr += 4;
        }
    }
    Ok(false)
}

// xbox prologue sequences:
// mfspr r12, LR / stw r12, -0x8(r1)
// mfspr r12, LR / bl saveregintrinsic
// subi r31, r12, XXXX / mfspr r12, LR (unwinds)
fn check_prologue_sequence(
    section: &ObjSection,
    addr: SectionAddress,
    ins: Option<Ins>,
) -> Result<bool> {
    #[inline(always)]
    fn is_mflr(ins: Ins) -> bool {
        // mfspr r0, LR
        ins.op == Opcode::Mfspr && ins.field_rd() == 12 && ins.field_spr() == 8
    }
    // #[inline(always)]
    // fn is_stwu(ins: Ins) -> bool {
    //     // stwu r1, d(r1)
    //     ins.op == Opcode::Stwu && ins.field_rs() == 1 && ins.field_ra() == 1
    // }
    #[inline(always)]
    fn is_stw(ins: Ins) -> bool {
        // stw r0, d(r1)
        ins.op == Opcode::Stw && ins.field_rs() == 0 && ins.field_ra() == 1
    }
    #[inline(always)]
    fn is_bl(ins: Ins) -> bool { ins.op == Opcode::B && ins.field_lk() }
    #[inline(always)]
    fn is_subi(ins: Ins) -> bool {
        ins.op == Opcode::Addi && ins.field_simm() < 0 && ins.field_simm() != -0x8000
    }
    check_sequence(section, addr, ins, &[
        (&is_mflr, &is_stw),
        (&is_mflr, &is_bl),
        (&is_subi, &is_mflr),
    ])
}

impl FunctionSlices {
    pub fn end(&self) -> Option<SectionAddress> {
        self.blocks.last_key_value().and_then(|(_, &end)| end)
    }

    pub fn start(&self) -> Option<SectionAddress> {
        self.blocks.first_key_value().map(|(&start, _)| start)
    }

    pub fn add_block_start(&mut self, addr: SectionAddress) -> bool {
        // Slice previous block.
        if let Some((_, end)) = self.blocks.range_mut(..addr).next_back() {
            if let Some(last_end) = *end {
                if last_end > addr {
                    *end = Some(addr);
                    self.blocks.insert(addr, Some(last_end));
                    return false;
                }
            }
        }
        // Otherwise, insert with no end.
        match self.blocks.entry(addr) {
            btree_map::Entry::Vacant(e) => {
                e.insert(None);
                true
            }
            btree_map::Entry::Occupied(_) => false,
        }
    }

    // fn check_prologue(
    //     &mut self,
    //     section: &ObjSection,
    //     addr: SectionAddress,
    //     ins: Ins,
    // ) -> Result<()> {
    //     #[inline(always)]
    //     fn is_lwz(ins: Ins) -> bool {
    //         // lwz r1, d(r)
    //         ins.op == Opcode::Lwz && ins.field_rd() == 1
    //     }
    //
    //     if is_lwz(ins) {
    //         self.has_r1_load = true;
    //         return Ok(()); // Possibly instead of a prologue
    //     }
    //     if check_prologue_sequence(section, addr, Some(ins))? {
    //         if let Some(prologue) = self.prologue {
    //             let invalid_seq = if prologue == addr {
    //                 false
    //             } else if prologue > addr {
    //                 true
    //             } else {
    //                 // Check if any instructions between the prologue and this address
    //                 // are branches or use r0 or r1.
    //                 let mut current_addr = prologue.address + 4;
    //                 loop {
    //                     if current_addr == addr.address {
    //                         break false;
    //                     }
    //                     let next = disassemble(section, current_addr).with_context(|| {
    //                         format!("Failed to disassemble {current_addr:#010X}")
    //                     })?;
    //                     if is_end_of_seq(&next) {
    //                         break true;
    //                     }
    //                     current_addr += 4;
    //                 }
    //             };
    //             if invalid_seq {
    //                 bail!("Found multiple functions inside a symbol: {:#010X} and {:#010X}. Check symbols.txt?", prologue, addr)
    //             }
    //         } else {
    //             self.prologue = Some(addr);
    //         }
    //     }
    //     Ok(())
    // }

    // fn check_epilogue(
    //     &mut self,
    //     section: &ObjSection,
    //     addr: SectionAddress,
    //     ins: Ins,
    // ) -> Result<()> {
    //     #[inline(always)]
    //     fn is_mtlr(ins: Ins) -> bool {
    //         // mtspr LR, r0
    //         ins.op == Opcode::Mtspr && ins.field_rs() == 12 && ins.field_spr() == 8
    //     }
    //     #[inline(always)]
    //     fn is_addi(ins: Ins) -> bool {
    //         // addi r1, r1, SIMM
    //         ins.op == Opcode::Addi && ins.field_rd() == 1 && ins.field_ra() == 1
    //     }
    //     #[inline(always)]
    //     fn is_or(ins: Ins) -> bool {
    //         // or r1, rA, rB
    //         ins.op == Opcode::Or && ins.field_rd() == 1
    //     }
    //
    //     if check_sequence(section, addr, Some(ins), &[(&is_mtlr, &is_addi), (&is_or, &is_mtlr)])? {
    //         if let Some(epilogue) = self.epilogue {
    //             if epilogue != addr {
    //                 bail!("Found duplicate epilogue: {:#010X} and {:#010X}", epilogue, addr)
    //             }
    //         } else {
    //             self.epilogue = Some(addr);
    //         }
    //     }
    //     Ok(())
    // }

    fn is_known_function(
        &self,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        addr: SectionAddress,
    ) -> Option<SectionAddress> {
        if self.function_references.contains(&addr) {
            return Some(addr);
        }
        if let Some((&fn_addr, info)) = known_functions.range(..=addr).next_back() {
            if fn_addr == addr || info.end.is_some_and(|end| addr < end) {
                return Some(fn_addr);
            }
        }
        None
    }

    fn instruction_callback(
        &mut self,
        data: ExecCbData,
        obj: &ObjInfo,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
    ) -> Result<ExecCbResult<bool>> {
        let ExecCbData { executor, vm, result, ins_addr, section, ins, block_start } = data;

        // no need to check for prologues/epilogues in MSVC
        // if a func came from pdata, it not only has a prologue/epilogue, but a known confirmed ending

        if !self.has_conditional_blr && is_conditional_blr(ins) {
            self.has_conditional_blr = true;
        }
        if !self.has_rfi && ins.op == Opcode::Rfi {
            self.has_rfi = true;
        }
        // If control flow hits a block we thought may be a tail call,
        // we know it isn't.
        if self.possible_blocks.contains_key(&ins_addr) {
            self.possible_blocks.remove(&ins_addr);
        }
        if let Some(fn_addr) = self.is_known_function(known_functions, ins_addr) {
            if fn_addr != function_start {
                log::warn!(
                    "Control flow from {} hit known function {} (instruction: {})",
                    function_start,
                    fn_addr,
                    ins_addr
                );
                // if we know the function end from pdata, just end the block here and continue processing
                return match function_end {
                    Some(_end) => {
                        self.blocks.insert(block_start, function_end);
                        Ok(ExecCbResult::EndBlock)
                    }
                    None => Ok(ExecCbResult::End(false)),
                };
            }
        }

        match result {
            StepResult::Continue | StepResult::LoadStore { .. } => {
                let next_address = ins_addr + 4;
                // If we already visited the next address, connect the blocks and end
                if executor.visited(section.address as u32, next_address)
                    || self.blocks.contains_key(&next_address)
                {
                    self.blocks.insert(block_start, Some(next_address));
                    self.branches.insert(ins_addr, vec![next_address]);
                    Ok(ExecCbResult::EndBlock)
                } else if function_end.is_some_and(|end| next_address >= end) {
                    self.blocks.insert(block_start, Some(next_address));
                    Ok(ExecCbResult::EndBlock)
                } else {
                    Ok(ExecCbResult::Continue)
                }
            }
            StepResult::Illegal => {
                if ins.code == 0 {
                    log::debug!("Hit zeroed padding @ {:#010X}", ins_addr);
                    Ok(ExecCbResult::End(false))
                } else {
                    log::debug!("Illegal instruction @ {:#010X}", ins_addr);
                    Ok(ExecCbResult::Continue)
                }
            }
            StepResult::Jump(target) => match target {
                BranchTarget::Unknown
                | BranchTarget::Address(RelocationTarget::External)
                | BranchTarget::JumpTable {
                    jump_table_address: RelocationTarget::External, ..
                } => {
                    // Likely end of function
                    let next_addr = ins_addr + 4;
                    self.blocks.insert(block_start, Some(next_addr));
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Return => {
                    self.blocks.insert(block_start, Some(ins_addr + 4));
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Address(RelocationTarget::Address(addr)) => {
                    // End of block
                    self.blocks.insert(block_start, Some(ins_addr + 4));
                    self.branches.insert(ins_addr, vec![addr]);
                    if addr == ins_addr {
                        // Infinite loop
                    } else if addr >= function_start
                        && (matches!(function_end, Some(known_end) if addr < known_end)
                            || matches!(self.end(), Some(end) if addr < end)
                            || addr < ins_addr)
                    {
                        // If target is within known function bounds, jump
                        if self.add_block_start(addr) {
                            return Ok(ExecCbResult::Jump(addr));
                        }
                    } else if let Some(fn_addr) = self.is_known_function(known_functions, addr) {
                        ensure!(fn_addr != function_start); // Sanity check
                        self.function_references.insert(fn_addr);
                    } else if addr.section != ins_addr.section
                        // If this branch has zeroed padding after it, assume tail call.
                        || matches!(section.data_range(ins_addr.address, ins_addr.address + 4), Ok(data) if data == [0u8; 4])
                    {
                        self.function_references.insert(addr);
                    } else {
                        self.possible_blocks.insert(addr, vm.clone_all());
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::JumpTable {
                    jump_table_type: jt,
                    jump_table_address: RelocationTarget::Address(address),
                    size,
                } => {
                    let next_addr_size = match jt {
                        JumpTableType::Absolute => match size {
                            Some(num) => num.get(),
                            None => 0,
                        },
                        _ => 0,
                    };

                    // End of block
                    let next_address = ins_addr + 4 + next_addr_size;
                    self.blocks.insert(block_start, Some(next_address));

                    log::debug!(
                        "Fetching {} jump table entries @ {} with size {:?}",
                        if jt == JumpTableType::Absolute { "absolute" } else { "relative" },
                        address,
                        size
                    );
                    let (entries, size) = uniq_jump_table_entries(
                        obj,
                        address,
                        jt,
                        size,
                        ins_addr,
                        function_start,
                        function_end.or_else(|| self.end()),
                    )?;
                    log::debug!("-> size {}: {:?}", size, entries);

                    // if this function has a known end, check that every jump table entry is within function bounds
                    let within_func_bounds = match function_end {
                        Some(end) => {
                            !entries.iter().any(|&addr| addr < function_start || addr >= end)
                        }
                        None => false,
                    };

                    // this if statements is true if:
                    // the next_address is in our jump table entries OR next_address marks the start of one our established blocks
                    // OR we're within known func bounds
                    // AND
                    // none of our jump table entries are known function starts
                    if (entries.contains(&next_address)
                        || self.blocks.contains_key(&next_address)
                        || within_func_bounds)
                        && !entries.iter().any(|&addr| {
                            self.is_known_function(known_functions, addr)
                                .is_some_and(|fn_addr| fn_addr != function_start)
                        })
                    {
                        self.jump_table_references.insert(address, size);
                        let mut branches = vec![];
                        for addr in entries {
                            branches.push(addr);
                            if self.add_block_start(addr) {
                                executor.push(addr, vm.clone_all(), true);
                            }
                        }
                        self.branches.insert(ins_addr, branches);
                    } else {
                        // If the table doesn't contain the next address,
                        // it could be a function jump table instead
                        self.possible_blocks
                            .extend(entries.into_iter().map(|addr| (addr, vm.clone_all())));
                    }
                    Ok(ExecCbResult::EndBlock)
                }
            },
            StepResult::Branch(branches) => {
                // End of block
                self.blocks.insert(block_start, Some(ins_addr + 4));

                let mut out_branches = vec![];
                for branch in branches {
                    match branch.target {
                        BranchTarget::Address(RelocationTarget::Address(addr)) => {
                            let known = self.is_known_function(known_functions, addr);
                            if let Some(fn_addr) = known {
                                if fn_addr != function_start {
                                    self.function_references.insert(fn_addr);
                                    continue;
                                }
                            }
                            if branch.link {
                                // See if any existing functions contain this address,
                                // since this could be a label inside a larger function.
                                let last_function = obj
                                    .symbols
                                    .for_section_range(addr.section, ..addr.address)
                                    .rfind(|(_, symbol)| symbol.kind == ObjSymbolKind::Function);
                                match last_function {
                                    Some((_, symbol))
                                        if symbol.address + symbol.size > addr.address as u64 =>
                                    {
                                        // Set the function reference to the start of the function
                                        self.function_references.insert(SectionAddress::new(
                                            addr.section,
                                            symbol.address as u32,
                                        ))
                                    }
                                    _ => self.function_references.insert(addr),
                                };
                            } else {
                                // MSVC likes to end functions with bl sometimes
                                // this lil hack will stop a new block from being added
                                // if the current addr goes beyond our known function end addr
                                // this should help our funcs from pdata that end in bl's
                                if function_end.is_none_or(|end| addr < end) {
                                    out_branches.push(addr);
                                    if self.add_block_start(addr) {
                                        executor.push(addr, branch.vm, true);
                                    }
                                }
                            }
                        }
                        BranchTarget::JumpTable {
                            jump_table_type: _,
                            jump_table_address: address,
                            size,
                        } => {
                            bail!(
                                "Conditional jump table unsupported @ {:#010X} -> {:?} size {:#X?}",
                                ins_addr,
                                address,
                                size
                            );
                        }
                        _ => continue,
                    }
                }
                if !out_branches.is_empty() {
                    self.branches.insert(ins_addr, out_branches);
                }
                Ok(ExecCbResult::EndBlock)
            }
        }
    }

    pub fn analyze(
        &mut self,
        obj: &ObjInfo,
        start: SectionAddress,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        vm: Option<Box<VM>>,
    ) -> Result<bool> {
        if !self.add_block_start(start) {
            return Ok(true);
        }

        let mut executor = Executor::new(obj);
        executor.push(start, vm.unwrap_or_else(|| VM::new_from_obj(obj)), false);
        let result = executor.run(obj, |data| {
            self.instruction_callback(data, obj, function_start, function_end, known_functions)
        })?;
        if matches!(result, Some(b) if !b) {
            return Ok(false);
        }

        // Visit unreachable blocks
        while let Some((first, _)) = self.first_disconnected_block() {
            let vm = self.possible_blocks.remove(&first.start);
            executor.push(first.end, vm.unwrap_or_else(|| VM::new_from_obj(obj)), true);

            match executor.run(obj, |data| {
                self.instruction_callback(data, obj, function_start, function_end, known_functions)
            })? {
                Some(true) => continue,
                Some(false) => return Ok(false),
                None => break,
            }

            // let result = executor.run(obj, |data| {
            //     self.instruction_callback(data, obj, function_start, function_end, known_functions)
            // })?;
            // if matches!(result, Some(b) if !b) {
            //     return Ok(false);
            // }
        }

        // Visit trailing blocks
        if let Some(known_end) = function_end {
            'outer: loop {
                let Some(mut end) = self.end() else {
                    log::warn!("Trailing block analysis failed @ {:#010X}", function_start);
                    break;
                };
                loop {
                    if end >= known_end {
                        break 'outer;
                    }
                    // Skip nops
                    match disassemble(&obj.sections[end.section], end.address) {
                        Some(ins) => {
                            if ins.op != Opcode::Illegal && !is_nop(ins) {
                                break;
                            }
                        }
                        _ => break,
                    }
                    end += 4;
                }
                executor.push(end, VM::new_from_obj(obj), true);
                match executor.run(obj, |data| {
                    self.instruction_callback(
                        data,
                        obj,
                        function_start,
                        function_end,
                        known_functions,
                    )
                })? {
                    Some(true) => continue,
                    Some(false) => return Ok(false),
                    None => break 'outer,
                }
            }
        }

        // Sanity check
        for (&start, &end) in &self.blocks {
            ensure!(end.is_some(), "Failed to finalize block @ {start:#010X}");
        }

        Ok(true)
    }

    pub fn can_finalize(&self) -> bool { self.possible_blocks.is_empty() }

    pub fn finalize(
        &mut self,
        obj: &ObjInfo,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
    ) -> Result<()> {
        ensure!(!self.finalized, "Already finalized");
        ensure!(self.can_finalize(), "Can't finalize");

        match (self.prologue, self.epilogue, self.has_r1_load) {
            (Some(_), Some(_), _) | (None, None, _) => {}
            (Some(_), None, _) => {
                // Likely __noreturn
            }
            (None, Some(e), false) => {
                log::warn!("{:#010X?}", self);
                bail!("Unpaired epilogue {:#010X}", e);
            }
            (None, Some(_), true) => {
                // Possible stack setup
            }
        }

        let Some(end) = self.end() else {
            bail!("Can't finalize function without known end: {:#010X?}", self.start())
        };
        // TODO: rework to make compatible with relocatable objects
        if obj.kind == ObjKind::Executable {
            match (
                (end.section, &obj.sections[end.section]),
                obj.sections.at_address(end.address - 4),
            ) {
                ((section_index, section), Ok((other_section_index, _other_section)))
                    if section_index == other_section_index =>
                {
                    // FIXME this is real bad
                    if !self.has_conditional_blr {
                        let ins_addr = end - 4;
                        if let Some(ins) = disassemble(section, ins_addr.address) {
                            if ins.op == Opcode::B {
                                if let Some(RelocationTarget::Address(target)) = ins
                                    .branch_dest(ins_addr.address)
                                    .and_then(|addr| section_address_for(obj, ins_addr, addr))
                                {
                                    if self.function_references.contains(&target) {
                                        for branches in self.branches.values() {
                                            if branches.len() > 1
                                                && branches.contains(
                                                    self.blocks.last_key_value().unwrap().0,
                                                )
                                            {
                                                self.has_conditional_blr = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // MWCC optimization sometimes leaves an unreachable blr
                    // after generating a conditional blr in the function.
                    if self.has_conditional_blr
                        && matches!(disassemble(section, end.address - 4), Some(ins) if !ins.is_blr())
                        && matches!(disassemble(section, end.address), Some(ins) if ins.is_blr())
                        && !known_functions.contains_key(&end)
                    {
                        log::trace!("Found trailing blr @ {:#010X}, merging with function", end);
                        self.blocks.insert(end, Some(end + 4));
                    }

                    // Some functions with rfi also include a trailing nop
                    if self.has_rfi
                        && matches!(disassemble(section, end.address), Some(ins) if is_nop(ins))
                        && !known_functions.contains_key(&end)
                    {
                        log::trace!("Found trailing nop @ {:#010X}, merging with function", end);
                        self.blocks.insert(end, Some(end + 4));
                    }
                }
                _ => {}
            }
        }

        self.finalized = true;

        Ok(())
    }

    pub fn check_tail_call(
        &mut self,
        obj: &ObjInfo,
        addr: SectionAddress,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        vm: Option<Box<VM>>,
    ) -> TailCallResult {
        // TODO: check if jump target is a reg intrinsic, as if it is, it might *not* be a tail call
        // you'd also have to check if there are visited addresses that go beyond the addr of the jump instruction

        // If jump target is already a known block or within known function bounds, not a tail call.
        if self.blocks.contains_key(&addr) {
            return TailCallResult::Not;
        }
        if let Some(function_end) = function_end {
            if addr >= function_start && addr < function_end {
                return TailCallResult::Not;
            }
        }
        // If there's a prologue in the current function, not a tail call.
        if self.prologue.is_some() {
            return TailCallResult::Not;
        }
        // If jump target is before the start of the function, known tail call.
        if addr < function_start {
            return TailCallResult::Is;
        }
        // If the jump target is in a different section, known tail call.
        if addr.section != function_start.section {
            return TailCallResult::Is;
        }
        // If the jump target has 0'd padding before it, known tail call.
        let target_section = &obj.sections[addr.section];
        if matches!(target_section.data_range(addr.address - 4, addr.address), Ok(data) if data == [0u8; 4])
        {
            return TailCallResult::Is;
        }
        // If we're not sure where the function ends yet, mark as possible tail call.
        // let end = self.end();
        if function_end.is_none() {
            return TailCallResult::Possible;
        }
        // If jump target is known to be a function, or there's a function in between
        // this and the jump target, known tail call.
        if self.function_references.range(function_start + 4..=addr).next().is_some()
            || known_functions.range(function_start + 4..=addr).next().is_some()
        {
            return TailCallResult::Is;
        }
        // If we haven't discovered a prologue yet, and one exists between the function
        // start and the jump target, known tail call.
        if self.prologue.is_none() {
            let mut current_address = function_start;
            while current_address < addr {
                match check_prologue_sequence(target_section, current_address, None) {
                    Ok(true) => {
                        log::debug!(
                            "Prologue discovered @ {}; known tail call: {}",
                            current_address,
                            addr
                        );
                        return TailCallResult::Is;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        log::warn!("Error while checking prologue sequence: {}", e);
                        return TailCallResult::Error(e);
                    }
                }
                current_address += 4;
            }
        }
        // Perform CFA on jump target to determine more
        let mut slices = FunctionSlices {
            function_references: self.function_references.clone(),
            ..Default::default()
        };
        if let Ok(result) =
            slices.analyze(obj, addr, function_start, function_end, known_functions, vm)
        {
            // If analysis failed, assume tail call.
            if !result {
                log::warn!("Tail call analysis failed for {:#010X}", addr);
                return TailCallResult::Is;
            }
            // If control flow jumps below the entry point, not a tail call.
            let start = slices.start().unwrap();
            if start < addr {
                log::trace!("Tail call possibility eliminated: {:#010X} < {:#010X}", start, addr);
                return TailCallResult::Not;
            }
            // If control flow includes another possible tail call, we know both are not tail calls.
            if let Some(end) = slices.end() {
                // TODO idk if wrapping this is right
                let other_blocks = self
                    .possible_blocks
                    .range(start + 4..end)
                    .map(|(&addr, _)| addr)
                    .collect::<Vec<SectionAddress>>();
                if !other_blocks.is_empty() {
                    for other_addr in other_blocks {
                        log::trace!("Logically eliminating {:#010X}", other_addr);
                        self.possible_blocks.remove(&other_addr);
                        // self.add_block_start(oth);
                    }
                    log::trace!("While analyzing {:#010X}", addr);
                    return TailCallResult::Not;
                }
            }
            // If we discovered a function prologue, known tail call.
            if slices.prologue.is_some() {
                log::trace!("Prologue discovered; known tail call: {:#010X}", addr);
                return TailCallResult::Is;
            }
        }
        // If all else fails, try again later.
        TailCallResult::Possible
    }

    pub fn first_disconnected_block(&self) -> Option<(BlockRange, BlockRange)> {
        let mut iter = self.blocks.iter().peekable();
        loop {
            let ((first_begin, first_end), (second_begin, second_end)) =
                match (iter.next(), iter.peek()) {
                    (Some((&b1s, &Some(b1e))), Some(&(&b2s, &Some(b2e)))) => {
                        ((b1s, b1e), (b2s, b2e))
                    }
                    (Some(_), Some(_)) => continue,
                    _ => break None,
                };
            if second_begin > first_end {
                break Some((first_begin..first_end, second_begin..second_end));
            }
        }
    }
}

#[inline]
fn is_conditional_blr(ins: Ins) -> bool {
    ins.op == Opcode::Bclr && ins.field_bo() & 0b10100 != 0b10100
}

#[inline]
fn is_nop(ins: Ins) -> bool {
    // ori r0, r0, 0
    ins.code == 0x60000000
}
