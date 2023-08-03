use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{bail, ensure, Context, Result};
use ppc750cl::{Ins, Opcode};

use crate::{
    analysis::{
        disassemble,
        executor::{ExecCbData, ExecCbResult, Executor},
        uniq_jump_table_entries,
        vm::{BranchTarget, StepResult, VM},
    },
    obj::{ObjInfo, ObjSection},
};

#[derive(Debug, Default, Clone)]
pub struct FunctionSlices {
    pub blocks: BTreeMap<u32, u32>,
    pub branches: BTreeMap<u32, Vec<u32>>,
    pub function_references: BTreeSet<u32>,
    pub jump_table_references: BTreeMap<u32, u32>,
    pub prologue: Option<u32>,
    pub epilogue: Option<u32>,
    // Either a block or tail call
    pub possible_blocks: BTreeSet<u32>,
    pub has_conditional_blr: bool,
    pub has_rfi: bool,
    pub finalized: bool,
}

pub enum TailCallResult {
    Not,
    Is,
    Possible,
    Error(anyhow::Error),
}

type BlockRange = Range<u32>;

#[inline(always)]
fn next_ins(section: &ObjSection, ins: &Ins) -> Option<Ins> { disassemble(section, ins.addr + 4) }

type InsCheck = dyn Fn(&Ins) -> bool;

#[inline(always)]
fn check_sequence(
    section: &ObjSection,
    ins: &Ins,
    sequence: &[(&InsCheck, &InsCheck)],
) -> Result<bool> {
    let mut found = false;

    for &(first, second) in sequence {
        if first(ins) {
            if let Some(next) = next_ins(section, ins) {
                if second(&next)
                    // Also check the following instruction, in case the scheduler
                    // put something in between.
                    || (!next.is_branch() && matches!(next_ins(section, &next), Some(ins) if second(&ins)))
                {
                    found = true;
                    break;
                }
            }
        }
    }

    Ok(found)
}

impl FunctionSlices {
    pub fn end(&self) -> u32 { self.blocks.last_key_value().map(|(_, &end)| end).unwrap_or(0) }

    pub fn start(&self) -> u32 {
        self.blocks.first_key_value().map(|(&start, _)| start).unwrap_or(0)
    }

    pub fn add_block_start(&mut self, addr: u32) -> bool {
        // Slice previous block.
        if let Some((_, end)) = self.blocks.range_mut(..addr).last() {
            let last_end = *end;
            if last_end > addr {
                *end = addr;
                self.blocks.insert(addr, last_end);
                return false;
            }
        }
        // Otherwise, insert with no end.
        match self.blocks.entry(addr) {
            btree_map::Entry::Vacant(e) => {
                e.insert(0);
                true
            }
            btree_map::Entry::Occupied(_) => false,
        }
    }

    fn check_prologue(&mut self, section: &ObjSection, ins: &Ins) -> Result<()> {
        #[inline(always)]
        fn is_mflr(ins: &Ins) -> bool {
            // mfspr r0, LR
            ins.op == Opcode::Mfspr && ins.field_rD() == 0 && ins.field_spr() == 8
        }
        #[inline(always)]
        fn is_stwu(ins: &Ins) -> bool {
            // stwu r1, d(r1)
            ins.op == Opcode::Stwu && ins.field_rS() == 1 && ins.field_rA() == 1
        }
        #[inline(always)]
        fn is_stw(ins: &Ins) -> bool {
            // stw r0, d(r1)
            ins.op == Opcode::Stw && ins.field_rS() == 0 && ins.field_rA() == 1
        }

        if check_sequence(section, ins, &[(&is_stwu, &is_mflr), (&is_mflr, &is_stw)])? {
            if let Some(prologue) = self.prologue {
                if prologue != ins.addr && prologue != ins.addr - 4 {
                    bail!("Found duplicate prologue: {:#010X} and {:#010X}", prologue, ins.addr)
                }
            } else {
                self.prologue = Some(ins.addr);
            }
        }
        Ok(())
    }

    fn check_epilogue(&mut self, section: &ObjSection, ins: &Ins) -> Result<()> {
        #[inline(always)]
        fn is_mtlr(ins: &Ins) -> bool {
            // mtspr LR, r0
            ins.op == Opcode::Mtspr && ins.field_rS() == 0 && ins.field_spr() == 8
        }
        #[inline(always)]
        fn is_addi(ins: &Ins) -> bool {
            // addi r1, r1, SIMM
            ins.op == Opcode::Addi && ins.field_rD() == 1 && ins.field_rA() == 1
        }
        #[inline(always)]
        fn is_or(ins: &Ins) -> bool {
            // or r1, rA, rB
            ins.op == Opcode::Or && ins.field_rD() == 1
        }

        if check_sequence(section, ins, &[(&is_mtlr, &is_addi), (&is_or, &is_mtlr)])? {
            if let Some(epilogue) = self.epilogue {
                if epilogue != ins.addr {
                    bail!("Found duplicate epilogue: {:#010X} and {:#010X}", epilogue, ins.addr)
                }
            } else {
                self.epilogue = Some(ins.addr);
            }
        }
        Ok(())
    }

    fn instruction_callback(
        &mut self,
        data: ExecCbData,
        obj: &ObjInfo,
        function_start: u32,
        function_end: Option<u32>,
        known_functions: &BTreeSet<u32>,
    ) -> Result<ExecCbResult<bool>> {
        let ExecCbData { executor, vm, result, section, ins, block_start } = data;

        // Track discovered prologue(s) and epilogue(s)
        self.check_prologue(section, ins)
            .with_context(|| format!("While processing {:#010X}", function_start))?;
        self.check_epilogue(section, ins)
            .with_context(|| format!("While processing {:#010X}", function_start))?;
        if !self.has_conditional_blr && is_conditional_blr(ins) {
            self.has_conditional_blr = true;
        }
        if !self.has_rfi && ins.op == Opcode::Rfi {
            self.has_rfi = true;
        }
        // If control flow hits a block we thought may be a tail call,
        // we know it isn't.
        if self.possible_blocks.contains(&ins.addr) {
            self.possible_blocks.remove(&ins.addr);
        }

        match result {
            StepResult::Continue | StepResult::LoadStore { .. } => {
                let next_address = ins.addr + 4;
                // If we already visited the next address, connect the blocks and end
                if executor.visited(section, next_address) {
                    self.blocks.insert(block_start, next_address);
                    self.branches.insert(ins.addr, vec![next_address]);
                    Ok(ExecCbResult::EndBlock)
                } else {
                    Ok(ExecCbResult::Continue)
                }
            }
            StepResult::Illegal => {
                log::debug!("Illegal instruction @ {:#010X}", ins.addr);
                Ok(ExecCbResult::End(false))
            }
            StepResult::Jump(target) => match target {
                BranchTarget::Unknown => {
                    // Likely end of function
                    let next_addr = ins.addr + 4;
                    self.blocks.insert(block_start, next_addr);
                    // If this function has a prologue but no epilogue, and this
                    // instruction is a bctr, we can assume it's an unrecovered
                    // jump table and continue analysis.
                    if self.prologue.is_some() && self.epilogue.is_none() {
                        log::debug!("Assuming unrecovered jump table {:#010X}", next_addr);
                        self.branches.insert(ins.addr, vec![next_addr]);
                        if self.add_block_start(next_addr) {
                            executor.push(next_addr, vm.clone_for_return(), true);
                        }
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Return => {
                    self.blocks.insert(block_start, ins.addr + 4);
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Address(addr) => {
                    // End of block
                    self.blocks.insert(block_start, ins.addr + 4);
                    self.branches.insert(ins.addr, vec![addr]);
                    if addr == ins.addr {
                        // Infinite loop
                    } else if addr >= function_start
                        && matches!(function_end, Some(known_end) if addr < known_end)
                    {
                        // If target is within known function bounds, jump
                        if self.add_block_start(addr) {
                            return Ok(ExecCbResult::Jump(addr));
                        }
                    } else if matches!(obj.section_data(ins.addr, ins.addr + 4), Ok((_, data)) if data == [0u8; 4])
                    {
                        // If this branch has zeroed padding after it, assume tail call.
                        self.function_references.insert(addr);
                    } else {
                        self.possible_blocks.insert(addr);
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::JumpTable { address, size } => {
                    // End of block
                    let next_address = ins.addr + 4;
                    self.blocks.insert(block_start, next_address);

                    let (mut entries, size) = uniq_jump_table_entries(
                        obj,
                        address,
                        size,
                        ins.addr,
                        function_start,
                        function_end.unwrap_or_else(|| self.end()),
                    )?;
                    if entries.contains(&next_address)
                        && !entries.iter().any(|addr| known_functions.contains(addr))
                    {
                        self.jump_table_references.insert(address, size);
                        let mut branches = vec![];
                        for addr in entries {
                            branches.push(addr);
                            if self.add_block_start(addr) {
                                executor.push(addr, vm.clone_all(), true);
                            }
                        }
                        self.branches.insert(ins.addr, branches);
                    } else {
                        // If the table doesn't contain the next address,
                        // it could be a function jump table instead
                        self.possible_blocks.append(&mut entries);
                    }
                    Ok(ExecCbResult::EndBlock)
                }
            },
            StepResult::Branch(branches) => {
                // End of block
                self.blocks.insert(block_start, ins.addr + 4);

                let mut out_branches = vec![];
                for branch in branches {
                    match branch.target {
                        BranchTarget::Unknown | BranchTarget::Return => {
                            continue;
                        }
                        BranchTarget::Address(addr) => {
                            if branch.link || known_functions.contains(&addr) {
                                self.function_references.insert(addr);
                            } else {
                                out_branches.push(addr);
                                if self.add_block_start(addr) {
                                    executor.push(addr, branch.vm, true);
                                }
                            }
                        }
                        BranchTarget::JumpTable { .. } => {
                            bail!("Conditional jump table unsupported @ {:#010X}", ins.addr);
                        }
                    }
                }
                if !out_branches.is_empty() {
                    self.branches.insert(ins.addr, out_branches);
                }
                Ok(ExecCbResult::EndBlock)
            }
        }
    }

    pub fn analyze(
        &mut self,
        obj: &ObjInfo,
        start: u32,
        function_start: u32,
        function_end: Option<u32>,
        known_functions: &BTreeSet<u32>,
    ) -> Result<bool> {
        if !self.add_block_start(start) {
            return Ok(true);
        }

        let mut executor = Executor::new(obj);
        executor.push(start, VM::new_from_obj(obj), false);
        let result = executor.run(obj, |data| {
            self.instruction_callback(data, obj, function_start, function_end, known_functions)
        })?;
        if matches!(result, Some(b) if !b) {
            return Ok(false);
        }

        // Visit unreachable blocks
        while let Some((first, _)) = self.first_disconnected_block() {
            executor.push(first.end, VM::new_from_obj(obj), true);
            let result = executor.run(obj, |data| {
                self.instruction_callback(data, obj, function_start, function_end, known_functions)
            })?;
            if matches!(result, Some(b) if !b) {
                return Ok(false);
            }
        }

        // Visit trailing blocks
        if let Some(known_end) = function_end {
            while self.end() < known_end {
                executor.push(self.end(), VM::new_from_obj(obj), true);
                let result = executor.run(obj, |data| {
                    self.instruction_callback(
                        data,
                        obj,
                        function_start,
                        function_end,
                        known_functions,
                    )
                })?;
                if matches!(result, Some(b) if !b) {
                    return Ok(false);
                }
            }
        }

        // Sanity check
        for (&start, &end) in &self.blocks {
            ensure!(end != 0, "Failed to finalize block @ {start:#010X}");
        }

        Ok(true)
    }

    pub fn can_finalize(&self) -> bool { self.possible_blocks.is_empty() }

    pub fn finalize(&mut self, obj: &ObjInfo, known_functions: &BTreeSet<u32>) -> Result<()> {
        ensure!(!self.finalized, "Already finalized");
        ensure!(self.can_finalize(), "Can't finalize");

        match (self.prologue, self.epilogue) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                // Likely __noreturn
            }
            (None, Some(e)) => {
                log::info!("{:#010X?}", self);
                bail!("Unpaired epilogue {:#010X}", e);
            }
        }

        let end = self.end();
        match (obj.section_at(end), obj.section_at(end - 4)) {
            (Ok(section), Ok(other_section)) if section.index == other_section.index => {
                // FIXME this is real bad
                if !self.has_conditional_blr {
                    if let Some(ins) = disassemble(section, end - 4) {
                        if ins.op == Opcode::B
                            && self.function_references.contains(&ins.branch_dest().unwrap())
                        {
                            for branches in self.branches.values() {
                                if branches.len() > 1
                                    && branches.contains(self.blocks.last_key_value().unwrap().0)
                                {
                                    self.has_conditional_blr = true;
                                }
                            }
                        }
                    }
                }

                // MWCC optimization sometimes leaves an unreachable blr
                // after generating a conditional blr in the function.
                if self.has_conditional_blr
                    && matches!(disassemble(section, end - 4), Some(ins) if !ins.is_blr())
                    && matches!(disassemble(section, end), Some(ins) if ins.is_blr())
                    && !known_functions.contains(&end)
                {
                    log::trace!("Found trailing blr @ {:#010X}, merging with function", end);
                    self.blocks.insert(end, end + 4);
                }

                // Some functions with rfi also include a trailing nop
                if self.has_rfi
                    && matches!(disassemble(section, end), Some(ins) if is_nop(&ins))
                    && !known_functions.contains(&end)
                {
                    log::trace!("Found trailing nop @ {:#010X}, merging with function", end);
                    self.blocks.insert(end, end + 4);
                }
            }
            _ => {}
        }

        self.finalized = true;

        Ok(())
    }

    pub fn check_tail_call(
        &mut self,
        obj: &ObjInfo,
        addr: u32,
        function_start: u32,
        function_end: u32,
        known_functions: &BTreeSet<u32>,
    ) -> TailCallResult {
        // If jump target is already a known block or within known function bounds, not a tail call.
        if self.blocks.contains_key(&addr) || (addr >= function_start && addr < function_end) {
            return TailCallResult::Not;
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
        let section = match obj.section_at(function_start) {
            Ok(section) => section,
            Err(e) => return TailCallResult::Error(e),
        };
        if !section.contains(addr) {
            return TailCallResult::Is;
        }
        // If the jump target has 0'd padding before it, known tail call.
        if matches!(obj.section_data(addr - 4, addr), Ok((_, data)) if data == [0u8; 4]) {
            return TailCallResult::Is;
        }
        // If we're not sure where the function ends yet, mark as possible tail call.
        // let end = self.end();
        if function_end == 0 {
            return TailCallResult::Possible;
        }
        // If jump target is known to be a function, or there's a function in between
        // this and the jump target, known tail call.
        if self.function_references.range(function_start + 4..=addr).next().is_some()
            || known_functions.range(function_start + 4..=addr).next().is_some()
        {
            return TailCallResult::Is;
        }
        // Perform CFA on jump target to determine more
        let mut slices = FunctionSlices {
            function_references: self.function_references.clone(),
            ..Default::default()
        };
        if let Ok(result) =
            slices.analyze(obj, addr, function_start, Some(function_end), known_functions)
        {
            // If analysis failed, assume tail call.
            if !result {
                log::warn!("Tail call analysis failed for {:#010X}", addr);
                return TailCallResult::Is;
            }
            // If control flow jumps below the entry point, not a tail call.
            let start = slices.start();
            if start < addr {
                log::trace!("Tail call possibility eliminated: {:#010X} < {:#010X}", start, addr);
                return TailCallResult::Not;
            }
            // If control flow includes another possible tail call, we know both are not tail calls.
            let end = slices.end();
            let other_blocks =
                self.possible_blocks.range(start + 4..end).cloned().collect::<Vec<u32>>();
            if !other_blocks.is_empty() {
                for other_addr in other_blocks {
                    log::trace!("Logically eliminating {:#010X}", other_addr);
                    self.possible_blocks.remove(&other_addr);
                    // self.add_block_start(oth);
                }
                log::trace!("While analyzing {:#010X}", addr);
                return TailCallResult::Not;
            }
            // If we discovered a function prologue, known tail call.
            if slices.prologue.is_some() {
                log::trace!("Prologue discovered; known tail call: {:#010X}", addr);
                return TailCallResult::Is;
            }
        }
        TailCallResult::Possible
    }

    pub fn first_disconnected_block(&self) -> Option<(BlockRange, BlockRange)> {
        let mut iter = self.blocks.iter().peekable();
        loop {
            let ((first_begin, first_end), (second_begin, second_end)) =
                match (iter.next(), iter.peek()) {
                    (Some((&b1s, &b1e)), Some(&(&b2s, &b2e))) => ((b1s, b1e), (b2s, b2e)),
                    _ => break None,
                };
            if second_begin > first_end {
                break Some((first_begin..first_end, second_begin..second_end));
            }
        }
    }
}

#[inline]
fn is_conditional_blr(ins: &Ins) -> bool {
    ins.op == Opcode::Bclr && ins.field_BO() & 0b10100 != 0b10100
}

#[inline]
fn is_nop(ins: &Ins) -> bool {
    // ori r0, r0, 0
    ins.code == 0x60000000
}
