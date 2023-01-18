use std::{collections::BTreeSet, num::NonZeroU32};

use anyhow::{Context, Result};
use fixedbitset::FixedBitSet;
use ppc750cl::Ins;

use crate::util::{
    obj::{ObjInfo, ObjSection, ObjSectionKind},
    vm::{StepResult, VM},
};

pub fn disassemble(section: &ObjSection, address: u32) -> Option<Ins> {
    read_u32(&section.data, address, section.address as u32).map(|code| Ins::new(code, address))
}

pub fn read_u32(data: &[u8], address: u32, section_address: u32) -> Option<u32> {
    let offset = (address - section_address) as usize;
    if data.len() < offset + 4 {
        return None;
    }
    Some(u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// Space-efficient implementation for tracking visited code addresses
struct VisitedAddresses {
    inner: Vec<FixedBitSet>,
}

impl VisitedAddresses {
    pub fn new(obj: &ObjInfo) -> Self {
        let mut inner = Vec::with_capacity(obj.sections.len());
        for section in &obj.sections {
            if section.kind == ObjSectionKind::Code {
                let size = (section.size / 4) as usize;
                inner.push(FixedBitSet::with_capacity(size));
            } else {
                // Empty
                inner.push(FixedBitSet::new())
            }
        }
        Self { inner }
    }

    pub fn contains(&self, section: &ObjSection, address: u32) -> bool {
        self.inner[section.index].contains(Self::bit_for(section, address))
    }

    pub fn insert(&mut self, section: &ObjSection, address: u32) {
        self.inner[section.index].insert(Self::bit_for(section, address));
    }

    #[inline]
    fn bit_for(section: &ObjSection, address: u32) -> usize {
        ((address as u64 - section.address) / 4) as usize
    }
}

pub struct VMState {
    pub vm: Box<VM>,
    pub address: u32,
}

/// Helper for branched VM execution, only visiting addresses once.
pub struct Executor {
    vm_stack: Vec<VMState>,
    visited: VisitedAddresses,
}

pub struct ExecCbData<'a> {
    pub executor: &'a mut Executor,
    pub vm: &'a mut VM,
    pub result: StepResult,
    pub section: &'a ObjSection,
    pub ins: &'a Ins,
    pub block_start: u32,
}

pub enum ExecCbResult<T = ()> {
    Continue,
    Jump(u32),
    EndBlock,
    End(T),
}

impl Executor {
    pub fn new(obj: &ObjInfo) -> Self {
        Self { vm_stack: vec![], visited: VisitedAddresses::new(obj) }
    }

    pub fn run<Cb, R>(&mut self, obj: &ObjInfo, mut cb: Cb) -> Result<Option<R>>
    where Cb: FnMut(ExecCbData) -> Result<ExecCbResult<R>> {
        while let Some(mut state) = self.vm_stack.pop() {
            let section = match obj.section_at(state.address) {
                Ok(section) => section,
                Err(e) => {
                    log::error!("{}", e);
                    // return Ok(None);
                    continue;
                }
            };
            if section.kind != ObjSectionKind::Code {
                log::warn!("Attempted to visit non-code address {:#010X}", state.address);
                continue;
            }

            // Already visited block
            if self.visited.contains(section, state.address) {
                continue;
            }

            let mut block_start = state.address;
            loop {
                self.visited.insert(section, state.address);

                let ins = match disassemble(section, state.address) {
                    Some(ins) => ins,
                    None => return Ok(None),
                };
                let result = state.vm.step(&ins);
                match cb(ExecCbData {
                    executor: self,
                    vm: &mut state.vm,
                    result,
                    section,
                    ins: &ins,
                    block_start,
                })? {
                    ExecCbResult::Continue => {
                        state.address += 4;
                    }
                    ExecCbResult::Jump(addr) => {
                        if self.visited.contains(section, addr) {
                            break;
                        }
                        block_start = addr;
                        state.address = addr;
                    }
                    ExecCbResult::EndBlock => break,
                    ExecCbResult::End(result) => return Ok(Some(result)),
                }
            }
        }
        Ok(None)
    }

    pub fn push(&mut self, address: u32, vm: Box<VM>, sort: bool) {
        self.vm_stack.push(VMState { address, vm });
        if sort {
            // Sort lowest to highest, so we always go highest address first
            self.vm_stack.sort_by_key(|state| state.address);
        }
    }

    pub fn visited(&self, section: &ObjSection, address: u32) -> bool {
        self.visited.contains(section, address)
    }
}

fn is_valid_jump_table_addr(obj: &ObjInfo, addr: u32) -> bool {
    matches!(obj.section_at(addr), Ok(section) if section.kind != ObjSectionKind::Bss)
}

fn get_jump_table_entries(
    obj: &ObjInfo,
    addr: u32,
    size: Option<NonZeroU32>,
    from: u32,
    function_start: u32,
    function_end: u32,
) -> Result<(Vec<u32>, u32)> {
    let section = obj.section_at(addr).with_context(|| {
        format!("Failed to get jump table entries @ {:#010X} size {:?}", addr, size)
    })?;
    let offset = (addr as u64 - section.address) as usize;
    if let Some(size) = size.map(|n| n.get()) {
        log::debug!(
            "Located jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            size / 4,
            from
        );
        let jt_data = &section.data[offset..offset + size as usize];
        let entries =
            jt_data.chunks_exact(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect();
        Ok((entries, size))
    } else {
        let mut entries = Vec::new();
        let mut cur_addr = addr;
        while let Some(value) = read_u32(&section.data, cur_addr, section.address as u32) {
            if value < function_start || value >= function_end {
                break;
            }
            entries.push(value);
            cur_addr += 4;
        }
        let size = cur_addr - addr;
        log::debug!(
            "Guessed jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            size / 4,
            from
        );
        Ok((entries, size))
    }
}

pub fn uniq_jump_table_entries(
    obj: &ObjInfo,
    addr: u32,
    size: Option<NonZeroU32>,
    from: u32,
    function_start: u32,
    function_end: u32,
) -> Result<(BTreeSet<u32>, u32)> {
    if !is_valid_jump_table_addr(obj, addr) {
        return Ok((BTreeSet::new(), 0));
    }
    let (entries, size) =
        get_jump_table_entries(obj, addr, size, from, function_start, function_end)?;
    Ok((BTreeSet::from_iter(entries.iter().cloned().filter(|&addr| addr != 0)), size))
}
