use anyhow::{ensure, Result};
use fixedbitset::FixedBitSet;
use powerpc::Ins;

use crate::{
    analysis::{
        cfa::SectionAddress,
        disassemble,
        vm::{StepResult, VM},
    },
    obj::{ObjInfo, ObjSection, ObjSectionKind},
};

/// Space-efficient implementation for tracking visited code addresses
struct VisitedAddresses {
    inner: Vec<FixedBitSet>,
}

impl VisitedAddresses {
    pub fn new(obj: &ObjInfo) -> Self {
        let mut inner = Vec::with_capacity(obj.sections.len() as usize);
        for (_, section) in obj.sections.iter() {
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

    pub fn contains(&self, section_address: u32, address: SectionAddress) -> bool {
        self.inner[address.section as usize]
            .contains(Self::bit_for(section_address, address.address))
    }

    pub fn insert(&mut self, section_address: u32, address: SectionAddress) {
        self.inner[address.section as usize]
            .insert(Self::bit_for(section_address, address.address));
    }

    #[inline]
    fn bit_for(section_address: u32, address: u32) -> usize {
        ((address - section_address) / 4) as usize
    }
}

pub struct VMState {
    pub vm: Box<VM>,
    pub address: SectionAddress,
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
    pub ins_addr: SectionAddress,
    pub section: &'a ObjSection,
    pub ins: Ins,
    pub block_start: SectionAddress,
}

pub enum ExecCbResult<T = ()> {
    Continue,
    Jump(SectionAddress),
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
            let section = &obj.sections[state.address.section];
            ensure!(
                section.contains(state.address.address),
                "Invalid address {:#010X} within section {} ({:#010X}-{:#010X})",
                state.address.address,
                section.name,
                section.address,
                section.address + section.size
            );
            if section.kind != ObjSectionKind::Code {
                log::warn!("Attempted to visit non-code address {:#010X}", state.address);
                continue;
            }

            // Already visited block
            let section_address = section.address as u32;
            if self.visited.contains(section_address, state.address) {
                continue;
            }

            let mut block_start = state.address;
            loop {
                self.visited.insert(section_address, state.address);

                let ins = match disassemble(section, state.address.address) {
                    Some(ins) => ins,
                    None => return Ok(None),
                };
                let result = state.vm.step(obj, state.address, ins);
                match cb(ExecCbData {
                    executor: self,
                    vm: &mut state.vm,
                    result,
                    ins_addr: state.address,
                    section,
                    ins,
                    block_start,
                })? {
                    ExecCbResult::Continue => {
                        state.address += 4;
                    }
                    ExecCbResult::Jump(addr) => {
                        if self.visited.contains(section_address, addr) {
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

    pub fn push(&mut self, address: SectionAddress, vm: Box<VM>, sort: bool) {
        self.vm_stack.push(VMState { address, vm });
        if sort {
            // Sort lowest to highest, so we always go highest address first
            self.vm_stack.sort_by_key(|state| state.address);
        }
    }

    pub fn visited(&self, section_address: u32, address: SectionAddress) -> bool {
        self.visited.contains(section_address, address)
    }
}
