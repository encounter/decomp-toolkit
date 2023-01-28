use anyhow::Result;
use fixedbitset::FixedBitSet;
use ppc750cl::Ins;

use crate::{
    analysis::{
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
