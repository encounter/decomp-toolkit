use std::num::NonZeroU32;

use powerpc::{Argument, Ins, Opcode, GPR};

use crate::{
    analysis::{cfa::SectionAddress, disassemble, relocation_target_for, RelocationTarget},
    obj::{ObjInfo, ObjKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpTableType {
    // the table came from an lwzx, contains absolute addresses
    Absolute,
    // the table came from an lbzx, contains relative byte offsets (no rlwinm before the bctr)
    RelativeBytes(Option<RelocationTarget>),
    // the table came from an lbzx, contains relative byte offsets that we must multiply by 4
    RelativeBytesTimes4(Option<RelocationTarget>),
    // the table came from an lhzx, contains relative short offsets (no rlwinm before the bctr)
    RelativeShorts(Option<RelocationTarget>),
    // the table came from an lhzx, contains relative short offsets that we must multiply by 2
    RelativeShortsTimes2(Option<RelocationTarget>),
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum GprSourceLocation {
    #[default]
    Unknown,
    Register(usize),
    Stack(usize),
    Memory(usize),
    MemoryOffset {
        address: usize,
        offset_register: usize,
    },
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct GprSource {
    pub kind: GprSourceLocation,
    pub version: usize,
}

impl GprSource {
    // fn from_register(source: &Gpr, regnum: usize) -> Self {
    //     Self { kind: GprSourceLocation::Register(regnum), version: source.version }
    // }

    // from stack

    // TODO: write helper that checks if GprSource matches with a reg currently in the VM
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum GprValue {
    #[default]
    /// GPR value is unknown
    Unknown,
    /// GPR value is a constant
    Constant(u64),
    /// GPR value is a known relocated address
    Address(RelocationTarget),
    /// Comparison result (CR field)
    ComparisonResult(u8),
    /// GPR value is within a range
    Range { min: u64, max: u64, step: u64 },
    /// GPR value is loaded from an address with a max offset (jump table)
    LoadIndexed {
        jump_table_type: JumpTableType,
        jump_table_address: RelocationTarget,
        max_offset: Option<NonZeroU32>,
    },
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Gpr {
    /// The current calculated value
    pub value: GprValue,
    /// Address that loads the hi part of this GPR
    pub hi_addr: Option<SectionAddress>,
    /// Address that loads the lo part of this GPR
    pub lo_addr: Option<SectionAddress>,
    /// The source of this GPR's value
    pub source: GprSource,
    /// The revision of this GPR's value
    pub version: usize,
}

impl Gpr {
    fn set_direct(&mut self, value: GprValue, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = None;
        self.lo_addr = None;
        self.set_source(src_reg);
    }

    fn set_hi(&mut self, value: GprValue, addr: SectionAddress, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = Some(addr);
        self.lo_addr = None;
        self.set_source(src_reg);
    }

    fn set_lo(&mut self, value: GprValue, addr: SectionAddress, hi_gpr: Gpr, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = hi_gpr.hi_addr;
        self.lo_addr = Some(hi_gpr.lo_addr.unwrap_or(addr));
        self.set_source(src_reg);
    }

    fn set_source(&mut self, src_reg: Option<u8>) {
        match src_reg {
            Some(reg_num) => {
                self.source = GprSource {
                    kind: GprSourceLocation::Register(reg_num as usize),
                    version: self.version,
                };
            }
            None => {
                self.source = GprSource { kind: GprSourceLocation::Unknown, version: self.version };
            }
        }
        self.version += 1;
    }

    fn address(&self, obj: &ObjInfo, ins_addr: SectionAddress) -> Option<RelocationTarget> {
        match self.value {
            GprValue::Constant(value) => section_address_for(obj, ins_addr, value as u32),
            GprValue::Address(target) => Some(target),
            _ => None,
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Cr {
    /// The left-hand value of this comparison
    pub left: GprValue,
    /// The right-hand value of this comparison
    pub right: GprValue,
    /// Whether this comparison is signed
    pub signed: bool,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct VM {
    /// General purpose registers
    pub gpr: [Gpr; 32],
    /// Condition registers
    pub cr: [Cr; 8],
    /// Link register
    pub lr: GprValue,
    /// Count register
    pub ctr: GprValue,
    /// The last modified CR
    pub last_modified_cr: u8,
}

impl VM {
    pub fn gpr_value(&self, reg: u8) -> GprValue { self.gpr[reg as usize].value }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BranchTarget {
    /// Unknown branch target (CTR without known value)
    Unknown,
    /// Branch to LR
    Return,
    /// Branch to address
    Address(RelocationTarget),
    /// Branch to jump table
    JumpTable {
        jump_table_type: JumpTableType,
        jump_table_address: RelocationTarget,
        size: Option<NonZeroU32>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Branch {
    /// Branch target
    pub target: BranchTarget,
    /// Branch with link
    pub link: bool,
    /// VM state for this branch
    pub vm: Box<VM>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StepResult {
    /// Continue normally
    Continue,
    /// Load from / store to
    LoadStore { address: RelocationTarget, source: Gpr, source_reg: u8 },
    /// Hit illegal instruction
    Illegal,
    /// Jump without affecting VM state
    Jump(BranchTarget),
    /// Branch with split VM states
    Branch(Vec<Branch>),
}

pub fn section_address_for(
    obj: &ObjInfo,
    ins_addr: SectionAddress,
    target_addr: u32,
) -> Option<RelocationTarget> {
    if let Some(target) = relocation_target_for(obj, ins_addr, None).ok().flatten() {
        return Some(target);
    }
    if obj.kind == ObjKind::Executable {
        let (section_index, _) = obj.sections.at_address(target_addr).ok()?;
        return Some(RelocationTarget::Address(SectionAddress::new(section_index, target_addr)));
    }
    if obj.sections[ins_addr.section].contains(target_addr) {
        Some(RelocationTarget::Address(SectionAddress::new(ins_addr.section, target_addr)))
    } else {
        None
    }
}

impl VM {
    #[inline]
    pub fn new() -> Box<Self> { Box::default() }

    #[inline]
    pub fn new_from_obj(obj: &ObjInfo) -> Box<Self> {
        Self::new_with_base(obj.sda2_base, obj.sda_base)
    }

    #[inline]
    pub fn new_with_base(sda2_base: Option<u32>, sda_base: Option<u32>) -> Box<Self> {
        let mut vm = Self::new();
        if let Some(value) = sda2_base {
            vm.gpr[2].value = GprValue::Constant(value as u64);
        }
        if let Some(value) = sda_base {
            vm.gpr[13].value = GprValue::Constant(value as u64);
        }
        vm
    }

    /// When calling a function, only preserve SDA bases
    #[inline]
    pub fn clone_for_link(&self) -> Box<Self> {
        let mut vm = Self::new();
        vm.gpr[2].value = self.gpr[2].value;
        vm.gpr[13].value = self.gpr[13].value;
        vm
    }

    /// When returning from a function call, only dedicated
    /// and nonvolatile registers are preserved
    #[inline]
    pub fn clone_for_return(&self) -> Box<Self> {
        let mut vm = Self::new();
        // Dedicated registers
        vm.gpr[1].value = self.gpr[1].value;
        vm.gpr[2].value = self.gpr[2].value;
        vm.gpr[13].value = self.gpr[13].value;
        // Non-volatile registers
        for i in 14..32 {
            vm.gpr[i] = self.gpr[i];
        }
        vm
    }

    #[inline]
    pub fn clone_all(&self) -> Box<Self> { Box::new(self.clone()) }

    pub fn step(&mut self, obj: &ObjInfo, ins_addr: SectionAddress, ins: Ins) -> StepResult {
        match ins.op {
            Opcode::Illegal => {
                println!("Warning! Illegal inst found at 0x{:X}", ins_addr.address);
                return StepResult::Illegal;
            }
            // add rD, rA, rB
            Opcode::Add => {
                let left = self.gpr[ins.field_ra() as usize].value;
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (GprValue::Constant(left), GprValue::Constant(right)) => {
                        GprValue::Constant(left.wrapping_add(right))
                    }
                    (
                        GprValue::Address(RelocationTarget::Address(left)),
                        GprValue::Constant(right),
                    ) => GprValue::Address(RelocationTarget::Address(
                        left.wrapping_add(right as u32),
                    )),
                    (
                        GprValue::Constant(left),
                        GprValue::Address(RelocationTarget::Address(right)),
                    ) => GprValue::Address(RelocationTarget::Address(
                        right.wrapping_add(left as u32),
                    )),
                    (
                        GprValue::Constant(left),
                        GprValue::LoadIndexed {
                            jump_table_type: jt,
                            jump_table_address: ja,
                            max_offset: m,
                        },
                    ) => {
                        match jt {
                            // if we reached this point, this should be a relative jump table
                            JumpTableType::Absolute => {
                                // this probably isn't a jump table anyway, so just keep the load indexed value
                                GprValue::LoadIndexed {
                                    jump_table_type: jt,
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            // anyways, mark down the relative address we should be adding offsets to
                            JumpTableType::RelativeBytes(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytes(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeBytesTimes4(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytesTimes4(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeShorts(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShorts(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeShortsTimes2(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShortsTimes2(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                        }
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // addis rD, rA, SIMM
            Opcode::Addis => {
                if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    debug_assert_eq!(ins.field_ra(), 0);
                    self.gpr[ins.field_rd() as usize].set_hi(
                        GprValue::Address(target),
                        ins_addr,
                        None,
                    );
                } else {
                    let left = if ins.field_ra() == 0 {
                        GprValue::Constant(0)
                    } else {
                        self.gpr[ins.field_ra() as usize].value
                    };
                    let value = match left {
                        GprValue::Constant(value) => {
                            GprValue::Constant(value.wrapping_add((ins.field_simm() as u64) << 16))
                        }
                        _ => GprValue::Unknown,
                    };
                    if ins.field_ra() == 0 {
                        // lis rD, SIMM
                        self.gpr[ins.field_rd() as usize].set_hi(value, ins_addr, None);
                    } else {
                        self.gpr[ins.field_rd() as usize].set_direct(value, None);
                    }
                }
            }
            // addi rD, rA, SIMM
            // addic rD, rA, SIMM
            // addic. rD, rA, SIMM
            Opcode::Addi | Opcode::Addic | Opcode::Addic_ => {
                if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    self.gpr[ins.field_rd() as usize].set_lo(
                        GprValue::Address(target),
                        ins_addr,
                        self.gpr[ins.field_ra() as usize],
                        None,
                    );
                } else {
                    let load_zero = ins.field_ra() == 0 && ins.op == Opcode::Addi;
                    let left = if load_zero {
                        GprValue::Constant(0)
                    } else {
                        self.gpr[ins.field_ra() as usize].value
                    };
                    let value = match left {
                        GprValue::Constant(value) => {
                            GprValue::Constant(value.wrapping_add(ins.field_simm() as u64))
                        }
                        GprValue::Address(RelocationTarget::Address(address)) => GprValue::Address(
                            RelocationTarget::Address(address.offset(ins.field_simm() as i32)),
                        ),
                        _ => GprValue::Unknown,
                    };
                    if load_zero {
                        // li rD, SIMM
                        self.gpr[ins.field_rd() as usize].set_direct(value, None);
                    } else {
                        self.gpr[ins.field_rd() as usize].set_lo(
                            value,
                            ins_addr,
                            self.gpr[ins.field_ra() as usize],
                            None,
                        );
                    }
                }
            }
            // subf rD, rA, rB
            // subfc rD, rA, rB
            Opcode::Subf | Opcode::Subfc => {
                self.gpr[ins.field_rd() as usize].set_direct(
                    match (
                        self.gpr[ins.field_ra() as usize].value,
                        self.gpr[ins.field_rb() as usize].value,
                    ) {
                        (GprValue::Constant(left), GprValue::Constant(right)) => {
                            GprValue::Constant((!left).wrapping_add(right).wrapping_add(1))
                        }
                        _ => GprValue::Unknown,
                    },
                    None,
                );
            }
            // subfic rD, rA, SIMM
            Opcode::Subfic => {
                self.gpr[ins.field_rd() as usize].set_direct(
                    match self.gpr[ins.field_ra() as usize].value {
                        GprValue::Constant(value) => GprValue::Constant(
                            (!value).wrapping_add(ins.field_simm() as u64).wrapping_add(1),
                        ),
                        _ => GprValue::Unknown,
                    },
                    None,
                );
            }
            // ori rA, rS, UIMM
            Opcode::Ori => {
                // evil hack to get through what are effectively nops (ori rX, rX, 0)
                if ins.field_uimm() == 0 && ins.field_ra() == ins.field_rs() {
                    // don't do anything
                } else if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    self.gpr[ins.field_ra() as usize].set_lo(
                        GprValue::Address(target),
                        ins_addr,
                        self.gpr[ins.field_rs() as usize],
                        None,
                    );
                } else {
                    let value = match self.gpr[ins.field_rs() as usize].value {
                        GprValue::Constant(value) => {
                            GprValue::Constant(value | ins.field_uimm() as u64)
                        }
                        _ => GprValue::Unknown,
                    };
                    self.gpr[ins.field_ra() as usize].set_lo(
                        value,
                        ins_addr,
                        self.gpr[ins.field_rs() as usize],
                        None,
                    );
                }
            }
            // or rA, rS, rB
            Opcode::Or => {
                if ins.field_rs() == ins.field_rb() {
                    // Register copy
                    self.gpr[ins.field_ra() as usize] = self.gpr[ins.field_rs() as usize];
                    self.gpr[ins.field_ra() as usize].set_source(Some(ins.field_rs()));
                } else {
                    let left = self.gpr[ins.field_rs() as usize].value;
                    let right = self.gpr[ins.field_rb() as usize].value;
                    let value = match (left, right) {
                        (GprValue::Constant(left), GprValue::Constant(right)) => {
                            GprValue::Constant(left | right)
                        }
                        _ => GprValue::Unknown,
                    };
                    self.gpr[ins.field_ra() as usize].set_direct(value, None);
                }
            }
            // cmp [crfD], [L], rA, rB
            // cmpi [crfD], [L], rA, SIMM
            // cmpl [crfD], [L], rA, rB
            // cmpli [crfD], [L], rA, UIMM
            Opcode::Cmp | Opcode::Cmpi | Opcode::Cmpl | Opcode::Cmpli => {
                if ins.field_l() == 0 {
                    let left_reg = ins.field_ra() as usize;
                    let left = self.gpr[left_reg].value;
                    let (right, signed) = match ins.op {
                        Opcode::Cmp => (self.gpr[ins.field_rb() as usize].value, true),
                        Opcode::Cmpl => (self.gpr[ins.field_rb() as usize].value, false),
                        Opcode::Cmpi => (GprValue::Constant(ins.field_simm() as u64), true),
                        Opcode::Cmpli => (GprValue::Constant(ins.field_uimm() as u64), false),
                        _ => unreachable!(),
                    };
                    let crf = ins.field_crfd();
                    self.cr[crf as usize] = Cr { signed, left, right };
                    self.gpr[left_reg].value = GprValue::ComparisonResult(crf);
                    self.last_modified_cr = crf;
                }
            }
            // rlwinm rA, rS, SH, MB, ME
            // rlwnm rA, rS, rB, MB, ME
            Opcode::Rlwinm | Opcode::Rlwnm => {
                let value = if let Some(shift) = match ins.op {
                    Opcode::Rlwinm => Some(ins.field_sh() as u32),
                    Opcode::Rlwnm => match self.gpr[ins.field_rb() as usize].value {
                        GprValue::Constant(value) => Some(value as u32),
                        _ => None,
                    },
                    _ => unreachable!(),
                } {
                    let mask = mask_value(ins.field_mb() as u32, ins.field_me() as u32);

                    // for jump table detection - check to see if rS has a source reg we can pull data from
                    if self.gpr[ins.field_rs() as usize].value == GprValue::Unknown {
                        // try to find source reg
                        let src = self.gpr[ins.field_rs() as usize].source;
                        if let GprSourceLocation::Register(r) = src.kind {
                            // check the src reg and the current src.version
                            // it MUST match src reg's current version in order to pull data from it
                            if self.gpr[r].version == src.version
                                && self.gpr[r].value != GprValue::Unknown
                            {
                                self.gpr[ins.field_rs() as usize].value = self.gpr[r].value;
                            }
                        }
                    }

                    match self.gpr[ins.field_rs() as usize].value {
                        // set everything as u32s before rotating
                        // because although regs are 64 bits on Xbox, 32-bit instructions run in 32-bit mode
                        GprValue::Constant(value) => {
                            GprValue::Constant(((value as u32).rotate_left(shift) & mask) as u64)
                        }
                        GprValue::Range { min, max, step } => GprValue::Range {
                            min: ((min as u32).rotate_left(shift) & mask) as u64,
                            max: ((max as u32).rotate_left(shift) & mask) as u64,
                            step: ((step as u32).rotate_left(shift)) as u64,
                        },
                        // if we've come across a rlwinm as a LoadIndexed...
                        GprValue::LoadIndexed {
                            jump_table_type: jt,
                            jump_table_address: ja,
                            max_offset: m,
                        } => {
                            let ret = match jt {
                                JumpTableType::Absolute => GprValue::LoadIndexed {
                                    jump_table_type: jt,
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                // if the table type is currently relative, it means we need to multiply offsets by 4
                                JumpTableType::RelativeBytes(addr) => GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytesTimes4(addr),
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                JumpTableType::RelativeBytesTimes4(addr) => {
                                    log::warn!("Reached rlwinm with a JumpTableType of RelativeTimes4. Can we even reach this point? {}", ins_addr);
                                    GprValue::LoadIndexed {
                                        jump_table_type: JumpTableType::RelativeBytesTimes4(addr),
                                        jump_table_address: ja,
                                        max_offset: m,
                                    }
                                }
                                JumpTableType::RelativeShorts(addr) => GprValue::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShortsTimes2(addr),
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                JumpTableType::RelativeShortsTimes2(addr) => {
                                    log::warn!("Reached rlwinm with a JumpTableType of RelativeTimes2. Can we even reach this point? {}", ins_addr);
                                    GprValue::LoadIndexed {
                                        jump_table_type: JumpTableType::RelativeShortsTimes2(addr),
                                        jump_table_address: ja,
                                        max_offset: m,
                                    }
                                }
                            };
                            ret
                        }
                        _ => GprValue::Range {
                            min: 0,
                            max: mask as u64,
                            step: 1u64.rotate_left(shift),
                        },
                    }
                } else {
                    GprValue::Unknown
                };
                self.gpr[ins.field_ra() as usize].set_direct(value, None);
            }
            // b[l][a] target_addr
            // b[c][l][a] BO, BI, target_addr
            // b[c]ctr[l] BO, BI
            // b[c]lr[l] BO, BI
            Opcode::B | Opcode::Bc | Opcode::Bcctr | Opcode::Bclr => {
                // HACK for `bla 0x60` in __OSDBJump
                if ins.op == Opcode::B && ins.field_lk() && ins.field_aa() {
                    return StepResult::Jump(BranchTarget::Unknown);
                }

                let branch_target = match ins.op {
                    Opcode::Bcctr => {
                        match self.ctr {
                            GprValue::Constant(value) => {
                                // TODO only check valid target?
                                if let Some(target) = section_address_for(obj, ins_addr, value as u32) {
                                    BranchTarget::Address(target)
                                } else {
                                    BranchTarget::Unknown
                                }
                            },
                            GprValue::Address(target) => BranchTarget::Address(target),
                            GprValue::LoadIndexed { jump_table_type: jtype, jump_table_address: address, max_offset }
                            // FIXME: avoids treating bctrl indirect calls as jump tables
                            if !ins.field_lk() => {
                                let add_increment = match jtype {
                                    JumpTableType::Absolute => 4,
                                    JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => 1,
                                    JumpTableType::RelativeShorts(_) | JumpTableType::RelativeShortsTimes2(_) => 2,
                                };
                                BranchTarget::JumpTable { jump_table_type: jtype, jump_table_address: address,
                                    size: max_offset.and_then(|n| n.checked_add( add_increment)) }
                            },
                            _ => BranchTarget::Unknown,
                        }
                    }
                    Opcode::Bclr => BranchTarget::Return,
                    _ => {
                        let value = ins.branch_dest(ins_addr.address).unwrap();
                        if let Some(target) = section_address_for(obj, ins_addr, value) {
                            BranchTarget::Address(target)
                        } else {
                            BranchTarget::Unknown
                        }
                    }
                };

                // If branching with link, use function call semantics
                if ins.field_lk() {
                    return StepResult::Branch(vec![
                        Branch {
                            target: BranchTarget::Address(RelocationTarget::Address(ins_addr + 4)),
                            link: false,
                            vm: self.clone_for_return(),
                        },
                        Branch { target: branch_target, link: true, vm: self.clone_for_link() },
                    ]);
                }

                // Branch always
                if ins.op == Opcode::B || ins.field_bo() & 0b10100 == 0b10100 {
                    return StepResult::Jump(branch_target);
                }

                // Branch conditionally
                let mut branches = vec![
                    // Branch not taken
                    Branch {
                        target: BranchTarget::Address(RelocationTarget::Address(ins_addr + 4)),
                        link: false,
                        vm: self.clone_all(),
                    },
                    // Branch taken
                    Branch { target: branch_target, link: ins.field_lk(), vm: self.clone_all() },
                ];

                // Use tracked CR to calculate new register values for branches
                let crf = (ins.field_bi() >> 2) as usize;
                let crb = ins.field_bi() & 3;
                let (f_val, t_val) =
                    split_values_by_crb(crb, self.cr[crf].left, self.cr[crf].right);
                if ins.field_bo() & 0b11110 == 0b00100 {
                    // Branch if false
                    branches[0].vm.set_comparison_result(t_val, crf);
                    branches[1].vm.set_comparison_result(f_val, crf);
                } else if ins.field_bo() & 0b11110 == 0b01100 {
                    // Branch if true
                    branches[0].vm.set_comparison_result(f_val, crf);
                    branches[1].vm.set_comparison_result(t_val, crf);
                }

                return StepResult::Branch(branches);
            }
            // lwzx rD, rA, rB
            Opcode::Lwzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), GprValue::Range { min: _, max, .. })
                        if /*min == 0 &&*/ max < u64::MAX - 4 && max & 3 == 0 =>
                    {
                        // If the jump_table_address is within .text (supposed to be right after the bctr), this is a jump table
                        // else, this is a data table (i.e. an array of strings)
                        // but! since no bctr's come after data tables, these don't get treated like jump tables, soooooo I think this is fine?
                        GprValue::LoadIndexed { jump_table_type: JumpTableType::Absolute, jump_table_address: address, max_offset: NonZeroU32::new(max as u32) }
                    }
                    (Some(address), _) => {
                        GprValue::LoadIndexed { jump_table_type: JumpTableType::Absolute, jump_table_address: address, max_offset: None }
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // lbzx rD, rA, rB
            Opcode::Lbzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), GprValue::Range { min: _, max, .. })
                        if /*min == 0 &&*/ max < u64::MAX - 4 =>
                    {
                        // if we never encountered a bgt before this, we don't know the bounds for sure
                        let bounds_known: bool = match self.cr[self.last_modified_cr as usize].right {
                            GprValue::Constant(c) => { max == c },
                            _ => false,
                        };
                        GprValue::LoadIndexed {
                            jump_table_type: JumpTableType::RelativeBytes(None),
                            jump_table_address: address,
                            max_offset: if bounds_known { NonZeroU32::new(max as u32) } else { None } }
                    }
                    (Some(address), _) => {
                        GprValue::LoadIndexed { jump_table_type: JumpTableType::RelativeBytes(None), jump_table_address: address, max_offset: None }
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // lhzx rD, rA, rB
            Opcode::Lhzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), GprValue::Range { min: _, max, .. })
                    if /*min == 0 &&*/ max < u64::MAX - 4 && max & 1 == 0 =>
                        {
                            GprValue::LoadIndexed { jump_table_type: JumpTableType::RelativeShorts(None), jump_table_address: address, max_offset: NonZeroU32::new(max as u32) }
                        }
                    (Some(address), _) => {
                        GprValue::LoadIndexed { jump_table_type: JumpTableType::RelativeShorts(None), jump_table_address: address, max_offset: None }
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // mtspr SPR, rS
            Opcode::Mtspr => match ins.field_spr() {
                8 => self.lr = self.gpr[ins.field_rs() as usize].value,
                9 => self.ctr = self.gpr[ins.field_rs() as usize].value,
                _ => {}
            },
            // mfspr rD, SPR
            Opcode::Mfspr => {
                let value = match ins.field_spr() {
                    8 => self.lr,
                    9 => self.ctr,
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // rfi
            Opcode::Rfi | Opcode::Rfid => {
                return StepResult::Jump(BranchTarget::Unknown);
            }
            op if is_load_store_op(op) => {
                let source = ins.field_ra() as usize;
                let mut result = StepResult::Continue;
                if let GprValue::Address(target) = self.gpr[source].value {
                    if is_update_op(op) {
                        self.gpr[source].set_lo(
                            GprValue::Address(target),
                            ins_addr,
                            self.gpr[source],
                            None,
                        );
                    }
                    result = StepResult::LoadStore {
                        address: target,
                        source: self.gpr[source],
                        source_reg: source as u8,
                    };
                } else if let GprValue::Constant(base) = self.gpr[source].value {
                    let address = base.wrapping_add(ins.field_simm() as u64) as u32;
                    if let Some(target) = section_address_for(obj, ins_addr, address) {
                        if is_update_op(op) {
                            self.gpr[source].set_lo(
                                GprValue::Address(target),
                                ins_addr,
                                self.gpr[source],
                                None,
                            );
                        }
                        result = StepResult::LoadStore {
                            address: target,
                            source: self.gpr[source],
                            source_reg: source as u8,
                        };
                    }
                } else if is_update_op(op) {
                    self.gpr[source].set_direct(GprValue::Unknown, None);
                }
                if op == Opcode::Lwz {
                    // the following sequence checkers are terrible hacks
                    // the "proper" way to do it would be to track values of stack offsets/memory offsets as they're written to/read from,
                    // but for the life me i can't figure out how to do that
                    // so until that system gets implemented, these hacks will have to do
                    let section = obj.sections.at_address(ins_addr.address).expect("no section").1;
                    // check for the evil microsoft jump table bound sequence: lwz, cmplwi, bgt, lwz
                    // we're gonna check for the sequence from the second lwz
                    if ins_addr.address - section.address as u32 >= 12 {
                        if let (Some(first_lwz), Some(cmp), Some(bgt)) = (
                            disassemble(section, ins_addr.address.wrapping_sub(12)),
                            disassemble(section, ins_addr.address.wrapping_sub(8)),
                            disassemble(section, ins_addr.address.wrapping_sub(4)),
                        ) {
                            let is_lwz = first_lwz.op == Opcode::Lwz
                                && first_lwz.field_ra() == ins.field_ra()
                                && first_lwz.field_offset() == ins.field_offset();
                            let is_cmplwi = cmp.op == Opcode::Cmpli && cmp.field_l() == 0;
                            let is_bgt = bgt.op == Opcode::Bc
                                && (bgt.field_bo() & 30) == 12
                                && (bgt.field_bi() & 3) == 1;

                            // if we've found the sequence, retrieve the data
                            if is_lwz && is_cmplwi && is_bgt {
                                // println!("found sequence at {}!", ins_addr);
                                self.gpr[ins.field_rd() as usize].set_direct(
                                    self.gpr[first_lwz.field_rd() as usize].value,
                                    None,
                                );
                                return result;
                            }
                        }
                    }
                    // check for the evil microsoft jump table bound sequence: lwz, cmplwi, ble, b, lwz
                    if ins_addr.address - section.address as u32 >= 16 {
                        if let (Some(first_lwz), Some(cmp), Some(ble), Some(branch)) = (
                            disassemble(section, ins_addr.address.wrapping_sub(16)),
                            disassemble(section, ins_addr.address.wrapping_sub(12)),
                            disassemble(section, ins_addr.address.wrapping_sub(8)),
                            disassemble(section, ins_addr.address.wrapping_sub(4)),
                        ) {
                            let is_lwz = first_lwz.op == Opcode::Lwz
                                && first_lwz.field_ra() == ins.field_ra()
                                && first_lwz.field_offset() == ins.field_offset();
                            let is_cmplwi = cmp.op == Opcode::Cmpli && cmp.field_l() == 0;
                            let is_ble = ble.op == Opcode::Bc
                                && (ble.field_bo() & 30) == 4
                                && (ble.field_bi() & 3) == 1;
                            let is_branch =
                                branch.op == Opcode::B && !branch.field_aa() && !branch.field_lk();

                            // if we've found the sequence, retrieve the data
                            if is_lwz && is_cmplwi && is_ble && is_branch {
                                // println!("found sequence at {}!", ins_addr);
                                self.gpr[ins.field_rd() as usize].set_direct(
                                    self.gpr[first_lwz.field_rd() as usize].value,
                                    None,
                                );
                                return result;
                            }
                        }
                    }
                }
                if is_load_op(op) {
                    self.gpr[ins.field_rd() as usize].set_direct(GprValue::Unknown, None);
                }
                return result;
            }
            _ => {
                for argument in ins.defs() {
                    if let Argument::GPR(GPR(reg)) = argument {
                        self.gpr[reg as usize].set_direct(GprValue::Unknown, None);
                    }
                }
            }
        }
        StepResult::Continue
    }

    #[inline]
    fn set_comparison_result(&mut self, value: GprValue, crf: usize) {
        for gpr in &mut self.gpr {
            if gpr.value == GprValue::ComparisonResult(crf as u8) {
                gpr.value = value;
            }
        }
    }
}

/// Given a condition register bit, calculate new register
/// values for each branch. (false / true)
fn split_values_by_crb(crb: u8, left: GprValue, right: GprValue) -> (GprValue, GprValue) {
    match crb {
        // lt
        0 => match (left, right) {
            (GprValue::Range { min, max, step }, GprValue::Constant(value)) => (
                // left >= right
                GprValue::Range {
                    min: std::cmp::max(min, value),
                    max: std::cmp::max(max, value),
                    step,
                },
                // left < right
                GprValue::Range {
                    min: std::cmp::min(min, value.wrapping_sub(1)),
                    max: std::cmp::min(max, value.wrapping_sub(1)),
                    step,
                },
            ),
            (_, GprValue::Constant(value)) => (
                // left >= right
                GprValue::Range { min: value, max: u64::MAX, step: 1 },
                // left < right
                GprValue::Range { min: 0, max: value.wrapping_sub(1), step: 1 },
            ),
            _ => (left, left),
        },
        // gt
        1 => match (left, right) {
            (GprValue::Range { min, max, step }, GprValue::Constant(value)) => (
                // left <= right
                GprValue::Range {
                    min: std::cmp::min(min, value),
                    max: std::cmp::min(max, value),
                    step,
                },
                // left > right
                GprValue::Range {
                    min: std::cmp::max(min, value.wrapping_add(1)),
                    max: std::cmp::max(max, value.wrapping_add(1)),
                    step,
                },
            ),
            (_, GprValue::Constant(value)) => (
                // left <= right
                GprValue::Range { min: 0, max: value, step: 1 },
                // left > right
                GprValue::Range { min: value.wrapping_add(1), max: u64::MAX, step: 1 },
            ),
            _ => (left, left),
        },
        // eq
        2 => match (left, right) {
            (GprValue::Constant(l), GprValue::Constant(r)) => (
                // left != right
                if l == r { GprValue::Unknown } else { left },
                // left == right
                GprValue::Constant(r),
            ),
            (_, GprValue::Constant(value)) => (
                // left != right
                left,
                // left == right
                GprValue::Constant(value),
            ),
            _ => (left, left),
        },
        // so
        3 => (left, left),
        _ => unreachable!(),
    }
}

#[inline]
fn mask_value(begin: u32, end: u32) -> u32 {
    if begin <= end {
        let mut mask = 0u32;
        for bit in begin..=end {
            mask |= 1 << (31 - bit);
        }
        mask
    } else if begin == end + 1 {
        u32::MAX
    } else {
        let mut mask = u32::MAX;
        for bit in end + 1..begin {
            mask &= !(1 << (31 - bit));
        }
        mask
    }
}

#[inline]
pub fn is_load_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Lbz
            | Opcode::Lbzu
            | Opcode::Lha
            | Opcode::Lhau
            | Opcode::Lhz
            | Opcode::Lhzu
            | Opcode::Lmw
            | Opcode::Lwa
            | Opcode::Lwz
            | Opcode::Lwzu
            | Opcode::Ld
            | Opcode::Ldu
    )
}

#[inline]
pub fn is_loadf_op(op: Opcode) -> bool {
    matches!(op, Opcode::Lfd | Opcode::Lfdu | Opcode::Lfs | Opcode::Lfsu)
}

#[inline]
pub fn is_store_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Stb
            | Opcode::Stbu
            | Opcode::Sth
            | Opcode::Sthu
            | Opcode::Stmw
            | Opcode::Stw
            | Opcode::Stwu
            | Opcode::Std
            | Opcode::Stdu
    )
}

#[inline]
pub fn is_storef_op(op: Opcode) -> bool {
    matches!(op, Opcode::Stfd | Opcode::Stfdu | Opcode::Stfs | Opcode::Stfsu)
}

#[inline]
pub fn is_load_store_op(op: Opcode) -> bool {
    is_load_op(op) || is_loadf_op(op) || is_store_op(op) || is_storef_op(op)
}

#[inline]
pub fn is_update_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Lbzu
            | Opcode::Lbzux
            | Opcode::Ldu
            | Opcode::Ldux
            | Opcode::Lfdu
            | Opcode::Lfdux
            | Opcode::Lfsu
            | Opcode::Lfsux
            | Opcode::Lhau
            | Opcode::Lhaux
            | Opcode::Lhzu
            | Opcode::Lhzux
            | Opcode::Lwaux
            | Opcode::Lwzu
            | Opcode::Lwzux
            | Opcode::Stbu
            | Opcode::Stbux
            | Opcode::Stdu
            | Opcode::Stdux
            | Opcode::Stfdu
            | Opcode::Stfdux
            | Opcode::Stfsu
            | Opcode::Stfsux
            | Opcode::Sthu
            | Opcode::Sthux
            | Opcode::Stwu
            | Opcode::Stwux
    )
}

// #[inline]
// fn is_indexed_load_op(op: Opcode) -> bool {
//     matches!(
//         op,
//         Opcode::Lbzux
//             | Opcode::Lbzx
//             | Opcode::Lhax
//             | Opcode::Lhaux
//             | Opcode::Lhzx
//             | Opcode::Lhzux
//             | Opcode::Lwzx
//             | Opcode::Lwzux
//     )
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_load_indexed_1() {
//         let mut vm = VM::new();
//         assert_eq!(vm.step(&Ins::new(0x3cc08052, 0x803dfe28)), StepResult::Continue); // lis r6, -0x7fae
//         assert_eq!(vm.step(&Ins::new(0x38c60e18, 0x803dfe30)), StepResult::Continue); // addi r6, r6, 0xe18
//         assert_eq!(vm.gpr[6].value, GprValue::Constant(0x80520e18));
//         assert_eq!(vm.step(&Ins::new(0x550066fa, 0x803dfe34)), StepResult::Continue); // rlwinm r0, r8, 12, 27, 29
//         assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 28, step: 1 << 12 });
//         assert_eq!(vm.step(&Ins::new(0x7d86002e, 0x803dfe3c)), StepResult::Continue); // lwzx r12, r6, r0
//         assert_eq!(vm.gpr[12].value, GprValue::LoadIndexed {
//             address: 0x80520e18,
//             max_offset: NonZeroU32::new(28)
//         });
//         assert_eq!(vm.step(&Ins::new(0x7d8903a6, 0x803dfe4c)), StepResult::Continue); // mtspr CTR, r12
//         assert_eq!(vm.ctr, GprValue::LoadIndexed {
//             address: 0x80520e18,
//             max_offset: NonZeroU32::new(28)
//         });
//         assert_eq!(
//             vm.step(&Ins::new(0x4e800420, 0x803dfe50)), // bctr
//             StepResult::Jump(BranchTarget::JumpTable {
//                 address: 0x80520e18,
//                 size: NonZeroU32::new(32)
//             })
//         );
//     }
//
//     #[test]
//     fn test_load_indexed_2() {
//         let mut vm = VM::new();
//         assert_eq!(vm.step(&Ins::new(0x3c808057, 0x80465320)), StepResult::Continue); // lis r4, -0x7fa9
//         assert_eq!(vm.step(&Ins::new(0x54600e7a, 0x80465324)), StepResult::Continue); // rlwinm r0, r3, 1, 25, 29
//         assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 124, step: 2 });
//         assert_eq!(vm.step(&Ins::new(0x38840f70, 0x80465328)), StepResult::Continue); // addi r4, r4, 0xf70
//         assert_eq!(vm.gpr[4].value, GprValue::Constant(0x80570f70));
//         assert_eq!(vm.step(&Ins::new(0x7d84002e, 0x80465330)), StepResult::Continue); // lwzx r12, r4, r0
//         assert_eq!(vm.gpr[12].value, GprValue::LoadIndexed {
//             address: 0x80570f70,
//             max_offset: NonZeroU32::new(124)
//         });
//         assert_eq!(vm.step(&Ins::new(0x7d8903a6, 0x80465340)), StepResult::Continue); // mtspr CTR, r12
//         assert_eq!(vm.ctr, GprValue::LoadIndexed {
//             address: 0x80570f70,
//             max_offset: NonZeroU32::new(124)
//         });
//         assert_eq!(
//             vm.step(&Ins::new(0x4e800420, 0x80465344)), // bctr
//             StepResult::Jump(BranchTarget::JumpTable {
//                 address: 0x80570f70,
//                 size: NonZeroU32::new(128)
//             })
//         );
//     }
//
//     #[test]
//     fn test_load_indexed_3() {
//         let mut vm = VM::new();
//         assert_eq!(vm.step(&Ins::new(0x28000127, 0x800ed458)), StepResult::Continue); // cmplwi r0, 0x127
//         assert_eq!(vm.cr[0], Cr {
//             signed: false,
//             left: GprValue::Unknown,
//             right: GprValue::Constant(295),
//         });
//
//         // When branch isn't taken, we know r0 is <= 295
//         let mut false_vm = vm.clone();
//         false_vm.gpr[0] =
//             Gpr { value: GprValue::Range { min: 0, max: 295, step: 1 }, ..Default::default() };
//         // When branch is taken, we know r0 is > 295
//         let mut true_vm = vm.clone();
//         true_vm.gpr[0] = Gpr {
//             value: GprValue::Range { min: 296, max: u32::MAX, step: 1 },
//             ..Default::default()
//         };
//         assert_eq!(
//             vm.step(&Ins::new(0x418160bc, 0x800ed45c)), // bgt 0x60bc
//             StepResult::Branch(vec![
//                 Branch {
//                     target: BranchTarget::Address(0x800ed460),
//                     link: false,
//                     vm: false_vm.clone()
//                 },
//                 Branch { target: BranchTarget::Address(0x800f3518), link: false, vm: true_vm }
//             ])
//         );
//
//         // Take the false branch
//         let mut vm = false_vm;
//         assert_eq!(vm.step(&Ins::new(0x3c608053, 0x800ed460)), StepResult::Continue); // lis r3, -0x7fad
//         assert_eq!(vm.step(&Ins::new(0x5400103a, 0x800ed464)), StepResult::Continue); // rlwinm r0, r0, 0x2, 0x0, 0x1d
//         assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 1180, step: 4 });
//         assert_eq!(vm.step(&Ins::new(0x3863ef6c, 0x800ed468)), StepResult::Continue); // subi r3, r3, 0x1094
//         assert_eq!(vm.gpr[3].value, GprValue::Constant(0x8052ef6c));
//         assert_eq!(vm.step(&Ins::new(0x7c63002e, 0x800ed46c)), StepResult::Continue); // lwzx r3, r3, r0
//         assert_eq!(vm.gpr[3].value, GprValue::LoadIndexed {
//             address: 0x8052ef6c,
//             max_offset: NonZeroU32::new(1180)
//         });
//         assert_eq!(vm.step(&Ins::new(0x7c6903a6, 0x800ed470)), StepResult::Continue); // mtspr CTR, r3
//         assert_eq!(vm.ctr, GprValue::LoadIndexed {
//             address: 0x8052ef6c,
//             max_offset: NonZeroU32::new(1180)
//         });
//         assert_eq!(
//             vm.step(&Ins::new(0x4e800420, 0x800ed474)), // bctr
//             StepResult::Jump(BranchTarget::JumpTable {
//                 address: 0x8052ef6c,
//                 size: NonZeroU32::new(1184)
//             })
//         );
//     }
// }
