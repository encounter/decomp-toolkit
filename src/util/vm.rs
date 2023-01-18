use std::num::NonZeroU32;

use ppc750cl::{Argument, Ins, Opcode, GPR};

use crate::util::obj::ObjInfo;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum GprValue {
    #[default]
    /// GPR value is unknown
    Unknown,
    /// GPR value is a constant
    Constant(u32),
    /// Comparison result (CR field)
    ComparisonResult(u8),
    /// GPR value is within a range
    Range { min: u32, max: u32, step: u32 },
    /// GPR value is loaded from an address with a max offset (jump table)
    LoadIndexed { address: u32, max_offset: Option<NonZeroU32> },
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Gpr {
    /// The current calculated value
    pub value: GprValue,
    /// Address that loads the hi part of this GPR
    pub hi_addr: Option<NonZeroU32>,
    /// Address that loads the lo part of this GPR
    pub lo_addr: Option<NonZeroU32>,
}

impl Gpr {
    fn set_direct(&mut self, value: GprValue) {
        self.value = value;
        self.hi_addr = None;
        self.lo_addr = None;
    }

    fn set_hi(&mut self, value: GprValue, addr: u32) {
        self.value = value;
        self.hi_addr = NonZeroU32::new(addr);
        self.lo_addr = None;
    }

    fn set_lo(&mut self, value: GprValue, addr: u32, hi_gpr: Gpr) {
        self.value = value;
        self.hi_addr = hi_gpr.hi_addr;
        self.lo_addr = hi_gpr.lo_addr.or_else(|| NonZeroU32::new(addr));
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Cr {
    /// The left-hand value of this comparison
    left: GprValue,
    /// The right-hand value of this comparison
    right: GprValue,
    /// Whether this comparison is signed
    signed: bool,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct VM {
    /// General purpose registers
    pub gpr: [Gpr; 32],
    /// Condition registers
    cr: [Cr; 8],
    /// Count register
    ctr: GprValue,
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
    Address(u32),
    /// Branch to jump table
    JumpTable { address: u32, size: Option<NonZeroU32> },
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
    LoadStore { address: u32, source: Gpr, source_reg: u8 },
    /// Hit illegal instruction
    Illegal,
    /// Jump without affecting VM state
    Jump(BranchTarget),
    /// Branch with split VM states
    Branch(Vec<Branch>),
}

impl VM {
    #[inline]
    pub fn new() -> Box<Self> { Box::default() }

    #[inline]
    pub fn new_from_obj(obj: &ObjInfo) -> Box<Self> {
        match (obj.sda2_base, obj.sda_base) {
            (Some(sda2_base), Some(sda_base)) => Self::new_with_base(sda2_base, sda_base),
            _ => Self::new(),
        }
    }

    #[inline]
    pub fn new_with_base(sda2_base: u32, sda_base: u32) -> Box<Self> {
        let mut vm = Self::new();
        vm.gpr[2].value = GprValue::Constant(sda2_base);
        vm.gpr[13].value = GprValue::Constant(sda_base);
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

    pub fn step(&mut self, ins: &Ins) -> StepResult {
        match ins.op {
            Opcode::Illegal => {
                return StepResult::Illegal;
            }
            Opcode::Add => {
                // add rD, rA, rB
                let left = self.gpr[ins.field_rA()].value;
                let right = self.gpr[ins.field_rB()].value;
                let value = match (left, right) {
                    (GprValue::Constant(left), GprValue::Constant(right)) => {
                        GprValue::Constant(left.wrapping_add(right))
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rD()].set_direct(value);
            }
            Opcode::Addis => {
                // addis rD, rA, SIMM
                let left = if ins.field_rA() == 0 {
                    GprValue::Constant(0)
                } else {
                    self.gpr[ins.field_rA()].value
                };
                let value = match left {
                    GprValue::Constant(value) => {
                        GprValue::Constant(value.wrapping_add((ins.field_simm() as u32) << 16))
                    }
                    _ => GprValue::Unknown,
                };
                if ins.field_rA() == 0 {
                    // lis rD, SIMM
                    self.gpr[ins.field_rD()].set_hi(value, ins.addr);
                } else {
                    self.gpr[ins.field_rD()].set_direct(value);
                }
            }
            Opcode::Addi | Opcode::Addic | Opcode::Addic_ => {
                // addi rD, rA, SIMM
                // addic rD, rA, SIMM
                // addic. rD, rA, SIMM
                let left = if ins.field_rA() == 0 && ins.op == Opcode::Addi {
                    GprValue::Constant(0)
                } else {
                    self.gpr[ins.field_rA()].value
                };
                let value = match left {
                    GprValue::Constant(value) => {
                        GprValue::Constant(value.wrapping_add(ins.field_simm() as u32))
                    }
                    _ => GprValue::Unknown,
                };
                if ins.field_rA() == 0 {
                    // li rD, SIMM
                    self.gpr[ins.field_rD()].set_direct(value);
                } else {
                    self.gpr[ins.field_rD()].set_lo(value, ins.addr, self.gpr[ins.field_rA()]);
                }
            }
            Opcode::Ori => {
                // ori rA, rS, UIMM
                let value = match self.gpr[ins.field_rS()].value {
                    GprValue::Constant(value) => {
                        GprValue::Constant(value | ins.field_uimm() as u32)
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rA()].set_lo(value, ins.addr, self.gpr[ins.field_rS()]);
            }
            Opcode::Or => {
                // or rA, rS, rB
                if ins.field_rS() == ins.field_rB() {
                    // Register copy
                    self.gpr[ins.field_rA()] = self.gpr[ins.field_rS()];
                } else {
                    let left = self.gpr[ins.field_rS()].value;
                    let right = self.gpr[ins.field_rB()].value;
                    let value = match (left, right) {
                        (GprValue::Constant(left), GprValue::Constant(right)) => {
                            GprValue::Constant(left | right)
                        }
                        _ => GprValue::Unknown,
                    };
                    self.gpr[ins.field_rA()].set_direct(value);
                }
            }
            // cmp [crfD], [L], rA, rB
            // cmpi [crfD], [L], rA, SIMM
            // cmpl [crfD], [L], rA, rB
            // cmpli [crfD], [L], rA, UIMM
            Opcode::Cmp | Opcode::Cmpi | Opcode::Cmpl | Opcode::Cmpli => {
                if ins.field_L() == 0 {
                    let left_reg = ins.field_rA();
                    let left = self.gpr[left_reg].value;
                    let (right, signed) = match ins.op {
                        Opcode::Cmp => (self.gpr[ins.field_rB()].value, true),
                        Opcode::Cmpl => (self.gpr[ins.field_rB()].value, false),
                        Opcode::Cmpi => (GprValue::Constant(ins.field_simm() as u32), true),
                        Opcode::Cmpli => (GprValue::Constant(ins.field_uimm() as u32), false),
                        _ => unreachable!(),
                    };
                    let crf = ins.field_crfD();
                    self.cr[crf] = Cr { signed, left, right };
                    self.gpr[left_reg].value = GprValue::ComparisonResult(crf as u8);
                }
            }
            // rlwinm rA, rS, SH, MB, ME
            // rlwnm rA, rS, rB, MB, ME
            Opcode::Rlwinm | Opcode::Rlwnm => {
                let value = if let Some(shift) = match ins.op {
                    Opcode::Rlwinm => Some(ins.field_SH() as u32),
                    Opcode::Rlwnm => match self.gpr[ins.field_rB()].value {
                        GprValue::Constant(value) => Some(value),
                        _ => None,
                    },
                    _ => unreachable!(),
                } {
                    let mask = mask_value(ins.field_MB() as u32, ins.field_ME() as u32);
                    match self.gpr[ins.field_rS()].value {
                        GprValue::Constant(value) => {
                            GprValue::Constant(value.rotate_left(shift) & mask)
                        }
                        GprValue::Range { min, max, step } => GprValue::Range {
                            min: min.rotate_left(shift) & mask,
                            max: max.rotate_left(shift) & mask,
                            step: step.rotate_left(shift),
                        },
                        _ => GprValue::Range { min: 0, max: mask, step: 1u32.rotate_left(shift) },
                    }
                } else {
                    GprValue::Unknown
                };
                self.gpr[ins.field_rA()].set_direct(value);
            }
            // b[l][a] target_addr
            // b[c][l][a] BO, BI, target_addr
            // b[c]ctr[l] BO, BI
            // b[c]lr[l] BO, BI
            Opcode::B | Opcode::Bc | Opcode::Bcctr | Opcode::Bclr => {
                // HACK for `bla 0x60` in __OSDBJump
                if ins.op == Opcode::B && ins.field_LK() && ins.field_AA() {
                    return StepResult::Jump(BranchTarget::Unknown);
                }

                let branch_target = match ins.op {
                    Opcode::Bcctr => {
                        match self.ctr {
                            GprValue::Constant(value) => BranchTarget::Address(value),
                            GprValue::LoadIndexed { address, max_offset }
                            // FIXME: avoids treating bctrl indirect calls as jump tables
                            if !ins.field_LK() => {
                                BranchTarget::JumpTable { address, size: max_offset.and_then(|n| n.checked_add(4)) }
                            }
                            _ => BranchTarget::Unknown,
                        }
                    }
                    Opcode::Bclr => BranchTarget::Return,
                    _ => BranchTarget::Address(ins.branch_dest().unwrap()),
                };

                // If branching with link, use function call semantics
                if ins.field_LK() {
                    return StepResult::Branch(vec![
                        Branch {
                            target: BranchTarget::Address(ins.addr + 4),
                            link: false,
                            vm: self.clone_for_return(),
                        },
                        Branch { target: branch_target, link: true, vm: self.clone_for_link() },
                    ]);
                }

                // Branch always
                if ins.op == Opcode::B || ins.field_BO() & 0b10100 == 0b10100 {
                    return StepResult::Jump(branch_target);
                }

                // Branch conditionally
                let mut branches = vec![
                    // Branch not taken
                    Branch {
                        target: BranchTarget::Address(ins.addr + 4),
                        link: false,
                        vm: self.clone_all(),
                    },
                    // Branch taken
                    Branch { target: branch_target, link: ins.field_LK(), vm: self.clone_all() },
                ];

                // Use tracked CR to calculate new register values for branches
                let crf = ins.field_BI() >> 2;
                let crb = (ins.field_BI() & 3) as u8;
                let (f_val, t_val) =
                    split_values_by_crb(crb, self.cr[crf].left, self.cr[crf].right);
                if ins.field_BO() & 0b11110 == 0b00100 {
                    // Branch if false
                    branches[0].vm.set_comparison_result(t_val, crf);
                    branches[1].vm.set_comparison_result(f_val, crf);
                } else if ins.field_BO() & 0b11110 == 0b01100 {
                    // Branch if true
                    branches[0].vm.set_comparison_result(f_val, crf);
                    branches[1].vm.set_comparison_result(t_val, crf);
                }

                return StepResult::Branch(branches);
            }
            // lwzx rD, rA, rB
            Opcode::Lwzx => {
                let left = self.gpr[ins.field_rA()].value;
                let right = self.gpr[ins.field_rB()].value;
                let value = match (left, right) {
                    (GprValue::Constant(address), GprValue::Range { min: _, max, .. })
                        if /*min == 0 &&*/ max < u32::MAX - 4 && max & 3 == 0 =>
                    {
                        GprValue::LoadIndexed { address, max_offset: NonZeroU32::new(max) }
                    }
                    (GprValue::Constant(address), _) => {
                        GprValue::LoadIndexed { address, max_offset: None }
                    }
                    _ => GprValue::Unknown,
                };
                self.gpr[ins.field_rD()].set_direct(value);
            }
            // mtspr SPR, rS
            Opcode::Mtspr => {
                if ins.field_spr() == 9 {
                    // CTR
                    self.ctr = self.gpr[ins.field_rS()].value;
                }
            }
            // mfspr rD, SPR
            Opcode::Mfspr => {
                let value = if ins.field_spr() == 9 {
                    // CTR
                    self.ctr
                } else {
                    GprValue::Unknown
                };
                self.gpr[ins.field_rD()].set_direct(value);
            }
            // rfi
            Opcode::Rfi => {
                return StepResult::Jump(BranchTarget::Unknown);
            }
            op if is_load_store_op(op) => {
                let source = ins.field_rA();
                let mut result = StepResult::Continue;
                if let GprValue::Constant(base) = self.gpr[source].value {
                    let address = base.wrapping_add(ins.field_simm() as u32);
                    if is_update_op(op) {
                        self.gpr[source].set_lo(
                            GprValue::Constant(address),
                            ins.addr,
                            self.gpr[source],
                        );
                    }
                    result = StepResult::LoadStore {
                        address,
                        source: self.gpr[source],
                        source_reg: source as u8,
                    };
                } else if is_update_op(op) {
                    self.gpr[source].set_direct(GprValue::Unknown);
                }
                if is_load_op(op) {
                    self.gpr[ins.field_rD()].set_direct(GprValue::Unknown);
                }
                return result;
            }
            _ => {
                for field in ins.defs() {
                    match field.argument() {
                        Some(Argument::GPR(GPR(reg))) => {
                            self.gpr[reg as usize].set_direct(GprValue::Unknown);
                        }
                        _ => {}
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
                GprValue::Range { min: value, max: u32::MAX, step: 1 },
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
                GprValue::Range { min: value.wrapping_add(1), max: u32::MAX, step: 1 },
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
    let mut mask = 0u32;
    for bit in begin..=end {
        mask |= 1 << (31 - bit);
    }
    mask
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
            | Opcode::Lwz
            | Opcode::Lwzu
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
            | Opcode::Lfdu
            | Opcode::Lfdux
            | Opcode::Lfsu
            | Opcode::Lfsux
            | Opcode::Lhau
            | Opcode::Lhaux
            | Opcode::Lhzu
            | Opcode::Lhzux
            | Opcode::Lwzu
            | Opcode::Lwzux
            | Opcode::Stbu
            | Opcode::Stbux
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_indexed_1() {
        let mut vm = VM::new();
        assert_eq!(vm.step(&Ins::new(0x3cc08052, 0x803dfe28)), StepResult::Continue); // lis r6, -0x7fae
        assert_eq!(vm.step(&Ins::new(0x38c60e18, 0x803dfe30)), StepResult::Continue); // addi r6, r6, 0xe18
        assert_eq!(vm.gpr[6].value, GprValue::Constant(0x80520e18));
        assert_eq!(vm.step(&Ins::new(0x550066fa, 0x803dfe34)), StepResult::Continue); // rlwinm r0, r8, 12, 27, 29
        assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 28, step: 1 << 12 });
        assert_eq!(vm.step(&Ins::new(0x7d86002e, 0x803dfe3c)), StepResult::Continue); // lwzx r12, r6, r0
        assert_eq!(vm.gpr[12].value, GprValue::LoadIndexed {
            address: 0x80520e18,
            max_offset: NonZeroU32::new(28)
        });
        assert_eq!(vm.step(&Ins::new(0x7d8903a6, 0x803dfe4c)), StepResult::Continue); // mtspr CTR, r12
        assert_eq!(vm.ctr, GprValue::LoadIndexed {
            address: 0x80520e18,
            max_offset: NonZeroU32::new(28)
        });
        assert_eq!(
            vm.step(&Ins::new(0x4e800420, 0x803dfe50)), // bctr
            StepResult::Jump(BranchTarget::JumpTable {
                address: 0x80520e18,
                size: NonZeroU32::new(32)
            })
        );
    }

    #[test]
    fn test_load_indexed_2() {
        let mut vm = VM::new();
        assert_eq!(vm.step(&Ins::new(0x3c808057, 0x80465320)), StepResult::Continue); // lis r4, -0x7fa9
        assert_eq!(vm.step(&Ins::new(0x54600e7a, 0x80465324)), StepResult::Continue); // rlwinm r0, r3, 1, 25, 29
        assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 124, step: 2 });
        assert_eq!(vm.step(&Ins::new(0x38840f70, 0x80465328)), StepResult::Continue); // addi r4, r4, 0xf70
        assert_eq!(vm.gpr[4].value, GprValue::Constant(0x80570f70));
        assert_eq!(vm.step(&Ins::new(0x7d84002e, 0x80465330)), StepResult::Continue); // lwzx r12, r4, r0
        assert_eq!(vm.gpr[12].value, GprValue::LoadIndexed {
            address: 0x80570f70,
            max_offset: NonZeroU32::new(124)
        });
        assert_eq!(vm.step(&Ins::new(0x7d8903a6, 0x80465340)), StepResult::Continue); // mtspr CTR, r12
        assert_eq!(vm.ctr, GprValue::LoadIndexed {
            address: 0x80570f70,
            max_offset: NonZeroU32::new(124)
        });
        assert_eq!(
            vm.step(&Ins::new(0x4e800420, 0x80465344)), // bctr
            StepResult::Jump(BranchTarget::JumpTable {
                address: 0x80570f70,
                size: NonZeroU32::new(128)
            })
        );
    }

    #[test]
    fn test_load_indexed_3() {
        let mut vm = VM::new();
        assert_eq!(vm.step(&Ins::new(0x28000127, 0x800ed458)), StepResult::Continue); // cmplwi r0, 0x127
        assert_eq!(vm.cr, Cr {
            signed: false,
            left: GprValue::Unknown,
            right: GprValue::Constant(295),
        });

        // When branch isn't taken, we know r0 is <= 295
        let mut false_vm = vm.clone();
        false_vm.gpr[0] =
            Gpr { value: GprValue::Range { min: 0, max: 295, step: 1 }, ..Default::default() };
        // When branch is taken, we know r0 is > 295
        let mut true_vm = vm.clone();
        true_vm.gpr[0] = Gpr {
            value: GprValue::Range { min: 296, max: u32::MAX, step: 1 },
            ..Default::default()
        };
        assert_eq!(
            vm.step(&Ins::new(0x418160bc, 0x800ed45c)), // bgt 0x60bc
            StepResult::Branch(vec![
                Branch {
                    target: BranchTarget::Address(0x800ed460),
                    link: false,
                    vm: false_vm.clone()
                },
                Branch { target: BranchTarget::Address(0x800f3518), link: false, vm: true_vm }
            ])
        );

        // Take the false branch
        let mut vm = false_vm;
        assert_eq!(vm.step(&Ins::new(0x3c608053, 0x800ed460)), StepResult::Continue); // lis r3, -0x7fad
        assert_eq!(vm.step(&Ins::new(0x5400103a, 0x800ed464)), StepResult::Continue); // rlwinm r0, r0, 0x2, 0x0, 0x1d
        assert_eq!(vm.gpr[0].value, GprValue::Range { min: 0, max: 1180, step: 4 });
        assert_eq!(vm.step(&Ins::new(0x3863ef6c, 0x800ed468)), StepResult::Continue); // subi r3, r3, 0x1094
        assert_eq!(vm.gpr[3].value, GprValue::Constant(0x8052ef6c));
        assert_eq!(vm.step(&Ins::new(0x7c63002e, 0x800ed46c)), StepResult::Continue); // lwzx r3, r3, r0
        assert_eq!(vm.gpr[3].value, GprValue::LoadIndexed {
            address: 0x8052ef6c,
            max_offset: NonZeroU32::new(1180)
        });
        assert_eq!(vm.step(&Ins::new(0x7c6903a6, 0x800ed470)), StepResult::Continue); // mtspr CTR, r3
        assert_eq!(vm.ctr, GprValue::LoadIndexed {
            address: 0x8052ef6c,
            max_offset: NonZeroU32::new(1180)
        });
        assert_eq!(
            vm.step(&Ins::new(0x4e800420, 0x800ed474)), // bctr
            StepResult::Jump(BranchTarget::JumpTable {
                address: 0x8052ef6c,
                size: NonZeroU32::new(1184)
            })
        );
    }
}
