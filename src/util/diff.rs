//! This includes helpers to convert between decomp-toolkit types and objdiff-core types.
//!
//! Eventually it'd be nice to share [ObjInfo] and related types between decomp-toolkit and
//! objdiff-core to avoid this conversion.
use std::{
    io::{stdout, Write},
    ops::Range,
};

use anyhow::Result;
use crossterm::style::Color;
use itertools::Itertools;
use objdiff_core::{
    arch::{ObjArch, ProcessCodeResult},
    diff::{
        display::{display_diff, DiffText},
        DiffObjConfig, ObjInsDiff, ObjInsDiffKind, ObjSymbolDiff,
    },
};
use object::RelocationFlags;

use crate::obj::{ObjInfo, ObjReloc, ObjSection, ObjSymbol};

/// Processes code for a PPC function using objdiff-core.
/// Returns [ProcessCodeResult] for other objdiff-core functions to accept.
pub fn process_code(
    obj: &ObjInfo,
    symbol: &ObjSymbol,
    section: &ObjSection,
    config: &DiffObjConfig,
) -> Result<ProcessCodeResult> {
    let arch = objdiff_core::arch::ppc::ObjArchPpc { extab: None };
    let orig_relocs = section
        .relocations
        .range(symbol.address as u32..symbol.address as u32 + symbol.size as u32)
        .map(|(a, r)| to_objdiff_reloc(obj, a, r))
        .collect_vec();
    let orig_data =
        section.data_range(symbol.address as u32, symbol.address as u32 + symbol.size as u32)?;
    arch.process_code(
        symbol.address,
        orig_data,
        section.elf_index,
        &orig_relocs,
        &Default::default(),
        config,
    )
}

/// Calculates ranges of instructions to print, collapsing ranges of unchanged instructions.
/// (e.g. `grep -C`)
pub fn calc_diff_ranges(
    left: &[ObjInsDiff],
    right: &[ObjInsDiff],
    collapse_lines: usize,
) -> Vec<Range<usize>> {
    enum State {
        None,
        DiffStart(usize),
        DiffRange(Range<usize>),
    }
    let mut state = State::None;
    let mut idx = 0usize;
    let mut left_iter = left.iter();
    let mut right_iter = right.iter();
    let mut ranges = Vec::new();

    // Left and right should always have the same number of instructions
    while let (Some(left_ins), Some(right_ins)) = (left_iter.next(), right_iter.next()) {
        match &state {
            State::None => {
                if left_ins.kind != ObjInsDiffKind::None || right_ins.kind != ObjInsDiffKind::None {
                    state = State::DiffStart(idx.saturating_sub(collapse_lines));
                }
            }
            State::DiffStart(start) => {
                if left_ins.kind == ObjInsDiffKind::None && right_ins.kind == ObjInsDiffKind::None {
                    state = State::DiffRange(*start..idx);
                }
            }
            State::DiffRange(range) => {
                if left_ins.kind != ObjInsDiffKind::None || right_ins.kind != ObjInsDiffKind::None {
                    // Restart the range if we find a another diff
                    state = State::DiffStart(range.start);
                } else if idx > range.end + collapse_lines * 2 {
                    // If we've gone collapse_lines * 2 instructions without a diff, add the range
                    ranges.push(range.start..range.end + collapse_lines);
                    state = State::None;
                }
            }
        }
        idx += 1;
    }

    // Handle the last range
    match state {
        State::None => {}
        State::DiffStart(start) => {
            ranges.push(start..idx);
        }
        State::DiffRange(range) => {
            ranges.push(range.start..idx.min(range.end + collapse_lines));
        }
    }

    ranges
}

pub fn print_diff(
    left: &ObjSymbolDiff,
    right: &ObjSymbolDiff,
    ranges: &[Range<usize>],
) -> Result<()> {
    let (w, _) = crossterm::terminal::size()?;
    let mut stdout = stdout();
    for range in ranges {
        if range.start > 0 {
            crossterm::queue!(stdout, crossterm::style::Print("...\n"))?;
        }
        let left_ins = left.instructions[range.clone()].iter();
        let right_ins = right.instructions[range.clone()].iter();
        for (left_diff, right_diff) in left_ins.zip(right_ins) {
            let left_line = print_line(left_diff, 0);
            let right_line = print_line(right_diff, 0);
            let mut x = 0;
            let hw = (w as usize - 3) / 2;
            for span in left_line {
                if span.color != Color::Reset {
                    crossterm::queue!(stdout, crossterm::style::SetForegroundColor(span.color))?;
                }
                let len = (hw - x).min(span.text.len());
                crossterm::queue!(stdout, crossterm::style::Print(&span.text[..len]))?;
                x += len;
            }
            if x < hw {
                crossterm::queue!(stdout, crossterm::style::Print(" ".repeat(hw - x)))?;
            }
            if left_diff.kind != ObjInsDiffKind::None || right_diff.kind != ObjInsDiffKind::None {
                crossterm::queue!(
                    stdout,
                    crossterm::style::ResetColor,
                    crossterm::style::Print(" | ")
                )?;
            } else {
                crossterm::queue!(
                    stdout,
                    crossterm::style::ResetColor,
                    crossterm::style::Print("   ")
                )?;
            }
            x = hw + 3;
            for span in right_line {
                if span.color != Color::Reset {
                    crossterm::queue!(stdout, crossterm::style::SetForegroundColor(span.color))?;
                }
                let len = (w as usize - x).min(span.text.len());
                crossterm::queue!(stdout, crossterm::style::Print(&span.text[..len]))?;
                x += len;
            }
            crossterm::queue!(stdout, crossterm::style::ResetColor, crossterm::style::Print("\n"))?;
        }
    }
    if matches!(ranges.last().map(|r| r.end), Some(n) if n != left.instructions.len()) {
        crossterm::queue!(stdout, crossterm::style::Print("...\n"))?;
    }
    stdout.flush()?;
    Ok(())
}

const COLOR_ROTATION: [Color; 7] = [
    Color::Magenta,
    Color::Cyan,
    Color::Green,
    Color::Red,
    Color::Yellow,
    Color::Blue,
    Color::Green,
];

struct Span {
    text: String,
    color: Color,
}

fn print_line(ins_diff: &ObjInsDiff, base_addr: u64) -> Vec<Span> {
    let mut line = Vec::new();
    display_diff(ins_diff, base_addr, |text| -> Result<()> {
        let label_text;
        let mut base_color = match ins_diff.kind {
            ObjInsDiffKind::None | ObjInsDiffKind::OpMismatch | ObjInsDiffKind::ArgMismatch => {
                Color::Grey
            }
            ObjInsDiffKind::Replace => Color::Cyan,
            ObjInsDiffKind::Delete => Color::Red,
            ObjInsDiffKind::Insert => Color::Green,
        };
        let mut pad_to = 0;
        match text {
            DiffText::Basic(text) => {
                label_text = text.to_string();
            }
            DiffText::BasicColor(s, idx) => {
                label_text = s.to_string();
                base_color = COLOR_ROTATION[idx % COLOR_ROTATION.len()];
            }
            DiffText::Line(num) => {
                label_text = format!("{num} ");
                base_color = Color::DarkGrey;
                pad_to = 5;
            }
            DiffText::Address(addr) => {
                label_text = format!("{:x}:", addr);
                pad_to = 5;
            }
            DiffText::Opcode(mnemonic, _op) => {
                label_text = mnemonic.to_string();
                if ins_diff.kind == ObjInsDiffKind::OpMismatch {
                    base_color = Color::Blue;
                }
                pad_to = 8;
            }
            DiffText::Argument(arg, diff) => {
                label_text = arg.to_string();
                if let Some(diff) = diff {
                    base_color = COLOR_ROTATION[diff.idx % COLOR_ROTATION.len()]
                }
            }
            DiffText::BranchDest(addr, diff) => {
                label_text = format!("{addr:x}");
                if let Some(diff) = diff {
                    base_color = COLOR_ROTATION[diff.idx % COLOR_ROTATION.len()]
                }
            }
            DiffText::Symbol(sym) => {
                let name = sym.demangled_name.as_ref().unwrap_or(&sym.name);
                label_text = name.clone();
                base_color = Color::White;
            }
            DiffText::Spacing(n) => {
                line.push(Span { text: " ".repeat(n), color: Color::Reset });
                return Ok(());
            }
            DiffText::Eol => {
                return Ok(());
            }
        }
        let len = label_text.len();
        line.push(Span { text: label_text, color: base_color });
        if pad_to > len {
            let pad = (pad_to - len) as u16;
            line.push(Span { text: " ".repeat(pad as usize), color: Color::Reset });
        }
        Ok(())
    })
    .unwrap();
    line
}

/// Converts an [ObjReloc] to an [objdiff_core::obj::ObjReloc].
fn to_objdiff_reloc(obj: &ObjInfo, address: u32, reloc: &ObjReloc) -> objdiff_core::obj::ObjReloc {
    let target_symbol = &obj.symbols[reloc.target_symbol];
    let target_section = target_symbol.section.map(|i| &obj.sections[i]);
    let (r_offset, r_type) = reloc.to_elf(address);
    objdiff_core::obj::ObjReloc {
        flags: RelocationFlags::Elf { r_type },
        address: r_offset,
        target: to_objdiff_symbol(target_symbol, target_section, reloc.addend),
        target_section: target_section.map(|s| s.name.clone()),
    }
}

/// Converts an [ObjSymbol] to an [objdiff_core::obj::ObjSymbol].
fn to_objdiff_symbol(
    symbol: &ObjSymbol,
    section: Option<&ObjSection>,
    addend: i64,
) -> objdiff_core::obj::ObjSymbol {
    let mut flags = objdiff_core::obj::ObjSymbolFlagSet::default();
    if symbol.flags.is_global() {
        flags.0 |= objdiff_core::obj::ObjSymbolFlags::Global;
    }
    if symbol.flags.is_local() {
        flags.0 |= objdiff_core::obj::ObjSymbolFlags::Local;
    }
    if symbol.flags.is_weak() {
        flags.0 |= objdiff_core::obj::ObjSymbolFlags::Weak;
    }
    if symbol.flags.is_common() {
        flags.0 |= objdiff_core::obj::ObjSymbolFlags::Common;
    }
    if symbol.flags.is_hidden() {
        flags.0 |= objdiff_core::obj::ObjSymbolFlags::Hidden;
    }
    let bytes = section.and_then(|s| s.symbol_data(symbol).ok()).map_or(vec![], |d| d.to_vec());
    objdiff_core::obj::ObjSymbol {
        name: symbol.name.clone(),
        demangled_name: symbol.demangled_name.clone(),
        address: symbol.address,
        section_address: symbol.address - section.map(|s| s.address).unwrap_or(0),
        size: symbol.size,
        size_known: symbol.size_known,
        flags,
        addend,
        virtual_address: None,
        original_index: None,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ins_diff {
        ($kind:expr) => {
            ObjInsDiff {
                ins: None,
                kind: $kind,
                branch_from: None,
                branch_to: None,
                arg_diff: vec![],
            }
        };
    }

    #[test]
    fn test_get_diff_ranges() {
        // Test single range
        let diff = vec![
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
        ];
        assert_eq!(calc_diff_ranges(&diff, &diff, 3), vec![0..10]);

        // Test combining ranges
        let diff = vec![
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            // This should be combined with the previous range,
            // since it's within collapse_lines * 2 + 1 instructions
            ins_diff!(ObjInsDiffKind::Replace),
        ];
        assert_eq!(calc_diff_ranges(&diff, &diff, 3), vec![0..15]);

        // Test separating ranges
        let diff = vec![
            // start range 1
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            // end range 1
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            // start range 2
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::None),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::Replace),
            ins_diff!(ObjInsDiffKind::None),
            // end range 2
        ];
        assert_eq!(calc_diff_ranges(&diff, &diff, 3), vec![0..7, 9..15]);
    }
}
