use std::{fmt, str::FromStr};

use crate::obj::{ObjSection, ObjSectionKind, ObjSymbol};

const PROLOGUE: &str = r#"
#ifndef ATTRIBUTE_ALIGN
#if defined(__MWERKS__) || defined(__GNUC__)
#define ATTRIBUTE_ALIGN(num) __attribute__((aligned(num)))
#elif defined(_MSC_VER) || defined(__INTELLISENSE__)
#define ATTRIBUTE_ALIGN(num)
#else
#error unknown compiler
#endif
#endif

"#;

/// The output header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    /// Do not generate a header. (Used for custom processing)
    None,
    /// A full symbol definition.
    Symbol,
    /// Raw array data.
    Raw,
}

impl FromStr for HeaderKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "symbol" => Ok(Self::Symbol),
            "raw" => Ok(Self::Raw),
            _ => Err(()),
        }
    }
}

impl fmt::Display for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Symbol => write!(f, "symbol"),
            Self::Raw => write!(f, "raw"),
        }
    }
}

/// Converts a binary blob into a C array.
pub fn bin2c(symbol: &ObjSymbol, section: &ObjSection, data: &[u8], kind: HeaderKind) -> String {
    match kind {
        HeaderKind::None => String::new(),
        HeaderKind::Symbol => bin2c_symbol(symbol, section, data),
        HeaderKind::Raw => bin2c_raw(data),
    }
}

fn bin2c_symbol(symbol: &ObjSymbol, section: &ObjSection, data: &[u8]) -> String {
    let mut output = String::new();
    output.push_str(PROLOGUE);
    output.push_str(&format!(
        "// {} (size: {:#X}, address: {:#X}, section: {})\n",
        symbol.name, symbol.size, symbol.address, section.name
    ));
    if symbol.flags.is_local() {
        output.push_str("static ");
    }
    if section.kind == ObjSectionKind::ReadOnlyData {
        output.push_str("const ");
    }
    output.push_str("unsigned char ");
    output.push_str(symbol.demangled_name.as_deref().unwrap_or(symbol.name.as_str()));
    output.push_str(&format!("[] ATTRIBUTE_ALIGN({}) = {{", symbol.align.unwrap_or(4)));
    for (i, byte) in data.iter().enumerate() {
        if i % 16 == 0 {
            output.push_str("\n    ");
        } else {
            output.push(' ');
        }
        output.push_str(&format!("0x{:02X},", byte));
    }
    output.push_str("\n};\n");
    output
}

fn bin2c_raw(data: &[u8]) -> String {
    let mut output = String::new();
    for (i, byte) in data.iter().enumerate() {
        if i > 0 {
            if i % 16 == 0 {
                output.push('\n');
            } else {
                output.push(' ');
            }
        }
        output.push_str(&format!("0x{:02X},", byte));
    }
    output.push('\n');
    output
}
