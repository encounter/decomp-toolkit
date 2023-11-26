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

/// Converts a binary blob into a C array.
pub fn bin2c(symbol: &ObjSymbol, section: &ObjSection, data: &[u8]) -> String {
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
