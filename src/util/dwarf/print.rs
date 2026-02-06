use std::{cmp::max, fmt::Write};

use anyhow::{anyhow, ensure, Result};
use cwdemangle::demangle as cw_demangle;
use gnuv2_demangle::{demangle as gnu_demangle, DemangleConfig};
use indent::indent_all_by;

use crate::util::dwarf::{
    get_udt_by_key, process_variable_tag, ud_type, ArrayType, AttributeKind, DwarfInfo,
    EnumerationType, FundType, MemberSubroutineDefType, Modifier, Producer, PtrToMemberType,
    StructureKind, StructureMember, StructureType, SubroutineBlock, SubroutineNode, SubroutineType,
    TagKind, TagType, Type, TypeKind, TypeString, TypedefMap, TypedefTag, UnionType,
    UserDefinedType, VariableTag, Visibility,
};

pub fn apply_modifiers(mut str: TypeString, modifiers: &[Modifier]) -> Result<TypeString> {
    let mut has_pointer = false;
    for &modifier in modifiers.iter().rev() {
        match modifier {
            Modifier::MwPointerTo | Modifier::PointerTo => {
                if !has_pointer && !str.suffix.is_empty() {
                    if str.member.is_empty() {
                        str.prefix.push_str(" (*");
                    } else {
                        write!(str.prefix, " ({}*", str.member)?;
                    }
                    str.suffix.insert(0, ')');
                } else {
                    str.prefix.push_str(" *");
                }
                has_pointer = true;
            }
            Modifier::ReferenceTo => {
                if !has_pointer && !str.suffix.is_empty() {
                    str.prefix.push_str(" (&");
                    str.suffix.insert(0, ')');
                } else {
                    str.prefix.push_str(" &");
                }
                has_pointer = true;
            }
            Modifier::Const => {
                if has_pointer {
                    str.prefix.push_str(" const");
                } else {
                    str.prefix.insert_str(0, "const ");
                }
            }
            Modifier::Volatile => {
                if has_pointer {
                    str.prefix.push_str(" volatile");
                } else {
                    str.prefix.insert_str(0, "volatile ");
                }
            }
        }
    }
    Ok(str)
}

pub fn type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &Type,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let str = match t.kind {
        TypeKind::Fundamental(ft) => {
            TypeString { prefix: ft.name()?.to_string(), ..Default::default() }
        }
        TypeKind::UserDefined(key) => {
            if let Some(&td_key) = typedefs.get(&key).and_then(|v| v.first()) {
                let tag = info
                    .tags
                    .get(&td_key)
                    .ok_or_else(|| anyhow!("Failed to locate typedef {}", key))?;
                let td_name = tag
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("typedef without name"))?;
                TypeString { prefix: td_name.clone(), ..Default::default() }
            } else {
                ud_type_string(
                    info,
                    typedefs,
                    &get_udt_by_key(info, key)?,
                    true,
                    include_anonymous_def,
                )?
            }
        }
    };
    apply_modifiers(str, &t.modifiers)
}

fn type_name(info: &DwarfInfo, typedefs: &TypedefMap, t: &Type) -> Result<String> {
    Ok(match t.kind {
        TypeKind::Fundamental(ft) => ft.name()?.to_string(),
        TypeKind::UserDefined(key) => {
            if let Some(&td_key) = typedefs.get(&key).and_then(|v| v.first()) {
                info.tags
                    .get(&td_key)
                    .ok_or_else(|| anyhow!("Failed to locate typedef {}", key))?
                    .string_attribute(AttributeKind::Name)
                    .ok_or_else(|| anyhow!("typedef without name"))?
                    .clone()
            } else {
                get_udt_by_key(info, key)?
                    .name()
                    .ok_or_else(|| anyhow!("User defined type without name"))?
            }
        }
    })
}

fn array_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &ArrayType,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let mut out = type_string(info, typedefs, t.element_type.as_ref(), include_anonymous_def)?;
    for dim in &t.dimensions {
        ensure!(
            matches!(
                dim.index_type.kind,
                TypeKind::Fundamental(FundType::Long | FundType::Integer)
            ),
            "Unsupported array index type '{}'",
            type_string(info, typedefs, &dim.index_type, true)?
        );
        match dim.size {
            None => out.suffix.insert_str(0, "[]"),
            Some(size) => out.suffix = format!("[{}]{}", size, out.suffix),
        };
    }
    Ok(out)
}

fn structure_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &StructureType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            structure_def_string(info, typedefs, t)?
        } else if include_keyword {
            match t.kind {
                StructureKind::Struct => format!("struct {name}"),
                StructureKind::Class => format!("class {name}"),
            }
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        structure_def_string(info, typedefs, t)?
    } else if include_keyword {
        match t.kind {
            StructureKind::Struct => "struct [anonymous]".to_string(),
            StructureKind::Class => "class [anonymous]".to_string(),
        }
    } else {
        match t.kind {
            StructureKind::Struct => "[anonymous struct]".to_string(),
            StructureKind::Class => "[anonymous class]".to_string(),
        }
    };
    Ok(TypeString { prefix, ..Default::default() })
}

fn enumeration_type_string(
    _info: &DwarfInfo,
    _typedefs: &TypedefMap,
    t: &EnumerationType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            enum_def_string(t)?
        } else if include_keyword {
            format!("enum {name}")
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        enum_def_string(t)?
    } else if include_keyword {
        "enum [anonymous]".to_string()
    } else {
        "[anonymous enum]".to_string()
    };
    Ok(TypeString { prefix, ..Default::default() })
}

fn union_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UnionType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    let prefix = if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            union_def_string(info, typedefs, t)?
        } else if include_keyword {
            format!("union {name}")
        } else {
            name.clone()
        }
    } else if include_anonymous_def {
        union_def_string(info, typedefs, t)?
    } else if include_keyword {
        "union [anonymous]".to_string()
    } else {
        "[anonymous union]".to_string()
    };
    Ok(TypeString { prefix, ..Default::default() })
}

pub fn ud_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UserDefinedType,
    include_keyword: bool,
    include_anonymous_def: bool,
) -> Result<TypeString> {
    Ok(match t {
        UserDefinedType::Array(t) => array_type_string(info, typedefs, t, include_anonymous_def)?,
        UserDefinedType::Structure(t) => {
            structure_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Enumeration(t) => {
            enumeration_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Union(t) => {
            union_type_string(info, typedefs, t, include_keyword, include_anonymous_def)?
        }
        UserDefinedType::Subroutine(t) => subroutine_type_string(info, typedefs, t)?,
        UserDefinedType::PtrToMember(t) => ptr_to_member_type_string(info, typedefs, t)?,
    })
}

fn ptr_to_member_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &PtrToMemberType,
) -> Result<TypeString> {
    let ts = type_string(info, typedefs, &t.kind, true)?;
    let containing_type = info
        .tags
        .get(&t.containing_type)
        .ok_or_else(|| anyhow!("Failed to locate containing type {}", t.containing_type))?;
    let containing_ts =
        ud_type_string(info, typedefs, &ud_type(info, containing_type)?, false, false)?;
    Ok(TypeString {
        prefix: format!("{} ({}::*", ts.prefix, containing_ts.prefix),
        suffix: format!("{}){}", containing_ts.suffix, ts.suffix),
        ..Default::default()
    })
}

pub fn ud_type_def(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &UserDefinedType,
    is_erased: bool,
) -> Result<String> {
    match t {
        UserDefinedType::Array(t) => {
            let ts = array_type_string(info, typedefs, t, false)?;
            Ok(format!("// Array: {}{}", ts.prefix, ts.suffix))
        }
        UserDefinedType::Subroutine(t) => Ok(subroutine_def_string(info, typedefs, t, is_erased)?),
        UserDefinedType::Structure(t) => Ok(structure_def_string(info, typedefs, t)?),
        UserDefinedType::Enumeration(t) => Ok(enum_def_string(t)?),
        UserDefinedType::Union(t) => Ok(union_def_string(info, typedefs, t)?),
        UserDefinedType::PtrToMember(t) => {
            let ts = ptr_to_member_type_string(info, typedefs, t)?;
            Ok(format!("// PtrToMember: {}{}", ts.prefix, ts.suffix))
        }
    }
}

pub fn subroutine_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &SubroutineType,
) -> Result<TypeString> {
    let mut out = type_string(info, typedefs, &t.return_type, true)?;
    let mut parameters = String::new();
    if t.parameters.is_empty() {
        if t.var_args {
            parameters = "...".to_string();
        } else if t.prototyped {
            parameters = "void".to_string();
        }
    } else {
        for (idx, parameter) in t.parameters.iter().enumerate() {
            if idx > 0 {
                write!(parameters, ", ")?;
            }
            let ts = type_string(info, typedefs, &parameter.kind, true)?;
            if let Some(name) = &parameter.name {
                write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
            } else {
                write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
            }
            if let Some(location) = &parameter.location {
                write!(parameters, " /* {location} */")?;
            }
        }
        if t.var_args {
            write!(parameters, ", ...")?;
        }
    }
    out.suffix = format!("({}){}", parameters, out.suffix);
    if let Some(member_of) = t.member_of {
        let tag = info
            .tags
            .get(&member_of)
            .ok_or_else(|| anyhow!("Failed to locate member_of tag {}", member_of))?;
        let base_name = tag
            .string_attribute(AttributeKind::Name)
            .ok_or_else(|| anyhow!("member_of tag {} has no name attribute", member_of))?;
        out.member = format!("{base_name}::");
    }
    Ok(out)
}

fn member_subroutine_def_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &MemberSubroutineDefType,
) -> Result<String> {
    let mut out = String::new();

    let mut base_name_opt = None;
    let mut direct_base_name_opt = None;

    if let Some(member_of) = t.member_of {
        let tag = info
            .tags
            .get(&member_of)
            .ok_or_else(|| anyhow!("Failed to locate member_of tag {}", member_of))?;
        let base_name = tag
            .string_attribute(AttributeKind::Name)
            .ok_or_else(|| anyhow!("member_of tag {} has no name attribute", member_of))?;

        if t.override_ {
            writeln!(out, "// Overrides: {}", base_name)?;
        }
        base_name_opt = Some(base_name);
    }

    if let Some(direct_member_of) = t.direct_member_of {
        let tag = info
            .tags
            .get(&direct_member_of)
            .ok_or_else(|| anyhow!("Failed to locate direct_member_of tag {}", direct_member_of))?;
        let direct_base_name = tag.string_attribute(AttributeKind::Name).ok_or_else(|| {
            anyhow!("direct_member_of tag {} has no name attribute", direct_member_of)
        })?;

        direct_base_name_opt = Some(direct_base_name);
        if base_name_opt.is_none() {
            // Fall back to the parsed out direct_base_name on PS2 MW because it doesn't emit a base class
            base_name_opt = direct_base_name_opt;
        }
    }

    let is_non_static_member = t.direct_member_of.is_some() && !t.static_member;

    if t.local || t.static_member {
        out.push_str("static ");
    }
    if t.inline {
        out.push_str("inline ");
    }
    if t.virtual_ && !t.override_ {
        out.push_str("virtual ");
    }

    let mut name_written = false;

    let mut omit_return_type = false;
    let mut is_gcc_destructor = false;
    let mut full_written_name = String::new();

    if t.override_ {
        if let Producer::GCC = info.producer {
            if let Some(direct_base_name) = direct_base_name_opt {
                if let Some(name) = t.name.as_ref() {
                    // in GCC the ctor and dtor are called the same, so we need to check the return value
                    // this is only for the dtor, the ctor can be left as is
                    if name == direct_base_name {
                        if let TypeKind::Fundamental(FundType::Void) = t.return_type.kind {
                            write!(full_written_name, "~{direct_base_name}")?;
                            is_gcc_destructor = true;
                            name_written = true;
                        }
                        omit_return_type = true;
                    }
                }
            }
        }
    } else if let Some(base_name) = base_name_opt {
        // Handle constructors and destructors
        if let Some(name) = t.name.as_ref() {
            if name == "__dt" {
                write!(full_written_name, "~{base_name}")?;
                name_written = true;
                omit_return_type = true;
            } else if name == "__ct" {
                write!(full_written_name, "{base_name}")?;
                name_written = true;
                omit_return_type = true;
            } else if name == base_name {
                if let TypeKind::Fundamental(FundType::Void) = t.return_type.kind {
                    write!(full_written_name, "~{base_name}")?;
                    if let Producer::GCC = info.producer {
                        is_gcc_destructor = true;
                    }
                    name_written = true;
                }
                omit_return_type = true;
            }
        }
    }
    if !name_written {
        if let Some(name) = t.name.as_ref() {
            full_written_name.push_str(&maybe_demangle_function_name(info, name));
        }
    }
    let rt = type_string(info, typedefs, &t.return_type, true)?;
    if !omit_return_type {
        out.push_str(&rt.prefix);
        out.push(' ');
    }

    out.push_str(&full_written_name);

    let mut parameters = String::new();
    if t.parameters.is_empty() {
        if t.var_args {
            parameters = "...".to_string();
        } else if t.prototyped {
            parameters = "void".to_string();
        }
    } else {
        let mut start_index = if is_non_static_member { 1 } else { 0 };
        // omit __in_chrg parameter
        if is_gcc_destructor {
            start_index += 1;
        }
        for (idx, parameter) in t.parameters.iter().enumerate().skip(start_index) {
            if idx > start_index {
                write!(parameters, ", ")?;
            }
            let ts = type_string(info, typedefs, &parameter.kind, true)?;
            if let Some(name) = &parameter.name {
                write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
            } else {
                write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
            }
        }
        if t.var_args {
            write!(parameters, ", ...")?;
        }
    }
    write!(out, "({}){}", parameters, rt.suffix)?;
    if t.const_ {
        write!(out, " const")?;
    }
    if t.volatile_ {
        write!(out, " volatile")?;
    }
    if t.override_ {
        write!(out, " override")?;
    }

    if t.inline {
        write!(out, " {{}}")?;
    } else {
        write!(out, ";")?;
    }

    Ok(out)
}

pub fn subroutine_def_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &SubroutineType,
    is_erased: bool,
) -> Result<String> {
    let mut out = String::new();
    if is_erased {
        out.push_str("// Erased\n");
    } else if let (Some(start), Some(end)) = (t.start_address, t.end_address) {
        writeln!(out, "// Range: {start:#X} -> {end:#X}")?;
    }

    let mut base_name_opt = None;
    let mut direct_base_name_opt = None;

    if let Some(member_of) = t.member_of {
        let tag = info
            .tags
            .get(&member_of)
            .ok_or_else(|| anyhow!("Failed to locate member_of tag {}", member_of))?;
        let base_name = tag
            .string_attribute(AttributeKind::Name)
            .ok_or_else(|| anyhow!("member_of tag {} has no name attribute", member_of))?;

        if t.override_ {
            writeln!(out, "// Overrides: {}", base_name)?;
        }
        base_name_opt = Some(base_name);
    }

    if let Some(direct_member_of) = t.direct_member_of {
        let tag = info
            .tags
            .get(&direct_member_of)
            .ok_or_else(|| anyhow!("Failed to locate direct_member_of tag {}", direct_member_of))?;
        let direct_base_name = tag.string_attribute(AttributeKind::Name).ok_or_else(|| {
            anyhow!("direct_member_of tag {} has no name attribute", direct_member_of)
        })?;

        direct_base_name_opt = Some(direct_base_name);
        if base_name_opt.is_none() {
            // Fall back to the parsed out direct_base_name on PS2 MW because it doesn't emit a base class
            base_name_opt = direct_base_name_opt;
        }
    }

    let is_non_static_member = t.direct_member_of.is_some() && !t.static_member;
    if is_non_static_member {
        if let Some(param) = t.parameters.first() {
            if let Some(location) = &param.location {
                writeln!(out, "// this: {}", location)?;
            }
        }
    }

    if t.local || t.static_member {
        out.push_str("static ");
    }
    if t.inline {
        out.push_str("inline ");
    }
    if t.virtual_ && !t.override_ {
        out.push_str("virtual ");
    }

    let mut name_written = false;

    let mut omit_return_type = false;
    let mut is_gcc_destructor = false;
    let mut full_written_name = String::new();

    if t.override_ {
        if let Producer::GCC = info.producer {
            if let Some(direct_base_name) = direct_base_name_opt {
                // we need to emit the real parent on GCC
                write!(full_written_name, "{direct_base_name}::")?;

                if let Some(name) = t.name.as_ref() {
                    // in GCC the ctor and dtor are called the same, so we need to check the return value
                    // this is only for the dtor, the ctor can be left as is
                    if name == direct_base_name {
                        if let TypeKind::Fundamental(FundType::Void) = t.return_type.kind {
                            write!(full_written_name, "~{direct_base_name}")?;
                            is_gcc_destructor = true;
                            name_written = true;
                        }
                        omit_return_type = true;
                    }
                }
            }
        }
    } else if let Some(base_name) = base_name_opt {
        write!(full_written_name, "{base_name}::")?;

        // Handle constructors and destructors
        if let Some(name) = t.name.as_ref() {
            if name == "__dt" {
                write!(full_written_name, "~{base_name}")?;
                name_written = true;
                omit_return_type = true;
            } else if name == "__ct" {
                write!(full_written_name, "{base_name}")?;
                name_written = true;
                omit_return_type = true;
            } else if name == base_name {
                if let TypeKind::Fundamental(FundType::Void) = t.return_type.kind {
                    write!(full_written_name, "~{base_name}")?;
                    if let Producer::GCC = info.producer {
                        is_gcc_destructor = true;
                    }
                    name_written = true;
                }
                omit_return_type = true;
            }
        }
    }
    if !name_written {
        if let Some(name) = t.name.as_ref() {
            full_written_name.push_str(&maybe_demangle_function_name(info, name));
        }
    }
    let rt = type_string(info, typedefs, &t.return_type, true)?;
    if !omit_return_type {
        out.push_str(&rt.prefix);
        out.push(' ');
    }

    out.push_str(&full_written_name);

    let mut parameters = String::new();
    if t.parameters.is_empty() {
        if t.var_args {
            parameters = "...".to_string();
        } else if t.prototyped {
            parameters = "void".to_string();
        }
    } else {
        let mut start_index = if is_non_static_member { 1 } else { 0 };
        // omit __in_chrg parameter
        if is_gcc_destructor {
            start_index += 1;
        }
        for (idx, parameter) in t.parameters.iter().enumerate().skip(start_index) {
            if idx > start_index {
                write!(parameters, ", ")?;
            }
            let ts = type_string(info, typedefs, &parameter.kind, true)?;
            if let Some(name) = &parameter.name {
                write!(parameters, "{} {}{}", ts.prefix, name, ts.suffix)?;
            } else {
                write!(parameters, "{}{}", ts.prefix, ts.suffix)?;
            }
            if let Some(location) = &parameter.location {
                write!(parameters, " /* {location} */")?;
            }
        }
        if t.var_args {
            write!(parameters, ", ...")?;
        }
    }
    write!(out, "({}){} ", parameters, rt.suffix)?;
    if t.const_ {
        write!(out, "const ")?;
    }
    if t.volatile_ {
        write!(out, "volatile ")?;
    }
    if t.override_ {
        write!(out, "override ")?;
    }
    write!(out, "{{")?;

    if !t.inner_types.is_empty() {
        writeln!(out, "\n    // Inner declarations")?;

        for inner_type in &t.inner_types {
            writeln!(
                out,
                "{};",
                &indent_all_by(4, &ud_type_def(info, typedefs, inner_type, false)?)
            )?;
        }
    }

    if !t.typedefs.is_empty() {
        writeln!(out, "\n    // Typedefs")?;
        for typedef in &t.typedefs {
            writeln!(out, "{}", &indent_all_by(4, &typedef_string(info, typedefs, typedef)?))?;
        }
    }

    if !t.variables.is_empty() {
        writeln!(out, "\n    // Local variables")?;
        let mut var_out = String::new();
        for variable in &t.variables {
            let ts = type_string(info, typedefs, &variable.kind, true)?;
            write!(
                var_out,
                "{} {}{};",
                ts.prefix,
                variable.name.as_deref().unwrap_or_default(),
                ts.suffix
            )?;
            if let Some(location) = &variable.location {
                write!(var_out, " // {location}")?;
            }
            writeln!(var_out)?;
        }
        write!(out, "{}", indent_all_by(4, var_out))?;
    }

    if !t.references.is_empty() {
        writeln!(out, "\n    // References")?;
        for &reference in &t.references {
            let tag = info
                .tags
                .get(&reference)
                .ok_or_else(|| anyhow!("Failed to locate reference tag {}", reference))?;
            if tag.kind == TagKind::Padding {
                writeln!(out, "    // -> ??? ({reference})")?;
                continue;
            }
            let variable = process_variable_tag(info, tag)?;
            writeln!(out, "    // -> {}", variable_string(info, typedefs, &variable, false)?)?;
        }
    }

    if !t.labels.is_empty() {
        writeln!(out, "\n    // Labels")?;
        for label in &t.labels {
            writeln!(out, "    {}: // {:#X}", label.name, label.address)?;
        }
    }

    if !t.blocks_and_inlines.is_empty() {
        for node in &t.blocks_and_inlines {
            let node_str = match node {
                SubroutineNode::Block(block) => subroutine_block_string(info, typedefs, block)?,
                SubroutineNode::Inline(inline) => {
                    subroutine_def_string(info, typedefs, inline, is_erased)?
                }
            };
            writeln!(out)?;
            out.push_str(&indent_all_by(4, node_str));
        }
    }

    writeln!(out, "}}")?;
    Ok(out)
}

fn subroutine_block_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    block: &SubroutineBlock,
) -> Result<String> {
    let mut out = String::new();
    if let Some(name) = &block.name {
        write!(out, "{name}: ")?;
    } else {
        out.push_str("/* anonymous block */ ");
    }
    out.push_str("{\n");
    if let (Some(start), Some(end)) = (block.start_address, block.end_address) {
        writeln!(out, "    // Range: {start:#X} -> {end:#X}")?;
    }
    let mut var_out = String::new();
    for variable in &block.variables {
        let ts = type_string(info, typedefs, &variable.kind, true)?;
        write!(
            var_out,
            "{} {}{};",
            ts.prefix,
            variable.name.as_deref().unwrap_or_default(),
            ts.suffix
        )?;
        if let Some(location) = &variable.location {
            write!(var_out, " // {location}")?;
        }
        writeln!(var_out)?;
    }
    write!(out, "{}", indent_all_by(4, var_out))?;

    if !block.inner_types.is_empty() {
        writeln!(out, "\n    // Inner declarations")?;

        for inner_type in &block.inner_types {
            writeln!(
                out,
                "{};",
                &indent_all_by(4, &ud_type_def(info, typedefs, inner_type, false)?)
            )?;
        }
    }

    if !block.typedefs.is_empty() {
        writeln!(out, "\n    // Typedefs")?;
        for typedef in &block.typedefs {
            writeln!(out, "{}", &indent_all_by(4, &typedef_string(info, typedefs, typedef)?))?;
        }
    }

    if !block.blocks_and_inlines.is_empty() {
        for node in &block.blocks_and_inlines {
            let node_str = match node {
                SubroutineNode::Block(block) => subroutine_block_string(info, typedefs, block)?,
                SubroutineNode::Inline(inline) => {
                    writeln!(out)?;
                    subroutine_def_string(info, typedefs, inline, false)?
                }
            };
            out.push_str(&indent_all_by(4, node_str));
        }
    }
    writeln!(out, "}}")?;
    Ok(out)
}

#[derive(Debug, Clone)]
struct AnonUnion {
    offset: u32,
    member_index: usize,
    member_count: usize,
}

#[derive(Debug, Clone)]
struct AnonUnionGroup {
    member_index: usize,
    member_count: usize,
}

fn get_anon_unions(info: &DwarfInfo, members: &[StructureMember]) -> Result<Vec<AnonUnion>> {
    let mut unions = Vec::<AnonUnion>::new();
    let mut offset = u32::MAX;
    'member: for (prev, member) in members.iter().skip(1).enumerate() {
        if let Some(bit) = &member.bit {
            if bit.bit_offset != 0 {
                continue;
            }
        }
        if member.offset <= members[prev].offset && member.offset != offset {
            offset = member.offset;
            for (i, member) in members.iter().enumerate() {
                if member.offset == offset {
                    for anon in &unions {
                        if anon.member_index == i {
                            continue 'member;
                        }
                    }
                    unions.push(AnonUnion { offset, member_index: i, member_count: 0 });
                    break;
                }
            }
        }
    }
    for anon in &mut unions {
        for (i, member) in members.iter().skip(anon.member_index).enumerate() {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset == anon.offset {
                anon.member_count = i;
            }
        }
        let mut max_offset = 0;
        for member in members.iter().skip(anon.member_index).take(anon.member_count + 1) {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            let size =
                if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
            max_offset = max(max_offset, member.offset + size);
        }
        for member in members.iter().skip(anon.member_index + anon.member_count) {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset >= max_offset || member.offset < anon.offset {
                break;
            }
            anon.member_count += 1;
        }
    }
    Ok(unions)
}

fn get_anon_union_groups(members: &[StructureMember], unions: &[AnonUnion]) -> Vec<AnonUnionGroup> {
    let mut groups = Vec::new();
    for anon in unions {
        for (i, member) in
            members.iter().skip(anon.member_index).take(anon.member_count).enumerate()
        {
            if let Some(bit) = &member.bit {
                if bit.bit_offset != 0 {
                    continue;
                }
            }
            if member.offset == anon.offset {
                let mut group =
                    AnonUnionGroup { member_index: anon.member_index + i, member_count: 1 };

                for member in
                    members.iter().skip(anon.member_index).take(anon.member_count).skip(i + 1)
                {
                    if member.offset == anon.offset {
                        break;
                    }

                    group.member_count += 1;
                }

                if group.member_count > 1 {
                    groups.push(group);
                }
            }
        }
    }
    groups
}

pub fn structure_def_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    t: &StructureType,
) -> Result<String> {
    let mut out = String::new();
    if let Some(byte_size) = t.byte_size {
        writeln!(out, "// total size: {byte_size:#X}")?;
    }
    match t.kind {
        StructureKind::Struct => out.push_str("struct"),
        StructureKind::Class => out.push_str("class"),
    };
    if let Some(name) = t.name.as_ref() {
        if name.starts_with('@') {
            write!(out, " /* {name} */")?;
        } else {
            write!(out, " {name}")?;
        }
    }
    let mut wrote_base = false;
    for base in &t.bases {
        if !wrote_base {
            out.push_str(" : ");
            wrote_base = true;
        } else {
            out.push_str(", ");
        }
        match base.visibility {
            Some(Visibility::Private) => out.push_str("private "),
            Some(Visibility::Protected) => out.push_str("protected "),
            Some(Visibility::Public) => out.push_str("public "),
            None => {}
        }
        if base.virtual_base {
            out.push_str("virtual ");
        }
        if let Some(name) = &base.name {
            out.push_str(name);
        } else {
            out.push_str(&type_name(info, typedefs, &base.base_type)?);
        }
    }
    out.push_str(" {");
    if !t.inner_types.is_empty() {
        writeln!(out, "\n    // Inner declarations")?;
        for inner_type in &t.inner_types {
            writeln!(
                out,
                "{};",
                &indent_all_by(4, &ud_type_def(info, typedefs, inner_type, false)?)
            )?;
        }
    }

    if !t.typedefs.is_empty() {
        writeln!(out, "\n    // Typedefs")?;
        for typedef in &t.typedefs {
            writeln!(out, "{}", &indent_all_by(4, &typedef_string(info, typedefs, typedef)?))?;
        }
    }

    if !t.member_functions.is_empty() {
        writeln!(out, "\n    // Functions")?;

        let len = t.member_functions.len();
        for (i, member_function) in t.member_functions.iter().enumerate() {
            writeln!(
                out,
                "{}",
                indent_all_by(4, member_subroutine_def_string(info, typedefs, member_function)?)
            )?;

            if i + 1 < len {
                writeln!(out)?;
            }
        }
    }

    if !t.static_members.is_empty() {
        writeln!(out, "\n    // Static members")?;
        for static_member in &t.static_members {
            let line = format!("static {}", variable_string(info, typedefs, static_member, true)?);
            writeln!(out, "{}", indent_all_by(4, &line))?;
        }
    }

    let mut vis = match t.kind {
        StructureKind::Struct => Visibility::Public,
        StructureKind::Class => Visibility::Private,
    };
    let mut indent = 4;
    let unions = get_anon_unions(info, &t.members)?;
    let groups = get_anon_union_groups(&t.members, &unions);
    let mut in_union = 0;
    let mut in_group = 0;
    if !t.members.is_empty() {
        writeln!(out, "\n    // Members")?;
    }
    for (i, member) in t.members.iter().enumerate() {
        if vis != member.visibility {
            vis = member.visibility;
            match member.visibility {
                Visibility::Private => out.push_str("private:\n"),
                Visibility::Protected => out.push_str("protected:\n"),
                Visibility::Public => out.push_str("public:\n"),
            }
        }
        for anon in &groups {
            if i == anon.member_index + anon.member_count {
                indent -= 4;
                out.push_str(&indent_all_by(indent, "};\n"));
                in_group -= 1;
            }
        }
        for anon in &unions {
            if anon.member_count < 2 {
                continue;
            }
            if i == anon.member_index + anon.member_count {
                indent -= 4;
                out.push_str(&indent_all_by(indent, "};\n"));
                in_union -= 1;
            }
        }
        for anon in &unions {
            if anon.member_count < 2 {
                continue;
            }
            if i == anon.member_index {
                out.push_str(&indent_all_by(indent, "union { // inferred\n"));
                indent += 4;
                in_union += 1;
            }
        }
        for anon in &groups {
            if i == anon.member_index {
                out.push_str(&indent_all_by(indent, "struct { // inferred\n"));
                indent += 4;
                in_group += 1;
            }
        }
        let mut var_out = String::new();
        let ts = type_string(info, typedefs, &member.kind, true)?;
        if let Some(name) = &member.name {
            write!(var_out, "{} {}{}", ts.prefix, name, ts.suffix)?;
        } else {
            write!(var_out, "{}{}", ts.prefix, ts.suffix)?;
        }
        if let Some(bit) = &member.bit {
            write!(var_out, " : {}", bit.bit_size)?;
        }
        let size = if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
        writeln!(var_out, "; // offset {:#X}, size {:#X}", member.offset, size)?;
        out.push_str(&indent_all_by(indent, var_out));
    }
    while in_group > 0 {
        indent -= 4;
        out.push_str(&indent_all_by(indent, "};\n"));
        in_group -= 1;
    }
    while in_union > 0 {
        indent -= 4;
        out.push_str(&indent_all_by(indent, "};\n"));
        in_union -= 1;
    }
    out.push('}');
    Ok(out)
}

pub fn enum_def_string(t: &EnumerationType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => {
            if name.starts_with('@') {
                format!("enum /* {name} */ {{\n")
            } else {
                format!("enum {name} {{\n")
            }
        }
        None => "enum {\n".to_string(),
    };
    for member in t.members.iter() {
        writeln!(out, "    {} = {},", member.name, member.value)?;
    }
    write!(out, "}}")?;
    Ok(out)
}

pub fn union_def_string(info: &DwarfInfo, typedefs: &TypedefMap, t: &UnionType) -> Result<String> {
    let mut out = match t.name.as_ref() {
        Some(name) => {
            if name.starts_with('@') {
                format!("union /* {name} */ {{\n")
            } else {
                format!("union {name} {{\n")
            }
        }
        None => "union {\n".to_string(),
    };
    let mut var_out = String::new();
    for member in t.members.iter() {
        let ts = type_string(info, typedefs, &member.kind, true)?;
        if let Some(name) = &member.name {
            write!(var_out, "{} {}{};", ts.prefix, name, ts.suffix)?;
        } else {
            write!(var_out, "{}{};", ts.prefix, ts.suffix)?;
        }
        let size = if let Some(size) = member.byte_size { size } else { member.kind.size(info)? };
        write!(var_out, " // offset {:#X}, size {:#X}", member.offset, size)?;
        writeln!(var_out)?;
    }
    write!(out, "{}", indent_all_by(4, var_out))?;
    write!(out, "}}")?;
    Ok(out)
}

pub fn tag_type_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    tag_type: &TagType,
    is_erased: bool,
) -> Result<String> {
    match tag_type {
        TagType::Typedef(t) => typedef_string(info, typedefs, t),
        TagType::Variable(v) => variable_string(info, typedefs, v, true),
        TagType::UserDefined(ud) => {
            let ud_str = ud_type_def(info, typedefs, ud, is_erased)?;
            match **ud {
                UserDefinedType::Structure(_)
                | UserDefinedType::Enumeration(_)
                | UserDefinedType::Union(_) => Ok(format!("{ud_str};")),
                _ => Ok(ud_str),
            }
        }
    }
}

fn typedef_string(info: &DwarfInfo, typedefs: &TypedefMap, typedef: &TypedefTag) -> Result<String> {
    let ts = type_string(info, typedefs, &typedef.kind, true)?;
    Ok(format!("typedef {} {}{};", ts.prefix, typedef.name, ts.suffix))
}

fn variable_string(
    info: &DwarfInfo,
    typedefs: &TypedefMap,
    variable: &VariableTag,
    include_extra: bool,
) -> Result<String> {
    let ts = type_string(info, typedefs, &variable.kind, include_extra)?;
    let mut out = if variable.local { "static ".to_string() } else { String::new() };
    out.push_str(&ts.prefix);
    out.push(' ');
    out.push_str(&maybe_demangle_name(info, variable.name.as_deref().unwrap_or("[unknown]")));
    out.push_str(&ts.suffix);
    out.push(';');
    if include_extra {
        let size = variable.kind.size(info)?;
        out.push_str(&format!(" // size: {size:#X}"));
        if let Some(addr) = variable.address {
            out.push_str(&format!(", address: {addr:#X}"));
        }
    }
    Ok(out)
}

// TODO expand for more compilers?
fn maybe_demangle_name(info: &DwarfInfo, name: &str) -> String {
    let name_opt = match info.producer {
        Producer::MWCC => cw_demangle(name, &Default::default()),
        Producer::GCC => gnu_demangle(name, &DemangleConfig::new()).ok(),
        Producer::OTHER => None,
    };
    name_opt.unwrap_or_else(|| name.to_string())
}

fn maybe_demangle_function_name(info: &DwarfInfo, name: &str) -> String {
    let fake_name = format!("{}__0", name);
    let name_opt = match info.producer {
        // for __pl this looks like operator+
        Producer::MWCC => cw_demangle(&fake_name, &Default::default()),
        // for __pl this looks like ::operator+(void)
        Producer::GCC => {
            gnu_demangle(&fake_name, &DemangleConfig::new()).ok().and_then(|demangled| {
                demangled
                    .split_once("::")
                    .and_then(|(_, rest)| rest.split_once("(void)"))
                    .map(|(op, _)| op.to_string())
            })
        }
        Producer::OTHER => None,
    };
    name_opt.unwrap_or_else(|| name.to_string())
}
