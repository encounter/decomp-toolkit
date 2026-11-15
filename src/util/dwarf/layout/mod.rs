//! Extraction of deduplicated type layouts (structs, unions, enums) from DWARF 1.1 info,
//! for consumers that need member offsets rather than printable C++.
//!
//! MWCC's DWARF 1.1 names types by their bare identifier: `rstl::vector<int>` is `vector`
//! and `CStateManager::EInitPhase` is `EInitPhase`, with no link to the enclosing scope.
//! Qualified names are recovered from mangled function and static member names in the same
//! compile unit. Names are then settled across all compile units in [`LayoutCollector::finish`],
//! where a bare-named definition is merged into the one qualified definition with an identical
//! layout, if there is exactly one. Anything still ambiguous is reported under `conflicts`, and
//! references to it carry the index of the variant they use.

mod collector;
mod cu_context;

use anyhow::Result;
pub use collector::LayoutCollector;
use serde::Serialize;

#[derive(Serialize)]
pub struct TypeLayouts {
    pub structs: Vec<StructLayout>,
    pub unions: Vec<UnionLayout>,
    pub enums: Vec<EnumLayout>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Serialize, Clone, Debug)]
pub struct StructLayout {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: &'static str,
    pub byte_size: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<BaseLayout>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<MemberLayout>,
}

#[derive(Serialize, Clone, Debug)]
pub struct BaseLayout {
    pub name: String,
    /// Index into the `conflicts` entry for `name`, if it has conflicting definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<usize>,
    pub offset: u32,
    #[serde(rename = "virtual")]
    pub virtual_base: bool,
    #[serde(skip)]
    origin: Option<TypeOrigin>,
}

#[derive(Serialize, Clone, Debug)]
pub struct MemberLayout {
    pub name: Option<String>,
    pub offset: u32,
    pub byte_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit: Option<BitLayout>,
    #[serde(rename = "type")]
    pub kind: TypeRef,
}

/// DWARF bitfield semantics: `bit_offset` counts from the most significant bit of the
/// member's `byte_size`-sized storage unit at `offset`.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct BitLayout {
    pub bit_size: u32,
    pub bit_offset: u16,
}

#[derive(Serialize, Clone, Debug)]
pub struct UnionLayout {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<MemberLayout>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct EnumLayout {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<EnumMemberLayout>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct EnumMemberLayout {
    pub name: String,
    pub value: i32,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseKind {
    Fundamental,
    Struct,
    Class,
    Union,
    Enum,
    Function,
    PtrToMember,
    Unknown,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModifierKind {
    Pointer,
    Reference,
    Const,
    Volatile,
}

/// A member type, flattened to `base`, then `modifiers`, then `array_dims`.
/// E.g. `const CActor* x[4]` is base `CActor`, modifiers `[const, pointer]`, dims `[4]`.
#[derive(Serialize, Clone, Debug)]
pub struct TypeRef {
    pub display: String,
    /// Fundamental type name or qualified UDT name. Empty for anonymous types,
    /// function types and pointers to members.
    pub base: String,
    pub base_kind: BaseKind,
    /// Index into the `conflicts` entry for `base`, if it has conflicting definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<usize>,
    /// Applied to `base`, innermost first (C reading order).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modifiers: Vec<ModifierKind>,
    /// Outermost first, as written in C. `null` for an unsized dimension.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub array_dims: Vec<Option<u32>>,
    /// Modifiers applied to the array as a whole, e.g. `pointer` for `float (*)[3]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub array_modifiers: Vec<ModifierKind>,
    /// Definition of an anonymous struct/union/enum base type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<Box<InlineDef>>,
    #[serde(skip)]
    origin: Option<TypeOrigin>,
}

impl TypeRef {
    fn new(base_kind: BaseKind) -> Self {
        Self {
            display: String::new(),
            base: String::new(),
            base_kind,
            variant: None,
            modifiers: vec![],
            array_dims: vec![],
            array_modifiers: vec![],
            inline: None,
            origin: None,
        }
    }

    /// Function types, pointers to members and types that don't fit the flattened form only
    /// have a display string, taken from the C++ printer.
    fn is_opaque(&self) -> bool {
        matches!(self.base_kind, BaseKind::Function | BaseKind::PtrToMember | BaseKind::Unknown)
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum InlineDef {
    Struct(StructLayout),
    Union(UnionLayout),
    Enum(EnumLayout),
}

#[derive(Serialize)]
pub struct Conflict {
    pub name: String,
    pub category: &'static str,
    pub likely_cause: ConflictCause,
    pub variants: Vec<ConflictVariant>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictCause {
    /// Instantiations of a template whose arguments could not be recovered: either other
    /// instantiations were qualified, or all variants share member names and offsets and
    /// differ only in member types.
    UnresolvedTemplate,
    /// Other types with this bare name are nested in a class or namespace; these are likely
    /// distinct nested types whose scope could not be recovered.
    UnresolvedScope,
    /// No qualified type has this bare name: a possible ODR violation, or distinct nested
    /// types whose scope was never recovered.
    Unknown,
}

#[derive(Serialize)]
pub struct ConflictVariant {
    pub compile_units: Vec<String>,
    pub definition: serde_json::Value,
}

/// A UDT tag within a specific compile unit: (compile unit index, tag key).
type TypeOrigin = (u32, u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Category {
    Struct,
    Union,
    Enum,
}

impl Category {
    fn as_str(self) -> &'static str {
        match self {
            Category::Struct => "struct",
            Category::Union => "union",
            Category::Enum => "enum",
        }
    }
}

#[derive(Clone, Debug)]
enum Def {
    Struct(StructLayout),
    Union(UnionLayout),
    Enum(EnumLayout),
}

impl Def {
    fn category(&self) -> Category {
        match self {
            Def::Struct(_) => Category::Struct,
            Def::Union(_) => Category::Union,
            Def::Enum(_) => Category::Enum,
        }
    }

    /// Forward declarations have no size and no members.
    fn is_complete(&self) -> bool {
        match self {
            Def::Struct(s) => s.byte_size != 0 || !s.members.is_empty() || !s.bases.is_empty(),
            Def::Union(u) => u.byte_size != 0 || !u.members.is_empty(),
            Def::Enum(e) => e.byte_size != 0 || !e.members.is_empty(),
        }
    }

    /// MWCC sometimes emits a class with its bases and size but no members (e.g. in
    /// `TCastTo.cpp`); such a definition is superseded by one that has members.
    fn has_members(&self) -> bool {
        match self {
            Def::Struct(s) => !s.members.is_empty(),
            Def::Union(u) => !u.members.is_empty(),
            Def::Enum(_) => true,
        }
    }

    /// Layout equality. Ignores struct vs. class, and compares type names without scopes or
    /// template arguments, since compile units differ in how much of a name they can recover.
    fn same_layout(&self, other: &Def) -> bool {
        match (self, other) {
            (Def::Struct(a), Def::Struct(b)) => same_struct(a, b),
            (Def::Union(a), Def::Union(b)) => same_union(a, b),
            (Def::Enum(a), Def::Enum(b)) => same_enum(a, b),
            _ => false,
        }
    }

    /// Like [`Def::same_layout`], but ignoring member types.
    fn same_shape(&self, other: &Def) -> bool {
        fn members(a: &[MemberLayout], b: &[MemberLayout]) -> bool {
            a.len() == b.len()
                && a.iter().zip(b).all(|(a, b)| {
                    a.name == b.name
                        && a.offset == b.offset
                        && a.byte_size == b.byte_size
                        && a.bit == b.bit
                })
        }
        match (self, other) {
            (Def::Struct(a), Def::Struct(b)) => {
                a.byte_size == b.byte_size
                    && a.bases.len() == b.bases.len()
                    && a.bases.iter().zip(&b.bases).all(|(a, b)| a.offset == b.offset)
                    && members(&a.members, &b.members)
            }
            (Def::Union(a), Def::Union(b)) => {
                a.byte_size == b.byte_size && members(&a.members, &b.members)
            }
            _ => false,
        }
    }

    fn for_each_type_mut(&mut self, f: &mut impl FnMut(&mut TypeRef)) {
        match self {
            Def::Struct(s) => struct_types_mut(s, f),
            Def::Union(u) => members_types_mut(&mut u.members, f),
            Def::Enum(_) => {}
        }
    }

    fn set_name(&mut self, name: String) {
        match self {
            Def::Struct(s) => s.name = Some(name),
            Def::Union(u) => u.name = Some(name),
            Def::Enum(e) => e.name = Some(name),
        }
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        Ok(match self {
            Def::Struct(s) => serde_json::to_value(s)?,
            Def::Union(u) => serde_json::to_value(u)?,
            Def::Enum(e) => serde_json::to_value(e)?,
        })
    }
}

fn struct_types_mut(s: &mut StructLayout, f: &mut impl FnMut(&mut TypeRef)) {
    members_types_mut(&mut s.members, f);
}

fn members_types_mut(members: &mut [MemberLayout], f: &mut impl FnMut(&mut TypeRef)) {
    for m in members {
        match m.kind.inline.as_deref_mut() {
            Some(InlineDef::Struct(s)) => struct_types_mut(s, f),
            Some(InlineDef::Union(u)) => members_types_mut(&mut u.members, f),
            _ => {}
        }
        f(&mut m.kind);
    }
}

fn same_name(a: &str, b: &str) -> bool { a == b || bare_name(a) == bare_name(b) }

/// Strips scopes and template arguments: `rstl::vector<int>::iterator` -> `iterator`.
fn bare_name(s: &str) -> &str {
    let last = bare_name_with_args(s);
    last.split('<').next().unwrap_or(last)
}

/// Strips scopes only: `rstl::vector<int>` -> `vector<int>`.
fn bare_name_with_args(s: &str) -> &str { rsplit_top_level(s).map_or(s, |(_, last)| last) }

fn is_qualified(s: &str) -> bool { s.contains("::") || s.contains('<') }

fn same_struct(a: &StructLayout, b: &StructLayout) -> bool {
    a.byte_size == b.byte_size
        && a.bases.len() == b.bases.len()
        && a.bases.iter().zip(&b.bases).all(|(a, b)| {
            a.offset == b.offset && a.virtual_base == b.virtual_base && same_name(&a.name, &b.name)
        })
        && same_members(&a.members, &b.members)
}

fn same_union(a: &UnionLayout, b: &UnionLayout) -> bool {
    a.byte_size == b.byte_size && same_members(&a.members, &b.members)
}

fn same_enum(a: &EnumLayout, b: &EnumLayout) -> bool {
    a.byte_size == b.byte_size && a.members == b.members
}

fn same_members(a: &[MemberLayout], b: &[MemberLayout]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.name == b.name
                && a.offset == b.offset
                && a.byte_size == b.byte_size
                && a.bit == b.bit
                && same_type(&a.kind, &b.kind)
        })
}

fn same_type(a: &TypeRef, b: &TypeRef) -> bool {
    use BaseKind::*;
    let kind_eq = a.base_kind == b.base_kind
        || matches!((a.base_kind, b.base_kind), (Struct, Class) | (Class, Struct));
    let base_eq = match (a.inline.as_deref(), b.inline.as_deref()) {
        (None, None) if a.is_opaque() => a.display == b.display,
        (None, None) => same_name(&a.base, &b.base),
        (Some(InlineDef::Struct(a)), Some(InlineDef::Struct(b))) => same_struct(a, b),
        (Some(InlineDef::Union(a)), Some(InlineDef::Union(b))) => same_union(a, b),
        (Some(InlineDef::Enum(a)), Some(InlineDef::Enum(b))) => same_enum(a, b),
        // C units see `typedef enum {...} X` as anonymous, C++ units name it `X`
        (Some(_), None) | (None, Some(_)) => true,
        _ => false,
    };
    kind_eq
        && base_eq
        && a.modifiers == b.modifiers
        && a.array_dims == b.array_dims
        && a.array_modifiers == b.array_modifiers
}

fn render_type_ref(t: &TypeRef) -> String {
    let base = if !t.base.is_empty() {
        t.base.clone()
    } else {
        match t.base_kind {
            BaseKind::Struct => "struct {...}",
            BaseKind::Class => "class {...}",
            BaseKind::Union => "union {...}",
            BaseKind::Enum => "enum {...}",
            _ => "?",
        }
        .to_string()
    };
    let mut out = apply_modifiers(base, &t.modifiers);
    if !t.array_modifiers.is_empty() {
        out.push_str(&format!(" ({})", apply_modifiers(String::new(), &t.array_modifiers)));
    }
    for dim in &t.array_dims {
        match dim {
            Some(n) => out.push_str(&format!("[{n}]")),
            None => out.push_str("[]"),
        }
    }
    out
}

fn apply_modifiers(mut out: String, modifiers: &[ModifierKind]) -> String {
    let mut indirect = false;
    for m in modifiers {
        match m {
            ModifierKind::Pointer => {
                out.push('*');
                indirect = true;
            }
            ModifierKind::Reference => {
                out.push('&');
                indirect = true;
            }
            ModifierKind::Const | ModifierKind::Volatile => {
                let word = if *m == ModifierKind::Const { "const" } else { "volatile" };
                if indirect || out.is_empty() {
                    out.push(' ');
                    out.push_str(word);
                } else {
                    out.insert_str(0, &format!("{word} "));
                }
            }
        }
    }
    out.trim_start().to_string()
}

/// Returns the scope of a demangled member name, e.g. `rstl::vector<int>` for
/// `rstl::vector<int>::push_back(const int&)`.
fn demangled_scope(demangled: &str) -> Option<String> {
    // Operator names contain `<`, `(` etc., so cut before them rather than at the last `::`
    if let Some(end) = find_top_level(demangled, |s| s.starts_with("::operator")) {
        return Some(demangled[..end].to_string());
    }
    let end = find_top_level(demangled, |s| s.starts_with('(')).unwrap_or(demangled.len());
    let (scope, _) = rsplit_top_level(&demangled[..end])?;
    Some(scope.to_string())
}

/// Returns the parameter types of a demangled function name.
fn demangled_parameters(demangled: &str) -> Option<Vec<&str>> {
    let mut s = demangled.trim_end();
    while let Some(rest) = s.strip_suffix(" const").or_else(|| s.strip_suffix(" volatile")) {
        s = rest;
    }
    let s = s.strip_suffix(')')?;
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in s.char_indices().rev() {
        match c {
            ')' | '>' => depth += 1,
            '<' => depth -= 1,
            '(' if depth == 0 => {
                start = Some(i + 1);
                break;
            }
            '(' => depth -= 1,
            _ => {}
        }
    }
    let params = &s[start?..];
    if params.is_empty() || params == "void" {
        return Some(vec![]);
    }
    let mut out = vec![];
    let mut depth = 0i32;
    let mut last = 0;
    for (i, c) in params.char_indices() {
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(params[last..i].trim());
                last = i + 1;
            }
            _ => {}
        }
    }
    out.push(params[last..].trim());
    if out.last() == Some(&"...") {
        out.pop();
    }
    Some(out)
}

/// `const rstl::vector<int>&` -> `rstl::vector<int>`. `None` for function pointers and arrays.
fn strip_type_modifiers(mut s: &str) -> Option<&str> {
    loop {
        let before = s;
        s = s.trim();
        for suffix in ["*", "&", " const", " volatile"] {
            s = s.strip_suffix(suffix).unwrap_or(s);
        }
        for prefix in ["const ", "volatile "] {
            s = s.strip_prefix(prefix).unwrap_or(s);
        }
        if s == before {
            break;
        }
    }
    let outer = &s[..s.find('<').unwrap_or(s.len())];
    (!s.is_empty() && !outer.contains(['(', '[', ' '])).then_some(s)
}

/// Splits at the last `::` outside of template arguments and parentheses.
fn rsplit_top_level(s: &str) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    let mut split = None;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'<' | b'(' => depth += 1,
            b'>' | b')' => depth -= 1,
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                split = Some(i);
            }
            _ => {}
        }
    }
    split.map(|i| (&s[..i], &s[i + 2..]))
}

fn find_top_level(s: &str, pred: impl Fn(&str) -> bool) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        if depth == 0 && pred(&s[i..]) {
            return Some(i);
        }
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use cwdemangle::demangle as cw_demangle;

    use super::{collector::template_args, *};

    fn demangle(s: &str) -> String { cw_demangle(s, &Default::default()).unwrap() }

    #[test]
    fn scope_from_mangled() {
        let d = demangle(
            "push_back__Q24rstl51list<16CCameraShakeData,Q24rstl17rmemory_allocator>FRC16CCameraShakeData",
        );
        assert_eq!(
            demangled_scope(&d).as_deref(),
            Some("rstl::list<CCameraShakeData, rstl::rmemory_allocator>")
        );
        assert_eq!(demangled_parameters(&d), Some(vec!["const CCameraShakeData&"]));
        let d = demangle("__lt__9TUniqueIdCFRC9TUniqueId");
        assert_eq!(demangled_scope(&d).as_deref(), Some("TUniqueId"));
        assert_eq!(demangled_parameters(&d), Some(vec!["const TUniqueId&"]));
        let d = demangle(
            "mNull__Q24rstl66basic_string<c,Q24rstl14char_traits<c>,Q24rstl17rmemory_allocator>",
        );
        assert_eq!(
            demangled_scope(&d).as_deref(),
            Some("rstl::basic_string<char, rstl::char_traits<char>, rstl::rmemory_allocator>")
        );
        assert_eq!(demangled_scope(&demangle("GetFoo__Fv")), None);
        assert_eq!(demangled_parameters(&demangle("GetFoo__Fv")), Some(vec![]));
    }

    #[test]
    fn modifiers() {
        use ModifierKind::*;
        assert_eq!(apply_modifiers("char".into(), &[Const, Pointer]), "const char*");
        assert_eq!(apply_modifiers("char".into(), &[Pointer, Const]), "char* const");
        assert_eq!(apply_modifiers(String::new(), &[Pointer]), "*");
        assert_eq!(
            strip_type_modifiers("const rstl::vector<int, A>&"),
            Some("rstl::vector<int, A>")
        );
        assert_eq!(strip_type_modifiers("CActor* const*"), Some("CActor"));
        assert_eq!(strip_type_modifiers("void (*)(int)"), None);
        assert_eq!(template_args("rstl::list<A, B<C>>::node<D*>"), vec!["A", "B<C>", "D*"]);
    }
}
