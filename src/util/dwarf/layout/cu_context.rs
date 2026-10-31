use std::collections::HashMap;

use anyhow::Result;
use cwdemangle::demangle as cw_demangle;

use super::{
    BaseKind, BaseLayout, BitLayout, Def, EnumLayout, EnumMemberLayout, InlineDef, MemberLayout,
    ModifierKind, StructLayout, TypeRef, UnionLayout, bare_name, demangled_parameters,
    demangled_scope, strip_type_modifiers,
};
use crate::util::dwarf::{
    AttributeKind, DwarfInfo, EnumerationType, Modifier, Producer, StructureKind, StructureMember,
    StructureType, Tag, TagKind, Type, TypeKind, TypedefMap, UnionType, UserDefinedType,
    get_udt_by_key, print::type_string, process_type, ud_type,
};

/// Anonymous types nested deeper than this are not expanded inline.
const MAX_INLINE_DEPTH: usize = 8;

/// All the information from a single compilation unit.
pub(super) struct CuContext<'a> {
    info: &'a DwarfInfo,
    unit: u32,
    /// Qualified names recovered from mangled names, keyed by UDT tag.
    recovered: HashMap<u32, String>,
    typedef_names: HashMap<u32, String>,
    /// Enclosing UDT of nested types that appear as tag children (GCC).
    tree_parents: HashMap<u32, u32>,
    names: HashMap<u32, Option<String>>,
    empty_typedefs: TypedefMap,
    pub(super) errors: usize,
}

impl<'a> CuContext<'a> {
    pub(super) fn new(info: &'a DwarfInfo, unit: u32, children: &[&'a Tag]) -> Self {
        let mut cx = Self {
            info,
            unit,
            recovered: HashMap::new(),
            typedef_names: HashMap::new(),
            tree_parents: HashMap::new(),
            names: HashMap::new(),
            empty_typedefs: TypedefMap::new(),
            errors: 0,
        };
        let member_functions = info.member_functions.borrow();
        for (&udt, functions) in member_functions.iter() {
            for function in functions {
                if let Some(mangled) = info.tags.get(function).and_then(|t| cx.mangled_name(t)) {
                    cx.recover_scope(udt, &mangled);
                }
            }
        }
        for &child in children {
            match child.kind {
                TagKind::Typedef => {
                    if let (Some(name), Some(key)) = (
                        child.string_attribute(AttributeKind::Name),
                        child.reference_attribute(AttributeKind::UserDefType),
                    ) {
                        cx.typedef_names.entry(key).or_insert_with(|| name.clone());
                    }
                }
                TagKind::StructureType | TagKind::ClassType | TagKind::UnionType => {
                    cx.index_udt_children(child);
                }
                TagKind::GlobalSubroutine | TagKind::Subroutine => cx.recover_parameters(child),
                _ => {}
            }
            if let (Some(parent), Some(mangled)) =
                (child.reference_attribute(AttributeKind::Member), cx.mangled_name(child))
            {
                cx.recover_scope(parent, &mangled);
            }
        }
        cx
    }

    fn index_udt_children(&mut self, tag: &Tag) {
        for child in tag.children(&self.info.tags) {
            match child.kind {
                TagKind::StructureType
                | TagKind::ClassType
                | TagKind::UnionType
                | TagKind::EnumerationType => {
                    self.tree_parents.insert(child.key, tag.key);
                    self.index_udt_children(child);
                }
                TagKind::GlobalVariable | TagKind::Typedef => {
                    if let Some(mangled) = self.mangled_name(child) {
                        self.recover_scope(tag.key, &mangled);
                    }
                }
                _ => {}
            }
        }
    }

    fn mangled_name(&self, tag: &Tag) -> Option<String> {
        if let Some(name) = tag.string_attribute(AttributeKind::MwMangled) {
            return Some(name.clone());
        }
        let spec = tag.reference_attribute(AttributeKind::Specification)?;
        self.info.tags.get(&spec)?.string_attribute(AttributeKind::MwMangled).cloned()
    }

    /// Records `name` as the qualified name of UDT `key` if their bare names agree.
    fn recover(&mut self, key: u32, name: &str) {
        let Some(tag) = self.info.tags.get(&key) else { return };
        if !matches!(
            tag.kind,
            TagKind::StructureType
                | TagKind::ClassType
                | TagKind::UnionType
                | TagKind::EnumerationType
        ) {
            return;
        }
        if tag.string_attribute(AttributeKind::Name).is_some_and(|n| n == bare_name(name)) {
            self.recovered.entry(key).or_insert_with(|| name.to_string());
        }
    }

    fn recover_scope(&mut self, key: u32, mangled: &str) {
        if self.info.producer != Producer::MWCC {
            return;
        }
        if let Some(scope) =
            cw_demangle(mangled, &Default::default()).and_then(|d| demangled_scope(&d))
        {
            self.recover(key, &scope);
        }
    }

    /// Pairs a function's DWARF parameter types with the parameter types in its demangled
    /// name, recovering qualified names for any UDT passed by value, pointer or reference.
    fn recover_parameters(&mut self, tag: &Tag) {
        if self.info.producer != Producer::MWCC {
            return;
        }
        let Some(demangled) =
            self.mangled_name(tag).and_then(|m| cw_demangle(&m, &Default::default()))
        else {
            return;
        };
        if let Some(scope) = demangled_scope(&demangled) {
            // Static member functions have no `this` parameter to link them to their class
            if let Some(key) = tag.reference_attribute(AttributeKind::Member) {
                self.recover(key, &scope);
            }
        }
        let Some(names) = demangled_parameters(&demangled) else { return };
        let mut keys = vec![];
        for child in tag.children(&self.info.tags) {
            if child.kind != TagKind::FormalParameter {
                continue;
            }
            if child.string_attribute(AttributeKind::Name).is_some_and(|n| n == "this") {
                continue;
            }
            match child.type_attribute().and_then(|a| process_type(a, self.info.e).ok()) {
                Some(Type { kind: TypeKind::UserDefined(key), .. }) => keys.push(Some(key)),
                Some(_) => keys.push(None),
                None => return,
            }
        }
        if keys.len() != names.len() {
            return;
        }
        for (key, name) in keys.into_iter().zip(names) {
            if let (Some(key), Some(name)) = (key, strip_type_modifiers(name)) {
                self.recover(key, name);
            }
        }
    }

    pub(super) fn collect_tag(&mut self, tag: &Tag, out: &mut Vec<(String, Def, u32)>) {
        if !matches!(
            tag.kind,
            TagKind::StructureType
                | TagKind::ClassType
                | TagKind::UnionType
                | TagKind::EnumerationType
        ) {
            return;
        }
        let udt = match ud_type(self.info, tag) {
            Ok(udt) => udt,
            Err(e) => {
                log::debug!("Failed to process tag {:X}: {:#}", tag.key, e);
                self.errors += 1;
                return;
            }
        };
        if matches!(udt, UserDefinedType::Structure(_)) {
            // Nested types of GCC structs are tag children rather than top-level tags
            for child in tag.children(&self.info.tags) {
                self.collect_tag(child, out);
            }
        }
        let Some(name) = self.qualified_name(tag.key, 0) else {
            return;
        };
        let def = match &udt {
            UserDefinedType::Structure(s) => Def::Struct(self.struct_layout(s, 0)),
            UserDefinedType::Union(u) => Def::Union(self.union_layout(u, 0)),
            UserDefinedType::Enumeration(e) => Def::Enum(enum_layout(e)),
            _ => return,
        };
        out.push((name, def, tag.key));
    }

    /// The best name for UDT `key` known to this compile unit; `None` for anonymous types.
    fn qualified_name(&mut self, key: u32, depth: usize) -> Option<String> {
        if let Some(name) = self.names.get(&key) {
            return name.clone();
        }
        let name = self.compute_qualified_name(key, depth);
        self.names.insert(key, name.clone());
        name
    }

    fn compute_qualified_name(&mut self, key: u32, depth: usize) -> Option<String> {
        if let Some(name) = self.recovered.get(&key) {
            return Some(name.clone());
        }
        let tag = self.info.tags.get(&key)?;
        let bare = match tag.string_attribute(AttributeKind::Name) {
            Some(name) if !name.starts_with('@') => name.clone(),
            _ => return self.typedef_names.get(&key).cloned(),
        };
        let parent = tag
            .reference_attribute(AttributeKind::Member)
            .or_else(|| self.tree_parents.get(&key).copied());
        if let Some(parent) = parent.filter(|_| depth < 16) {
            if let Some(parent_name) = self.qualified_name(parent, depth + 1) {
                return Some(format!("{parent_name}::{bare}"));
            }
        }
        Some(bare)
    }

    fn struct_layout(&mut self, t: &StructureType, depth: usize) -> StructLayout {
        let bases = t
            .bases
            .iter()
            .map(|b| {
                let (name, origin) = match b.base_type.kind {
                    TypeKind::UserDefined(key) => {
                        (self.qualified_name(key, 0), Some((self.unit, key)))
                    }
                    TypeKind::Fundamental(_) => (None, None),
                };
                BaseLayout {
                    name: name.or_else(|| b.name.clone()).unwrap_or_default(),
                    variant: None,
                    offset: b.offset,
                    virtual_base: b.virtual_base,
                    origin,
                }
            })
            .collect();
        StructLayout {
            name: None,
            kind: match t.kind {
                StructureKind::Struct => "struct",
                StructureKind::Class => "class",
            },
            byte_size: t.byte_size.unwrap_or(0),
            bases,
            members: self.members(&t.members, depth),
        }
    }

    fn union_layout(&mut self, t: &UnionType, depth: usize) -> UnionLayout {
        UnionLayout { name: None, byte_size: t.byte_size, members: self.members(&t.members, depth) }
    }

    fn members(&mut self, members: &[StructureMember], depth: usize) -> Vec<MemberLayout> {
        members
            .iter()
            .map(|m| MemberLayout {
                name: m.name.clone(),
                offset: m.offset,
                byte_size: m.byte_size.or_else(|| m.kind.size(self.info).ok()),
                bit: m
                    .bit
                    .as_ref()
                    .map(|b| BitLayout { bit_size: b.bit_size, bit_offset: b.bit_offset }),
                kind: self.type_ref(&m.kind, depth),
            })
            .collect()
    }

    fn type_ref(&mut self, t: &Type, depth: usize) -> TypeRef {
        self.type_ref_inner(t, depth).unwrap_or_else(|e| {
            log::debug!("Failed to resolve type {:?}: {:#}", t, e);
            self.errors += 1;
            TypeRef::new(BaseKind::Unknown)
        })
    }

    fn type_ref_inner(&mut self, t: &Type, depth: usize) -> Result<TypeRef> {
        let modifiers: Vec<ModifierKind> =
            t.modifiers.iter().rev().map(|&m| modifier_kind(m)).collect();
        let key = match t.kind {
            TypeKind::Fundamental(ft) => {
                let mut out = TypeRef::new(BaseKind::Fundamental);
                out.base = ft.name()?.to_string();
                out.modifiers = modifiers;
                return Ok(out);
            }
            TypeKind::UserDefined(key) => key,
        };
        let udt = get_udt_by_key(self.info, key)?;
        let mut out = match &udt {
            UserDefinedType::Array(a) => {
                let element = self.type_ref(&a.element_type, depth);
                if !element.array_modifiers.is_empty() {
                    return self.opaque_type(t, BaseKind::Unknown);
                }
                let mut dims: Vec<Option<u32>> =
                    a.dimensions.iter().map(|d| d.size.map(|s| s.get())).collect();
                // MWCC lists dimensions innermost first
                if self.info.producer == Producer::MWCC {
                    dims.reverse();
                }
                dims.extend(element.array_dims);
                return Ok(TypeRef { array_dims: dims, array_modifiers: modifiers, ..element });
            }
            UserDefinedType::Subroutine(_) => return self.opaque_type(t, BaseKind::Function),
            UserDefinedType::PtrToMember(_) => return self.opaque_type(t, BaseKind::PtrToMember),
            UserDefinedType::Structure(s) => TypeRef::new(match s.kind {
                StructureKind::Struct => BaseKind::Struct,
                StructureKind::Class => BaseKind::Class,
            }),
            UserDefinedType::Union(_) => TypeRef::new(BaseKind::Union),
            UserDefinedType::Enumeration(_) => TypeRef::new(BaseKind::Enum),
        };
        out.modifiers = modifiers;
        match self.qualified_name(key, 0) {
            Some(name) => {
                out.base = name;
                out.origin = Some((self.unit, key));
            }
            None if depth < MAX_INLINE_DEPTH => {
                out.inline = Some(Box::new(match &udt {
                    UserDefinedType::Structure(s) => {
                        InlineDef::Struct(self.struct_layout(s, depth + 1))
                    }
                    UserDefinedType::Union(u) => InlineDef::Union(self.union_layout(u, depth + 1)),
                    UserDefinedType::Enumeration(e) => InlineDef::Enum(enum_layout(e)),
                    _ => unreachable!(),
                }));
            }
            None => {}
        }
        Ok(out)
    }

    fn opaque_type(&self, t: &Type, base_kind: BaseKind) -> Result<TypeRef> {
        let mut out = TypeRef::new(base_kind);
        out.display = type_string(self.info, &self.empty_typedefs, t, false)?.to_string();
        Ok(out)
    }
}

fn modifier_kind(m: Modifier) -> ModifierKind {
    match m {
        Modifier::MwPointerTo | Modifier::PointerTo => ModifierKind::Pointer,
        Modifier::ReferenceTo => ModifierKind::Reference,
        Modifier::Const => ModifierKind::Const,
        Modifier::Volatile => ModifierKind::Volatile,
    }
}

fn enum_layout(t: &EnumerationType) -> EnumLayout {
    EnumLayout {
        name: None,
        byte_size: t.byte_size,
        members: t
            .members
            .iter()
            .map(|m| EnumMemberLayout { name: m.name.clone(), value: m.value })
            .collect(),
    }
}
