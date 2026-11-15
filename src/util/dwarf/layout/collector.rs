use std::collections::{BTreeMap, HashMap};

use anyhow::{Result, bail};

use super::{
    Category, Conflict, ConflictCause, ConflictVariant, Def, TypeLayouts, TypeOrigin, TypeRef,
    bare_name, bare_name_with_args, cu_context::CuContext, is_qualified, render_type_ref,
    strip_type_modifiers,
};
use crate::util::dwarf::{
    DwarfInfo, MemberFunctionMap, TagKind, parse_producer, preprocess_cu_tag, process_compile_unit,
};

struct Variant {
    def: Def,
    /// Indices into [`LayoutCollector::units`].
    units: Vec<u32>,
    origins: Vec<TypeOrigin>,
}

#[derive(Default)]
struct Group {
    variants: Vec<Variant>,
    /// Forward declarations and superseded stubs; they refer to whichever variant wins.
    forward_origins: Vec<TypeOrigin>,
}

/// Accumulates type definitions across compile units, deduplicating by qualified name.
#[derive(Default)]
pub struct LayoutCollector {
    groups: BTreeMap<(Category, String), Group>,
    units: Vec<String>,
    pub errors: usize,
}

impl LayoutCollector {
    fn add(&mut self, name: String, def: Def, origin: TypeOrigin) {
        let group = self.groups.entry((def.category(), name)).or_default();
        if !def.is_complete()
            || (!def.has_members() && group.variants.iter().any(|v| v.def.has_members()))
        {
            group.forward_origins.push(origin);
            return;
        }
        if def.has_members() {
            let (stubs, rest) =
                group.variants.drain(..).partition::<Vec<_>, _>(|v| !v.def.has_members());
            group.variants = rest;
            group.forward_origins.extend(stubs.into_iter().flat_map(|v| v.origins));
        }
        add_variant(&mut group.variants, def, origin);
    }

    /// Collects all struct, union and enum definitions from every compile unit in `info`.
    pub fn add_info(&mut self, info: &mut DwarfInfo) -> Result<()> {
        let Some((_, mut tag)) = info.tags.first_key_value() else {
            return Ok(());
        };
        loop {
            match tag.kind {
                TagKind::Padding | TagKind::MwOverlayBranch => {}
                TagKind::CompileUnit => {
                    let unit = process_compile_unit(tag)?;
                    if let Some(producer) = &unit.producer {
                        info.producer = parse_producer(producer);
                    }
                    let unit_index = self.units.len() as u32;
                    self.units.push(unit.name);
                    let children = tag.children(&info.tags);
                    info.member_functions.replace(MemberFunctionMap::new());
                    for &child in &children {
                        preprocess_cu_tag(info, child);
                    }
                    let mut cx = CuContext::new(info, unit_index, &children);
                    let mut defs = Vec::new();
                    for &child in &children {
                        cx.collect_tag(child, &mut defs);
                    }
                    self.errors += cx.errors;
                    for (name, def, key) in defs {
                        self.add(name, def, (unit_index, key));
                    }
                }
                kind => bail!("Unhandled root tag type {:?}", kind),
            }
            match tag.next_sibling(&info.tags) {
                Some(next) => tag = next,
                None => break,
            }
        }
        Ok(())
    }

    /// Merges bare-named definitions into matching qualified ones, then resolves every type
    /// reference to its final name.
    pub fn finish(mut self) -> Result<TypeLayouts> {
        let mut causes = HashMap::<(Category, &str), ConflictCause>::new();
        for (category, name) in self.groups.keys() {
            if is_qualified(name) {
                let cause = if bare_name_with_args(name).contains('<') {
                    ConflictCause::UnresolvedTemplate
                } else {
                    ConflictCause::UnresolvedScope
                };
                let entry = causes.entry((*category, bare_name(name))).or_insert(cause);
                if cause == ConflictCause::UnresolvedTemplate {
                    *entry = cause;
                }
            }
        }
        let causes: HashMap<(Category, String), ConflictCause> =
            causes.into_iter().map(|((c, n), cause)| ((c, n.to_string()), cause)).collect();
        self.merge_bare_names();

        let mut resolved = HashMap::<TypeOrigin, (String, Option<usize>)>::new();
        for ((_, name), group) in &self.groups {
            let conflicted = group.variants.len() > 1;
            for (i, v) in group.variants.iter().enumerate() {
                for &origin in &v.origins {
                    resolved.insert(origin, (name.clone(), conflicted.then_some(i)));
                }
            }
            for &origin in &group.forward_origins {
                resolved.insert(origin, (name.clone(), None));
            }
        }
        let mut resolve = |t: &mut TypeRef| {
            if let Some((name, variant)) = t.origin.and_then(|o| resolved.get(&o)) {
                t.base.clone_from(name);
                t.variant = *variant;
            }
            if !t.is_opaque() {
                t.display = render_type_ref(t);
            }
        };

        let mut out =
            TypeLayouts { structs: vec![], unions: vec![], enums: vec![], conflicts: vec![] };
        for ((category, name), group) in self.groups {
            let mut variants = group.variants;
            for v in &mut variants {
                v.def.set_name(name.clone());
                v.def.for_each_type_mut(&mut resolve);
                if let Def::Struct(s) = &mut v.def {
                    for base in &mut s.bases {
                        if let Some((name, variant)) = base.origin.and_then(|o| resolved.get(&o)) {
                            base.name.clone_from(name);
                            base.variant = *variant;
                        }
                    }
                }
            }
            if variants.len() > 1 {
                log::warn!(
                    "Conflicting definitions of {} {} ({} variants)",
                    category.as_str(),
                    name,
                    variants.len()
                );
                let likely_cause = match causes.get(&(category, name.clone())) {
                    Some(&cause) => cause,
                    None if variants.windows(2).all(|w| w[0].def.same_shape(&w[1].def)) => {
                        ConflictCause::UnresolvedTemplate
                    }
                    None => ConflictCause::Unknown,
                };
                out.conflicts.push(Conflict {
                    name,
                    category: category.as_str(),
                    likely_cause,
                    variants: variants
                        .into_iter()
                        .map(|v| {
                            let mut units: Vec<String> =
                                v.units.iter().map(|&u| self.units[u as usize].clone()).collect();
                            units.sort();
                            units.dedup();
                            Ok(ConflictVariant {
                                compile_units: units,
                                definition: v.def.to_json()?,
                            })
                        })
                        .collect::<Result<_>>()?,
                });
                continue;
            }
            match variants.pop().map(|v| v.def) {
                Some(Def::Struct(s)) => out.structs.push(s),
                Some(Def::Union(u)) => out.unions.push(u),
                Some(Def::Enum(e)) => out.enums.push(e),
                None => {}
            }
        }
        Ok(out)
    }

    /// Moves each variant of a bare-named group (`vector`) into the qualified group
    /// (`rstl::vector<int>`) whose layout it matches, when exactly one does and the layout
    /// determines the template arguments.
    fn merge_bare_names(&mut self) {
        let mut qualified_by_bare = BTreeMap::<(Category, String), Vec<String>>::new();
        for (category, name) in self.groups.keys() {
            if is_qualified(name) {
                qualified_by_bare
                    .entry((*category, bare_name(name).to_string()))
                    .or_default()
                    .push(name.clone());
            }
        }
        for ((category, bare), candidates) in qualified_by_bare {
            let Some(mut group) = self.groups.remove(&(category, bare.clone())) else {
                continue;
            };
            let mut unmatched = vec![];
            for variant in group.variants {
                let mut matches = candidates.iter().flat_map(|name| {
                    let target = &self.groups[&(category, name.clone())];
                    target
                        .variants
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| v.def.same_layout(&variant.def))
                        .filter(|_| template_args_visible(name, &variant.def))
                        .map(move |(i, _)| (name, i))
                });
                match (matches.next(), matches.next()) {
                    (Some((name, i)), None) => {
                        let target = &mut self.groups.get_mut(&(category, name.clone())).unwrap();
                        target.variants[i].units.extend(variant.units);
                        target.variants[i].origins.extend(variant.origins);
                    }
                    _ => unmatched.push(variant),
                }
            }
            group.variants = unmatched;
            if !group.variants.is_empty() || !group.forward_origins.is_empty() {
                self.groups.insert((category, bare), group);
            }
        }
    }
}

/// Whether every template argument in `name` names a type used by `def`'s members or bases.
/// Otherwise a matching layout proves nothing about the arguments: `rstl::reserved_vector<T, 8>`
/// stores `unsigned char mData[8 * sizeof(T)]`, so every 8-byte `T` has the same layout.
fn template_args_visible(name: &str, def: &Def) -> bool {
    let mut used = std::collections::HashSet::new();
    let mut def = def.clone();
    def.for_each_type_mut(&mut |t| {
        used.insert(bare_name(&t.base).to_string());
    });
    if let Def::Struct(s) = &def {
        used.extend(s.bases.iter().map(|b| bare_name(&b.name).to_string()));
    }
    template_args(name)
        .into_iter()
        .all(|arg| strip_type_modifiers(arg).is_some_and(|t| used.contains(bare_name(t))))
}

/// All template arguments of all components of a qualified name.
pub(super) fn template_args(name: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in name.char_indices() {
        match c {
            '<' => {
                depth += 1;
                if depth == 1 {
                    start = i + 1;
                }
            }
            '>' => {
                if depth == 1 {
                    out.push(name[start..i].trim());
                }
                depth -= 1;
            }
            ',' if depth == 1 => {
                out.push(name[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out
}

fn add_variant(variants: &mut Vec<Variant>, def: Def, origin: TypeOrigin) {
    if let Some(v) = variants.iter_mut().find(|v| v.def.same_layout(&def)) {
        v.units.push(origin.0);
        v.origins.push(origin);
    } else {
        variants.push(Variant { def, units: vec![origin.0], origins: vec![origin] });
    }
}
