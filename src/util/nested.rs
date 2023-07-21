use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    hash::Hash,
};

use anyhow::{bail, Result};

pub trait NestedMap<T1, T2, T3> {
    fn nested_insert(&mut self, v1: T1, v2: T2, v3: T3) -> Result<()>;
}

pub trait NestedVec<T1, T2> {
    fn nested_push(&mut self, v1: T1, v2: T2);
    fn nested_remove(&mut self, v1: &T1, v2: &T2);
}

impl<T1, T2, T3> NestedMap<T1, T2, T3> for BTreeMap<T1, BTreeMap<T2, T3>>
where
    T1: Eq + Ord,
    T2: Eq + Ord,
{
    fn nested_insert(&mut self, v1: T1, v2: T2, v3: T3) -> Result<()> {
        match self.entry(v1).or_default().entry(v2) {
            btree_map::Entry::Occupied(_) => bail!("Entry already exists"),
            btree_map::Entry::Vacant(entry) => entry.insert(v3),
        };
        Ok(())
    }
}

impl<T1, T2, T3> NestedMap<T1, T2, T3> for HashMap<T1, HashMap<T2, T3>>
where
    T1: Eq + Hash,
    T2: Eq + Hash,
{
    fn nested_insert(&mut self, v1: T1, v2: T2, v3: T3) -> Result<()> {
        match self.entry(v1).or_default().entry(v2) {
            hash_map::Entry::Occupied(_) => bail!("Entry already exists"),
            hash_map::Entry::Vacant(entry) => entry.insert(v3),
        };
        Ok(())
    }
}

impl<T1, T2> NestedVec<T1, T2> for BTreeMap<T1, Vec<T2>>
where
    T1: Ord,
    T2: PartialEq,
{
    fn nested_push(&mut self, v1: T1, v2: T2) { self.entry(v1).or_default().push(v2); }

    fn nested_remove(&mut self, v1: &T1, v2: &T2) {
        if let Some(vec) = self.get_mut(v1) {
            vec.retain(|n| n != v2);
        }
    }
}

impl<T1, T2> NestedVec<T1, T2> for HashMap<T1, Vec<T2>>
where
    T1: Ord + Hash,
    T2: PartialEq,
{
    fn nested_push(&mut self, v1: T1, v2: T2) { self.entry(v1).or_default().push(v2); }

    fn nested_remove(&mut self, v1: &T1, v2: &T2) {
        if let Some(vec) = self.get_mut(v1) {
            vec.retain(|n| n != v2);
        }
    }
}
