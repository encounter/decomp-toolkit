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
}

impl<T1, T2, T3> NestedMap<T1, T2, T3> for BTreeMap<T1, BTreeMap<T2, T3>>
where
    T1: Eq + Ord,
    T2: Eq + Ord,
{
    fn nested_insert(&mut self, v1: T1, v2: T2, v3: T3) -> Result<()> {
        let inner = match self.entry(v1) {
            btree_map::Entry::Occupied(entry) => entry.into_mut(),
            btree_map::Entry::Vacant(entry) => entry.insert(Default::default()),
        };
        match inner.entry(v2) {
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
        let inner = match self.entry(v1) {
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hash_map::Entry::Vacant(entry) => entry.insert(Default::default()),
        };
        match inner.entry(v2) {
            hash_map::Entry::Occupied(_) => bail!("Entry already exists"),
            hash_map::Entry::Vacant(entry) => entry.insert(v3),
        };
        Ok(())
    }
}

impl<T1, T2> NestedVec<T1, T2> for BTreeMap<T1, Vec<T2>>
where T1: Ord
{
    fn nested_push(&mut self, v1: T1, v2: T2) {
        match self.entry(v1) {
            btree_map::Entry::Occupied(mut e) => {
                e.get_mut().push(v2);
            }
            btree_map::Entry::Vacant(e) => {
                e.insert(vec![v2]);
            }
        }
    }
}
