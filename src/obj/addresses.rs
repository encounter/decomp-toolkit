use crate::analysis::cfa::SectionAddress;

/// A collection of address ranges.
/// Slow to insert, but fast to check if an address is contained in any of the ranges.
#[derive(Debug, Clone)]
pub struct AddressRanges {
    /// (start, end) pairs of addresses.
    inner: Vec<(SectionAddress, u32)>,
}

impl Default for AddressRanges {
    fn default() -> Self { Self::new() }
}

impl AddressRanges {
    #[inline]
    pub fn new() -> Self { Self { inner: vec![] } }

    pub fn insert(&mut self, start: SectionAddress, end: SectionAddress) {
        debug_assert_eq!(
            start.section, end.section,
            "AddressIntervals::insert: start and end must be in the same section"
        );
        // TODO: Handle overlapping ranges?
        match self.inner.binary_search_by_key(&start, |&(start, _)| start) {
            Ok(pos) => {
                let (_, end_ref) = &mut self.inner[pos];
                *end_ref = end.address.max(*end_ref);
            }
            Err(pos) => self.inner.insert(pos, (start, end.address)),
        }
    }

    pub fn contains(&self, address: SectionAddress) -> bool {
        let pos = match self.inner.binary_search_by_key(&address, |&(start, _)| start) {
            Ok(_) => return true,
            Err(pos) => pos,
        };
        if pos == 0 {
            return false;
        }
        let (start, end) = &self.inner[pos - 1];
        start.section == address.section
            && address.address >= start.address
            && address.address < *end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains() {
        let mut intervals = AddressRanges::new();
        intervals.insert(SectionAddress { section: 0, address: 0x80000000 }, SectionAddress {
            section: 0,
            address: 0x80000004,
        });
        intervals.insert(SectionAddress { section: 0, address: 0x80000008 }, SectionAddress {
            section: 0,
            address: 0x8000000C,
        });
        intervals.insert(SectionAddress { section: 12, address: 0x80004000 }, SectionAddress {
            section: 12,
            address: 0x80004004,
        });
        intervals.insert(SectionAddress { section: 12, address: 0x80004008 }, SectionAddress {
            section: 12,
            address: 0x8000400C,
        });

        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000000 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000001 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000002 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000003 }));
        assert!(!intervals.contains(SectionAddress { section: 0, address: 0x80000004 }));
        assert!(!intervals.contains(SectionAddress { section: 0, address: 0x80000005 }));
        assert!(!intervals.contains(SectionAddress { section: 0, address: 0x80000006 }));
        assert!(!intervals.contains(SectionAddress { section: 0, address: 0x80000007 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000008 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x80000009 }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x8000000A }));
        assert!(intervals.contains(SectionAddress { section: 0, address: 0x8000000B }));

        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004000 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004001 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004002 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004003 }));
        assert!(!intervals.contains(SectionAddress { section: 12, address: 0x80004004 }));
        assert!(!intervals.contains(SectionAddress { section: 12, address: 0x80004005 }));
        assert!(!intervals.contains(SectionAddress { section: 12, address: 0x80004006 }));
        assert!(!intervals.contains(SectionAddress { section: 12, address: 0x80004007 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004008 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x80004009 }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x8000400A }));
        assert!(intervals.contains(SectionAddress { section: 12, address: 0x8000400B }));
        assert!(!intervals.contains(SectionAddress { section: 12, address: 0x8000400C }));
    }
}
