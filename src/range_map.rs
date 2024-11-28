//! Map for a number range to a value. Based on a BTReeMap.

use std::{
    collections::BTreeMap,
    fmt,
    ops::{Bound, Range, RangeBounds},
};

pub struct Val<V> {
    len: usize,
    value: V,
}

#[derive(Default)]
pub struct RangeMap<V> {
    inner: BTreeMap<usize, Val<V>>,
}

impl<V> RangeMap<V> {
    pub fn new() -> Self {
        Self { inner: BTreeMap::new() }
    }

    pub fn insert(&mut self, key: impl RangeBounds<usize>, value: V) {
        let start = match key.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start.saturating_add(1),
            Bound::Unbounded => usize::MIN,
        };
        let end = match key.end_bound() {
            Bound::Included(&end) => end.saturating_add(1),
            Bound::Excluded(&end) => end,
            Bound::Unbounded => usize::MIN,
        };
        self.inner.insert(start, Val { len: end - start, value });
    }

    pub fn get(&self, index: usize) -> Option<&V> {
        let (&start, val) = self.inner.range(..=index).rev().next()?;
        if start <= index && index < start + val.len {
            Some(&val.value)
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (Range<usize>, &V)> {
        self.inner.iter().map(|(&start, v)| (start..(start + v.len), &v.value))
    }
}

impl<V: fmt::Debug> fmt::Debug for RangeMap<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<V, R: RangeBounds<usize>> FromIterator<(R, V)> for RangeMap<V> {
    fn from_iter<T: IntoIterator<Item = (R, V)>>(iter: T) -> Self {
        let mut ret = Self::new();
        for (r, v) in iter {
            ret.insert(r, v);
        }
        ret
    }
}

impl<V> IntoIterator for RangeMap<V> {
    type Item = (Range<usize>, V);
    type IntoIter = std::iter::Map<
        <BTreeMap<usize, Val<V>> as IntoIterator>::IntoIter,
        fn(<BTreeMap<usize, Val<V>> as IntoIterator>::Item) -> Self::Item,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter().map(|(start, v)| (start..(start + v.len), v.value))
    }
}
