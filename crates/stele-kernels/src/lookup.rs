//! RFC-0014 A6 and RFC-0008 A7. Tops and child layers from proof-local original messages.
use crate::gkr::{GkrConstruction, RelationBackend};
use crate::{Error, SourceGeometry, QM31};
use alloc::vec::Vec;
use core::ops::Range;

/// Actual lookup draws and dimensions, retained by the reduction for both visits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key<K = QM31> {
    pub id: u64,
    pub variables: usize,
    pub top_variables: usize,
    pub beta: K,
    pub alpha: K,
}

/// Logical original column interval in the upper-left quadrant of one physical A5 owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub owner: usize,
    pub geometry: SourceGeometry,
    pub offset: usize,
    pub len: usize,
}

impl Column {
    pub fn check(self) -> Result<(), Error> {
        let quarter = self.geometry.word_count()? / 4;
        if self.len.is_power_of_two()
            && self
                .offset
                .checked_add(self.len)
                .is_some_and(|end| end <= quarter)
        {
            Ok(())
        } else {
            Err(Error::Shape)
        }
    }

    pub fn physical(self, position: usize) -> Result<usize, Error> {
        self.check()?;
        if position >= self.len {
            return Err(Error::Shape);
        }
        let x = self.offset + position;
        let width = self.geometry.columns / 2;
        Ok(x / width * self.geometry.columns + x % width)
    }
}

pub struct Leg<'a> {
    pub column: Column,
    pub coordinates: &'a [usize],
    pub shift: i64,
}
pub struct Member<'a> {
    pub range: Range<usize>,
    pub selector: Option<(&'a [i64], &'a [usize])>,
    pub tuple: Vec<Leg<'a>>,
}
pub struct Input<'a, K = QM31> {
    pub key: Key<K>,
    pub multiplicity: Column,
    pub members: &'a [Member<'a>],
    pub table: &'a [Vec<i64>],
    pub valid: usize,
}

fn coordinates(positions: &[usize], len: usize, n: usize) -> bool {
    if !len.is_power_of_two() || positions.len() != len.ilog2() as usize {
        return false;
    }
    let mut seen = 0usize;
    for &q in positions {
        if q >= n || seen & (1 << q) != 0 {
            return false;
        }
        seen |= 1 << q;
    }
    true
}

impl<K> Input<'_, K> {
    /// Validate every extent, selector and projection before allocating or launching.
    pub fn check(&self) -> Result<(), Error> {
        let n = self.key.variables;
        if !(1..=30).contains(&n) || self.key.top_variables > n || self.members.is_empty() {
            return Err(Error::Shape);
        }
        let size = 1usize << n;
        self.multiplicity.check()?;
        let width = self.members[0].tuple.len();
        if width == 0
            || self.table.len() != self.multiplicity.len
            || self.table.len() > size
            || self.valid > self.table.len()
            || self.table.iter().any(|r| r.len() != width)
        {
            return Err(Error::Shape);
        }
        let mut next = 0;
        for m in self.members {
            let Some(len) = m.range.end.checked_sub(m.range.start) else {
                return Err(Error::Shape);
            };
            if !len.is_power_of_two()
                || m.range.start != next
                || !next.is_multiple_of(len)
                || m.range.end > size
                || m.tuple.len() != width
            {
                return Err(Error::Shape);
            }
            next = m.range.end;
            for l in &m.tuple {
                l.column.check()?;
                if !coordinates(l.coordinates, l.column.len, n) {
                    return Err(Error::Shape);
                }
            }
            if let Some((v, c)) = m.selector {
                if !coordinates(c, v.len(), n) || v.iter().any(|&s| s != 0 && s != 1) {
                    return Err(Error::Shape);
                }
            }
        }
        Ok(())
    }
}

/// Keep earlier layers for the next step or give up the tree after its final child reads.
pub enum Visit<'a, T> {
    Borrow(&'a T),
    Last(T),
}
impl<T> Visit<'_, T> {
    pub fn tree(&self) -> &T {
        match self {
            Self::Borrow(t) => t,
            Self::Last(t) => t,
        }
    }
}

pub trait LookupBackend: RelationBackend<QM31> {
    type Tree<'s>
    where
        Self: 's;
    fn lookup_top(
        &self,
        input: &Input<'_>,
        originals: &[&Self::Original<'_>],
    ) -> Result<Vec<[QM31; 2]>, Self::Error>;
    fn lookup_tree<'s>(
        &'s self,
        input: &Input<'_>,
        originals: &[&Self::Original<'_>],
    ) -> Result<Self::Tree<'s>, Self::Error>;
    fn lookup_gkr<'s>(
        &'s self,
        key: Key,
        tree: Visit<'_, Self::Tree<'_>>,
        input: &GkrConstruction<'_, QM31>,
    ) -> Result<Self::Gkr<'s>, Self::Error>;
}
