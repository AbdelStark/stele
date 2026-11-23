//! [`Ref::index`] prepared for a loop over many domain points (RFC-0026 §3.2).
use super::Ref;
use alloc::vec::Vec;

/// Loops shorter than this gather bits directly: a table costs more than it saves.
const TABLE_FROM: usize = 512;

/// The column index of a [`Ref`] at a domain point, equal to [`Ref::index`]. A column read
/// in its natural order is a mask; any other `Ref` is one table per byte of the point.
pub struct Indexer<'a>(Kind<'a>);

enum Kind<'a> {
    /// Index bit `j` is domain bit `j`.
    Natural(u64),
    Direct(&'a Ref),
    /// `index(x)` is the OR of the byte entries: each index bit reads one domain bit or a
    /// fixed constant, so it comes from one byte's entry, and the constants are in every
    /// entry. Points have at most `2 * MAX_VARS = 60` bits (split virtual contractions).
    Table(Vec<[usize; 256]>),
}

impl<'a> Indexer<'a> {
    /// `points` is the number of domain points the loop reads.
    pub fn new(r: &'a Ref, points: usize) -> Self {
        if r.vars.len() < 64 && r.vars.iter().enumerate().all(|(j, &v)| usize::from(v) == j) {
            return Self(Kind::Natural((1u64 << r.vars.len()) - 1));
        }
        if points < TABLE_FROM {
            return Self(Kind::Direct(r));
        }
        let bytes = r
            .vars
            .iter()
            .copied()
            .filter(|&v| Ref::fixed(v).is_none())
            .map(|v| usize::from(v) / 8 + 1)
            .max()
            .unwrap_or(1)
            .max(4);
        Self(Kind::Table(
            (0..bytes)
                .map(|c| core::array::from_fn(|b| r.index((b as u64) << (8 * c))))
                .collect(),
        ))
    }

    /// [`Ref::index`] of the prepared `Ref` at `x`.
    #[inline]
    pub fn index(&self, x: u64) -> usize {
        match &self.0 {
            Kind::Natural(mask) => (x & mask) as usize,
            Kind::Direct(r) => r.index(x),
            Kind::Table(t) => {
                let mut out = t[0][(x & 0xff) as usize]
                    | t[1][((x >> 8) & 0xff) as usize]
                    | t[2][((x >> 16) & 0xff) as usize]
                    | t[3][((x >> 24) & 0xff) as usize];
                for (c, table) in t.iter().enumerate().skip(4) {
                    out |= table[((x >> (8 * c)) & 0xff) as usize];
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::ColumnId;

    #[test]
    fn matches_reference_ref_index_on_natural_permuted_and_fixed_reads() {
        let refs = [
            Ref::identity(ColumnId(0), 0),
            Ref::identity(ColumnId(0), 12),
            Ref {
                column: ColumnId(1),
                vars: alloc::vec![3, 0, 17, Ref::FIXED_1, 9, 33, Ref::FIXED_0, 1],
            },
            Ref {
                column: ColumnId(2),
                vars: alloc::vec![1, 0, 2],
            },
        ];
        let mut state = 0x5354_454c_u64;
        for r in &refs {
            for points in [1usize, 600] {
                let prepared = Indexer::new(r, points);
                for _ in 0..2_000 {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let x = state >> 24;
                    assert_eq!(prepared.index(x), r.index(x));
                }
            }
        }
    }
}
