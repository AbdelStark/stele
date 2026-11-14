//! Plain integer checker of RFC-0026 §3.7: every relation evaluated over Z, no proof.

use super::{Invalid, Ref, Relation, Values, Violation};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rayon::prelude::*;

/// A named constraint, for `check_except`'s skip list.
trait Named {
    fn name(&self) -> &str;
}
macro_rules! named {
    ($($t:ty),*) => {$(impl Named for $t { fn name(&self) -> &str { &self.name } })*};
}
named!(
    super::Range,
    super::Lookup,
    super::Compose,
    super::Identity,
    super::Matmul
);

/// The first failure, in `items` order, of `failure` over the kept items.
fn first<T: Named + Sync>(
    items: &[T],
    kept: &(dyn Fn(&str) -> bool + Sync),
    failure: impl Fn(&T) -> Option<Violation> + Sync,
) -> Result<(), Violation> {
    let one = |item: &T| kept(item.name()).then(|| failure(item)).flatten();
    #[cfg(feature = "std")]
    let found = items
        .par_iter()
        .map(one)
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .next();
    #[cfg(not(feature = "std"))]
    let found = items.iter().find_map(one);
    found.map_or(Ok(()), Err)
}

/// [`Ref::index`] as one table per byte of the domain point: `index(x)` is the OR of
/// the four bytes' entries. Exact: each index bit reads one domain bit or a fixed
/// constant, so it comes from exactly one byte's entry, and the fixed constants are the
/// same in every entry. Domain points have at most `MAX_VARS = 30` bits.
struct Gather(Vec<[usize; 256]>);
impl Gather {
    fn new(r: &Ref) -> Self {
        Self(
            (0..4)
                .map(|c| core::array::from_fn(|b| r.index((b as u64) << (8 * c))))
                .collect(),
        )
    }
    #[inline]
    fn index(&self, x: u64) -> usize {
        let t = &self.0;
        t[0][(x & 0xff) as usize]
            | t[1][((x >> 8) & 0xff) as usize]
            | t[2][((x >> 16) & 0xff) as usize]
            | t[3][((x >> 24) & 0xff) as usize]
    }
}

/// Matmul operands precompute their summed-bit indices when `summed` is at most this:
/// at most 2^20 index pairs, 16 MB per matmul, about 256 MB with 16 matmuls in parallel.
const SUMMED_TABLE: u8 = 20;

/// The least `x < n` with `failed(x)`.
fn first_point(n: u64, failed: impl Fn(u64) -> bool + Sync) -> Option<u64> {
    #[cfg(feature = "std")]
    return (0..n).into_par_iter().find_first(|x| failed(*x));
    #[cfg(not(feature = "std"))]
    (0..n).find(|x| failed(*x))
}

/// Validate `relation`, then evaluate ranges, lookups, compositions, identities and matmuls over
/// the integers. Returns the first failure in that order.
pub fn check(relation: &Relation, values: &Values) -> Result<(), Violation> {
    check_except(relation, values, &[])
}

/// Test aid for mutation surveys: [`check`] with every constraint whose name is in
/// `skip` left unevaluated (after a full `validate`). It is not a verifier mode; no
/// proof path calls it.
pub fn check_except(relation: &Relation, values: &Values, skip: &[&str]) -> Result<(), Violation> {
    check_with(relation, values, skip, SUMMED_TABLE)
}

/// [`check_except`] with the matmul summed-index table limit as a parameter, so tests
/// can force the per-entry path (`summed_table = 0` with any `summed >= 1`).
pub(crate) fn check_with(
    relation: &Relation,
    values: &Values,
    skip: &[&str],
    summed_table: u8,
) -> Result<(), Violation> {
    let kept = |name: &str| !skip.contains(&name);
    relation.validate()?;
    let columns: Vec<&[i64]> = (0..relation.columns.len())
        .map(|i| {
            let id = super::ColumnId(i as u32);
            values.get(relation, id).ok_or(Violation::Missing(id))
        })
        .collect::<Result<_, _>>()?;
    for (i, column) in columns.iter().enumerate() {
        if column.len() != 1usize << relation.columns[i].log_len {
            return Err(Invalid::Column(super::ColumnId(i as u32)).into());
        }
    }
    let column = |r: &Ref| columns[r.column.0 as usize];

    // E16-22: with `std` each category's constraints, and the points of each one, are
    // checked on the pool. `first` keeps constraint order and `first_point` returns
    // the least failing point, so the result is the sequential first failure.
    first(&relation.ranges, &kept, |range| {
        let column = columns[range.column.0 as usize];
        first_point(column.len() as u64, |i| {
            !range.width.contains(column[i as usize])
        })
        .map(|index| Violation::Range {
            relation: range.name.clone(),
            index: index as usize,
        })
    })?;
    first(&relation.lookups, &kept, |lookup| {
        let rows: BTreeSet<&[i64]> = relation.tables[lookup.table.0 as usize]
            .rows
            .iter()
            .map(Vec::as_slice)
            .collect();
        let selector = lookup
            .selector
            .as_ref()
            .map(|s| (column(s), Gather::new(s)));
        let tuple: Vec<_> = lookup
            .tuple
            .iter()
            .map(|r| (column(r), Gather::new(r)))
            .collect();
        first_point(1u64 << lookup.vars, |x| {
            if selector.as_ref().is_some_and(|(c, g)| c[g.index(x)] == 0) {
                return false;
            }
            let tuple: Vec<i64> = tuple.iter().map(|(c, g)| c[g.index(x)]).collect();
            !rows.contains(tuple.as_slice())
        })
        .map(|point| Violation::Lookup {
            relation: lookup.name.clone(),
            point,
        })
    })?;
    first(&relation.composes, &kept, |compose| {
        let column = columns[compose.column.0 as usize];
        first_point(column.len() as u64, |i| {
            let i = i as usize;
            let sum: i128 = compose
                .limbs
                .iter()
                .map(|&(limb, shift)| (columns[limb.0 as usize][i] as i128) << shift)
                .sum();
            sum != column[i] as i128
        })
        .map(|index| Violation::Compose {
            relation: compose.name.clone(),
            index: index as usize,
        })
    })?;
    // After ranges, lookups and compositions every column is within its declared width (discipline),
    // so the static bounds keep every sum below p; checked arithmetic is a second guard.
    first(&relation.identities, &kept, |identity| {
        let terms: Vec<(i64, Vec<_>)> = identity
            .terms
            .iter()
            .map(|t| {
                let factors = t.factors.iter().map(|f| (column(f), Gather::new(f)));
                (t.coeff, factors.collect())
            })
            .collect();
        first_point(1u64 << identity.vars, |x| {
            let sum = terms.iter().try_fold(0i128, |sum, (coeff, factors)| {
                let product = factors.iter().try_fold(*coeff as i128, |p, (c, g)| {
                    p.checked_mul(c[g.index(x)] as i128)
                });
                product.and_then(|p| sum.checked_add(p))
            });
            sum != Some(0)
        })
        .map(|point| Violation::Identity {
            relation: identity.name.clone(),
            point,
        })
    })?;
    first(&relation.matmuls, &kept, |matmul| {
        let (lhs, rhs, out) = (&matmul.lhs, &matmul.rhs, &matmul.out);
        let (lc, rc, oc) = (column(lhs), column(rhs), column(out));
        let (lg, rg, og) = (Gather::new(lhs), Gather::new(rhs), Gather::new(out));
        // index(x | y << free) = index(x) | index(y << free): x reads only the free bits.
        let summed = 0..1u64 << matmul.summed;
        let ys: Vec<(usize, usize)> = match matmul.summed <= summed_table {
            true => summed
                .clone()
                .map(|y| (lg.index(y << matmul.free), rg.index(y << matmul.free)))
                .collect(),
            false => Vec::new(),
        };
        first_point(1u64 << matmul.free, |x| {
            let (l, r) = (lg.index(x), rg.index(x));
            // Two i64 factors never overflow i128; the sum stays checked.
            let term = |(yl, yr): (usize, usize)| lc[l | yl] as i128 * rc[r | yr] as i128;
            let sum = match ys.is_empty() {
                false => ys
                    .iter()
                    .try_fold(0i128, |sum, y| sum.checked_add(term(*y))),
                true => summed.clone().try_fold(0i128, |sum, y| {
                    let z = y << matmul.free;
                    sum.checked_add(term((lg.index(z), rg.index(z))))
                }),
            };
            sum != Some(oc[og.index(x)] as i128)
        })
        .map(|point| Violation::Matmul {
            relation: matmul.name.clone(),
            point,
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::ColumnId;

    /// The byte tables give exactly `Ref::index` for permuted, broadcast and fixed-bit
    /// refs, over a spread of 30-bit domain points.
    #[test]
    fn gathers_exactly_the_ref_index() {
        let refs = [
            alloc::vec![0, 1, 2, 3],
            alloc::vec![29, 0, 17, 8, 23],
            alloc::vec![Ref::FIXED_1, 9, Ref::FIXED_0, 29, 16, 7],
            (0..30).rev().collect(),
            alloc::vec![],
        ];
        let mask = (1u64 << 30) - 1;
        for vars in refs {
            let r = Ref {
                column: ColumnId(0),
                vars,
            };
            let g = Gather::new(&r);
            let mut x = 0x2545_f491u64 & mask;
            for _ in 0..20_000 {
                assert_eq!(g.index(x), r.index(x), "{:?} {x:#x}", r.vars);
                x = (x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1) >> 17) & mask;
            }
            assert_eq!(g.index(mask), r.index(mask));
        }
    }
}
