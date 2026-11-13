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
    let read = |r: &Ref, x: u64| columns[r.column.0 as usize][r.index(x)];

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
        first_point(1u64 << lookup.vars, |x| {
            if lookup.selector.as_ref().is_some_and(|s| read(s, x) == 0) {
                return false;
            }
            let tuple: Vec<i64> = lookup.tuple.iter().map(|r| read(r, x)).collect();
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
        first_point(1u64 << identity.vars, |x| {
            let sum = identity.terms.iter().try_fold(0i128, |sum, term| {
                let product = term
                    .factors
                    .iter()
                    .try_fold(term.coeff as i128, |p, f| p.checked_mul(read(f, x) as i128));
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
        first_point(1u64 << matmul.free, |x| {
            let sum = (0..1u64 << matmul.summed).try_fold(0i128, |sum, y| {
                let z = x | (y << matmul.free);
                (read(&matmul.lhs, z) as i128)
                    .checked_mul(read(&matmul.rhs, z) as i128)
                    .and_then(|p| sum.checked_add(p))
            });
            sum != Some(read(&matmul.out, x) as i128)
        })
        .map(|point| Violation::Matmul {
            relation: matmul.name.clone(),
            point,
        })
    })?;
    Ok(())
}
