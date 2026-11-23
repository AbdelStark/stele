//! Plain integer checker of RFC-0026 §3.7 and RFC-0028 §2.1: every relation evaluated over Z, no proof.

use super::{ColumnId, ColumnSlice, Def, Indexer, Invalid, Kind, Ref, Relation, Values, Violation};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rayon::prelude::*;

/// The first failure, in `items` order, of `failure` over the kept items.
fn first_item<T: Sync>(
    items: &[T],
    kept: &(dyn Fn(&T) -> bool + Sync),
    failure: impl Fn(&T) -> Option<Violation> + Sync,
) -> Result<(), Violation> {
    let one = |item: &T| kept(item).then(|| failure(item)).flatten();
    #[cfg(feature = "std")]
    let found = if items.len() >= 16 {
        items
            .par_iter()
            .map(one)
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .next()
    } else {
        items.iter().find_map(one)
    };
    #[cfg(not(feature = "std"))]
    let found = items.iter().find_map(one);
    found.map_or(Ok(()), Err)
}

/// Resolved values of one column during plain checking.
///
/// Committed/public columns borrow directly from `Values`/`Relation`; virtual columns
/// (RFC-0028 §2.1) are computed from their definitions over `Z` (`None` on `i128` overflow).
enum ColData<'a> {
    Borrowed(ColumnSlice<'a>),
    /// A computed column whose every entry is an `i32`. A valid witness's virtual columns
    /// are below `p` (RFC-0028 A1); the checked form is 32 bytes an entry.
    Narrow(Vec<i32>),
    Computed(Vec<Option<i128>>),
}

impl<'a> ColData<'a> {
    /// A computed column, narrow when every entry fits.
    fn computed(values: Vec<Option<i128>>) -> Self {
        let mut narrow = Vec::with_capacity(values.len());
        for value in &values {
            match value.and_then(|v| i32::try_from(v).ok()) {
                Some(v) => narrow.push(v),
                None => return ColData::Computed(values),
            }
        }
        ColData::Narrow(narrow)
    }

    /// The entries as a typed slice, for the columns that have one.
    fn slice(&self) -> Option<ColumnSlice<'_>> {
        match self {
            ColData::Borrowed(s) => Some(*s),
            ColData::Narrow(v) => Some(ColumnSlice::I32(v)),
            ColData::Computed(_) => None,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            ColData::Borrowed(s) => s.len(),
            ColData::Narrow(v) => v.len(),
            ColData::Computed(v) => v.len(),
        }
    }

    #[inline]
    fn get(&self, idx: usize) -> Option<i128> {
        match self {
            ColData::Borrowed(s) => Some(s.at(idx) as i128),
            ColData::Narrow(v) => Some(i128::from(v[idx])),
            ColData::Computed(v) => v[idx],
        }
    }
}

/// Compute a virtual column's integer values over `{0,1}^log_len` from already-resolved
/// earlier columns, ignoring any entry in `Values` (RFC-0028 §2.1).
fn eval_virtual(
    log_len: u8,
    def: &Def,
    resolved: &[Option<ColData<'_>>],
    summed_table: u8,
) -> Vec<Option<i128>> {
    let n = 1usize << log_len;
    let col = |id: ColumnId| resolved[id.0 as usize].as_ref().expect("operand resolved");
    match def {
        Def::Linear { constant, terms } => {
            let compiled: Vec<(i128, &ColData<'_>, Indexer<'_>)> = terms
                .iter()
                .map(|(c, r)| (*c as i128, col(r.column), Indexer::new(r, n)))
                .collect();
            let c0 = *constant as i128;
            let eval_at = |x: usize| {
                compiled.iter().try_fold(c0, |acc, (coeff, data, g)| {
                    let v = data.get(g.index(x as u64))?;
                    acc.checked_add(coeff.checked_mul(v)?)
                })
            };
            #[cfg(feature = "std")]
            {
                if n >= 4096 {
                    (0..n).into_par_iter().map(eval_at).collect()
                } else {
                    (0..n).map(eval_at).collect()
                }
            }
            #[cfg(not(feature = "std"))]
            {
                (0..n).map(eval_at).collect()
            }
        }
        Def::Pointwise { terms } => {
            let compiled: Vec<(i128, Vec<(&ColData<'_>, Indexer<'_>)>)> = terms
                .iter()
                .map(|t| {
                    let factors = t
                        .factors
                        .iter()
                        .map(|f| (col(f.column), Indexer::new(f, n)))
                        .collect();
                    (t.coeff as i128, factors)
                })
                .collect();
            let eval_at = |x: usize| {
                compiled.iter().try_fold(0i128, |sum, (coeff, factors)| {
                    let prod = factors.iter().try_fold(*coeff, |p, (data, g)| {
                        p.checked_mul(data.get(g.index(x as u64))?)
                    })?;
                    sum.checked_add(prod)
                })
            };
            #[cfg(feature = "std")]
            {
                if n >= 4096 {
                    (0..n).into_par_iter().map(eval_at).collect()
                } else {
                    (0..n).map(eval_at).collect()
                }
            }
            #[cfg(not(feature = "std"))]
            {
                (0..n).map(eval_at).collect()
            }
        }
        Def::Contraction {
            free,
            summed,
            lhs,
            rhs,
        } => {
            let (lc, rc) = (col(lhs.column), col(rhs.column));
            // Typed operands: one exact dot product per entry (`contract`); sums that may
            // leave `i64`, and operands in the checked form, keep the checked loop below.
            if let (Some(l), Some(r)) = (lc.slice(), rc.slice()) {
                if let Some(out) = super::contract(*free, *summed, (lhs, l), (rhs, r)) {
                    if out.len() == n {
                        return out.into_iter().map(|v| Some(i128::from(v))).collect();
                    }
                }
            }
            let total_work =
                n.saturating_mul(1usize.checked_shl(u32::from(*summed)).unwrap_or(usize::MAX));
            let (lg, rg) = (Indexer::new(lhs, total_work), Indexer::new(rhs, total_work));
            let summed_range = 0..1u64 << *summed;
            let ys: Vec<(usize, usize)> = if *summed <= summed_table {
                summed_range
                    .clone()
                    .map(|y| (lg.index(y << *free), rg.index(y << *free)))
                    .collect()
            } else {
                Vec::new()
            };
            let eval_at = |x: usize| {
                let (l, r) = (lg.index(x as u64), rg.index(x as u64));
                let term = |(yl, yr): (usize, usize)| -> Option<i128> {
                    lc.get(l | yl)?.checked_mul(rc.get(r | yr)?)
                };
                if !ys.is_empty() {
                    ys.iter()
                        .try_fold(0i128, |sum, y| sum.checked_add(term(*y)?))
                } else {
                    summed_range.clone().try_fold(0i128, |sum, y| {
                        let z = y << *free;
                        sum.checked_add(term((lg.index(z), rg.index(z)))?)
                    })
                }
            };
            #[cfg(feature = "std")]
            {
                if n >= 256 {
                    (0..n).into_par_iter().map(eval_at).collect()
                } else {
                    (0..n).map(eval_at).collect()
                }
            }
            #[cfg(not(feature = "std"))]
            {
                (0..n).map(eval_at).collect()
            }
        }
    }
}

/// Matmul operands precompute their summed-bit indices when `summed` is at most this:
/// at most 2^20 index pairs, 16 MB per matmul, about 256 MB with 16 matmuls in parallel.
const SUMMED_TABLE: u8 = 20;

/// The least `x < n` with `failed(x)`.
fn first_point(n: u64, failed: impl Fn(u64) -> bool + Sync) -> Option<u64> {
    #[cfg(feature = "std")]
    if n >= 4096 {
        return (0..n).into_par_iter().find_first(|x| failed(*x));
    }
    (0..n).find(|x| failed(*x))
}

/// Validate `relation`, then evaluate ranges, lookups, compositions, identities and matmuls over
/// the integers. Returns the first failure in that order.
pub fn check(relation: &Relation, values: &Values) -> Result<(), Violation> {
    check_except(relation, values, &[])
}

/// Evaluate one column's integer values from `values` (borrowing public/witness/weight columns
/// or recursively evaluating `Kind::Virtual` operands over `Z`, RFC-0028 §2.1).
pub fn eval_column(
    relation: &Relation,
    values: &Values,
    target: ColumnId,
) -> Result<Vec<i64>, Violation> {
    let idx = target.0 as usize;
    if idx >= relation.columns.len() {
        return Err(Violation::Missing(target));
    }
    if !matches!(relation.columns[idx].kind, Kind::Virtual(_)) {
        return values
            .get(relation, target)
            .map(|s| s.to_vec())
            .ok_or(Violation::Missing(target));
    }
    // Mark transitive dependencies needed for `target`.
    let mut needed = alloc::vec![false; idx + 1];
    needed[idx] = true;
    for i in (0..=idx).rev() {
        if needed[i] {
            if let Kind::Virtual(def) = &relation.columns[i].kind {
                for op in def.operands() {
                    if (op.0 as usize) < i {
                        needed[op.0 as usize] = true;
                    }
                }
            }
        }
    }
    let mut resolved: Vec<Option<ColData<'_>>> = (0..=idx).map(|_| None).collect();
    for (i, &need) in needed.iter().enumerate() {
        if !need {
            continue;
        }
        let cid = ColumnId(i as u32);
        let col = &relation.columns[i];
        match &col.kind {
            Kind::Virtual(def) => {
                let data = eval_virtual(col.log_len, def, &resolved, SUMMED_TABLE);
                resolved[i] = Some(ColData::computed(data));
            }
            _ => {
                let slice = values.get(relation, cid).ok_or(Violation::Missing(cid))?;
                resolved[i] = Some(ColData::Borrowed(slice));
            }
        }
    }
    match resolved[idx].take().ok_or(Violation::Missing(target))? {
        ColData::Borrowed(s) => Ok(s.to_vec()),
        ColData::Narrow(v) => Ok(v.into_iter().map(i64::from).collect()),
        ColData::Computed(v) => v
            .into_iter()
            .map(|x| x.and_then(|n| i64::try_from(n).ok()))
            .collect::<Option<Vec<i64>>>()
            .ok_or(Violation::Missing(target)),
    }
}

/// Validate `relation`, then evaluate every constraint owned by `segment` over the integers
/// (RFC-0026 A27). Only columns belonging to `segment` or referenced by `segment`'s constraints
/// must be assigned in `values`.
pub fn check_segment(relation: &Relation, segment: u32, values: &Values) -> Result<(), Violation> {
    check_inner(relation, values, &[], SUMMED_TABLE, Some(segment))
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
    check_inner(relation, values, skip, summed_table, None)
}

fn check_inner(
    relation: &Relation,
    values: &Values,
    skip: &[&str],
    summed_table: u8,
    segment: Option<u32>,
) -> Result<(), Violation> {
    relation.validate()?;
    let col_segs = relation.column_segments();
    let weight_segs = relation.weight_segments();
    let in_segment = |item_seg: u32| segment.is_none_or(|s| s == item_seg);
    let mut required = alloc::vec![segment.is_none(); relation.columns.len()];
    if let Some(seg) = segment {
        for (i, &cseg) in col_segs.iter().enumerate() {
            if cseg == Some(seg) {
                required[i] = true;
            }
        }
        for range in &relation.ranges {
            if relation.range_segment_with_segs(range, &col_segs, &weight_segs) == seg {
                required[range.column.0 as usize] = true;
            }
        }
        for lookup in &relation.lookups {
            if relation.lookup_segment_with(lookup, &col_segs) == seg {
                for r in lookup.tuple.iter().chain(lookup.selector.iter()) {
                    required[r.column.0 as usize] = true;
                }
            }
        }
        for compose in &relation.composes {
            if relation.compose_segment_with(compose, &col_segs) == seg {
                required[compose.column.0 as usize] = true;
                for &(limb, _) in &compose.limbs {
                    required[limb.0 as usize] = true;
                }
            }
        }
        for identity in &relation.identities {
            if relation.identity_segment_with(identity, &col_segs) == seg {
                for term in &identity.terms {
                    for f in &term.factors {
                        required[f.column.0 as usize] = true;
                    }
                }
            }
        }
        for matmul in &relation.matmuls {
            if relation.matmul_segment_with(matmul, &col_segs) == seg {
                for r in [&matmul.out, &matmul.lhs, &matmul.rhs] {
                    required[r.column.0 as usize] = true;
                }
            }
        }
        // Transitive closure over virtual column dependencies in decreasing ColumnId order.
        for i in (0..relation.columns.len()).rev() {
            if !required[i] {
                continue;
            }
            if let Kind::Virtual(def) = &relation.columns[i].kind {
                for op in def.operands() {
                    required[op.0 as usize] = true;
                }
            }
        }
    }
    let mut columns: Vec<Option<ColData<'_>>> = Vec::with_capacity(relation.columns.len());
    for (i, col_meta) in relation.columns.iter().enumerate() {
        let id = super::ColumnId(i as u32);
        if !required[i] {
            columns.push(None);
            continue;
        }
        match &col_meta.kind {
            Kind::Virtual(def) => {
                // RFC-0028 §2.1: compute from definition over earlier columns; ignore any supplied values.
                let computed = eval_virtual(col_meta.log_len, def, &columns, summed_table);
                columns.push(Some(ColData::computed(computed)));
            }
            _ => {
                let slice = values.get(relation, id).ok_or(Violation::Missing(id))?;
                if slice.len() != 1usize << col_meta.log_len {
                    return Err(Invalid::Column(id).into());
                }
                columns.push(Some(ColData::Borrowed(slice)));
            }
        }
    }
    let col_data = |id: super::ColumnId| {
        columns[id.0 as usize]
            .as_ref()
            .expect("required column checked")
    };
    let column = |r: &Ref| col_data(r.column);

    let kept_range = |r: &super::Range| {
        in_segment(relation.range_segment_with_segs(r, &col_segs, &weight_segs))
            && !skip.contains(&r.name.as_str())
    };
    let kept_lookup = |l: &super::Lookup| {
        in_segment(relation.lookup_segment_with(l, &col_segs)) && !skip.contains(&l.name.as_str())
    };
    let kept_compose = |c: &super::Compose| {
        in_segment(relation.compose_segment_with(c, &col_segs)) && !skip.contains(&c.name.as_str())
    };
    let kept_identity = |i: &super::Identity| {
        in_segment(relation.identity_segment_with(i, &col_segs)) && !skip.contains(&i.name.as_str())
    };
    let kept_matmul = |m: &super::Matmul| {
        in_segment(relation.matmul_segment_with(m, &col_segs)) && !skip.contains(&m.name.as_str())
    };

    // E16-22: with `std` each category's constraints, and the points of each one, are
    // checked on the pool. `first` keeps constraint order and `first_point` returns
    // the least failing point, so the result is the sequential first failure.
    first_item(&relation.ranges, &kept_range, |range| {
        let column = col_data(range.column);
        let (min_v, max_v) = (range.width.min() as i128, range.width.max() as i128);
        first_point(column.len() as u64, |i| {
            column
                .get(i as usize)
                .is_none_or(|v| v < min_v || v > max_v)
        })
        .map(|index| Violation::Range {
            relation: range.name.clone(),
            index: index as usize,
        })
    })?;
    first_item(&relation.lookups, &kept_lookup, |lookup| {
        let rows: BTreeSet<&[i64]> = relation.tables[lookup.table.0 as usize]
            .rows
            .iter()
            .map(Vec::as_slice)
            .collect();
        let selector = lookup
            .selector
            .as_ref()
            .map(|s| (column(s), Indexer::new(s, usize::MAX)));
        let tuple: Vec<_> = lookup
            .tuple
            .iter()
            .map(|r| (column(r), Indexer::new(r, usize::MAX)))
            .collect();
        first_point(1u64 << lookup.vars, |x| {
            if selector
                .as_ref()
                .is_some_and(|(c, g)| c.get(g.index(x)) == Some(0))
            {
                return false;
            }
            let Some(tuple): Option<Vec<i64>> = tuple
                .iter()
                .map(|(c, g)| c.get(g.index(x)).and_then(|v| i64::try_from(v).ok()))
                .collect()
            else {
                return true;
            };
            !rows.contains(tuple.as_slice())
        })
        .map(|point| Violation::Lookup {
            relation: lookup.name.clone(),
            point,
        })
    })?;
    first_item(&relation.composes, &kept_compose, |compose| {
        let column = col_data(compose.column);
        first_point(column.len() as u64, |i| {
            let i = i as usize;
            let sum = compose.limbs.iter().try_fold(0i128, |acc, &(limb, shift)| {
                let v = col_data(limb).get(i)?;
                // `shift <= MAX_WIDTH_BITS = 30`, so `1i128 << shift` is exact and
                // `checked_mul` catches any arithmetic overflow that `checked_shl` ignores.
                acc.checked_add(v.checked_mul(1i128 << shift)?)
            });
            sum.is_none() || sum != column.get(i)
        })
        .map(|index| Violation::Compose {
            relation: compose.name.clone(),
            index: index as usize,
        })
    })?;
    // After ranges, lookups and compositions every column is within its declared width (discipline),
    // so the static bounds keep every sum below p; checked arithmetic is a second guard.
    first_item(&relation.identities, &kept_identity, |identity| {
        let terms: Vec<(i64, Vec<_>)> = identity
            .terms
            .iter()
            .map(|t| {
                let factors = t
                    .factors
                    .iter()
                    .map(|f| (column(f), Indexer::new(f, usize::MAX)));
                (t.coeff, factors.collect())
            })
            .collect();
        first_point(1u64 << identity.vars, |x| {
            let sum = terms.iter().try_fold(0i128, |sum, (coeff, factors)| {
                let product = factors.iter().try_fold(*coeff as i128, |p, (c, g)| {
                    p.checked_mul(c.get(g.index(x))?)
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
    first_item(&relation.matmuls, &kept_matmul, |matmul| {
        let (lhs, rhs, out) = (&matmul.lhs, &matmul.rhs, &matmul.out);
        let (lc, rc, oc) = (column(lhs), column(rhs), column(out));
        let (lg, rg, og) = (
            Indexer::new(lhs, usize::MAX),
            Indexer::new(rhs, usize::MAX),
            Indexer::new(out, usize::MAX),
        );
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
            let term = |(yl, yr): (usize, usize)| -> Option<i128> {
                lc.get(l | yl)?.checked_mul(rc.get(r | yr)?)
            };
            let sum = match ys.is_empty() {
                false => ys
                    .iter()
                    .try_fold(0i128, |sum, y| sum.checked_add(term(*y)?)),
                true => summed.clone().try_fold(0i128, |sum, y| {
                    let z = y << matmul.free;
                    sum.checked_add(term((lg.index(z), rg.index(z)))?)
                }),
            };
            sum.is_none() || sum != oc.get(og.index(x))
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
    /// refs, over both 30-bit and 60-bit (split virtual contraction) domain points.
    #[test]
    fn gathers_exactly_the_ref_index() {
        let refs = [
            alloc::vec![0, 1, 2, 3],
            alloc::vec![29, 0, 17, 8, 23],
            alloc::vec![Ref::FIXED_1, 9, Ref::FIXED_0, 29, 16, 7],
            (0..30).rev().collect(),
            alloc::vec![59, 44, 33, 31, Ref::FIXED_1, 12, 0],
            alloc::vec![],
        ];
        let mask = (1u64 << 60) - 1;
        for vars in refs {
            let r = Ref {
                column: ColumnId(0),
                vars,
            };
            let g = Indexer::new(&r, usize::MAX);
            let mut x = 0x2545_f491_9e37_79b9u64 & mask;
            for _ in 0..20_000 {
                assert_eq!(g.index(x), r.index(x), "{:?} {x:#x}", r.vars);
                x = (x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1) >> 4) & mask;
            }
            assert_eq!(g.index(mask), r.index(mask));
        }
    }
}
