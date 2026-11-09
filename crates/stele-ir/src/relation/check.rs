//! Plain integer checker of RFC-0026 §3.7: every relation evaluated over Z, no proof.

use super::{Invalid, Ref, Relation, Values, Violation};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

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

    for range in relation.ranges.iter().filter(|c| kept(&c.name)) {
        if let Some(index) = columns[range.column.0 as usize]
            .iter()
            .position(|&v| !range.width.contains(v))
        {
            return Err(Violation::Range {
                relation: range.name.clone(),
                index,
            });
        }
    }
    for lookup in relation.lookups.iter().filter(|c| kept(&c.name)) {
        let rows: BTreeSet<&[i64]> = relation.tables[lookup.table.0 as usize]
            .rows
            .iter()
            .map(Vec::as_slice)
            .collect();
        for x in 0..1u64 << lookup.vars {
            if lookup.selector.as_ref().is_some_and(|s| read(s, x) == 0) {
                continue;
            }
            let tuple: Vec<i64> = lookup.tuple.iter().map(|r| read(r, x)).collect();
            if !rows.contains(tuple.as_slice()) {
                return Err(Violation::Lookup {
                    relation: lookup.name.clone(),
                    point: x,
                });
            }
        }
    }
    for compose in relation.composes.iter().filter(|c| kept(&c.name)) {
        let column = columns[compose.column.0 as usize];
        let wrong = (0..column.len()).find(|&i| {
            let sum: i128 = compose
                .limbs
                .iter()
                .map(|&(limb, shift)| (columns[limb.0 as usize][i] as i128) << shift)
                .sum();
            sum != column[i] as i128
        });
        if let Some(index) = wrong {
            return Err(Violation::Compose {
                relation: compose.name.clone(),
                index,
            });
        }
    }
    // After ranges, lookups and compositions every column is within its declared width (discipline),
    // so the static bounds keep every sum below p; checked arithmetic is a second guard.
    for identity in relation.identities.iter().filter(|c| kept(&c.name)) {
        for x in 0..1u64 << identity.vars {
            let sum = identity.terms.iter().try_fold(0i128, |sum, term| {
                let product = term
                    .factors
                    .iter()
                    .try_fold(term.coeff as i128, |p, f| p.checked_mul(read(f, x) as i128));
                product.and_then(|p| sum.checked_add(p))
            });
            if sum != Some(0) {
                return Err(Violation::Identity {
                    relation: identity.name.clone(),
                    point: x,
                });
            }
        }
    }
    for matmul in relation.matmuls.iter().filter(|c| kept(&c.name)) {
        for x in 0..1u64 << matmul.free {
            let sum = (0..1u64 << matmul.summed).try_fold(0i128, |sum, y| {
                let z = x | (y << matmul.free);
                (read(&matmul.lhs, z) as i128)
                    .checked_mul(read(&matmul.rhs, z) as i128)
                    .and_then(|p| sum.checked_add(p))
            });
            if sum != Some(read(&matmul.out, x) as i128) {
                return Err(Violation::Matmul {
                    relation: matmul.name.clone(),
                    point: x,
                });
            }
        }
    }
    Ok(())
}
