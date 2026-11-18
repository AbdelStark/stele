//! RFC-0008 A7 and RFC-0014 A3. Recover the original GKR inputs at the actual sumcheck point.
use super::{
    block_bits, column_point, complex, element, kappa, weight, zero, Coord, Error, Gin, GkrStep,
    Occurrence, Plan,
};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_pcs::CodeField;

/// Evaluate a masked original member after the compact polynomial's final fold.
/// The compact member contains a shifted column; the routed occurrence uses the
/// bare column, with the shift accounted for in the existing term construction.
pub(super) fn member<K: ChallengeField>(
    point: &[K],
    column: &[K],
    coords: &[Coord],
    block: &[M31],
    v: usize,
    u: &[usize],
) -> Result<K, Error> {
    let x = stele_sumcheck::parallel::eq_table(&column_point(coords, point, &[]))
        .map_err(|_| Error::Statement)?;
    let at: Vec<_> = u.iter().map(|&j| point[j]).collect();
    let r = stele_sumcheck::parallel::eq_table(&at).map_err(|_| Error::Statement)?;
    if x.len() != column.len() || r.len() != block.len() {
        return Err(Error::Statement);
    }
    let data = column
        .iter()
        .zip(x)
        .fold(zero::<K>(), |sum, (a, b)| sum + *a * b);
    let mask = block
        .iter()
        .zip(r)
        .fold(zero::<K>(), |sum, (a, b)| sum + element::<K>(*a) * b);
    Ok(data + kappa(point[v]) * mask)
}

pub(in crate::zk::claims) fn field_finals<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    step: &GkrStep,
    data: &[Vec<K>],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
    point: &[K],
    compact: &[K],
) -> Result<Vec<K>, Error> {
    let lp = &plan.lookups[step.lookup];
    if point.len() != step.num_vars as usize {
        return Err(Error::Statement);
    }
    if !complex(step, lp) {
        if compact.len() != step.inputs.len() {
            return Err(Error::Statement);
        }
        return Ok(compact.to_vec());
    }
    let get = |i: usize| compact.get(i).copied().ok_or(Error::Statement);
    let mut i = 0usize;
    let mut mult = false;
    let mut selector = None;
    let mut out = Vec::with_capacity(step.inputs.len());
    for input in &step.inputs {
        let value = match input {
            Gin::Leaf(o) if mult => {
                member(point, &data[o.column], &o.coords, &block_of(o), o.v, &o.u)?
            }
            Gin::Member(m) => {
                let b = weight(&block_bits(lp, &lp.members[*m]), &point[step.xo..]);
                b * selector.unwrap_or(K::from_i64(1))
            }
            _ => {
                if matches!(input, Gin::Leaf(_)) {
                    mult = true;
                }
                if matches!(input, Gin::Table) {
                    i = i.checked_add(lp.c).ok_or(Error::Statement)?;
                }
                let value = get(i)?;
                i += 1;
                if matches!(input, Gin::Selector) {
                    selector = Some(value);
                }
                if matches!(input, Gin::Pad) {
                    get(0)? * value
                } else {
                    value
                }
            }
        };
        out.push(value);
    }
    if i != compact.len() {
        return Err(Error::Statement);
    }
    Ok(out)
}
