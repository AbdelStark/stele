//! RFC-0013 A5 items 2 and 5. Evaluate verifier-derived occurrence weights
//! on the source data face using the offsets from the verifier's own plan.

use super::{
    basis, column_point, dim, kappa, zero, ChallengeField, CodeField, Error, Occurrence, Plan,
    Source,
};
use alloc::vec::Vec;

/// A verifier-derived claim has one translated equality table per column limb,
/// then a translated equality table for its mask block (A5 item 2).
pub(super) struct Routed<K> {
    at: usize,
    limbs: usize,
    point: Vec<K>,
    mask_at: usize,
    mask_point: Vec<K>,
    mask_scale: K,
    pub(super) value: K,
}

pub(super) fn route<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    o: &Occurrence,
    point: &[K],
    free: &[K],
    value: K,
) -> Result<(usize, Routed<K>), Error> {
    let column = plan.columns[o.column];
    if o.coords.len() != column.log_len as usize {
        return Err(Error::Statement);
    }
    let (at, blocks) = plan.offsets[o.column];
    let mask_at = o
        .block
        .checked_mul(dim::<K>())
        .and_then(|offset| blocks.checked_add(offset))
        .ok_or(Error::Statement)?;
    Ok((
        column.source,
        Routed {
            at,
            limbs: column.limbs,
            point: column_point(&o.coords, point, free),
            mask_at,
            mask_point: o.u.iter().map(|q| point[*q]).collect(),
            mask_scale: kappa(point[o.v]),
            value,
        },
    ))
}

fn width(variables: usize) -> Result<usize, Error> {
    1usize
        .checked_shl(u32::try_from(variables).map_err(|_| Error::Statement)?)
        .ok_or(Error::Statement)
}

/// Sum eq(z, at+j)·eq(q,j) over the whole q-cube. At bit k, mass[c] is the
/// sum of the products for the low k bits of j and at+j with carry c.
/// Every j follows its unique ordinary integer addition path, including when
/// the source offset is unaligned. Coordinates are stored MSB first.
fn shifted_eq<K: ChallengeField>(z: &[K], at: usize, q: &[K]) -> Result<K, Error> {
    let domain = width(z.len())?;
    if at.checked_add(width(q.len())?).ok_or(Error::Statement)? > domain {
        return Err(Error::Statement);
    }
    let one = K::from_i64(1);
    let zero = zero::<K>();
    let mut mass = [one, zero];
    let q_bits = q.iter().rev().copied().chain(core::iter::repeat(zero));
    for (k, (&source, input)) in z.iter().rev().zip(q_bits).enumerate() {
        let offset_bit = (at >> k) & 1;
        let source_weights = [one - source, source];
        let mut next = [zero; 2];
        for (carry, prior) in mass.into_iter().enumerate() {
            for (bit, weight) in [one - input, input].into_iter().enumerate() {
                let sum = offset_bit + carry + bit;
                next[sum >> 1] = next[sum >> 1] + prior * weight * source_weights[sum & 1];
            }
        }
        mass = next;
    }
    // The checked interval fits the source face, so every valid j ends at carry zero.
    Ok(mass[0])
}

pub(super) fn expected<K: ChallengeField + CodeField>(
    source: &Source<K>,
    claims: &[Routed<K>],
    gammas: &[K],
    point: &[K],
) -> Result<K, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    super::on_data_face(source, point, claims.len(), gammas.len(), |z| {
        let mut total = zero::<K>();
        for (claim, gamma) in claims.iter().zip(gammas) {
            if claim.limbs != 1 && claim.limbs != dim::<K>() {
                return Err(Error::Statement);
            }
            let len = width(claim.point.len())?;
            let mut at = claim.at;
            let mut value = shifted_eq(z, at, &claim.point)?;
            for d in 1..claim.limbs {
                at = at.checked_add(len).ok_or(Error::Statement)?;
                value = value + basis::<K>(d)? * shifted_eq(z, at, &claim.point)?;
            }
            value = value + claim.mask_scale * shifted_eq(z, claim.mask_at, &claim.mask_point)?;
            total = total + *gamma * value;
        }
        Ok(total)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use stele_field::{Field, QM31};

    #[test]
    fn matches_reference_shifted_equality_for_all_small_intervals() {
        let one = QM31::from_i64(1);
        let zero = QM31::from_i64(0);
        let basis = basis::<QM31>(1).expect("extension basis");
        for n in 0..=6 {
            let z: Vec<_> = (0..n)
                .map(|i| basis + QM31::from_i64(3 + i as i64))
                .collect();
            let z_table = stele_poly::eq_table(&z).expect("source equality table");
            for m in 0..=n {
                let free: Vec<_> = (0..m)
                    .map(|i| basis * QM31::from_i64(4 + i as i64))
                    .collect();
                for q in [
                    free,
                    (0..m)
                        .map(|i| if i % 2 == 0 { one } else { zero })
                        .collect(),
                ] {
                    let weights = stele_poly::eq_table(&q).expect("column equality table");
                    for at in 0..=z_table.len() - weights.len() {
                        let expected = weights
                            .iter()
                            .zip(&z_table[at..])
                            .fold(zero, |s, (a, b)| s + *a * *b);
                        assert_eq!(
                            shifted_eq(&z, at, &q),
                            Ok(expected),
                            "n={n}, m={m}, at={at}"
                        );
                    }
                    assert_eq!(
                        shifted_eq(&z, z_table.len() - weights.len() + 1, &q),
                        Err(Error::Statement)
                    );
                }
            }
            assert_eq!(shifted_eq(&z, usize::MAX, &[]), Err(Error::Statement));
            assert_eq!(shifted_eq(&z, 0, &vec![one; n + 1]), Err(Error::Statement));
        }
    }
    #[test]
    fn matches_reference_routed_limb_mask_and_claim_order() {
        use super::super::{expected_weight, Claim, BLOWUP, MIN_M};
        let source = Source::<QM31>::hiding(0, 3, MIN_M, BLOWUP, [0; 32]).expect("hiding source");
        let q = |x| QM31::from_i64(x) + basis::<QM31>(1).expect("extension basis");
        let make = |at, limbs| Routed {
            at,
            limbs,
            point: vec![q(2), QM31::from_i64(1), q(5)],
            mask_at: 24,
            mask_point: vec![q(7), QM31::from_i64(0)],
            mask_scale: q(11),
            value: q(13),
        };
        let dense = |r: &Routed<QM31>| {
            let mut weights = Vec::new();
            let x = stele_poly::eq_table(&r.point).expect("column equality table");
            for limb in 0..r.limbs {
                for (i, w) in x.iter().enumerate() {
                    weights.push((
                        r.at + limb * x.len() + i,
                        basis::<QM31>(limb).expect("limb basis") * *w,
                    ));
                }
            }
            for (i, w) in stele_poly::eq_table(&r.mask_point)
                .expect("mask equality table")
                .into_iter()
                .enumerate()
            {
                weights.push((r.mask_at + i, r.mask_scale * w));
            }
            Claim {
                weights,
                value: r.value,
            }
        };
        let mut p: Vec<_> = (0..source.rows().ilog2() + source.columns().ilog2() - 1)
            .map(|i| q(i64::from(i) + 17))
            .collect();
        let gamma = [q(37), q(41)];
        for face in [q(3), QM31::from_i64(0), QM31::from_i64(1)] {
            p[0] = face;
            for rs in [
                [make(17, 4), make(20, 1)],
                [make(20, 1), make(17, 4)],
                [make(17, 4), make(17, 4)],
            ] {
                let ordinary: Vec<_> = rs.iter().map(&dense).collect();
                assert_eq!(
                    expected(&source, &rs, &gamma, &p),
                    expected_weight(&source, &ordinary, &gamma, &p)
                );
                assert_eq!(
                    expected(&source, &rs[..1], &gamma, &p),
                    Err(Error::Statement)
                );
                assert_eq!(
                    expected(&source, &rs, &gamma, &p[1..]),
                    Err(Error::Statement)
                );
            }
        }
        // Even a zero coefficient and a zero data face must reject an invalid extent.
        let zeros = [QM31::from_i64(0)];
        let end = (source.rows() / 2) * (source.columns() / 2);
        for bad in [
            make(end - 8, 4),
            Routed {
                mask_at: end - 3,
                ..make(1, 1)
            },
            make(0, 0),
            make(0, dim::<QM31>() + 1),
        ] {
            assert_eq!(expected(&source, &[bad], &zeros, &p), Err(Error::Statement));
        }
    }
}
