//! RFC-0014 A4. Prepare the original RFC-0013 A5 relation factors in instance order.
use super::{domain_table, Coord, Error, Occurrence, Step};
use alloc::{borrow::Cow, vec::Vec};
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_kernels::gkr::{GkrMask, Projected, RelationConstruction, Term};
use stele_sumcheck::Instance;

pub(super) struct Prepared<'a, K: Clone> {
    values: Cow<'a, [K]>,
    coordinates: Vec<usize>,
    mask: Option<GkrMask<'a>>,
}

fn project<'a, K: ChallengeField>(
    values: &'a [K],
    coords: &[Coord],
    free: &[K],
    n: usize,
) -> Result<Prepared<'a, K>, Error> {
    let log = u32::try_from(coords.len()).map_err(|_| Error::Statement)?;
    if 1usize.checked_shl(log) != Some(values.len()) {
        return Err(Error::Statement);
    }
    let mut seen = 0usize;
    let mut variables = Vec::with_capacity(coords.len());
    for &c in coords {
        match c {
            Coord::Var(q) if q < n => {
                let bit = 1usize << q;
                if seen & bit == 0 {
                    variables.push(q);
                }
                seen |= bit;
            }
            Coord::Free(i) if i < free.len() => {}
            Coord::Fixed(0 | 1) => {}
            _ => return Err(Error::Statement),
        }
    }
    // Distinct variable coordinates are a direct gather. Fixed, free or repeated
    // coordinates keep the reference's original accumulation and broadcast rules.
    let (values, coordinates) = if variables.len() == coords.len() {
        (Cow::Borrowed(values), variables)
    } else {
        (
            Cow::Owned(domain_table(values, coords, free, n)),
            (0..n).collect(),
        )
    };
    Ok(Prepared {
        values,
        coordinates,
        mask: None,
    })
}

pub(super) fn prepare<'a, K: ChallengeField>(
    step: &'a Step<K>,
    data: &'a [Vec<K>],
    free: &[K],
    block_of: &dyn Fn(&Occurrence) -> Vec<M31>,
) -> Result<Vec<Prepared<'a, K>>, Error> {
    let n = step.num_vars as usize;
    if !(1..=30).contains(&n) {
        return Err(Error::Statement);
    }
    let mut factors =
        Vec::with_capacity(step.first() + step.occurrences.len() + step.publics.len());
    if step.eq.is_some() {
        let tau = step.tau(free);
        if tau.len() > n {
            return Err(Error::Statement);
        }
        factors.push(Prepared {
            values: Cow::Owned(
                stele_sumcheck::parallel::eq_table(&tau).map_err(|_| Error::Statement)?,
            ),
            coordinates: (0..tau.len()).collect(),
            mask: None,
        });
    }
    for o in &step.occurrences {
        let mut f = project(
            data.get(o.column).ok_or(Error::Statement)?,
            &o.coords,
            free,
            n,
        )?;
        f.mask = Some(GkrMask {
            values: block_of(o),
            coordinates: &o.u,
            vanishing: o.v,
        });
        factors.push(f);
    }
    for p in &step.publics {
        factors.push(project(&p.values, &p.coords, free, n)?);
    }
    Ok(factors)
}

pub(super) fn construction<'a, K: ChallengeField>(
    prepared: &'a mut [Prepared<'_, K>],
    instance: &Instance<K>,
    degree: usize,
) -> RelationConstruction<'a, K> {
    RelationConstruction {
        num_vars: instance.num_vars,
        degree,
        terms: instance
            .terms
            .iter()
            .map(|t| Term {
                coefficient: t.coefficient,
                factors: t.factors.clone(),
            })
            .collect(),
        factors: prepared
            .iter_mut()
            .map(|f| Projected {
                values: f.values.as_ref(),
                coordinates: core::mem::take(&mut f.coordinates),
                mask: f.mask.take(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    #[test]
    fn matches_reference_fixed_free_repeated_and_permuted_projections() {
        let data: Vec<_> = (0..8).map(|i| QM31::from_i64(3 * i - 4)).collect();
        let free = [QM31::from_i64(7)];
        for (coords, borrowed) in [
            ([Coord::Var(2), Coord::Var(0), Coord::Var(1)], true),
            ([Coord::Var(2), Coord::Fixed(1), Coord::Free(0)], false),
            ([Coord::Var(1), Coord::Var(1), Coord::Var(2)], false),
            ([Coord::Free(0), Coord::Var(1), Coord::Fixed(0)], false),
        ] {
            let f = project(&data, &coords, &free, 4).expect("genuine projection");
            assert_eq!(matches!(f.values, Cow::Borrowed(_)), borrowed);
            let evaluated: Vec<_> = (0..16)
                .map(|i| {
                    f.values[f
                        .coordinates
                        .iter()
                        .fold(0, |j, &c| (j << 1) | ((i >> (3 - c)) & 1))]
                })
                .collect();
            assert_eq!(evaluated, domain_table(&data, &coords, &free, 4));
        }
        for coord in [Coord::Fixed(2), Coord::Var(4), Coord::Free(1)] {
            assert!(project(&data[..2], &[coord], &free, 4).is_err());
        }
        assert!(project(
            &data[..7],
            &[Coord::Var(1), Coord::Var(0), Coord::Var(2)],
            &free,
            4
        )
        .is_err());
    }
}
