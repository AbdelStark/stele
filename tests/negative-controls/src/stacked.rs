//! RFC-0006 A4 §6: one changed final reaches an actual public stacked consumer.
use crate::{check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Coefficient, Kind},
    stacked::{self, Claim, Error, Limits, Order, Prepared, Statement},
};
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};
use stele_sumcheck::{Proof, Term};

const LIMITS: Limits = Limits {
    descriptor_bytes: 4096,
    proof_bytes: 4096,
    prepared_entries: 128,
    partial_entries: 64,
    axis_entries: 16,
};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"stacked control").expect("public fixture")
}
struct Change<K> {
    at: usize,
    value: K,
}
impl<K: Copy + Eq + core::fmt::Debug> ProverHook<Proof<K>> for Change<K> {
    fn tamper(&self, proof: &mut Proof<K>) {
        let before = proof.clone();
        proof.final_values[self.at] = self.value;
        assert_eq!(before.rounds, proof.rounds);
        assert_eq!(
            before
                .final_values
                .iter()
                .zip(&proof.final_values)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(case: u16) -> Result<(), String> {
    let axes = match case {
        212 => vec![Axis { bits: 0, real: 1 }, Axis { bits: 1, real: 2 }],
        1212 => vec![Axis { bits: 0, real: 1 }],
        _ => vec![Axis { bits: 1, real: 2 }; 2],
    };
    let z = [K::from_i64(1)];
    let mut selectors = vec![None; axes.len()];
    if case == 203 {
        selectors[0] = Some(&z[..]);
    }
    let expected_values = [M31::from_i64(7)];
    let changed_values = [M31::from_i64(8)];
    let kind = match case {
        212 => Kind::OnehotSparse {
            row: 0,
            column: 1,
            indices: &[0],
        },
        1212 => Kind::RopeTables {
            axes: &[0],
            values: &expected_values,
        },
        _ => Kind::Eq,
    };
    let original: Vec<_> = [2, 3, 5, 7]
        .into_iter()
        .take(1usize << axes.iter().map(|a| usize::from(a.bits)).sum::<usize>())
        .map(K::from_i64)
        .collect();
    let tables = [&original[..]];
    let s = Statement {
        id: 31,
        axes: &axes,
        order: Order::LayerLast,
        output: Claim {
            id: 50,
            axes: &[],
            point: &[],
            value: K::from_i64(0),
        },
        coefficient_id: 90,
        inputs: &[41],
        terms: &[],
        selectors: &selectors,
        kind,
        source_id: if matches!(case, 212 | 1212) {
            Some(99)
        } else {
            None
        },
    };
    let produce = || stacked::prove_public(&mut transcript(), &s, &tables, LIMITS);
    let honest = produce().map_err(|e| format!("{e:?}"))?;
    let (record, _) = stacked::verify_public(&mut transcript(), &s, &honest, &tables, LIMITS)
        .map_err(|e| format!("{e:?}"))?;
    let mut point = record.point().to_vec();
    let replacement = match case {
        203 => {
            point[0] = point[0] + K::from_i64(1);
            Coefficient::new(&axes, &selectors, kind, 16)
                .expect("coefficient")
                .evaluate(&point)
                .expect("point")
        }
        211 => {
            point.rotate_left(1); // Restore inversion deliberately omitted for the first unused original.
            let weights = stele_poly::eq_table(&point).expect("point");
            original
                .iter()
                .zip(weights)
                .fold(K::from_i64(0), |sum, (x, w)| sum + *x * w)
        }
        212 | 1212 => {
            let changed = if case == 212 {
                Kind::OnehotSparse {
                    row: 0,
                    column: 1,
                    indices: &[1],
                }
            } else {
                Kind::RopeTables {
                    axes: &[0],
                    values: &changed_values,
                }
            };
            Coefficient::new(&axes, &selectors, changed, 16)
                .expect("changed source")
                .evaluate(&point)
                .expect("point")
        }
        _ => return Err("unknown stacked control".into()),
    };
    let hook = Change {
        at: usize::from(case != 211),
        value: replacement,
    };
    let mut tampered = honest.clone();
    hook.tamper(&mut tampered);
    // Empty P lets the actual nested A1 pass; only the real terminal consumer rejects.
    let prepared = Prepared::new(&s, LIMITS).expect("statement");
    let mut raw = transcript();
    raw.absorb(
        AbsorbLabel::StackSources,
        &prepared.source_bytes(&tables).expect("sources"),
    )
    .expect("source frame");
    raw.absorb(AbsorbLabel::Stack, prepared.bytes())
        .expect("statement frame");
    let _ = stele_sumcheck::verify(prepared.instance(), &tampered, &mut raw)
        .map_err(|e| format!("wrong rejecting layer: {e:?}"))?;
    check_proof_control(
        produce,
        &hook,
        |proof| {
            stacked::verify_public(&mut transcript(), &s, proof, &tables, LIMITS)
                .map(|_| ())
                .map_err(|e| e.cause)
        },
        if case == 211 {
            Error::ClaimMismatch
        } else {
            Error::CoefficientMismatch
        },
    )
    .map_err(|e| format!("{e:?}"))
}
/// Full public NC-0203 or both source variants of NC-0212.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id)?;
    check::<OM31>(id)?;
    if id == 212 {
        check::<QM31>(1212)?;
        check::<OM31>(1212)?;
    }
    Ok(())
}
/// Public NC-0211 variant only; catalog completion still requires certified closure.
pub fn run_public_original() -> Result<(), String> {
    check::<QM31>(211)?;
    check::<OM31>(211)
}

fn continuation<K: ChallengeField + Eq + core::fmt::Debug>(
    omit_sources: bool,
) -> Result<(), String> {
    let axes = [Axis { bits: 0, real: 1 }];
    let terms = [Term {
        coefficient: K::from_i64(3),
        factors: vec![],
    }];
    let s = Statement {
        id: 1,
        axes: &axes,
        order: Order::LayerFirst,
        output: Claim {
            id: 2,
            axes: &[],
            point: &[],
            value: K::from_i64(3),
        },
        coefficient_id: 3,
        inputs: &[],
        terms: &terms,
        selectors: &[None],
        kind: Kind::Eq,
        source_id: None,
    };
    let successor = crate::sumcheck::instance::<K>(4, false);
    let produce = || -> Result<Vec<Proof<K>>, Error> {
        let mut t = transcript();
        let first = stacked::prove_public(&mut t, &s, &[], LIMITS).map_err(|e| e.cause)?;
        Ok(vec![
            first,
            crate::sumcheck::produce(&successor, &mut t).map_err(Error::Sumcheck)?,
        ])
    };
    let baseline = produce().map_err(|e| format!("{e:?}"))?;
    let prepared = Prepared::new(&s, LIMITS).map_err(|e| format!("{e:?}"))?;
    let mut adversarial = transcript();
    if !omit_sources {
        adversarial
            .absorb(
                AbsorbLabel::StackSources,
                &prepared.source_bytes(&[]).expect("empty roster"),
            )
            .expect("source frame");
    }
    if omit_sources {
        adversarial
            .absorb(AbsorbLabel::Stack, prepared.bytes())
            .expect("statement frame");
    }
    let _ = stele_sumcheck::verify(prepared.instance(), &baseline[0], &mut adversarial)
        .map_err(|e| format!("predecessor: {e:?}"))?;
    let changed = crate::sumcheck::produce(&successor, &mut adversarial)
        .map_err(|e| format!("successor: {e:?}"))?;
    assert_eq!(changed.rounds, baseline[1].rounds);
    check_proof_control(
        produce,
        &crate::sumcheck::Change {
            round: false,
            value: changed.final_values[0],
        },
        |proofs: &Vec<Proof<K>>| {
            let mut t = transcript();
            let _ =
                stacked::verify_public(&mut t, &s, &proofs[0], &[], LIMITS).map_err(|e| e.cause)?;
            let _ = stele_sumcheck::verify_public(
                &successor,
                &proofs[1],
                &[vec![K::from_i64(3), K::from_i64(5)]],
                &mut t,
            )
            .map_err(Error::Sumcheck)?;
            Ok(())
        },
        Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}
/// NC-0802: omit each new frame separately, mutate one real successor final.
pub fn run_continuation() -> Result<(), String> {
    for omit_sources in [false, true] {
        continuation::<QM31>(omit_sources)?;
        continuation::<OM31>(omit_sources)?;
    }
    Ok(())
}
