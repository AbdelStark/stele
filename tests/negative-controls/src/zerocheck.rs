//! RFC-0006 A3: real prover/public-verifier one-value controls, both fields.
use crate::{
    check_proof_control,
    sumcheck::{instance, produce, transcript},
    ProverHook,
};
use stele_field::{OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel};
use stele_sumcheck::{
    message_bytes,
    zerocheck::{Proof, Zerocheck},
    Error, Instance, Term,
};
struct Change(u16);
impl<K: ChallengeField + Eq> ProverHook<Proof<K>> for Change {
    fn tamper(&self, p: &mut Proof<K>) {
        let before = p.clone();
        let value = match self.0 {
            207 => &mut p.skip_values[0],
            208 => &mut p.rounds[0][0],
            _ => p.final_values.last_mut().expect("fixture"),
        };
        *value = *value + K::from_i64(1);
        let scalars = |p: &Proof<K>| {
            p.skip_values
                .iter()
                .chain(p.rounds.iter().flatten())
                .chain(&p.final_values)
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            scalars(&before)
                .iter()
                .zip(scalars(p))
                .filter(|(a, b)| **a != *b)
                .count(),
            1
        );
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(id: u16, skip: u8) -> Result<(), String> {
    let terms = [
        Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 0],
        },
        Term {
            coefficient: K::from_i64(-1),
            factors: vec![1],
        },
    ];
    let relation = Instance {
        id: 1,
        num_vars: 2,
        inputs: vec![11, 12, 13],
        terms: terms.to_vec(),
        claimed_sum: K::from_i64(0),
    };
    let z = Zerocheck {
        instance: &relation,
        skip,
    };
    let a: Vec<_> = (1..=4).map(K::from_i64).collect();
    let tables = vec![a.clone(), a.iter().map(|v| *v * *v).collect(), a];
    if id == 802 {
        let mut honest = transcript();
        let first = z
            .prove(&tables, &mut honest)
            .map_err(|e| format!("{e:?}"))?;
        let next = instance(2, false);
        let second = produce(&next, &mut honest).map_err(|e| format!("{e:?}"))?;
        let wrong = (|| -> Result<_, Error> {
            let mut omitted = transcript();
            omitted.absorb(AbsorbLabel::Zero, &z.encode()?)?;
            for _ in skip..2 {
                omitted.challenge(ChallengeLabel::ZeroWeight)?;
            }
            if skip > 0 {
                let payload = message_bytes(
                    relation.id,
                    first.skip_values.len() as u32,
                    &first.skip_values,
                )?;
                omitted.absorb(AbsorbLabel::ZeroSkip, &payload)?;
                omitted.challenge(ChallengeLabel::Sumcheck)?;
            }
            for (h, row) in first.rounds.iter().enumerate() {
                let payload = message_bytes(relation.id, h as u32, row)?;
                omitted.absorb(AbsorbLabel::Round, &payload)?;
                omitted.challenge(ChallengeLabel::Sumcheck)?;
            }
            produce(&next, &mut omitted)
        })()
        .map_err(|e| format!("{e:?}"))?;
        assert_eq!(wrong.rounds, second.rounds);
        return check_proof_control(
            || Ok::<_, Error>(vec![second.clone()]),
            &crate::sumcheck::Change {
                round: false,
                value: wrong.final_values[0],
            },
            |p| {
                let mut t = transcript();
                let _ = z.verify_public(&first, &tables, &mut t)?;
                stele_sumcheck::verify_public(
                    &next,
                    &p[0],
                    &[vec![K::from_i64(3), K::from_i64(5)]],
                    &mut t,
                )
                .map(|_| ())
            },
            Error::FinalEvaluationMismatch,
        )
        .map_err(|e| format!("{e:?}"));
    }
    let expected = match id {
        209 => Error::ClaimMismatch,
        207 if skip == 2 => Error::FinalEvaluationMismatch,
        _ => Error::RoundSumMismatch,
    };
    check_proof_control(
        || z.prove(&tables, &mut transcript()),
        &Change(id),
        |p| z.verify_public(p, &tables, &mut transcript()).map(|_| ()),
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}
/// Execute both fields and applicable eq-only/partial/complete-skip variants.
pub fn run(id: u16) -> Result<(), String> {
    for skip in 0..=2 {
        if (id == 207 && skip == 0) || (id == 208 && skip == 2) {
            continue;
        }
        check::<QM31>(id, skip)?;
        check::<OM31>(id, skip)?;
    }
    Ok(())
}
#[test]
fn rejects_zerocheck_binding_tampers() {
    for id in [207, 208, 209, 802] {
        run(id).expect("exact real rejection");
    }
}
