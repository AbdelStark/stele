//! RFC-0008 A3: real fraction prover and unchanged original-array consumer.
use crate::{check_proof_control, ProverHook};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_lookup::fraction::{Descriptor, Error, Proof};
struct Change(u16);
impl<K: ChallengeField + Eq> ProverHook<Proof<K>> for Change {
    fn tamper(&self, proof: &mut Proof<K>) {
        let before = proof.clone();
        let value = match self.0 {
            406 => &mut proof.root[0],
            407 => &mut proof.steps[0].final_values[2],
            _ => &mut proof.steps[0].final_values[4],
        };
        *value = *value + K::from_i64(1);
        let scalars = |p: &Proof<K>| {
            p.root
                .iter()
                .chain(
                    p.steps
                        .iter()
                        .flat_map(|s| s.rounds.iter().flatten().chain(&s.final_values)),
                )
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            scalars(&before)
                .iter()
                .zip(scalars(proof))
                .filter(|(a, b)| **a != *b)
                .count(),
            1
        );
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String> {
    let zero = K::from_i64(0);
    let d = Descriptor::new(41, 1, 1, [71, 72], &[]).map_err(|e| format!("{e:?}"))?;
    // Zero denominators make the P1 and Eq finals unused by A1; both still bind.
    let leaves = if id == 406 {
        vec![
            [K::from_i64(3), K::from_i64(1)],
            [K::from_i64(5), K::from_i64(1)],
        ]
    } else {
        vec![[zero, zero]; 2]
    };
    let transcript = || Transcript::<K>::new(b"fixed fraction originals").expect("transcript");
    check_proof_control(
        || d.prove(&leaves, &mut transcript()).map(|p| p.0),
        &Change(id),
        |p| d.verify_public(p, &leaves, &mut transcript()).map(|_| ()),
        match id {
            406 => Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
            407 => Error::LeafMismatch,
            _ => Error::CoefficientMismatch,
        },
    )
    .map_err(|e| format!("{e:?}"))
}
/// Execute each actual typed-rejection control in both extension fields.
pub fn run(id: u16) -> Result<(), String> {
    if !(406..=408).contains(&id) {
        return Err("unknown fraction control".into());
    }
    check::<QM31>(id)?;
    check::<OM31>(id)
}
#[test]
fn rejects_fraction_tree_binding_tampers() {
    for id in [406, 407, 408] {
        run(id).expect("one-value real rejection");
    }
}
