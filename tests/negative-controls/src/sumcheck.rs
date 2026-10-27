//! RFC-0006 A1: real-prover/real-public-verifier controls, independent of core.
use crate::{check_proof_control, ProverHook};
use stele_field::{Field, OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    message_bytes, prove, verify_public, Dense, Error, Instance, Proof, Summand, Term,
};

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"control public").expect("public fixture")
}
fn instance<K: Field>(id: u64, constant: bool) -> Instance<K> {
    Instance {
        id,
        num_vars: 1,
        inputs: vec![11],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: if constant { vec![] } else { vec![0] },
        }],
        claimed_sum: K::from_i64(if constant { 2 } else { 8 }),
    }
}
fn produce<K: ChallengeField + Eq>(
    i: &Instance<K>,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error> {
    prove(
        i,
        Dense::new(i, vec![vec![K::from_i64(3), K::from_i64(5)]])?,
        t,
    )
}
fn scalars<K: Copy>(proofs: &[Proof<K>]) -> Vec<K> {
    proofs
        .iter()
        .flat_map(|p| p.rounds.iter().flatten().chain(&p.final_values))
        .copied()
        .collect()
}
struct Change<K> {
    round: bool,
    value: K,
}
impl<K: Copy + Eq> ProverHook<Vec<Proof<K>>> for Change<K> {
    fn tamper(&self, proofs: &mut Vec<Proof<K>>) {
        let before = scalars(proofs);
        let last = proofs.last_mut().expect("honest chain");
        if self.round {
            last.rounds[0][0] = self.value;
        } else {
            last.final_values[0] = self.value;
        }
        let after = scalars(proofs);
        assert_eq!(before.len(), after.len());
        assert_eq!(before.iter().zip(&after).filter(|(a, b)| a != b).count(), 1);
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String> {
    let first = instance::<K>(1, id == 205);
    let second = instance::<K>(2, false);
    let instances = if id == 802 {
        vec![first, second]
    } else {
        vec![first]
    };
    let honest = || -> Result<Vec<Proof<K>>, Error> {
        let mut t = transcript();
        instances.iter().map(|i| produce(i, &mut t)).collect()
    };
    let baseline = honest().map_err(|e| format!("{e:?}"))?;
    let replacement = (|| -> Result<K, Error> {
        Ok(match id {
            200 => baseline[0].rounds[0][0] + K::from_i64(1),
            205 => baseline[0].final_values[0] + K::from_i64(1),
            201 => produce(&instance(2, false), &mut transcript())?.final_values[0],
            800 | 802 => {
                let mut t = transcript();
                t.absorb(AbsorbLabel::Instance, &instances[0].encode()?)?;
                if id == 800 {
                    let r = t.challenge(ChallengeLabel::Sumcheck)?;
                    let mut dense =
                        Dense::new(&instances[0], vec![vec![K::from_i64(3), K::from_i64(5)]])?;
                    dense.fold(r)?;
                    dense.final_values()?[0]
                } else {
                    t.absorb(
                        AbsorbLabel::Round,
                        &message_bytes(instances[0].id, 0, &baseline[0].rounds[0])?,
                    )?;
                    t.challenge(ChallengeLabel::Sumcheck)?;
                    let forged = produce(&instances[1], &mut t)?;
                    assert_eq!(forged.rounds, baseline[1].rounds);
                    forged.final_values[0]
                }
            }
            _ => return Err(Error::InvalidInstance),
        })
    })()
    .map_err(|e| format!("{e:?}"))?;
    let verify = |proofs: &Vec<Proof<K>>| -> Result<(), Error> {
        if proofs.len() != instances.len() {
            return Err(Error::ProofShape);
        }
        let mut t = transcript();
        for (i, p) in instances.iter().zip(proofs) {
            let _ = verify_public(i, p, &[vec![K::from_i64(3), K::from_i64(5)]], &mut t)?;
        }
        Ok(())
    };
    let expected = match id {
        200 => Error::RoundSumMismatch,
        205 => Error::ClaimMismatch,
        _ => Error::FinalEvaluationMismatch,
    };
    check_proof_control(
        honest,
        &Change {
            round: id == 200,
            value: replacement,
        },
        verify,
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}
/// Run the named control through both production challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id)?;
    check::<OM31>(id)
}
