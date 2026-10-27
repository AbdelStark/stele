//! RFC-0006 A2: one-value controls through the real instance-batch engine.
use crate::{
    check_proof_control,
    sumcheck::{instance, produce, transcript, Change},
};
use stele_field::{OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel};
use stele_sumcheck::{batch::Batch, message_bytes, Dense, Error, Proof, Summand};
fn check<K: ChallengeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String> {
    let members = vec![instance::<K>(1, id == 205), instance::<K>(2, id == 205)];
    let b = Batch {
        id: 3,
        instances: &members,
    };
    let tables = vec![vec![vec![K::from_i64(3), K::from_i64(5)]]; 2];
    let next = instance::<K>(4, false);
    let honest = || -> Result<Vec<Proof<K>>, Error> {
        let mut t = transcript();
        let mut proofs = vec![b.prove(tables.clone(), &mut t)?];
        if id == 802 {
            proofs.push(produce(&next, &mut t)?);
        }
        Ok(proofs)
    };
    let baseline = honest().map_err(|e| format!("{e:?}"))?;
    let value = (|| -> Result<K, Error> {
        let mut t = transcript();
        if id == 206 {
            let early = t.challenge(ChallengeLabel::BatchCoefficient)?;
            let row = Dense::new(&members[0], tables[0].clone())?.round(&members[0])?;
            return Ok(row[0] + early * row[0]);
        }
        t.absorb(AbsorbLabel::Batch, &b.encode()?)?;
        let gamma = t.challenge(ChallengeLabel::BatchCoefficient)?;
        Ok(match id {
            202 => {
                baseline[0].rounds[0][0]
                    - gamma * Dense::new(&members[1], tables[1].clone())?.round(&members[1])?[0]
            }
            205 => baseline[0].final_values[0] + K::from_i64(1),
            802 => {
                t.absorb(
                    AbsorbLabel::Round,
                    &message_bytes(b.id, 0, &baseline[0].rounds[0])?,
                )?;
                t.challenge(ChallengeLabel::Sumcheck)?;
                let forged = produce(&next, &mut t)?;
                assert_eq!(forged.rounds, baseline[1].rounds);
                forged.final_values[0]
            }
            _ => return Err(Error::InvalidBatch),
        })
    })()
    .map_err(|e| format!("{e:?}"))?;
    let verify = |proofs: &Vec<Proof<K>>| -> Result<(), Error> {
        if proofs.len() != baseline.len() {
            return Err(Error::ProofShape);
        }
        let mut t = transcript();
        let _ = b.verify_public(&proofs[0], &tables, &mut t)?;
        if id == 802 {
            let _ = stele_sumcheck::verify_public(&next, &proofs[1], &tables[0], &mut t)?;
        }
        Ok(())
    };
    let expected = match id {
        202 | 206 => Error::RoundSumMismatch,
        205 => Error::ClaimMismatch,
        _ => Error::FinalEvaluationMismatch,
    };
    check_proof_control(
        honest,
        &Change {
            round: matches!(id, 202 | 206),
            value,
        },
        verify,
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}
/// Execute each instance-mode control; claim-mode coverage remains E3-02 work.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id)?;
    check::<OM31>(id)
}
#[test]
fn rejects_batch_binding_tampers() {
    for id in [202, 206, 205, 802] {
        run(id).expect("exact rejection, both fields");
    }
}
