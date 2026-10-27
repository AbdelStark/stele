//! RFC-0006 A2: one-value controls through both real batching engines.
use crate::{
    check_control, check_proof_control,
    sumcheck::{instance, produce, transcript, Change},
    ProverHook,
};
use stele_field::{OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel};
use stele_sumcheck::{batch::Batch, message_bytes, Dense, Error, Proof, Summand};
struct ChangeEntry;
impl<K: ChallengeField + Eq> ProverHook<Vec<K>> for ChangeEntry {
    fn tamper(&self, table: &mut Vec<K>) {
        let before = table.clone();
        table[1] = table[1] + K::from_i64(1);
        assert_eq!(
            before.iter().zip(table).filter(|(a, b)| *a != *b).count(),
            1
        );
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(
    id: u16,
    claim_mode: bool,
) -> Result<(), String> {
    let members = vec![instance::<K>(1, id == 205), instance::<K>(2, id == 205)];
    let b = Batch {
        id: 3,
        instances: &members,
    };
    let tables = vec![vec![vec![K::from_i64(3), K::from_i64(5)]]; 2];
    let points = vec![(vec![K::from_i64(0)], K::from_i64(3)); 2];
    let claims = stele_sumcheck::claim_batch::Batch {
        id: 3,
        tensor: 11,
        num_vars: 1,
        claims: &points,
    };
    if claim_mode && id == 205 {
        // The claims at zero survive a change to y[1]; the final y(r) must still be closed.
        return check_control(
            &tables[0][0],
            &ChangeEntry,
            |table| claims.prove(table.clone(), &mut transcript()),
            |proof| {
                claims
                    .verify_public(proof, &tables[0][0], &mut transcript())
                    .map(|_| ())
            },
            Error::ClaimMismatch,
        )
        .map_err(|e| format!("{e:?}"));
    }
    let next = instance::<K>(4, false);
    let honest = || -> Result<Vec<Proof<K>>, Error> {
        let mut t = transcript();
        let first = if claim_mode {
            claims.prove(tables[0][0].clone(), &mut t)?
        } else {
            b.prove(tables.clone(), &mut t)?
        };
        let mut proofs = vec![first];
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
        t.absorb(
            AbsorbLabel::Batch,
            &if claim_mode {
                claims.encode()?
            } else {
                b.encode()?
            },
        )?;
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
        let _ = if claim_mode {
            claims.verify_public(&proofs[0], &tables[0][0], &mut t)?
        } else {
            b.verify_public(&proofs[0], &tables, &mut t)?
        };
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
/// Execute both modes/fields; NC-0205 checks each public claim consumer.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id, false)?;
    check::<OM31>(id, false)?;
    check::<QM31>(id, true)?;
    check::<OM31>(id, true)?;
    Ok(())
}
#[test]
fn rejects_batch_binding_tampers() {
    for id in [202, 206, 205, 802] {
        run(id).expect("exact rejection, both fields");
    }
}
