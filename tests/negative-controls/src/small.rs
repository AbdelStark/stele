//! RFC-0006 A5: real small-strategy truncation misuse, unchanged original consumer.
use crate::{
    check_proof_control,
    sumcheck::{transcript, Change},
};
use stele_field::{OM31, QM31};
use stele_hash::ChallengeField;
use stele_sumcheck::{prove, verify_public, Dense, Error, Instance, Proof, Small, SmallTable};
fn check<K: ChallengeField + Eq + core::fmt::Debug>() -> Result<(), String> {
    let i = Instance {
        id: 204,
        num_vars: 2,
        inputs: vec![11],
        terms: vec![],
        claimed_sum: K::from_i64(0),
    };
    let original = vec![vec![
        K::from_i64(65536),
        K::from_i64(0),
        K::from_i64(0),
        K::from_i64(0),
    ]];
    let honest = || prove(&i, Dense::new(&i, original.clone())?, &mut transcript());
    let baseline = honest().map_err(|e| format!("{e:?}"))?;
    let truncated = (|| -> Result<Proof<K>, Error> {
        // Malicious adapter only: represent one original out-of-range value as zero.
        prove(
            &i,
            Small::new(&i, vec![SmallTable::Unsigned(vec![0; 4])], 2)?,
            &mut transcript(),
        )
    })()
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(baseline.rounds, truncated.rounds);
    assert_eq!(baseline.final_values.len(), 1);
    assert_eq!(truncated.final_values.len(), 1);
    assert_ne!(baseline.final_values, truncated.final_values);
    let verify = |proofs: &Vec<Proof<K>>| -> Result<(), Error> {
        if proofs.len() != 1 {
            return Err(Error::ProofShape);
        }
        let _ = verify_public(&i, &proofs[0], &original, &mut transcript())?;
        Ok(())
    };
    check_proof_control(
        || honest().map(|p| vec![p]),
        &Change {
            round: false,
            value: truncated.final_values[0],
        },
        verify,
        Error::ClaimMismatch,
    )
    .map_err(|e| format!("{e:?}"))
}
/// Run NC-0204 through both production challenge fields.
pub fn run() -> Result<(), String> {
    check::<QM31>()?;
    check::<OM31>()
}
