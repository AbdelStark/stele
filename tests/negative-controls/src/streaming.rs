//! RFC-0006 A6: actual source substitution and proof-artifact ProverHook path.
use crate::{
    check_proof_control,
    sumcheck::{transcript, Change},
};
use std::{
    fs,
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use stele_field::{OM31, QM31};
use stele_hash::ChallengeField;
use stele_sumcheck::{
    file::{prepare, FileSource},
    prove_into, verify_public, Error, Instance, Proof, Streaming,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn proof<K: ChallengeField + Eq>(i: &Instance<K>, path: &Path) -> Result<Proof<K>, Error>
where
    K::Bytes: AsMut<[u8]>,
{
    let source = FileSource::<K>::open(i, &[path])?;
    let n = Streaming::<K, FileSource<K>>::workspace_len(i, &[1, 1])?;
    let mut state = Streaming::new(i, source, &[1, 1], vec![K::from_i64(0); n], n)?;
    let mut output = Proof {
        rounds: vec![vec![K::from_i64(0)]; 3],
        final_values: vec![K::from_i64(0)],
    };
    prove_into(i, &mut state, &mut output, &mut [0; 128], &mut transcript())?;
    Ok(output)
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    K::Bytes: AsMut<[u8]>,
{
    let dir = std::env::temp_dir().join(format!(
        "stele-nc0210-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).map_err(|_| "control directory creation failed")?;
    let result = (|| -> Result<(), String> {
        let original = vec![vec![K::from_i64(0); 8]];
        let i = Instance {
            id: 210,
            num_vars: 3,
            inputs: vec![11],
            terms: vec![],
            claimed_sum: K::from_i64(0),
        };
        let input = dir.join("original");
        let source = dir.join("prepared");
        fs::write(&input, vec![0u8; 8 * 4 * K::DEGREE]).map_err(|_| "fixture write failed")?;
        prepare::<K>(&input, &source, 3).map_err(|e| format!("preparation {e:?}"))?;
        let baseline = proof(&i, &source).map_err(|e| format!("honest prover {e:?}"))?;
        let verify = |proofs: &Vec<Proof<K>>| -> Result<(), Error> {
            if proofs.len() != 1 {
                return Err(Error::ProofShape);
            }
            let _ = verify_public(&i, &proofs[0], &original, &mut transcript())?;
            Ok(())
        };
        verify(&vec![baseline.clone()]).map_err(|e| format!("honest consumer {e:?}"))?;
        // Exactly one prepared record changes; original file/table and descriptor stay fixed.
        fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .and_then(|mut f| f.write_all(K::from_i64(1).to_le_bytes().as_ref()))
            .map_err(|_| "source mutation failed")?;
        let bytes = fs::read(&source).map_err(|_| "source inspection failed")?;
        assert_eq!(
            &bytes[..4 * K::DEGREE],
            K::from_i64(1).to_le_bytes().as_ref()
        );
        assert!(bytes[4 * K::DEGREE..].iter().all(|b| *b == 0));
        assert!(fs::read(&input)
            .map_err(|_| "original inspection failed")?
            .iter()
            .all(|b| *b == 0));
        let forged = proof(&i, &source).map_err(|e| format!("changed-source prover {e:?}"))?;
        assert_eq!(baseline.rounds, forged.rounds);
        assert_eq!(baseline.final_values.len(), 1);
        assert_eq!(forged.final_values.len(), 1);
        assert_ne!(baseline.final_values, forged.final_values);
        check_proof_control(
            || Ok::<_, Error>(vec![baseline.clone()]),
            &Change {
                round: false,
                value: forged.final_values[0],
            },
            verify,
            Error::ClaimMismatch,
        )
        .map_err(|e| format!("{e:?}"))
    })();
    fs::remove_dir_all(&dir).map_err(|_| "control directory cleanup failed")?;
    result
}
/// Execute the real source/prover/consumer control in both challenge fields.
pub fn run() -> Result<(), String> {
    check::<QM31>()?;
    check::<OM31>()
}
