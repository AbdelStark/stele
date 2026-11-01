//! RFC-0007 A2 §7 controls. Control-only composers; only production verify decides.
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{merkle, ChallengeField, HashUsage};
use stele_pcs::{CodeField, VerifiedCertificate};
use stele_reductions::matmul::{self, Error, Statement};
use stele_sumcheck::Proof;
#[path = "matmul_composer.rs"]
mod composer;
use composer::{Artifact, LIMITS};

fn checked<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    s: &Statement<'_, K>,
    certs: [&VerifiedCertificate<K>; 2],
    artifact: &Artifact<K>,
    side: usize,
    expected: Error,
) -> Result<(), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut t = composer::transcript();
    let result = matmul::verify(&mut t, s, certs, &artifact.wire(), LIMITS);
    match result {
        Ok(_) => Ok(()),
        Err(failure) => {
            // A wrong earlier rejection is a control failure, not the intended evidence.
            assert_eq!(failure.cause, expected);
            let (prefix, mut hashes) = composer::prefix(s, certs, artifact, side);
            assert_eq!(failure.usage.transcript, t.usage());
            if expected == Error::Pcs(stele_pcs::Error::ValueMismatch) {
                let mut exact = prefix.usage();
                exact.hash_evaluations += 2;
                exact.state_updates += 2;
                assert_eq!(failure.usage.transcript, exact); // No affected-source query.
            } else {
                // Both ColumnMismatch and RootMismatch follow exactly one authentic-path attempt.
                hashes.hash_evaluations += 1 + certs[side].record().source().path_height() as u64;
                assert!(failure.usage.transcript.column_attempts > prefix.usage().column_attempts);
            }
            assert_eq!(failure.usage.non_transcript, hashes);
            Err(failure.cause)
        }
    }
}

#[derive(Clone, PartialEq)]
struct RowWitness<K> {
    point: Vec<K>,
    rows: [Vec<K>; 2],
}
struct ChangeRow {
    id: u16,
    side: usize,
    coordinate: usize,
}
impl<K: ChallengeField + Eq> ProverHook<RowWitness<K>> for ChangeRow {
    fn tamper(&self, w: &mut RowWitness<K>) {
        let before = w.clone();
        if self.id == 306 {
            w.point[self.coordinate] = w.point[self.coordinate] + K::from_i64(1);
        } else {
            assert_eq!(self.id, 611);
            w.rows[self.side][0] = w.rows[self.side][0] + K::from_i64(1);
        }
        assert_eq!(
            before
                .point
                .iter()
                .zip(&w.point)
                .filter(|(a, b)| a != b)
                .count()
                + before
                    .rows
                    .iter()
                    .flatten()
                    .zip(w.rows.iter().flatten())
                    .filter(|(a, b)| a != b)
                    .count(),
            1
        );
    }
}
fn row<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    id: u16,
    side: usize,
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bits = [0, 1, 0, 2]; // L=d=1; row-index source => every code column detects the scalar error.
    let (messages, point) = composer::fixture::<K>(bits, side);
    let sources = composer::sources::<K>(bits, &messages);
    let certificates = sources.each_ref().map(composer::certificate);
    let refs = sources.each_ref();
    let certs = certificates.each_ref();
    let s = composer::statement(bits, &point, K::from_i64(0));
    let honest = RowWitness {
        point: point.clone(),
        rows: composer::rows(&s, refs, &point),
    };
    let baseline = composer::honest(&s, refs, certs, &honest.rows);
    assert_eq!(honest.rows[1 - side], vec![K::from_i64(0)]);
    check_control(
        &honest,
        &ChangeRow {
            id,
            side,
            coordinate: if side == 0 { 0 } else { 1 },
        },
        |w| -> Result<_, String> {
            let rows = if id == 306 {
                composer::rows(&s, refs, &w.point)
            } else {
                w.rows.clone()
            };
            assert_eq!(rows[1 - side], honest.rows[1 - side]);
            if w != &honest {
                assert_ne!(rows[side], honest.rows[side]);
            }
            let artifact = composer::produce(&s, refs, certs, &rows).0;
            if w == &honest {
                assert_eq!(artifact, baseline);
            }
            // Reconstructing the real kernel prefix must pass even for the false functional.
            let _ = composer::prefix(&s, certs, &artifact, 0);
            Ok(artifact)
        },
        |p| {
            checked(
                &s,
                certs,
                p,
                side,
                Error::Pcs(stele_pcs::Error::ColumnMismatch),
            )
        },
        Error::Pcs(stele_pcs::Error::ColumnMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

struct ChangeFinal<K> {
    index: usize,
    value: K,
}
impl<K: ChallengeField + Eq> ProverHook<Proof<K>> for ChangeFinal<K> {
    fn tamper(&self, proof: &mut Proof<K>) {
        let before = proof.clone();
        proof.final_values[self.index] = self.value;
        assert!(before.rounds == proof.rounds);
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
fn final_value<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    side: usize,
    stacked_case: bool,
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bits = if stacked_case {
        [1, 1, 1, 2]
    } else {
        [0, 1, 0, 2]
    };
    let (messages, point) = composer::fixture::<K>(bits, side);
    let sources = composer::sources::<K>(bits, &messages);
    let certificates = sources.each_ref().map(composer::certificate);
    let refs = sources.each_ref();
    let certs = certificates.each_ref();
    let s = composer::statement(bits, &point, K::from_i64(0));
    let rows = composer::rows(&s, refs, &point);
    let honest = composer::honest(&s, refs, certs, &rows);
    let replacement = if stacked_case {
        assert_eq!(honest.point.len(), 2);
        assert!(honest
            .point
            .iter()
            .all(|r| *r != K::from_i64(0) && *r != K::from_i64(1)));
        let mut full = composer::outer(&s, &point, side).to_vec();
        full.extend_from_slice(&honest.point);
        assert_eq!(
            composer::original_value(refs[side], &full),
            honest.proof.final_values[side]
        );
        let offset = full.len() - 2;
        full.swap(offset, offset + 1);
        composer::original_value(refs[side], &full)
    } else {
        honest.proof.final_values[side] + K::from_i64(1)
    };
    assert_ne!(replacement, honest.proof.final_values[side]);
    // Witness-first harness: the witness is the already genuine A1 proof.
    // Hook changes ONE final; dependent response bytes are then regenerated.
    check_control(
        &honest.proof,
        &ChangeFinal {
            index: side,
            value: replacement,
        },
        |proof| -> Result<_, String> {
            assert_eq!(proof.rounds, honest.proof.rounds);
            let artifact = composer::rebuild(&s, refs, certs, &rows, proof);
            assert_eq!(artifact.point, honest.point);
            for (i, source) in sources.iter().enumerate() {
                let old = source
                    .source()
                    .parse(stele_pcs::ProofKind::Opening, &honest.openings[i])
                    .expect("honest row");
                let new = source
                    .source()
                    .parse(stele_pcs::ProofKind::Opening, &artifact.openings[i])
                    .expect("rebuilt row");
                assert_eq!(old.row_bytes(), new.row_bytes());
            }
            Ok(artifact)
        },
        |p| {
            checked(
                &s,
                certs,
                p,
                side,
                Error::Pcs(stele_pcs::Error::ValueMismatch),
            )
        },
        Error::Pcs(stele_pcs::Error::ValueMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

#[derive(Clone)]
struct CertificateWitness<'a, K: ChallengeField> {
    certs: [&'a VerifiedCertificate<K>; 2],
}
impl<K: ChallengeField> PartialEq for CertificateWitness<'_, K> {
    fn eq(&self, other: &Self) -> bool {
        self.certs
            .iter()
            .zip(other.certs)
            .all(|(a, b)| core::ptr::eq(*a, b))
    }
}
struct ChangeCertificate<'a, K: ChallengeField> {
    side: usize,
    replacement: &'a VerifiedCertificate<K>,
}
impl<'a, K: ChallengeField> ProverHook<CertificateWitness<'a, K>> for ChangeCertificate<'a, K> {
    fn tamper(&self, w: &mut CertificateWitness<'a, K>) {
        let before = w.certs;
        let old = before[self.side].record().source();
        let new = self.replacement.record().source();
        assert_eq!(old.descriptor().id, new.descriptor().id);
        assert_eq!(
            (old.rows(), old.columns(), old.code().code_id()),
            (new.rows(), new.columns(), new.code().code_id())
        );
        assert_ne!(old.root(), new.root());
        w.certs[self.side] = self.replacement;
        assert_eq!(
            before
                .iter()
                .zip(w.certs)
                .filter(|(a, b)| !core::ptr::eq(**a, *b))
                .count(),
            1
        );
    }
}
fn certificate_swap<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(
    side: usize,
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bits = [0; 4];
    let point = [];
    let original = [vec![M31::from_i64(0)], vec![M31::from_i64(0)]];
    let changed = [vec![M31::from_i64(1)], vec![M31::from_i64(1)]];
    let sources = composer::sources::<K>(bits, &original);
    let replacements = composer::sources::<K>(bits, &changed);
    let certs = sources.each_ref().map(composer::certificate);
    let other = replacements.each_ref().map(composer::certificate);
    let s = composer::statement(bits, &point, K::from_i64(0));
    let refs = sources.each_ref();
    let rows = composer::rows(&s, refs, &point);
    let baseline = composer::honest(&s, refs, certs.each_ref(), &rows);
    check_control(
        &CertificateWitness {
            certs: certs.each_ref(),
        },
        &ChangeCertificate {
            side,
            replacement: &other[side],
        },
        |w| -> Result<_, String> {
            // Exactly one handle was substituted; regenerate dependent responses.
            // Prefix X uses its genuine owner so W cannot be masked by stale X paths.
            // The affected response owner remains the ORIGINAL prepared source.
            let artifact = composer::produce(&s, refs, w.certs, &rows).0;
            assert_eq!(artifact.proof, baseline.proof);
            for (i, source) in sources.iter().enumerate() {
                assert_eq!(
                    source
                        .source()
                        .parse(stele_pcs::ProofKind::Opening, &artifact.openings[i])
                        .expect("new row")
                        .row_bytes(),
                    source
                        .source()
                        .parse(stele_pcs::ProofKind::Opening, &baseline.openings[i])
                        .expect("old row")
                        .row_bytes()
                );
            }
            Ok((w.certs, artifact))
        },
        |(handles, p)| {
            checked(
                &s,
                *handles,
                p,
                side,
                Error::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch)),
            )
        },
        Error::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch)),
    )
    .map_err(|e| format!("{e:?}"))
}

#[derive(Debug, PartialEq)]
enum ChainError {
    Matmul(Error),
    Sumcheck(stele_sumcheck::Error),
}
fn continuation<K: ChallengeField + CodeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let messages = [vec![M31::from_i64(2)], vec![M31::from_i64(3)]];
    let sources = composer::sources::<K>([0; 4], &messages);
    let certificates = sources.each_ref().map(composer::certificate);
    let certs = certificates.each_ref();
    let refs = sources.each_ref();
    let s = composer::statement([0; 4], &[], K::from_i64(6));
    let rows = composer::rows(&s, refs, &[]);
    let artifact = composer::honest(&s, refs, certs, &rows);
    let (same, original_t) = composer::produce(&s, refs, certs, &rows);
    assert_eq!(same, artifact);
    let wire = artifact.wire();
    let _ = matmul::verify(&mut composer::transcript(), &s, certs, &wire, LIMITS)
        .expect("complete closed baseline");
    let next = crate::sumcheck::instance::<K>(901, false);
    let honest = || -> Result<_, String> {
        let (same, mut t) = composer::produce(&s, refs, certs, &rows);
        assert_eq!(same.wire(), wire);
        Ok(vec![
            crate::sumcheck::produce(&next, &mut t).map_err(|e| format!("{e:?}"))?
        ])
    };
    let baseline = honest()?;
    let mut replay = composer::omitted(&s, certs, &artifact, composer::Omit::Nothing);
    assert_eq!(replay.usage(), original_t.usage());
    assert_eq!(
        crate::sumcheck::produce(&next, &mut replay).expect("full replay next"),
        baseline[0]
    );
    for omit in [
        composer::Omit::Statement,
        composer::Omit::Responses(0),
        composer::Omit::Responses(1),
    ] {
        let mut bad = composer::omitted(&s, certs, &artifact, omit);
        let wrong =
            crate::sumcheck::produce(&next, &mut bad).expect("actual omitted-history prover");
        assert_eq!(wrong.rounds, baseline[0].rounds);
        assert_ne!(wrong.final_values[0], baseline[0].final_values[0]);
        check_proof_control(
            honest,
            &crate::sumcheck::Change {
                round: false,
                value: wrong.final_values[0],
            },
            |proofs| {
                let mut t = composer::transcript();
                // The accepted matmul artifact never changes. Only the following final does.
                let (_record, _) = matmul::verify(&mut t, &s, certs, &wire, LIMITS)
                    .map_err(|e| ChainError::Matmul(e.cause))?;
                stele_sumcheck::verify_public(
                    &next,
                    &proofs[0],
                    &[vec![K::from_i64(3), K::from_i64(5)]],
                    &mut t,
                )
                .map(|_| ())
                .map_err(ChainError::Sumcheck)
            },
            ChainError::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
        )
        .map_err(|e| format!("{omit:?}: {e:?}"))?;
    }
    Ok(())
}

struct ChangeCoefficient<K>(K);
impl<K: ChallengeField + Eq> ProverHook<Artifact<K>> for ChangeCoefficient<K> {
    fn tamper(&self, a: &mut Artifact<K>) {
        let before = a.clone();
        ChangeFinal {
            index: 2,
            value: self.0,
        }
        .tamper(&mut a.proof);
        assert_eq!(a.openings, before.openings);
        assert!(a.point == before.point);
    }
}
fn coefficient<K: ChallengeField + CodeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bits = [1, 1, 1, 2];
    let (mut messages, point) = composer::fixture::<K>(bits, 0);
    for values in &mut messages {
        values.fill(M31::from_i64(0));
    }
    let sources = composer::sources::<K>(bits, &messages);
    let certificates = sources.each_ref().map(composer::certificate);
    let certs = certificates.each_ref();
    let refs = sources.each_ref();
    let s = composer::statement(bits, &point, K::from_i64(0));
    let rows = composer::rows(&s, refs, &point);
    let honest = composer::honest(&s, refs, certs, &rows);
    check_proof_control(
        || Ok::<_, String>(honest.clone()),
        &ChangeCoefficient(honest.proof.final_values[2] + K::from_i64(1)),
        |artifact| {
            let mut t = composer::transcript();
            let result = matmul::verify(&mut t, &s, certs, &artifact.wire(), LIMITS);
            if let Err(failure) = &result {
                let mut raw = composer::transcript();
                composer::bind(&mut raw, &s, certs);
                composer::a1_only(&mut raw, &s, &artifact.proof);
                assert_eq!(failure.usage.transcript, raw.usage());
                assert_eq!(failure.usage.non_transcript, HashUsage::default());
                assert_eq!(failure.usage.transcript.column_attempts, 0);
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        Error::Stacked(stacked::Error::CoefficientMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

fn field<K: ChallengeField + CodeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    if id == 802 {
        return continuation::<K>();
    }
    for side in 0..2 {
        match id {
            306 | 611 => row::<K>(id, side)?,
            307 => {
                final_value::<K>(side, false)?;
                final_value::<K>(side, true)?;
            }
            606 => certificate_swap::<K>(side)?,
            _ => return Err(format!("unknown matmul control {id}")),
        }
    }
    Ok(())
}
/// Extend the existing registry entries; do not remove their old consumers.
pub fn run(id: u16) -> Result<(), String> {
    field::<QM31>(id)?;
    field::<OM31>(id)
}
/// Integration assertion for the existing A7 binding; no new catalog credit.
pub fn run_coefficient() -> Result<(), String> {
    coefficient::<QM31>()?;
    coefficient::<OM31>()
}
