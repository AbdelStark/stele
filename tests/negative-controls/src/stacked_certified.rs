//! RFC-0006 A4 §6: unchanged opening bytes reach the actual certified consumers.
use crate::{check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{Claim, Limits, Order, Prepared, Statement},
};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, VerifiedCertificate};
use stele_reductions::{prove_stacked_sources, verify_stacked_sources, StackedError, StackedProof};

const LIMITS: Limits = Limits {
    descriptor_bytes: 100_000,
    proof_bytes: 100_000,
    prepared_entries: 1024,
    partial_entries: 64,
    axis_entries: 16,
};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"certified stacked control").expect("fixture")
}
fn certificate<K: ChallengeField + CodeField>(
    source: &PreparedSource<'_, K>,
) -> VerifiedCertificate<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (bytes, _) = source.certificate().expect("actual certificate producer");
    verify_certificate(*source.source(), &bytes)
        .expect("actual certificate consumer")
        .0
}
fn bind<K: ChallengeField>(t: &mut Transcript<K>, id: u64, c: &VerifiedCertificate<K>) {
    let mut bytes = vec![1, 1];
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&c.record().source().bytes());
    bytes.extend_from_slice(&c.record().id());
    t.absorb(AbsorbLabel::StackSources, &bytes)
        .expect("source frame");
}
struct ChangeFinal<K>(K);
impl<K: ChallengeField + Eq + core::fmt::Debug> ProverHook<StackedProof<K>> for ChangeFinal<K> {
    fn tamper(&self, proof: &mut StackedProof<K>) {
        let before = proof.clone();
        proof.sumcheck.final_values[0] = self.0;
        assert_eq!(before.openings, proof.openings);
        assert_eq!(before.sumcheck.rounds, proof.sumcheck.rounds);
        assert_eq!(
            before
                .sumcheck
                .final_values
                .iter()
                .zip(&proof.sumcheck.final_values)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
    }
}
fn point<K: ChallengeField + CodeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [0, 0, 1, 1].map(M31::from_i64);
    // The PCS row split is zero, deliberately different from the layer width one.
    let source =
        PreparedSource::<K>::new(41, 0, 2, 1, &message, &mut HashUsage::default()).expect("source");
    let c = certificate(&source);
    let s = Statement {
        id: 31,
        axes: &[Axis { bits: 1, real: 2 }; 2],
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
        selectors: &[None, None],
        kind: Kind::Eq,
        source_id: None,
    };
    let produce = || {
        prove_stacked_sources(&mut transcript(), &s, &[&source], &[&c], LIMITS)
            .map(|(proof, _)| proof)
    };
    let honest = produce().map_err(|e| format!("{e:?}"))?;
    let prepared = Prepared::for_certified_sources(&s, LIMITS).expect("statement");
    let mut raw = transcript();
    bind(&mut raw, s.id, &c);
    let (reduction, _) = prepared
        .verify_reduction(&mut raw, &honest.sumcheck)
        .expect("actual stacked kernel");
    // f(x_layer,x_inner)=x_layer; draw-order evaluation incorrectly uses x_inner.
    let replacement = reduction.point[1];
    assert_eq!(honest.sumcheck.final_values[0], reduction.point[0]);
    assert_ne!(replacement, honest.sumcheck.final_values[0]);
    check_proof_control(
        produce,
        &ChangeFinal(replacement),
        |proof| {
            let bytes: Vec<_> = proof.openings.iter().map(Vec::as_slice).collect();
            let mut t = transcript();
            let result = verify_stacked_sources(&mut t, &s, &[&c], &proof.sumcheck, &bytes, LIMITS);
            if proof.sumcheck.final_values[0] == replacement {
                let mut raw = transcript();
                bind(&mut raw, s.id, &c);
                let _ = prepared
                    .verify_reduction(&mut raw, &proof.sumcheck)
                    .expect("A1 and A7 still pass");
                let failure = result.as_ref().err().expect("actual opening rejects");
                assert_eq!(failure.usage.non_transcript, HashUsage::default());
                let mut expected = raw.usage();
                expected.hash_evaluations += 2; // Opening and OpeningRow, then the scalar check.
                expected.state_updates += 2;
                assert_eq!(failure.usage.transcript, expected);
                assert_eq!(expected.column_attempts, 0);
                assert_eq!(failure.usage.transcript, t.usage());
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        StackedError::Pcs(stele_pcs::Error::ValueMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

#[derive(Clone)]
struct Attempt<'a, K: ChallengeField> {
    certificate: &'a VerifiedCertificate<K>,
    proof: StackedProof<K>,
}
impl<K: ChallengeField + Eq> PartialEq for Attempt<'_, K> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.certificate, other.certificate) && self.proof == other.proof
    }
}
struct ChangeCertificate<'a, K: ChallengeField>(&'a VerifiedCertificate<K>);
impl<'a, K: ChallengeField + Eq> ProverHook<Attempt<'a, K>> for ChangeCertificate<'a, K> {
    fn tamper(&self, attempt: &mut Attempt<'a, K>) {
        let before = attempt.proof.clone();
        let old = attempt.certificate.record().source();
        let new = self.0.record().source();
        assert_eq!(old.descriptor().id, new.descriptor().id);
        assert_eq!((old.rows(), old.columns()), (new.rows(), new.columns()));
        assert_ne!(old.root(), new.root());
        // A4 §6 authorizes this one expected-handle substitution. There is no
        // production mode flag or fabricated certificate/receipt in this control.
        attempt.certificate = self.0;
        assert!(before == attempt.proof);
    }
}
fn root<K: ChallengeField + CodeField + Eq + core::fmt::Debug>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let zero = [M31::from_i64(0)];
    let one = [M31::from_i64(1)];
    let a = PreparedSource::<K>::new(41, 0, 0, 1, &zero, &mut HashUsage::default()).expect("A");
    let b = PreparedSource::<K>::new(41, 0, 0, 1, &one, &mut HashUsage::default()).expect("B");
    let ca = certificate(&a);
    let cb = certificate(&b);
    let s = Statement {
        id: 31,
        axes: &[Axis { bits: 0, real: 1 }],
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
        selectors: &[None],
        kind: Kind::Eq,
        source_id: None,
    };
    check_proof_control(
        || {
            prove_stacked_sources(&mut transcript(), &s, &[&a], &[&ca], LIMITS).map(|(proof, _)| {
                Attempt {
                    certificate: &ca,
                    proof,
                }
            })
        },
        &ChangeCertificate(&cb),
        |attempt| {
            let proof = &attempt.proof;
            let mut raw = transcript();
            bind(&mut raw, s.id, attempt.certificate);
            let prepared = Prepared::for_certified_sources(&s, LIMITS).expect("statement");
            let (reduction, _) = prepared
                .verify_reduction(&mut raw, &proof.sumcheck)
                .expect("A1 and A7 pass with either genuine certificate");
            assert_eq!(reduction.claims, [(41, K::from_i64(0))]);
            let bytes: Vec<_> = proof.openings.iter().map(Vec::as_slice).collect();
            let mut t = transcript();
            let result = verify_stacked_sources(
                &mut t,
                &s,
                &[attempt.certificate],
                &proof.sumcheck,
                &bytes,
                LIMITS,
            );
            if core::ptr::eq(attempt.certificate, &cb) {
                let failure = result.as_ref().err().expect("actual path rejects");
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    1 + cb.record().source().path_height() as u64
                );
                assert!(failure.usage.transcript.column_attempts >= 1);
                assert_eq!(failure.usage.transcript, t.usage());
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        StackedError::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch)),
    )
    .map_err(|e| format!("{e:?}"))
}
/// NC-0211: public and certified wrong-coordinate consumers, in both fields.
pub fn run_point() -> Result<(), String> {
    crate::stacked::run_public_original()?;
    point::<QM31>()?;
    point::<OM31>()
}
/// NC-0213: independently verified replacement certificates, in both fields.
pub fn run_root() -> Result<(), String> {
    root::<QM31>()?;
    root::<OM31>()
}
