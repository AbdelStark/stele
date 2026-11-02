//! RFC-0024 §6: complete accepted baseline, one encoded K value, actual rejection.
use crate::{check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::{
    byte_range, integer_linear as linear, lookup, matmul,
    requant::{EmbeddedSchema, Format},
};

const LIMITS: lookup::Limits = lookup::Limits {
    positions: 1 << 16,
    public_bytes: 64 << 20,
    proof_bytes: 64 << 20,
};
const MATMUL: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 16,
    partial_entries: 1 << 16,
    axis_entries: 0,
};
struct Cell {
    at: usize,
    value: Vec<u8>,
}
impl ProverHook<Vec<u8>> for Cell {
    fn tamper(&self, wire: &mut Vec<u8>) {
        let before = wire.clone();
        let end = self.at + self.value.len();
        assert_ne!(&before[self.at..end], &self.value);
        wire[self.at..end].copy_from_slice(&self.value);
        assert_eq!(&wire[..self.at], &before[..self.at]);
        assert_eq!(&wire[end..], &before[end..]);
        assert_eq!(wire.len(), before.len());
    }
}
/// Execute the specified new binding in both fields and both repetition counts.
pub fn run(id: u16) -> Result<(), String> {
    run_field::<QM31>(id)?;
    run_field::<OM31>(id)
}
fn run_field<K: ChallengeField + CodeField + lookup::TableField + Eq + core::fmt::Debug>(
    id: u16,
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    for repetitions in 1..=2 {
        let x = [M31::from_i64(125)];
        let w = [M31::from_i64(126)];
        let px = PreparedSource::<K>::new(101, 0, 0, 1, &x, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let pw = PreparedSource::<K>::new(102, 0, 0, 2, &w, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let cx = verify_certificate(
            *px.source(),
            &px.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let cw = verify_certificate(
            *pw.source(),
            &pw.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let dx = byte_range::Descriptor::new(&cx, 9, &[111, 112][..repetitions], LIMITS)
            .expect("valid fixed fixture");
        let dw = byte_range::Descriptor::new(&cw, 10, &[121, 122][..repetitions], LIMITS)
            .expect("valid fixed fixture");
        let range = |d: &byte_range::Descriptor<'_, K>, p: &PreparedSource<'_, K>| {
            d.prove(
                p,
                lookup::ProducerLimits {
                    public_bytes: d.producer_public_bytes().expect("valid fixed fixture"),
                    dense_elements: d.producer_dense_elements().expect("valid fixed fixture"),
                },
            )
            .expect("valid fixed fixture")
            .0
        };
        let rx = range(&dx, &px);
        let rw = range(&dw, &pw);
        let mx = dx
            .register_multiplicities(&rx, usize::MAX)
            .expect("valid fixed fixture")
            .0;
        let mw = dw
            .register_multiplicities(&rw, usize::MAX)
            .expect("valid fixed fixture")
            .0;
        let mxr: Vec<_> = mx.iter().collect();
        let mwr: Vec<_> = mw.iter().collect();
        let xr = dx.verify(&mxr, &rx).expect("valid fixed fixture");
        let wr = dw.verify(&mwr, &rw).expect("valid fixed fixture");
        let schema = EmbeddedSchema::new(0, 1, 1, Format::Int8).expect("valid fixed fixture");
        let witness = schema.witness(&[6], 1 << 16).expect("valid fixed fixture");
        let pa = PreparedSource::<K>::new(
            (31u64 << 40) + 2,
            schema.rows().ilog2() as u8,
            0,
            1,
            witness.advice(),
            &mut HashUsage::default(),
        )
        .expect("valid fixed fixture");
        let certificate = pa.certificate().expect("valid fixed fixture").0;
        let ca = verify_certificate(*pa.source(), &certificate)
            .expect("valid fixed fixture")
            .0;
        let d = linear::Descriptor::new(
            linear::Statement {
                stage: 31,
                bits: [0; 4],
                mantissa: 1,
                shift: 1,
                format: Format::Int8,
                repetitions: repetitions as u8,
                advice_blowup: 1,
                point: &[],
                value: K::from_i64(3),
                originals: [&xr, &wr],
            },
            &ca,
            LIMITS,
            MATMUL,
        )
        .expect("valid fixed fixture");
        let transcript =
            || Transcript::<K>::new(b"RFC0024/complete-control/v1").expect("valid fixed fixture");
        let produce = || {
            d.prove(
                &mut transcript(),
                [&px, &pw],
                &pa,
                &certificate,
                linear::ProducerLimits {
                    public_bytes: d.producer_public_bytes().expect("valid fixed fixture"),
                    dense_elements: d.producer_dense_elements().expect("valid fixed fixture"),
                    retained_row_entries: d.retained_row_entries(),
                },
            )
        };
        let honest = produce().map_err(|f| format!("honest producer:{f:?}"))?.0;
        let mu = d
            .register_multiplicities(&honest, usize::MAX)
            .expect("valid fixed fixture")
            .0;
        let refs: Vec<_> = mu.iter().collect();
        let width = core::mem::size_of::<K>();
        let suffix = 1
            + 3 * width
            + px.source()
                .proof_size(ProofKind::Opening)
                .expect("valid fixed fixture")
            + pw.source()
                .proof_size(ProofKind::Opening)
                .expect("valid fixed fixture");
        let start = honest.len() - suffix;
        let (at, value, expected) = match id {
            316 => {
                let q = schema.semantic().values()[2].value().len();
                let zero_end = start
                    - 3 * pa
                        .source()
                        .proof_size(ProofKind::Opening)
                        .expect("valid fixed fixture")
                    - width * (q + 2);
                let zero_start = zero_end - width * (schema.rows() + 1);
                let ordinal = 1 + schema.semantic().allocated_rows() + 7;
                assert_eq!(
                    &honest[zero_start + ordinal * width..zero_start + (ordinal + 1) * width],
                    K::from_i64(0).to_le_bytes().as_ref()
                );
                (
                    zero_start + ordinal * width,
                    K::from_i64(1),
                    linear::Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
                )
            }
            317 => (
                start + 1,
                K::from_i64(-2),
                linear::Error::Matmul(matmul::Error::Stacked(stacked::Error::Sumcheck(
                    stele_sumcheck::Error::FinalEvaluationMismatch,
                ))),
            ),
            318 => (
                start + 1 + 3 * width + 1,
                K::from_i64(-3),
                linear::Error::Matmul(matmul::Error::Pcs(stele_pcs::Error::ValueMismatch)),
            ),
            _ => return Err(format!("unknown integer-linear control {id}")),
        };
        check_proof_control(
            // The actual producer already ran above so its mu packets could be imported.
            || Ok::<_, core::convert::Infallible>(honest.clone()),
            &Cell {
                at,
                value: value.to_le_bytes().as_ref().to_vec(),
            },
            |proof| {
                let mut t = transcript();
                d.verify(&mut t, &refs, proof).map(|_| ()).map_err(|f| {
                    assert_eq!(f.usage.transcript, t.usage());
                    if id == 318 {
                        let original_hashes: u64 = [px.source(), pw.source()]
                            .iter()
                            .map(|s| {
                                u64::from(s.queries(ProofKind::Opening))
                                    * (1 + s.path_height() as u64)
                            })
                            .sum();
                        assert_eq!(
                            f.usage.non_transcript.hash_evaluations,
                            d.max_local_hashes() - original_hashes
                        );
                    }
                    f.cause
                })
            },
            expected,
        )
        .map_err(|e| {
            format!(
                "NC-{id:04}, K{}, r{repetitions}: {e:?}",
                <K as CodeField>::DEGREE
            )
        })?;
    }
    Ok(())
}
