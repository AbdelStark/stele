//! RFC-0010 A9 §4: native functional/query/context controls, including zero b.
use crate::{check_control, ProverHook};
use stele_field::{Field, OM31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_opening, Error, Failure, Functional, PreparedSource, ProofKind,
    Source, Usage, VerifiedCertificate,
};

#[derive(Clone, PartialEq)]
struct Witness {
    row: u32,
    query: u16,
    certificate: u64,
    value: u32,
}
struct Change(u16);
impl ProverHook<Witness> for Change {
    fn tamper(&self, w: &mut Witness) {
        match self.0 {
            600 => w.row = 7,
            601 | 803 => w.query = self.0,
            606 => w.certificate = 42,
            610 => w.value = 1,
            _ => unreachable!(),
        }
        assert_eq!(
            usize::from(w.row != 6)
                + usize::from(w.query != 0)
                + usize::from(w.certificate != 41)
                + usize::from(w.value != 0),
            1
        );
    }
}
fn check<K: ChallengeField>(
    id: u16,
    certify: impl Fn(Source<K>, &[u8]) -> Result<VerifiedCertificate<K>, Error>,
    verify: impl Fn(
        &mut Transcript<K>,
        &VerifiedCertificate<K>,
        Functional<'_, K>,
        &[u8],
    ) -> Result<Usage, Failure>,
) -> Result<(), String> {
    let expected = match id {
        600 => Error::ColumnMismatch,
        610 => Error::ValueMismatch,
        _ => Error::Merkle(merkle::Error::RootMismatch),
    };
    check_control(
        &Witness {
            row: 6,
            query: 0,
            certificate: 41,
            value: 0,
        },
        &Change(id),
        |w| {
            let message = [stele_field::M31::from_i64(6)];
            let prepared =
                PreparedSource::<K>::new(41, 0, 0, 2, &message, &mut HashUsage::default())?;
            let (proof, _) = prepared.certificate().map_err(|e| e.cause)?;
            let original = certify(*prepared.source(), &proof)?;
            let mut t = Transcript::<K>::new(b"opening control").map_err(Error::Transcript)?;
            let mut frame = 12u64.to_le_bytes().to_vec();
            frame.extend_from_slice(&prepared.source().bytes());
            frame.extend_from_slice(&original.record().id());
            for value in [1, 0, 0] {
                frame.extend_from_slice(K::from_i64(value).to_le_bytes().as_ref());
            }
            t.absorb(AbsorbLabel::Opening, &frame)
                .map_err(Error::Transcript)?;
            let mut stale = Transcript::<K>::new(b"opening control").map_err(Error::Transcript)?;
            stale
                .absorb(AbsorbLabel::Opening, &frame)
                .map_err(Error::Transcript)?;
            let row = K::from_i64(i64::from(w.row)).to_le_bytes();
            t.absorb(AbsorbLabel::OpeningRow, row.as_ref())
                .map_err(Error::Transcript)?;
            let mut opening = vec![1];
            opening.extend_from_slice(row.as_ref());
            let mut changed = false;
            for _ in 0..prepared.source().queries(ProofKind::Opening) {
                let mut index = t.opening_column(4).map_err(Error::Transcript)?;
                let stale_index = stale.opening_column(4).map_err(Error::Transcript)?;
                if !changed && (w.query == 601 || (w.query == 803 && stale_index != index)) {
                    index = if w.query == 601 {
                        index ^ 1
                    } else {
                        stale_index
                    };
                    changed = true;
                }
                let response = prepared.response(index)?;
                opening.extend_from_slice(response.payload);
                for sibling in response.siblings {
                    opening.extend_from_slice(&sibling);
                }
            }
            assert_eq!(changed, w.query != 0);
            let expected = PreparedSource::<K>::new(
                w.certificate,
                0,
                0,
                2,
                &message,
                &mut HashUsage::default(),
            )?;
            let (proof, _) = expected.certificate().map_err(|e| e.cause)?;
            Ok::<_, Error>((certify(*expected.source(), &proof)?, opening, w.value))
        },
        |(certificate, proof, value)| {
            let mut t = Transcript::<K>::new(b"opening control").map_err(Error::Transcript)?;
            let before = t.usage();
            let a = [K::from_i64(1)];
            let b = [K::from_i64(0)];
            let result = verify(
                &mut t,
                certificate,
                Functional {
                    id: 12,
                    a: &a,
                    b: &b,
                    value: K::from_i64(i64::from(*value)),
                },
                proof,
            );
            if id == 610 && *value != 0 {
                let failure = result.as_ref().expect_err("scalar rejects");
                assert_eq!(failure.usage.transcript.xof_requests, before.xof_requests);
                assert_eq!(
                    failure.usage.transcript.column_attempts,
                    before.column_attempts
                );
                assert_eq!(
                    failure.usage.transcript.hash_evaluations,
                    before.hash_evaluations + 2
                );
                assert_eq!(failure.usage.non_transcript, HashUsage::default());
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}
/// Execute the same one-value control against both native challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(
        id,
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|(_, u)| u),
    )?;
    check::<OM31>(
        id,
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|(_, u)| u),
    )
}
