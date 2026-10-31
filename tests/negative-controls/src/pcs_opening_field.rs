//! RFC-0010 A9 §§4,8: an authenticated noncanonical leaf at the opening consumer.
use crate::{check_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, Transcript};
use stele_pcs::{
    verify_certificate, verify_opening, Error, Failure, Functional, ProofKind, Source, Usage,
    VerifiedCertificate,
};

struct Noncanonical;
impl ProverHook<u32> for Noncanonical {
    fn tamper(&self, leaf: &mut u32) {
        assert_eq!(*leaf, 0);
        *leaf = M31::MODULUS;
    }
}

fn check<K: ChallengeField>(
    source_id: u64,
    opening_id: u64,
    bad_draw: usize,
    certify: impl Fn(Source<K>, &[u8]) -> Result<VerifiedCertificate<K>, Error>,
    verify: impl Fn(
        &mut Transcript<K>,
        &VerifiedCertificate<K>,
        Functional<'_, K>,
        &[u8],
    ) -> Result<Usage, Failure>,
) -> Result<(), String> {
    check_control(
        &0,
        &Noncanonical,
        |leaf| {
            // One semantic leaf changes; rebuild its actual tree and dependent proofs.
            let mut payloads = vec![[0u8; 4]; 1024];
            payloads[0] = leaf.to_le_bytes();
            let descriptor = Source::<K>::new(source_id, 0, 9, 1, [0; 32])?.descriptor();
            let leaves: Vec<_> = payloads.iter().map(|p| p.as_slice()).collect();
            let tree = merkle::Tree::new(descriptor, &leaves).map_err(Error::Merkle)?;
            let source = Source::<K>::new(source_id, 0, 9, 1, tree.root())?;
            let row = vec![0; 512 * 4 * K::DEGREE];
            let mut public = b"stele/v0.1/pcs-certificate/public".to_vec();
            public.extend_from_slice(&source.bytes());
            let mut t = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
            t.absorb(AbsorbLabel::CertificateRow, &row)
                .map_err(Error::Transcript)?;
            let mut certificate = vec![1];
            certificate.extend_from_slice(&row);
            for _ in 0..source.queries(ProofKind::Certificate) {
                let index = t.certificate_column(1024).map_err(Error::Transcript)?;
                if *leaf != 0 {
                    assert_ne!(
                        index, 0,
                        "the genuine certificate never queries the bad leaf"
                    );
                }
                certificate.extend_from_slice(&payloads[index as usize]);
                for sibling in tree.path(index).map_err(Error::Merkle)? {
                    certificate.extend_from_slice(&sibling);
                }
            }
            // No forged handle: the unchanged native verifier must accept all 494 responses.
            let verified = certify(source, &certificate)?;
            let mut t =
                Transcript::<K>::new(b"opening authenticated field").map_err(Error::Transcript)?;
            let mut frame = opening_id.to_le_bytes().to_vec();
            frame.extend_from_slice(&source.bytes());
            frame.extend_from_slice(&verified.record().id());
            frame.extend_from_slice(K::from_i64(0).to_le_bytes().as_ref()); // a=[0]
            frame.extend_from_slice(&row); // b=[0; 512]
            frame.extend_from_slice(K::from_i64(0).to_le_bytes().as_ref()); // v=0
            t.absorb(AbsorbLabel::Opening, &frame)
                .map_err(Error::Transcript)?;
            t.absorb(AbsorbLabel::OpeningRow, &row)
                .map_err(Error::Transcript)?;
            let mut proof = vec![1];
            proof.extend_from_slice(&row);
            let mut first_bad = None;
            for draw in 0..source.queries(ProofKind::Opening) {
                let index = t.opening_column(1024).map_err(Error::Transcript)?;
                if index == 0 && first_bad.is_none() {
                    first_bad = Some(usize::from(draw));
                }
                proof.extend_from_slice(&payloads[index as usize]);
                for sibling in tree.path(index).map_err(Error::Merkle)? {
                    proof.extend_from_slice(&sibling);
                }
            }
            if *leaf != 0 {
                assert_eq!(first_bad, Some(bad_draw));
            }
            Ok::<_, Error>((verified, proof, *leaf))
        },
        |(certificate, proof, leaf)| {
            let mut t =
                Transcript::<K>::new(b"opening authenticated field").map_err(Error::Transcript)?;
            let a = [K::from_i64(0)];
            let b = vec![K::from_i64(0); 512];
            let result = verify(
                &mut t,
                certificate,
                Functional {
                    id: opening_id,
                    a: &a,
                    b: &b,
                    value: K::from_i64(0),
                },
                proof,
            );
            if *leaf != 0 {
                let failure = result
                    .as_ref()
                    .expect_err("authenticated p rejects even with a=0");
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    ((bad_draw + 1) * 11) as u64
                );
            }
            result.map(|_| ()).map_err(|e| e.cause)
        },
        Error::NoncanonicalField,
    )
    .map_err(|e| format!("{e:?}"))
}

/// Both actual opening consumers reject after authentication, including zero weights.
pub fn run() -> Result<(), String> {
    check::<QM31>(
        43,
        1,
        104,
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|(_, usage)| usage),
    )?;
    check::<OM31>(
        41,
        0,
        25,
        |s, p| {
            verify_certificate(s, p)
                .map(|(c, _)| c)
                .map_err(|e| e.cause)
        },
        |t, c, f, p| verify_opening(t, c, f, p).map(|(_, usage)| usage),
    )
}
