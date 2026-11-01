//! RFC-0010 A9 §3: actual certificate verification against independent bytes.
use super::*;
use stele_field::{OM31, QM31};
use stele_hash::{merkle, ChallengeField};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}
fn corpus<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut cases = 0;
    for (vector, line) in include_str!("../tests/fixtures/field-wire.jsonl")
        .lines()
        .enumerate()
    {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if v["degree"].as_u64().expect("degree") != u64::from(<K as CodeField>::DEGREE) {
            continue;
        }
        let (ell, m, b) = (
            v["ell"].as_u64().expect("ell") as u8,
            v["m"].as_u64().expect("m") as u8,
            v["blowup"].as_u64().expect("b") as u8,
        );
        let context = unhex(v["source"].as_str().expect("source"));
        let root: [u8; 32] = context[73..].try_into().expect("root");
        let source = Source::<K>::new(41, ell, m, b, root).expect("source");
        let proof = unhex(v["certificate"].as_str().expect("proof"));
        let (verified, usage) = verify_both(source, &proof).expect("honest certificate");
        let wire = source
            .parse(ProofKind::Certificate, &proof)
            .expect("parsed");
        let mut continuation = transcript(&source).expect("fresh transcript");
        verify_inner(
            &source,
            &proof,
            &wire,
            &mut continuation,
            &mut Default::default(),
            &mut VerifierWork::default(),
        )
        .expect("complete inner verifier");
        let expected = include_str!("../tests/fixtures/certificate-continuation.txt")
            .lines()
            .nth(vector)
            .expect("continuation");
        assert_eq!(
            continuation
                .challenge(ChallengeLabel::Sumcheck)
                .expect("continuation draw")
                .to_le_bytes()
                .as_ref(),
            unhex(expected)
        );
        let record = verified.record();
        assert_eq!(record.source().bytes(), source.bytes());
        assert_eq!(
            record.id().as_slice(),
            unhex(v["certificate_id"].as_str().expect("id"))
        );
        assert_eq!(record.parameters(), source.parameters());
        assert_eq!(record.ell(), ell);
        assert_eq!(record.degree(), <K as CodeField>::DEGREE);
        assert_eq!(record.kind(), ProofKind::Certificate);
        let queries = u64::from(source.queries(ProofKind::Certificate));
        assert_eq!(
            usage.non_transcript.hash_evaluations,
            queries * (1 + source.path_height() as u64) + 1
        );
        assert!(usage.transcript.column_attempts >= queries);
        assert_eq!(
            usage.transcript.xof_requests,
            u64::from(ell) + usage.transcript.column_attempts
        );
        assert_eq!(
            usage.transcript.hash_evaluations,
            usage.transcript.xof_requests + 4
        );
        let (reused, repeated_work) = verify_both(source, &proof).expect("reverified import");
        assert_eq!(reused.record().id(), record.id());
        assert_eq!(reused.record().parameters(), record.parameters());
        assert_eq!(usage, repeated_work);
        let row_end = 1 + 4 * usize::from(<K as CodeField>::DEGREE) * source.columns();
        for offset in (1..row_end).step_by(4) {
            let mut changed = proof.clone();
            changed[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
            let failure = verify_both(source, &changed).err().expect("bad row");
            assert_eq!(failure.cause, Error::NoncanonicalField);
            assert_eq!(failure.usage, Usage::default());
        }
        for changed in [
            proof[..proof.len() - 1].to_vec(),
            [&proof[..], &[0]].concat(),
            [&[2], &proof[1..]].concat(),
        ] {
            let failure = verify_both(source, &changed).err().expect("bad shape");
            assert_eq!(failure.cause, Error::ProofShape);
            assert_eq!(failure.usage, Usage::default());
        }
        let mut changed = proof.clone();
        changed[row_end] ^= 1;
        let failure = verify_both(source, &changed)
            .err()
            .expect("changed imported leaf");
        assert_eq!(failure.cause, Error::Merkle(merkle::Error::RootMismatch));
        assert_eq!(
            failure.usage.non_transcript.hash_evaluations,
            1 + source.path_height() as u64
        );
        assert!(failure.usage.transcript.column_attempts > 0);
        // Authentication must precede canonical decoding, even for a visibly invalid limb.
        changed[row_end..row_end + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        let failure = verify_both(source, &changed)
            .err()
            .expect("unauthenticated limb");
        assert_eq!(failure.cause, Error::Merkle(merkle::Error::RootMismatch));
        assert_eq!(
            failure.usage.non_transcript.hash_evaluations,
            1 + source.path_height() as u64
        );
        let mut late = proof.clone();
        *late.last_mut().expect("last sibling") ^= 1;
        let failure = verify_both(source, &late).err().expect("late path");
        assert_eq!(failure.cause, Error::Merkle(merkle::Error::RootMismatch));
        assert_eq!(
            failure.usage.non_transcript.hash_evaluations,
            queries * (1 + source.path_height() as u64)
        );
        malformed_sweep(source, &proof, row_end);
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        let wrong = Source::<K>::new(41, ell, m, b, wrong_root).expect("different expected root");
        assert_eq!(
            verify_both(wrong, &proof)
                .err()
                .expect("context substitution")
                .cause,
            Error::Merkle(merkle::Error::RootMismatch)
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}
// Exercise both public entry points on every targeted success and rejection.
fn verify_both<K: ChallengeField + CodeField>(
    source: Source<K>,
    proof: &[u8],
) -> Result<(VerifiedCertificate<K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let ordinary = verify_certificate(source, proof);
    let measured = verify_certificate_measured(source, proof);
    match &ordinary {
        Ok((record, usage)) => {
            let (actual, observed, work) = measured.expect("measured accepts");
            assert_eq!(record.record().id(), actual.record().id());
            assert_eq!(
                record.record().source().bytes(),
                actual.record().source().bytes()
            );
            assert_eq!(*usage, observed);
            let wire = source.parse(ProofKind::Certificate, proof).expect("wire");
            let row: Vec<K> = wire
                .row_bytes()
                .chunks_exact(4 * usize::from(<K as CodeField>::DEGREE))
                .map(|b| {
                    K::from_le_bytes(K::Bytes::try_from(b).ok().expect("width")).expect("field")
                })
                .collect();
            let encoded = Encoder::from_code_id(&source.code().code_id())
                .expect("encoder")
                .encode_measured(&row)
                .expect("encoding");
            assert_eq!(work.encoder, encoded.work);
            assert_eq!(
                work.encoded_bytes,
                encoded.values.capacity() * core::mem::size_of::<K>()
            );
            assert!(work.row_bytes >= core::mem::size_of_val(row.as_slice()));
            assert!(work.weights_bytes >= source.rows() * core::mem::size_of::<K>());
            assert_eq!(work.frame_bytes, 0);
            assert_eq!(
                work.peak_owned_bytes,
                work.weights_bytes
                    + work.row_bytes
                    + work.encoder.peak_owned_bytes.max(work.encoded_bytes)
            );
            assert_eq!(
                work.responses,
                usize::from(source.queries(ProofKind::Certificate))
            );
            assert_eq!(
                work.column_bytes_authenticated,
                work.responses * 4 * source.rows()
            );
            assert_eq!(work.column_bytes_decoded, work.column_bytes_authenticated);
            assert_eq!(
                work.path_bytes_copied,
                work.responses * 32 * source.path_height()
            );
            assert_eq!(work.encoded_values_read, work.responses);
        }
        Err(expected) => assert_eq!(*expected, measured.err().expect("measured rejects")),
    }
    ordinary
}

// Bounded deterministic fuzzing covers header, row, payload, path and arbitrary truncations.
fn malformed_sweep<K: ChallengeField + CodeField>(source: Source<K>, proof: &[u8], row_end: usize)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut seed = 0x3141_5926_5358_9793u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let width = 4 * source.rows();
    let path = 32 * source.path_height();
    let stride = width + path;
    for trial in 0..128 {
        let response = next() as usize % usize::from(source.queries(ProofKind::Certificate));
        let offset = match trial % 4 {
            0 => 0,
            1 => 1 + next() as usize % (row_end - 1),
            2 => row_end + response * stride + next() as usize % width,
            _ => row_end + response * stride + width + next() as usize % path,
        };
        let mut changed = proof.to_vec();
        changed[offset] ^= 1 + (next() % 255) as u8;
        assert!(
            verify_certificate(source, &changed).is_err(),
            "mutation {trial} at {offset}"
        );
        let end = next() as usize % proof.len();
        let failure = verify_certificate(source, &proof[..end])
            .err()
            .expect("truncated");
        assert_eq!(failure.cause, Error::ProofShape);
        assert_eq!(failure.usage, Usage::default());
    }
}
#[test]
fn matches_reference_qm31_certificates() {
    corpus::<QM31>();
}
#[test]
fn matches_reference_om31_certificates() {
    corpus::<OM31>();
}
