//! RFC-0010 A9 §3: actual production, full-wire parity and final absorption.
use super::*;
use stele_field::{Field, M31, OM31, QM31};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}
fn corpus<K: ChallengeField>() {
    let mut cases = 0;
    for (vector, line) in include_str!("../tests/fixtures/field-wire.jsonl")
        .lines()
        .enumerate()
    {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if v["degree"].as_u64().expect("degree") != K::DEGREE as u64 {
            continue;
        }
        let (ell, m, b) = (
            v["ell"].as_u64().expect("ell") as u8,
            v["m"].as_u64().expect("m") as u8,
            v["blowup"].as_u64().expect("b") as u8,
        );
        let message: Vec<_> = (0..1 << ell)
            .flat_map(|i| (0..1 << m).map(move |j| M31::from_i64((i + 2) * (j + 3))))
            .collect();
        let prepared = PreparedSource::<K>::new(41, ell, m, b, &message, &mut HashUsage::default())
            .expect("prepared");
        let (proof, usage) = prepared.certificate().expect("certificate");
        assert_eq!(proof, unhex(v["certificate"].as_str().expect("proof")));
        assert_eq!(
            prepared.certificate().expect("deterministic"),
            (proof.clone(), usage)
        );
        let (measured, measured_usage, work) = prepared.certificate_measured().expect("measured");
        assert_eq!((&measured, measured_usage), (&proof, usage));
        let source = prepared.source();
        let response = prepared.response(0).expect("actual path capacity");
        let path_bytes = response.siblings.capacity() * core::mem::size_of::<[u8; 32]>();
        assert_eq!(work.proof_bytes, measured.capacity());
        assert_eq!(work.frame_bytes, 0);
        assert!(work.weights_bytes >= source.rows() * core::mem::size_of::<K>());
        assert_eq!(work.path_peak_bytes, path_bytes);
        assert_eq!(
            work.peak_owned_bytes,
            work.proof_bytes + work.weights_bytes.max(path_bytes)
        );
        assert_eq!(work.source_elements, message.len());
        assert_eq!(work.row_values, source.columns());
        assert_eq!(
            work.responses,
            usize::from(source.queries(ProofKind::Certificate))
        );
        assert_eq!(
            work.column_bytes_copied,
            work.responses * response.payload.len()
        );
        assert_eq!(
            work.path_bytes_copied,
            work.responses * source.path_height() * 32
        );
        assert_eq!(
            source.bytes().as_slice(),
            unhex(v["source"].as_str().expect("source"))
        );
        let queries = u64::from(source.queries(ProofKind::Certificate));
        assert!(usage.column_attempts >= queries);
        assert_eq!(usage.xof_requests, u64::from(ell) + usage.column_attempts);
        assert_eq!(usage.hash_evaluations, usage.xof_requests + 4);
        // Exercise the actual production helper, including final response absorption.
        let mut t = transcript(source).expect("transcript");
        assert_eq!(
            produce_inner(&prepared, &mut t, &mut ProverWork::default()).expect("inner"),
            proof
        );
        assert_eq!(t.usage(), usage);
        let expected = include_str!("../tests/fixtures/certificate-continuation.txt")
            .lines()
            .nth(vector)
            .expect("continuation");
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck)
                .expect("continuation")
                .to_le_bytes()
                .as_ref(),
            unhex(expected)
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}
#[test]
fn matches_reference_qm31_certificate_production() {
    corpus::<QM31>();
}
#[test]
fn matches_reference_om31_certificate_production() {
    corpus::<OM31>();
}
