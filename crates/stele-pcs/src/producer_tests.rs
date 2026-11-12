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
            &source.bytes()[..],
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
/// RFC-0013 A8 item 4: a policy-2 hiding certificate's grinding nonces are the least
/// passing ones. The verifier's transcript is replayed and, at each grind round, every
/// smaller nonce is checked to fail (a failed check leaves the state unchanged).
#[test]
fn matches_reference_least_nonces_on_policy_two_hiding_certificate() {
    let (ell, m, id, seed) = (3u8, 9u8, 41u64, [9u8; 32]);
    let x: Vec<M31> = (0..1usize << (ell + m))
        .map(|i| M31::from_i64(i as i64 % 251 - 125))
        .collect();
    let message = crate::hiding_message(id, ell, m, &x, &seed).expect("message");
    let prepared = PreparedSource::<QM31>::hiding_with(
        id,
        ell,
        m,
        2,
        &message,
        &seed,
        &mut HashUsage::default(),
        crate::Policy::Two,
    )
    .expect("prepare");
    let (proof, _) = prepared.certificate().expect("certificate");
    let source = prepared.source();
    let (tensor_bits, column_bits) = source.grind_bits(ProofKind::Certificate);
    assert!(column_bits > 0, "policy 2 grinds the column round");
    let nonce_at = |at: usize| u64::from_le_bytes(proof[at..at + 8].try_into().expect("nonce"));
    let least = |t: &mut Transcript<QM31>, bits: u8, nonce: u64| {
        for smaller in 0..nonce {
            assert_eq!(
                t.verify_grind(bits, smaller),
                Err(stele_hash::Error::GrindMismatch)
            );
        }
        t.verify_grind(bits, nonce)
            .expect("the proof's nonce passes");
    };
    let mut t = transcript(source).expect("transcript");
    let mut at = 1;
    if tensor_bits > 0 {
        least(&mut t, tensor_bits, nonce_at(at));
        at += 8;
    }
    for _ in 0..source.rows().trailing_zeros() {
        t.challenge(ChallengeLabel::CertificateWeight)
            .expect("weight");
    }
    let row = source.columns() * 16; // QM31 row values, 16 bytes each
    t.absorb(AbsorbLabel::CertificateRow, &proof[at..at + row])
        .expect("row");
    least(&mut t, column_bits, nonce_at(at + row));
}
