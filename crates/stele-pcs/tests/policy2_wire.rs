//! RFC-0010 A14 / RFC-0012 A17 item 5: Policy 2 sources, column and tensor nonces,
//! byte parity with research/merkle-oracle/check_policy2_wire.py.
#![cfg(feature = "standard-unproven")]
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{certificate_id, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_point, Error, Policy, PreparedSource, ProofKind, Source,
};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}

fn element<K: ChallengeField + CodeField>(bytes: &[u8]) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    K::from_le_bytes(K::Bytes::try_from(bytes).ok().expect("width")).expect("canonical")
}

fn nonce(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

fn corpus<K: ChallengeField + CodeField>() -> usize
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut cases = 0;
    for line in include_str!("fixtures/policy2-wire.jsonl").lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if v["degree"].as_u64() != Some(u64::from(<K as CodeField>::DEGREE)) {
            continue;
        }
        let field = |key: &str| v[key].as_u64().expect(key);
        let (ell, m, blowup) = (field("ell") as u8, field("m") as u8, field("blowup") as u8);
        let code = [&b"stele/circle-m31/v1"[..], &[m, blowup]].concat();
        let message: Vec<_> = (0..1i64 << ell)
            .flat_map(|i| (0..1i64 << m).map(move |j| M31::from_i64((i + 2) * (j + 3))))
            .collect();
        let prepared = PreparedSource::<K>::from_code_id_policy(
            41,
            ell,
            &code,
            &message,
            &mut HashUsage::default(),
            Policy::Two,
        )
        .expect("prepare");
        let expected = unhex(v["source"].as_str().expect("source"));
        assert_eq!(&prepared.source().bytes()[..], expected);
        let parsed = Source::<K>::from_bytes(&expected).expect("policy byte 2 is admitted");
        assert_eq!(parsed.parameters().policy, Policy::Two);
        let (tensor_bits, column_bits) = parsed.grind_bits(ProofKind::Certificate);
        assert_eq!(
            (u64::from(tensor_bits), column_bits),
            (field("tensor_bits"), 16)
        );

        let (certificate, _) = prepared.certificate().expect("certificate");
        assert_eq!(certificate.len() as u64, field("certificate_bytes"));
        let tensor = usize::from(tensor_bits > 0);
        if tensor == 1 {
            assert_eq!(nonce(&certificate, 1), field("tensor_nonce"));
        } else {
            assert!(v["tensor_nonce"].is_null());
        }
        let at = 1 + 8 * tensor + parsed.columns() * 4 * usize::from(<K as CodeField>::DEGREE);
        assert_eq!(nonce(&certificate, at), field("certificate_nonce"));
        let (verified, _) = verify_certificate(parsed, &certificate).expect("Policy 2 consumer");
        assert_eq!(
            verified.record().id().to_vec(),
            unhex(v["certificate_id"].as_str().expect("id"))
        );

        let point: Vec<K> = (0..usize::from(ell + m))
            .map(|i| {
                let limbs: Vec<u8> = (0..usize::from(<K as CodeField>::DEGREE))
                    .flat_map(|k| (((i + 1) * (k + 2)) as u32).to_le_bytes())
                    .collect();
                element(&limbs)
            })
            .collect();
        let value: K = element(&unhex(v["value"].as_str().expect("value")));
        let mut prover = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (opening, _) = prepared
            .opening_point(&mut prover, &verified, 12, &point, value)
            .expect("opening");
        assert_eq!(opening.len() as u64, field("opening_bytes"));
        let row = 1 + parsed.columns() * 4 * usize::from(<K as CodeField>::DEGREE);
        assert_eq!(nonce(&opening, row), field("opening_nonce"));
        let mut verifier = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        verify_point(&mut verifier, &verified, 12, &point, value, &opening).expect("opening");
        let digest = certificate_id(&expected, &opening, &mut HashUsage::default()).expect("id");
        assert_eq!(
            digest.to_vec(),
            unhex(v["opening_digest"].as_str().expect("digest"))
        );
        let next = verifier.challenge(ChallengeLabel::Sumcheck).expect("next");
        assert_eq!(
            next.to_le_bytes().as_ref(),
            unhex(v["continuation"].as_str().expect("continuation"))
        );

        // A14 item 8: a missing or extra nonce is ProofShape, before any transcript work.
        let mut short = opening.clone();
        short.drain(row..row + 8);
        let mut fresh = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let failure = verify_point(&mut fresh, &verified, 12, &point, value, &short)
            .err()
            .expect("missing nonce");
        assert_eq!(failure.cause, Error::ProofShape);
        let mut long = certificate.clone();
        long.splice(at..at, [0; 8]);
        let failure = verify_certificate(parsed, &long)
            .err()
            .expect("extra nonce");
        assert_eq!(failure.cause, Error::ProofShape);
        cases += 1;
    }
    cases
}

#[test]
fn matches_reference_qm31_policy2_wire() {
    assert_eq!(corpus::<QM31>(), 2);
}

#[test]
fn matches_reference_om31_policy2_wire() {
    assert_eq!(corpus::<OM31>(), 1);
}

// A14 item 1: Policy 1 sources and proofs are unchanged; only the policy byte differs.
#[test]
fn accepts_policy1_unchanged_beside_policy2() {
    let code = b"stele/circle-m31/v1\x05\x01";
    let one = Source::<QM31>::from_code_id(41, 2, code, [7; 32]).expect("policy 1");
    let two =
        Source::<QM31>::from_code_id_policy(41, 2, code, [7; 32], Policy::Two).expect("policy 2");
    let (b1, b2) = (one.bytes(), two.bytes());
    let differing: Vec<usize> = (0..b1.len()).filter(|&i| b1[i] != b2[i]).collect();
    assert_eq!(differing, [b1.len() - 33]);
    assert_eq!((b1[b1.len() - 33], b2[b2.len() - 33]), (1, 2));
    assert_eq!(one.grind_bits(ProofKind::Certificate), (0, 0));
    assert_eq!(one.queries(ProofKind::Certificate), 478);
    assert_eq!(two.queries(ProofKind::Certificate), 339);
    assert_eq!(two.queries(ProofKind::Opening), 152);
    // Same code and field: Policy 2 adds exactly one 8-byte nonce per column round here.
    let stride = 16 + 32 * 6;
    assert_eq!(
        two.proof_size(ProofKind::Opening),
        Ok(1 + 32 * 16 + 8 + 152 * stride)
    );
    // v2 J = 15 has no A14 entry: the resolver fails closed, so no Policy 2 source.
    assert!(Source::<QM31>::from_code_id_policy(
        41,
        0,
        b"stele/expander-seed/v2\x0f\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07",
        [0; 32],
        Policy::Two
    )
    .is_err());
}
