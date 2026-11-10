//! RFC-0012 A17 — proof-of-work nonce: independent Python vectors, rejections and work counts.
use super::*;
use serde_json::Value;
use std::vec::Vec;

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex fixture");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex byte"))
        .collect()
}
fn start<K: ChallengeField>(message: &[u8]) -> Transcript<K> {
    let mut t = Transcript::<K>::new(b"synthetic public input; not a proof").expect("public input");
    t.absorb(AbsorbLabel::Round, message).expect("message");
    t
}
fn vector<K: ChallengeField>(record: &Value) {
    let events = record["events"].as_array().expect("events");
    let mut prover = start::<K>(b"grinding round");
    let mut verifier = start::<K>(b"grinding round");
    assert_eq!(prover.state.as_slice(), bytes(&events[0]["state_hex"]));
    for event in &events[1..] {
        let bits = u8::try_from(event["bits"].as_u64().expect("bits")).expect("small");
        let nonce = prover.grind(bits).expect("prover finds the least nonce");
        assert_eq!(nonce, event["nonce"].as_u64().expect("nonce"));
        verifier
            .verify_grind(bits, nonce)
            .expect("verifier accepts");
        for t in [&mut prover, &mut verifier] {
            let value = t.challenge(ChallengeLabel::Sumcheck).expect("challenge");
            assert_eq!(value.to_le_bytes().as_ref(), bytes(&event["challenge_hex"]));
            assert_eq!(t.state.as_slice(), bytes(&event["state_hex"]));
        }
    }
}
#[test]
fn matches_reference_grind_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("../tests/fixtures/grind.json")).expect("fixture JSON");
    assert_eq!(fixture["spec"], "RFC-0012-A17");
    let vectors = fixture["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 2);
    vector::<QM31>(&vectors[0]);
    vector::<OM31>(&vectors[1]);
}
#[test]
fn rejects_invalid_grind_bits_and_nonce() {
    let mut t = start::<QM31>(b"grinding round");
    let state = t.state;
    for bits in [0, MAX_GRIND_BITS + 1, u8::MAX] {
        assert_eq!(t.verify_grind(bits, 0), Err(Error::InvalidGrindBits));
        assert_eq!(t.grind(bits), Err(Error::InvalidGrindBits));
    }
    let nonce = start::<QM31>(b"grinding round").grind(12).expect("nonce");
    // The prover's nonce is the least valid one: every smaller nonce fails.
    for bad in 0..nonce {
        assert_eq!(t.verify_grind(12, bad), Err(Error::GrindMismatch));
    }
    assert_eq!(t.state, state, "rejections leave the state unchanged");
    t.verify_grind(12, nonce).expect("valid nonce");
    assert_ne!(t.state, state);
}
#[test]
fn matches_reference_grind_usage() {
    let mut t = start::<QM31>(b"grinding round");
    let before = t.usage();
    let nonce = t.grind(8).expect("nonce");
    // nonce+1 PoW hashes that update no state, then one absorb that does.
    assert_eq!(
        t.usage().hash_evaluations - before.hash_evaluations,
        nonce + 2
    );
    assert_eq!(t.usage().state_updates - before.state_updates, 1);
    let mut v = start::<QM31>(b"grinding round");
    let before = v.usage();
    v.verify_grind(8, nonce).expect("valid");
    assert_eq!(v.usage().hash_evaluations - before.hash_evaluations, 2);
    assert_eq!(v.usage().state_updates - before.state_updates, 1);
    if nonce > 0 {
        let mut w = start::<QM31>(b"grinding round");
        let before = w.usage();
        assert_eq!(w.verify_grind(8, 0), Err(Error::GrindMismatch));
        assert_eq!(w.usage().hash_evaluations - before.hash_evaluations, 1);
        assert_eq!(w.usage().state_updates, before.state_updates);
    }
}
