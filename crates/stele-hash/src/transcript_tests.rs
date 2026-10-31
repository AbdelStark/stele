//! RFC-0012 A1 — byte oracle, decoder boundaries and distribution diagnostics.
use super::*;
use serde_json::Value;
use std::{vec, vec::Vec};
use stele_field::{Field, Serialize};

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex fixture");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex byte"))
        .collect()
}
fn vector<K: ChallengeField>(record: &Value) {
    let events = record["events"].as_array().expect("events");
    let mut t = Transcript::<K>::new(&bytes(&events[0]["public_hex"])).expect("valid public input");
    assert_eq!(t.state.as_slice(), bytes(&events[0]["state_hex"]));
    let mut usage = HashUsage {
        hash_evaluations: 2,
        state_updates: 1,
        ..HashUsage::default()
    };
    assert_eq!(t.usage(), usage);
    for event in &events[1..] {
        usage.hash_evaluations += 1;
        usage.state_updates += 1;
        if event.get("label").is_some() {
            let label = [
                AbsorbLabel::Instance,
                AbsorbLabel::Round,
                AbsorbLabel::Final,
            ]
            .into_iter()
            .find(|label| label.entry().label == event["label"].as_str().expect("label"))
            .expect("registered absorb label");
            t.absorb(label, &bytes(&event["message_hex"]))
                .expect("valid message");
        } else {
            let value = t
                .challenge(ChallengeLabel::Sumcheck)
                .expect("sampling succeeds");
            assert_eq!(value.to_le_bytes().as_ref(), bytes(&event["challenge_hex"]));
            usage.xof_requests += 1;
            usage.xof_bytes += 256;
            usage.candidate_words += event["consumed_words"].as_u64().expect("consumed words");
        }
        assert_eq!(t.state.as_slice(), bytes(&event["state_hex"]));
        assert_eq!(t.usage(), usage);
    }
}
#[test]
fn matches_reference_transcript_vectors() {
    let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/transcript.json"))
        .expect("fixture JSON");
    let vectors = fixture["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 2);
    assert_eq!(vectors[0]["degree"], 4);
    assert_eq!(vectors[1]["degree"], 8);
    vector::<QM31>(&vectors[0]);
    vector::<OM31>(&vectors[1]);
}
fn raw(words: &[u32; 64]) -> [u8; 256] {
    let mut raw = [0; 256];
    for (out, value) in raw.chunks_exact_mut(4).zip(words) {
        out.copy_from_slice(&value.to_le_bytes());
    }
    raw
}
#[test]
fn rejects_noncanonical_candidates_and_exhaustion() {
    let p = M31::MODULUS;
    let mut words = [5; 64];
    words[..10].copy_from_slice(&[p, u32::MAX, 0, 0x80000000, p - 1, 0xfffffffe, 1, 2, 3, 4]);
    let (limbs, consumed) = sample::<OM31>(&raw(&words), &mut HashUsage::default())
        .expect("enough canonical candidates");
    assert_eq!(consumed, 10);
    assert_eq!(
        limbs.map(|v| v.to_i64_signed()),
        [
            Some(0),
            Some(0),
            Some(-1),
            Some(-1),
            Some(1),
            Some(2),
            Some(3),
            Some(4)
        ]
    );
    let mut words = [p; 64];
    assert_eq!(
        sample::<OM31>(&raw(&words), &mut HashUsage::default()),
        Err(Error::SamplingExhausted)
    );
    assert_eq!(
        sample::<QM31>(&raw(&words), &mut HashUsage::default()),
        Err(Error::SamplingExhausted)
    );
    words[56..].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        sample::<OM31>(&raw(&words), &mut HashUsage::default())
            .expect("last allowed word")
            .1,
        64
    );
    words[56] = p;
    assert_eq!(
        sample::<OM31>(&raw(&words), &mut HashUsage::default()),
        Err(Error::SamplingExhausted)
    );
    assert_eq!(
        sample::<QM31>(&raw(&words), &mut HashUsage::default())
            .expect("four coefficients")
            .1,
        61
    );
}
#[test]
fn rejects_empty_public_input() {
    assert!(matches!(
        Transcript::<QM31>::new(&[]),
        Err(Error::EmptyPublicInput)
    ));
    assert!(matches!(
        Transcript::<OM31>::new(&[]),
        Err(Error::EmptyPublicInput)
    ));
}
#[test]
fn matches_reference_state_updates_and_message_binding() {
    let mut t = Transcript::<QM31>::new(b"public").expect("public input");
    let first = t.challenge(ChallengeLabel::Sumcheck).expect("first");
    let second = t.challenge(ChallengeLabel::Sumcheck).expect("second");
    assert_ne!(first.to_le_bytes(), second.to_le_bytes());
    let mut other = Transcript::<OM31>::new(b"public").expect("public input");
    assert_ne!(
        first.to_le_bytes(),
        other
            .challenge(ChallengeLabel::Sumcheck)
            .expect("octic")
            .to_le_bytes()[..16]
    );
    let mut fresh = Transcript::<QM31>::new(b"public").expect("public input");
    fresh.absorb(AbsorbLabel::Round, b"a").expect("round");
    assert_ne!(
        first.to_le_bytes(),
        fresh
            .challenge(ChallengeLabel::Sumcheck)
            .expect("round challenge")
            .to_le_bytes()
    );
    // Framing distinguishes empty messages, binary contents and concatenation boundaries.
    let mut a = Transcript::<QM31>::new(b"public").expect("public");
    let mut b = Transcript::<QM31>::new(b"public").expect("public");
    a.absorb(AbsorbLabel::Final, b"ab").expect("final");
    a.absorb(AbsorbLabel::Round, b"c").expect("round");
    b.absorb(AbsorbLabel::Final, b"a").expect("final");
    b.absorb(AbsorbLabel::Round, b"bc").expect("round");
    assert_ne!(a.state, b.state);
    let old = a.state;
    a.absorb(AbsorbLabel::Round, b"").expect("empty message");
    assert_ne!(a.state, old);
}
fn distribution<K: ChallengeField>() {
    let mut bins = vec![[0usize; 16]; K::DEGREE];
    for i in 0u32..10000 {
        let mut t = Transcript::<K>::new(&i.to_le_bytes()).expect("public input");
        let value = t
            .challenge(ChallengeLabel::Sumcheck)
            .expect("challenge")
            .to_le_bytes();
        for (limb, word) in value.as_ref().chunks_exact(4).enumerate() {
            bins[limb][usize::from(word[0] & 15)] += 1;
            assert!(u32::from_le_bytes(word.try_into().expect("four bytes")) < M31::MODULUS);
        }
    }
    // Fixed diagnostic inputs; this broad gross-bias check does not prove uniformity or soundness.
    for bin in bins.into_iter().flatten() {
        assert!((400..850).contains(&bin), "bucket count {bin}");
    }
}
#[test]
fn matches_reference_challenge_distribution_diagnostic() {
    distribution::<QM31>();
    distribution::<OM31>();
}

#[test]
fn matches_reference_message_order_and_final_absorption() {
    fn challenge(messages: &[(AbsorbLabel, &[u8])]) -> [u8; 32] {
        let mut t = Transcript::<OM31>::new(b"public").expect("public");
        for &(label, bytes) in messages {
            t.absorb(label, bytes).expect("message");
        }
        t.challenge(ChallengeLabel::Sumcheck)
            .expect("challenge")
            .to_le_bytes()
    }
    let round = (AbsorbLabel::Round, b"round".as_slice());
    let final_claim = (AbsorbLabel::Final, b"claim".as_slice());
    let honest = challenge(&[round, final_claim]);
    assert_eq!(honest, challenge(&[round, final_claim]));
    assert_ne!(honest, challenge(&[final_claim, round]));
    assert_ne!(honest, challenge(&[round]));
    assert_ne!(honest, challenge(&[round, (AbsorbLabel::Final, b"clain")]));
    assert_ne!(honest, challenge(&[round, (AbsorbLabel::Round, b"claim")]));
}
