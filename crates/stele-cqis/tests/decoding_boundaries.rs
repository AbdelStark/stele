//! RFC-0025 decoding: maximum vocabulary, empty positive CDF buckets and last position.
use stele_cqis::{
    execution::{Decision, Executor, Request},
    model::{Model, Preparation, Scales},
};

fn hex(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().expect("hex");
    assert!(text.is_ascii() && text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("byte"))
        .collect()
}
fn expand(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    for part in value.as_array().expect("segments") {
        out.extend_from_slice(
            &hex(&part["bytes"]).repeat(part["repeat"].as_u64().expect("repeat") as usize),
        );
    }
    out
}
fn digest(decision: &Decision) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(&decision.position().to_le_bytes());
    hash.update(&decision.token().to_le_bytes());
    hash.update(&(decision.arguments().len() as u32).to_le_bytes());
    for value in decision.arguments() {
        hash.update(&value.to_le_bytes());
    }
    for row in [decision.weights(), decision.order()] {
        hash.update(&(row.len() as u32).to_le_bytes());
        for value in row {
            hash.update(&value.to_le_bytes());
        }
    }
    hash.update(&(decision.cdf().len() as u32).to_le_bytes());
    for value in decision.cdf() {
        hash.update(&value.to_le_bytes());
    }
    hash.update(&[u8::from(decision.draw().is_some())]);
    if let Some(draw) = decision.draw() {
        hash.update(&draw.to_le_bytes());
    }
    hash.finalize().to_hex().to_string()
}

#[test]
fn matches_reference_full_vocabulary_empty_cdf_buckets_and_last_position() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/decoding-boundaries.json")).expect("corpus");
    for case in corpus["cases"].as_array().expect("cases") {
        let model = Model::decode(&hex(&case["model"])).expect("Model");
        let preparation_raw = hex(&case["preparation"]);
        let preparation = Preparation::decode(&model, &preparation_raw).expect("Preparation");
        let scales = Scales::decode(&model, &expand(&case["scales"])).expect("Scales");
        let artifact = expand(&case["artifact"]);
        let identity: [u8; 32] = hex(&case["artifact_id"]).try_into().expect("identity");
        // Host allowance for conservative full-prefix admission. This test uses
        // the ordinary checked numerical API, with complete expanded frames.
        let mut executor = Executor::new(
            &model,
            &preparation,
            &scales,
            &artifact,
            &identity,
            32u64 << 30,
        )
        .expect("complete admission");
        let position = case["position"].as_u64().expect("position") as u32;
        let prompt = vec![0; position as usize];
        let seed: Option<[u8; 32]> =
            (!case["seed"].is_null()).then(|| hex(&case["seed"]).try_into().expect("seed"));
        let request = Request::new(
            &model,
            position,
            1,
            &[model.shape().vocabulary() - 1],
            seed.as_ref().map(Request::commit_seed),
        )
        .expect("request");
        let mut logits = vec![0; model.shape().vocabulary() as usize];
        if seed.is_some() {
            let n = logits.len();
            logits[n - 3..].fill(-10);
        }
        let decision = executor
            .choose(
                &request,
                &prompt,
                &prompt,
                &logits,
                seed.as_ref().map(|s| s.as_slice()),
            )
            .expect("complete vocabulary choice");
        assert_eq!(decision.position(), position);
        assert_eq!(
            u64::from(decision.token()),
            case["token"].as_u64().expect("token")
        );
        assert_eq!(
            digest(&decision),
            case["decision_blake3"].as_str().expect("digest")
        );
        let empty = decision
            .cdf()
            .windows(2)
            .filter(|pair| pair[0] == pair[1])
            .count();
        assert_eq!(
            empty as u64,
            case["empty_cdf_buckets"].as_u64().expect("empty buckets")
        );
        if seed.is_some() {
            assert_eq!(model.shape().vocabulary(), 1 << 20);
            assert_eq!(decision.cdf().last(), Some(&(1u64 << 32)));
            assert_eq!(&decision.weights()[logits.len() - 3..], &[1, 1, 1]);
            assert!(
                decision
                    .weights()
                    .iter()
                    .map(|w| u64::from(*w))
                    .sum::<u64>()
                    > u64::from(u32::MAX)
            );
            assert_eq!(empty, 2);
        } else {
            assert_eq!(position, (1 << 20) - 1);
        }
    }
}
