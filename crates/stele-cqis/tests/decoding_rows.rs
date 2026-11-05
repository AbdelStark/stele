//! RFC-0025 decoding: full temperature/exp/permutation/CDF/draw composition parity.
use stele_cqis::{
    execution::{Error, Executor, Request},
    model::{Model, Preparation, Scales},
};

struct Words(u64);
impl Words {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
}
fn bytes(span: &serde_json::Value) -> &'static [u8] {
    let raw = include_bytes!("fixtures/decoding-rows.bin");
    let at = span["offset"].as_u64().expect("offset") as usize;
    &raw[at..at + span["length"].as_u64().expect("length") as usize]
}

#[test]
fn matches_reference_ten_thousand_complete_rows_per_decoding_mode() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/decoding-rows.json")).expect("corpus");
    let mut counts = [0; 4];
    for group in corpus["groups"].as_array().expect("groups") {
        let mode = group["mode"].as_i64().expect("mode");
        let model = Model::decode(bytes(&group["model"])).expect("Model");
        let preparation =
            Preparation::decode(&model, bytes(&group["preparation"])).expect("Preparation");
        let scales = Scales::decode(&model, bytes(&group["scales"])).expect("Scales");
        let raw = bytes(&group["artifact"]);
        let identity = *blake3::hash(raw).as_bytes();
        assert_eq!(
            blake3::hash(raw).to_hex().as_str(),
            group["artifact_id"].as_str().expect("identity")
        );
        let mut executor = Executor::new(&model, &preparation, &scales, raw, &identity, 1 << 30)
            .expect("complete admission");
        let mut words = Words(group["seed"].as_u64().expect("seed"));
        let mut digest = blake3::Hasher::new();
        let mut accepted = 0;
        let count = group["count"].as_u64().expect("count");
        counts[(mode + 1) as usize] += count;
        for i in 0..count {
            let mut logits: Vec<_> = (0..model.shape().vocabulary())
                .map(|_| ((words.next() % 65536) as i32 - 32768) as i16)
                .collect();
            if i % 7 == 0 {
                let first = logits[0];
                logits.fill(first);
            }
            if i % 11 == 0 {
                logits.fill(-32768);
                logits[0] = 0;
            }
            let mut seed = [0; 32];
            for word in seed.chunks_exact_mut(4) {
                word.copy_from_slice(&words.next().to_le_bytes());
            }
            let position = 1 + words.next() % 63;
            let eos = model.shape().vocabulary() - 1;
            let mut prefix = vec![0; position as usize];
            prefix[0] = eos; // Prompt EOS is legal; generated EOS would already stop.
            let supplied = (mode >= 0).then_some(seed.as_slice());
            let request = Request::new(
                &model,
                1,
                63,
                &[eos],
                supplied.map(|_| Request::commit_seed(&seed)),
            )
            .expect("request");
            match executor.choose(&request, &[eos], &prefix, &logits, supplied) {
                Err(Error::ExpDomain) => {
                    digest.update(&[0]);
                }
                Ok(decision) => {
                    accepted += 1;
                    digest.update(&[1]);
                    digest.update(&decision.position().to_le_bytes());
                    digest.update(&decision.token().to_le_bytes());
                    digest.update(&(decision.arguments().len() as u32).to_le_bytes());
                    for value in decision.arguments() {
                        digest.update(&value.to_le_bytes());
                    }
                    for values in [decision.weights(), decision.order()] {
                        digest.update(&(values.len() as u32).to_le_bytes());
                        for value in values {
                            digest.update(&value.to_le_bytes());
                        }
                    }
                    digest.update(&(decision.cdf().len() as u32).to_le_bytes());
                    for value in decision.cdf() {
                        digest.update(&value.to_le_bytes());
                    }
                    digest.update(&[u8::from(decision.draw().is_some())]);
                    if let Some(draw) = decision.draw() {
                        digest.update(&draw.to_le_bytes());
                    }
                }
                other => assert!(other.is_ok(), "unexpected rejection {other:?}"),
            }
        }
        assert_eq!(accepted, group["accepted"].as_u64().expect("accepted"));
        assert_eq!(
            digest.finalize().to_hex().as_str(),
            group["digest"].as_str().expect("digest")
        );
    }
    assert_eq!(counts, [10000; 4]);
}
