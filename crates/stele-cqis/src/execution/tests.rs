//! RFC-0025 execution: fixed absolute blocks, static admission and boundary fixtures.
use super::{Error, Executor, Request};
use crate::model::{Model, Preparation, Scales};

pub(super) struct Fixture {
    pub model: Model,
    pub scales: Scales,
    pub preparation: &'static [u8],
    pub artifact: &'static [u8],
}
impl Fixture {
    pub fn new(name: &str) -> Self {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/execution-boundaries.json"
        ))
        .expect("fixture");
        let case = &corpus["cases"][name];
        let bytes = |name: &str| {
            let span = &case[name];
            let start = span["offset"].as_u64().expect("offset") as usize;
            let length = span["length"].as_u64().expect("length") as usize;
            &include_bytes!("../../tests/fixtures/execution-boundaries.bin")[start..start + length]
        };
        let model = Model::decode(bytes("model")).expect("Model");
        let scales = Scales::decode(&model, bytes("scales")).expect("Scales");
        Self {
            model,
            scales,
            preparation: bytes("preparation"),
            artifact: bytes("artifact"),
        }
    }
    pub fn executor(&self) -> Result<Executor<'_>, Error> {
        self.with_budget(1 << 30)
    }
    pub fn with_budget(&self, budget: u64) -> Result<Executor<'_>, Error> {
        let preparation = Preparation::decode(&self.model, self.preparation).expect("Preparation");
        Executor::new(
            &self.model,
            &preparation,
            &self.scales,
            self.artifact,
            blake3::hash(self.artifact).as_bytes(),
            budget,
        )
    }
}

#[test]
fn matches_reference_signed_absolute_blocks_and_masked_suffixes() {
    for name in ["blocks", "exact"] {
        let fixture = Fixture::new(name);
        let mut executor = fixture.executor().expect("static full-1024 admission");
        let q = executor.quantisers[0][1].convert_wide(&[0, 0]).expect("Q");
        for sign in [-1, 1] {
            let keys: alloc::vec::Vec<_> = (0..2048)
                .map(|j| {
                    let k = executor.quantisers[0][2].convert_wide(&[0, 0]).expect("K");
                    let value = sign * if j == 1024 { 100 } else { 1 };
                    let v = executor.quantisers[0][3]
                        .convert_wide(&[value, value])
                        .expect("V");
                    (k, v)
                })
                .collect();
            for position in [1, 1023, 1024] {
                let actual = executor.attend(0, &q, position, &keys).expect("attention");
                assert_eq!(
                    actual,
                    executor
                        .attend(0, &q, position, &keys[..=position])
                        .expect("causal prefix")
                );
                let expected = if name == "exact" {
                    sign
                } else if position >= 1023 {
                    2 * sign
                } else {
                    0
                };
                assert_eq!(actual, [expected; 2]);
            }
        }
    }
}

#[test]
fn rejects_static_overflow_before_short_zero_execution_and_capacity() {
    for name in ["score_overflow", "block_overflow"] {
        assert!(matches!(
            Fixture::new(name).executor(),
            Err(Error::Bounds(_))
        ));
    }
    assert!(matches!(
        Fixture::new("early_failure").with_budget(0),
        Err(Error::Capacity)
    ));
}

#[test]
fn rejects_request_framing_prompt_and_stop_substitutions() {
    let fixture = Fixture::new("early_failure");
    let m = &fixture.model;
    let good = Request::new(m, 1, 1, &[1], None).expect("request");
    for (prompt, maximum, eos) in [
        (0, 1, &[1][..]),
        (1, 3, &[1][..]),
        (1, 1, &[][..]),
        (1, 1, &[1, 1][..]),
        (1, 1, &[1, 0][..]),
    ] {
        assert_eq!(
            Request::new(m, prompt, maximum, eos, None),
            Err(Error::Request)
        );
    }
    let raw = good.encode().expect("encode");
    assert_eq!(
        Request::decode(m, &raw[..raw.len() - 1]),
        Err(Error::Request)
    );
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(Request::decode(m, &trailing), Err(Error::Request));
    assert_eq!(
        good.check_completion(m, &[0], &[1, 1], 1),
        Err(Error::Prefix)
    );
    assert_eq!(good.check_completion(m, &[0], &[0, 1], 0), Err(Error::Stop));
    assert_eq!(good.check_completion(m, &[0], &[0], 0), Err(Error::Stop));
    assert_eq!(good.check_completion(m, &[1], &[1, 1], 1), Ok(()));
    let mut executor = fixture.executor().expect("executor");
    let logits = alloc::vec![0; m.shape().vocabulary() as usize];
    assert!(matches!(
        executor.choose(&good, &[0], &[1], &logits, None),
        Err(Error::Prefix)
    ));
    assert!(matches!(
        executor.choose(&good, &[0], &[0], &logits[1..], None),
        Err(Error::Logits)
    ));
}

#[test]
fn matches_reference_twelve_thousand_rotated_rows_and_unrotated_tails() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/rotary-execution.json"))
            .expect("corpus");
    let mut count = 0;
    for group in corpus["groups"].as_array().expect("groups") {
        let bytes = |name: &str| {
            let start = group[name]["offset"].as_u64().expect("offset") as usize;
            let length = group[name]["length"].as_u64().expect("length") as usize;
            &include_bytes!("../../tests/fixtures/rotary-execution.bin")[start..start + length]
        };
        let model = Model::decode(bytes("model")).expect("Model");
        let fixture = Fixture {
            scales: Scales::decode(&model, bytes("scales")).expect("Scales"),
            model,
            preparation: bytes("preparation"),
            artifact: bytes("artifact"),
        };
        let mut executor = fixture.executor().expect("executor");
        let mut state = group["seed"].as_u64().expect("seed");
        let mut word = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 32) as u32
        };
        let mut digest = blake3::Hasher::new();
        let mut accepted = 0;
        let total = group["count"].as_u64().expect("count");
        count += total;
        for _ in 0..total {
            let position = word() % 64;
            let values: alloc::vec::Vec<_> = (0..fixture.model.shape().width())
                .map(|_| ((word() % 65536) as i32 - 32768) as i16)
                .collect();
            digest.update(&position.to_le_bytes());
            for value in &values {
                digest.update(&value.to_le_bytes());
            }
            match executor.rotate(
                fixture.model.blocks()[0].rotation(),
                &values,
                position as usize,
                fixture.model.shape().heads(),
            ) {
                Err(Error::Range) => {
                    digest.update(&[0]);
                }
                Ok(values) => {
                    accepted += 1;
                    digest.update(&[1]);
                    for value in values {
                        digest.update(&value.to_le_bytes());
                    }
                }
                other => assert!(other.is_ok(), "unexpected rejection: {other:?}"),
            }
        }
        assert_eq!(accepted, group["accepted"].as_u64().expect("accepted"));
        assert_eq!(
            digest.finalize().to_hex().as_str(),
            group["digest"].as_str().expect("digest")
        );
    }
    assert_eq!(count, 12000);
}
