//! RFC-0025 execution: every residual/logit/cache byte from independent small models.
use stele_cqis::{
    execution::{Error, Executor, Request},
    model::{Model, Preparation, Scales},
};

fn bytes(span: &serde_json::Value) -> &'static [u8] {
    let raw = include_bytes!("fixtures/model-execution.bin");
    let offset = span["offset"].as_u64().expect("offset") as usize;
    let length = span["length"].as_u64().expect("length") as usize;
    &raw[offset..offset + length]
}
fn hex32(s: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("digest"))
}

#[test]
fn matches_reference_full_rows_and_every_cached_step() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/model-execution.json")).expect("fixtures");
    for case in fixtures["cases"].as_array().expect("cases") {
        let model = Model::decode(bytes(&case["model"])).expect("Model");
        let prep = Preparation::decode(&model, bytes(&case["preparation"])).expect("Preparation");
        let scales = Scales::decode(&model, bytes(&case["scales"])).expect("Scales");
        let expected = hex32(case["artifact_id"].as_str().expect("Artifact id"));
        let mut executor = Executor::new(
            &model,
            &prep,
            &scales,
            bytes(&case["artifact"]),
            &expected,
            1 << 30,
        )
        .expect("complete load");
        let tokens: Vec<_> = case["tokens"]
            .as_array()
            .expect("tokens")
            .iter()
            .map(|v| v.as_u64().expect("token") as u32)
            .collect();
        let full = executor.full(&tokens);
        if let Some(reason) = case["expected"].as_str() {
            let error = full.expect_err("oracle rejection");
            let expected = match reason {
                "Range" => Some(Error::Range),
                "RowRange" => Some(Error::Row(stele_cqis::row::Error::Range)),
                "ExpDomain" => Some(Error::ExpDomain),
                _ => None,
            };
            assert_eq!(Some(error), expected, "known oracle rejection");
            continue;
        }
        let full = full.expect("complete evaluation");
        let cuts: Vec<_> = full
            .cuts()
            .iter()
            .flatten()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let logits: Vec<_> = full
            .logits()
            .iter()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(cuts, bytes(&case["expected"]["cuts"]));
        assert_eq!(logits, bytes(&case["expected"]["logits"]));
        let mut state = None;
        for (position, token) in tokens.iter().enumerate() {
            let (step, cache) = executor
                .step(*token, state.as_ref())
                .expect("cached evaluation");
            for (layer, row) in step.cuts().iter().enumerate() {
                assert_eq!(*row, full.cuts()[layer][position]);
            }
            assert_eq!(step.logits(), full.logits()[position]);
            state = Some(cache);
        }
        assert_eq!(state.as_ref(), Some(full.cache()));
        let cache_bytes: Vec<_> = full
            .cache()
            .layers()
            .iter()
            .flatten()
            .flat_map(|(k, v)| [k, v])
            .flat_map(|row| {
                let mut raw = row.scale().to_le_bytes().to_vec();
                raw.push(row.fraction());
                raw.extend(row.codes().iter().map(|v| *v as u8));
                raw
            })
            .collect();
        assert_eq!(cache_bytes, bytes(&case["expected"]["cache"]));
        for generation in case["generations"].as_array().expect("generations") {
            let request = Request::decode(&model, bytes(&generation["request"])).expect("request");
            assert_eq!(
                request.encode().expect("request bytes"),
                bytes(&generation["request"])
            );
            let prompt: Vec<_> = generation["prompt"]
                .as_array()
                .expect("prompt")
                .iter()
                .map(|t| t.as_u64().expect("token") as u32)
                .collect();
            let seed = generation["seed"].as_str().map(hex32);
            let result = executor.generate(&request, &prompt, seed.as_ref().map(|s| &s[..]));
            if generation["expected"].is_string() {
                assert!(result.is_err());
            } else {
                let result = result.expect("complete generation");
                let expected: Vec<_> = generation["expected"]["tokens"]
                    .as_array()
                    .expect("tokens")
                    .iter()
                    .map(|t| t.as_u64().expect("token") as u32)
                    .collect();
                assert_eq!(result.cache().tokens(), expected);
                assert_eq!(
                    u64::from(result.reason()),
                    generation["expected"]["reason"].as_u64().expect("reason")
                );
                let replay = executor
                    .full(&expected)
                    .expect("every returned token including EOS");
                assert_eq!(result.cache(), replay.cache());
            }
            if let Some(mut seed) = seed {
                seed[0] ^= 1;
                assert_eq!(
                    executor
                        .generate(&request, &prompt, Some(&seed))
                        .expect_err("seed binding even at zero limit"),
                    Error::Seed
                );
            } else {
                assert_eq!(
                    executor
                        .generate(&request, &prompt, Some(&[0; 32]))
                        .expect_err("inactive seed"),
                    Error::Seed
                );
            }
        }
        assert_eq!(executor.full(&[]).expect_err("empty"), Error::Length);
        assert_eq!(
            executor
                .step(model.shape().vocabulary(), None)
                .expect_err("token"),
            Error::Token
        );
        assert_eq!(
            executor
                .step(0, Some(full.cache()))
                .expect_err("full cache"),
            Error::Length
        );
        let mut wrong = expected;
        wrong[0] ^= 1;
        assert!(matches!(
            Executor::new(
                &model,
                &prep,
                &scales,
                bytes(&case["artifact"]),
                &wrong,
                1 << 30
            ),
            Err(Error::Model(stele_cqis::model::Error::Identity))
        ));
    }
}
