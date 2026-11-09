//! Test-only: the real executor's prefill capture (task E16-03) on every successful
//! `stele-cqis` model-execution fixture, so module tests compare against
//! `Executor::capture` rather than a restatement.
//!
//! The fixture index is JSON; this reads only the fields it needs (byte spans,
//! artifact id, tokens, an `"expected"` rejection) without a JSON dependency.

use alloc::vec::Vec;
use stele_cqis::execution::{Capture, Executor};
use stele_cqis::model::{Model, Preparation, Scales};

const INDEX: &str = include_str!("../../stele-cqis/tests/fixtures/model-execution.json");
const BYTES: &[u8] = include_bytes!("../../stele-cqis/tests/fixtures/model-execution.bin");

/// The text after `"key":` in `case` (the index is compact JSON).
fn after<'a>(case: &'a str, key: &str) -> &'a str {
    let needle = alloc::format!("\"{key}\":");
    let at = case.find(&needle).expect("fixture field");
    &case[at + needle.len()..]
}

fn number(text: &str) -> usize {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .expect("number end");
    text[..end].parse().expect("number")
}

fn span(case: &str, key: &str) -> &'static [u8] {
    let field = after(case, key);
    let offset = number(after(field, "offset"));
    let length = number(after(field, "length"));
    &BYTES[offset..offset + length]
}

/// Every fixture case the executor accepts: its Model and complete capture.
pub(crate) fn captures() -> Vec<(Model, Capture)> {
    let mut all = Vec::new();
    for case in INDEX.split("{\"model\":").skip(1) {
        let case = alloc::format!("\"model\":{case}");
        if after(&case, "expected").starts_with('"') {
            continue;
        }
        let model = Model::decode(span(&case, "model")).expect("Model");
        let preparation = Preparation::decode(&model, span(&case, "preparation")).expect("prep");
        let scales = Scales::decode(&model, span(&case, "scales")).expect("Scales");
        let hex = &after(&case, "artifact_id")[1..65];
        let id: [u8; 32] = core::array::from_fn(|i| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("artifact id")
        });
        let list = after(&case, "tokens");
        let tokens: Vec<u32> = list[1..list.find(']').expect("tokens end")]
            .split(',')
            .map(|t| t.parse().expect("token"))
            .collect();
        let capture = {
            let artifact = span(&case, "artifact");
            let mut executor = Executor::new(&model, &preparation, &scales, artifact, &id, 1 << 30)
                .expect("complete load");
            executor.capture(&tokens).expect("fixture evaluates")
        };
        all.push((model, capture));
    }
    assert!(!all.is_empty(), "no accepted fixture");
    all
}
