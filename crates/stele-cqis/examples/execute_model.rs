//! RFC-0025 §2/execution: full original-Artifact numerical qualification adapter.
//! Binary output is for exact local comparison; logs contain no weights/activations.
#![forbid(unsafe_code)]
use std::{
    env,
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};
use stele_cqis::{
    execution::{Cache, Decision, Executor, Full, Request},
    model::{Model, Preparation, Scales},
};

fn frame(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    if length > limit {
        return Err("frame exceeds explicit host allowance".into());
    }
    let length = usize::try_from(length).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(length).map_err(|e| e.to_string())?;
    raw.resize(length, 0);
    file.read_exact(&mut raw).map_err(|e| e.to_string())?;
    if file.read(&mut [0]).map_err(|e| e.to_string())? != 0 {
        return Err("file changed length".into());
    }
    Ok(raw)
}
fn hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err("hex encoding".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn tokens(value: &serde_json::Value) -> Result<Vec<u32>, String> {
    value
        .as_array()
        .ok_or("token array")?
        .iter()
        .map(|t| {
            t.as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or("u32 token".into())
        })
        .collect()
}
fn result<T, E: core::fmt::Debug>(value: Result<T, E>) -> Result<T, String> {
    value.map_err(|e| format!("{e:?}"))
}
fn bytes(out: &mut impl Write, raw: &[u8]) -> Result<(), String> {
    out.write_all(raw).map_err(|e| e.to_string())
}
fn word(out: &mut impl Write, v: usize) -> Result<(), String> {
    bytes(
        out,
        &u32::try_from(v).map_err(|e| e.to_string())?.to_le_bytes(),
    )
}
fn cache(out: &mut impl Write, c: &Cache) -> Result<(), String> {
    word(out, c.tokens().len())?;
    for t in c.tokens() {
        bytes(out, &t.to_le_bytes())?;
    }
    for layer in c.layers() {
        for (k, v) in layer {
            for row in [k, v] {
                bytes(out, &row.scale().to_le_bytes())?;
                bytes(out, &[row.fraction()])?;
                for chunk in row.codes().chunks(65536) {
                    let mut buffer = [0u8; 65536];
                    for (a, b) in buffer.iter_mut().zip(chunk) {
                        *a = *b as u8;
                    }
                    bytes(out, &buffer[..chunk.len()])?;
                }
            }
        }
    }
    Ok(())
}
fn full(out: &mut impl Write, f: &Full) -> Result<(), String> {
    for cut in f.cuts() {
        for row in cut {
            for v in row {
                bytes(out, &v.to_le_bytes())?;
            }
        }
    }
    for row in f.logits() {
        for v in row {
            bytes(out, &v.to_le_bytes())?;
        }
    }
    cache(out, f.cache())
}
fn decision(out: &mut impl Write, d: &Decision) -> Result<(), String> {
    bytes(out, &d.position().to_le_bytes())?;
    bytes(out, &d.token().to_le_bytes())?;
    word(out, d.arguments().len())?;
    for v in d.arguments() {
        bytes(out, &v.to_le_bytes())?;
    }
    word(out, d.weights().len())?;
    for v in d.weights() {
        bytes(out, &v.to_le_bytes())?;
    }
    word(out, d.order().len())?;
    for v in d.order() {
        bytes(out, &v.to_le_bytes())?;
    }
    word(out, d.cdf().len())?;
    for v in d.cdf() {
        bytes(out, &v.to_le_bytes())?;
    }
    bytes(out, &[u8::from(d.draw().is_some())])?;
    if let Some(v) = d.draw() {
        bytes(out, &v.to_le_bytes())?;
    }
    Ok(())
}
fn main() -> Result<(), String> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: execute_model PREPARED_DIR EXPECTED_ARTIFACT_HEX INPUT_JSON NEW_OUTPUT".into(),
        );
    }
    let directory = Path::new(&args[0]);
    let model_raw = frame(&directory.join("model.bin"), 1 << 20)?;
    let prep_raw = frame(&directory.join("preparation.bin"), 17 << 20)?;
    let scales_raw = frame(&directory.join("scales.bin"), 1 << 26)?;
    let model = result(Model::decode(&model_raw))?;
    let preparation = result(Preparation::decode(&model, &prep_raw))?;
    let scales = result(Scales::decode(&model, &scales_raw))?;
    let artifact = frame(&directory.join("artifact.bin"), 1 << 35)?;
    let expected: [u8; 32] = hex(args[1].to_str().ok_or("expected digest")?)?
        .try_into()
        .map_err(|_| "32-byte digest")?;
    let input: serde_json::Value =
        serde_json::from_slice(&frame(Path::new(&args[2]), 1 << 24)?).map_err(|e| e.to_string())?;
    let object = input.as_object().ok_or("input object")?;
    if object.len() != 4
        || !["tokens", "prompt", "request", "seed"]
            .iter()
            .all(|k| object.contains_key(*k))
    {
        return Err("input fields".into());
    }
    let sequence = tokens(&input["tokens"])?;
    let prompt = tokens(&input["prompt"])?;
    let request_raw = hex(input["request"].as_str().ok_or("request bytes")?)?;
    let request = result(Request::decode(&model, &request_raw))?;
    let seed = if input["seed"].is_null() {
        None
    } else {
        Some(hex(input["seed"].as_str().ok_or("seed bytes")?)?)
    };
    let mut executor = result(Executor::new(
        &model,
        &preparation,
        &scales,
        &artifact,
        &expected,
        8u64 << 30,
    ))?;
    eprintln!("complete Artifact and static execution configuration validated");
    let original = result(executor.full(&sequence))?;
    eprintln!("complete original sequence evaluated");
    let mut state = None;
    for (position, token) in sequence.iter().enumerate() {
        let (step, next) = result(executor.step(*token, state.as_ref()))?;
        if step.logits() != original.logits()[position]
            || step
                .cuts()
                .iter()
                .enumerate()
                .any(|(layer, row)| *row != original.cuts()[layer][position])
        {
            return Err("full/cache row mismatch".into());
        }
        state = Some(next);
    }
    if state.as_ref() != Some(original.cache()) {
        return Err("full/cache K/V mismatch".into());
    }
    eprintln!("every original full/cache row and K/V byte matched");
    let file = File::create_new(Path::new(&args[3])).map_err(|e| e.to_string())?;
    let mut out = BufWriter::new(file);
    bytes(&mut out, b"stele-e504-numerical-v1")?;
    word(&mut out, sequence.len())?;
    full(&mut out, &original)?;
    drop(original);
    drop(state);
    let generated = result(executor.generate(&request, &prompt, seed.as_deref()))?;
    let replay = result(executor.full(generated.cache().tokens()))?;
    if replay.cache() != generated.cache() {
        return Err("generation/full replay mismatch".into());
    }
    bytes(&mut out, &[generated.reason()])?;
    word(&mut out, generated.decisions().len())?;
    for d in generated.decisions() {
        decision(&mut out, d)?;
    }
    word(&mut out, generated.cache().tokens().len())?;
    full(&mut out, &replay)?;
    out.flush().map_err(|e| e.to_string())?;
    out.get_ref().sync_all().map_err(|e| e.to_string())?;
    eprintln!("complete generation, stop cause and final-token full/cache equality validated");
    Ok(())
}
