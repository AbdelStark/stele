//! RFC-0018 §1 — benchmark ledger validation; no performance measurement is implied.
#![forbid(unsafe_code)]
mod json;
use serde_json::{Map, Value};

/// Maximum serialized ledger size; validation retains the JSON parser's depth limit.
pub const MAX_LEDGER_BYTES: usize = 1 << 20;

const FIELDS: &[&str] = &[
    "schema_version",
    "kind",
    "workload",
    "commit",
    "toolchain",
    "device",
    "driver",
    "model_config",
    "plan_digest",
    "profile",
    "bindings_all_on",
    "batch_size",
    "prompt_tokens",
    "generated_tokens",
    "prover_time_ns",
    "witness_recompute_ns",
    "stage_times_ns",
    "kernel_counters",
    "proof_size_bytes",
    "verifier_time_ns",
    "controls",
    "note",
];

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let map = value.as_object().ok_or("expected an object")?;
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err("missing or unknown fields".into());
    }
    Ok(map)
}
fn uint(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| "expected an unsigned 64-bit integer".into())
}
fn text(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| "expected a nonempty string".into())
}
fn digest(value: &Value, length: usize) -> Result<(), String> {
    let value = text(value)?;
    if value.len() != length
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid lowercase hexadecimal digest".into());
    }
    Ok(())
}
fn counters(value: &Value) -> Result<Vec<u64>, String> {
    let map = value
        .as_object()
        .filter(|map| !map.is_empty())
        .ok_or("expected nonempty counters")?;
    map.values().map(uint).collect()
}

/// Check RFC-0018 metadata, integer encoding, enabled bindings, and internal consistency.
/// This validates a record's claims, not its measurement provenance or proof soundness.
pub fn validate_ledger(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_LEDGER_BYTES {
        return Err("ledger exceeds byte limit".into());
    }
    let json::IntegerJson(value) =
        serde_json::from_slice(bytes).map_err(|_| "invalid integer JSON or duplicate keys")?;
    object(&value, FIELDS)?;
    if uint(&value["schema_version"])? != 1 {
        return Err("unsupported schema version".into());
    }
    let inference = match text(&value["kind"])? {
        "inference" => true,
        "micro" => false,
        _ => return Err("unknown benchmark kind".into()),
    };
    let workload = text(&value["workload"])?;
    // RFC-0018 A1: a development-profile record is an inference record on a `dev/` workload.
    let development = match text(&value["profile"])? {
        "standard" | "treaty" => false,
        "development" => true,
        _ => return Err("unknown profile".into()),
    };
    if development
        && (!inference || !workload.starts_with("dev/") || workload[4..].trim().is_empty())
    {
        return Err("development record needs an inference dev/ workload".into());
    }
    if inference
        && !development
        && !matches!(
            workload,
            "W1" | "W2" | "W3" | "W4" | "W5" | "W6" | "W7" | "W8"
        )
    {
        return Err("unknown inference workload".into());
    }
    if !inference && (!workload.starts_with("micro/") || workload[6..].trim().is_empty()) {
        return Err("micro workload needs micro/ prefix".into());
    }
    digest(&value["commit"], 40)?;
    digest(&value["plan_digest"], 64)?;
    for key in ["toolchain", "device", "driver", "note"] {
        text(&value[key])?;
    }
    if value["model_config"]
        .as_object()
        .is_none_or(|map| map.is_empty())
    {
        return Err("model_config must be a nonempty object".into());
    }
    // RFC-0018 A1: the statement (model, `T`, tokens, checked range) is in `model_config`.
    if development {
        let statement = &value["model_config"]["statement"];
        for key in ["model", "T", "tokens", "checked"] {
            text(&statement[key])?;
        }
    }
    if value["bindings_all_on"] != Value::Bool(true) {
        return Err("bindings_all_on must be true".into());
    }
    let batch = uint(&value["batch_size"])?;
    let positions = uint(&value["prompt_tokens"])?
        .checked_add(uint(&value["generated_tokens"])?)
        .ok_or("position count overflow")?;
    positions
        .checked_mul(batch)
        .ok_or("batch position count overflow")?;
    let total = uint(&value["prover_time_ns"])?;
    if batch == 0 || total == 0 || (inference && positions == 0) {
        return Err("empty batch, request, or measurement".into());
    }
    if uint(&value["witness_recompute_ns"])? > total
        || counters(&value["stage_times_ns"])?
            .iter()
            .any(|&time| time > total)
    {
        return Err("stage or witness time exceeds inclusive prover time".into());
    }
    counters(&value["kernel_counters"])?;
    object(&value["verifier_time_ns"], &["rust", "python"])?;
    let rust = uint(&value["verifier_time_ns"]["rust"])?;
    let python = uint(&value["verifier_time_ns"]["python"])?;
    let proof_bytes = uint(&value["proof_size_bytes"])?;
    object(&value["controls"], &["total", "passed", "failed"])?;
    let controls = uint(&value["controls"]["total"])?;
    if uint(&value["controls"]["failed"])? != 0 || uint(&value["controls"]["passed"])? != controls {
        return Err("controls failed or summary is inconsistent".into());
    }
    // RFC-0018 A1: RFC-0026 has no Python verifier, so a development record has none.
    if development && python != 0 {
        return Err("development record has no Python verifier".into());
    }
    if inference
        && (controls == 0 || rust == 0 || (python == 0 && !development) || proof_bytes == 0)
    {
        return Err("inference record needs controls, proof bytes, and both verifiers".into());
    }
    if !inference && (controls != 0 || rust != 0 || python != 0 || proof_bytes != 0) {
        return Err("micro record cannot claim inference proof evidence".into());
    }
    Ok(())
}
