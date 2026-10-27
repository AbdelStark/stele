//! RFC-0018 §1 — reject disabled bindings and malformed benchmark records.
#![forbid(unsafe_code)]
use stele_bench::validate_ledger;
const VALID: &str = include_str!("fixtures/valid.json");

#[test]
fn accepts_complete_record() {
    assert_eq!(validate_ledger(VALID.as_bytes()), Ok(()));
}

#[test]
fn rejects_disabled_bindings() {
    let text = VALID.replace("\"bindings_all_on\": true", "\"bindings_all_on\": false");
    assert_eq!(
        validate_ledger(text.as_bytes()),
        Err("bindings_all_on must be true".into())
    );
}

#[test]
fn rejects_duplicate_keys_at_any_depth() {
    for text in [
        VALID.replace(
            "\"bindings_all_on\": true",
            "\"bindings_all_on\": false, \"bindings_all_on\": true",
        ),
        VALID.replace(
            "\"synthetic_counter\": 1",
            "\"synthetic_counter\": 0, \"synthetic_counter\": 1",
        ),
        VALID.replace("\"name\":", "\"name\": 0, \"name\":"),
    ] {
        assert!(validate_ledger(text.as_bytes()).is_err());
    }
}

#[test]
fn rejects_missing_unknown_and_invalid_fields() {
    let value: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    for key in value.as_object().expect("object").keys() {
        let mut mutated = value.clone();
        mutated.as_object_mut().expect("object").remove(key);
        assert!(
            validate_ledger(mutated.to_string().as_bytes()).is_err(),
            "missing {key}"
        );
    }
    for (key, replacement) in [
        ("schema_version", "2"),
        ("profile", "\"unknown\""),
        ("kind", "\"unknown\""),
        ("workload", "\"W99\""),
        ("commit", "\"bad\""),
        ("plan_digest", "\"bad\""),
        ("toolchain", "\" \""),
        ("batch_size", "0"),
        ("prompt_tokens", "-1"),
        ("prover_time_ns", "0"),
        ("witness_recompute_ns", "101"),
        ("stage_times_ns", "{\"x\":101}"),
        ("kernel_counters", "{}"),
        ("proof_size_bytes", "0"),
        ("verifier_time_ns", "{\"rust\":0,\"python\":1}"),
        ("controls", "{\"total\":1,\"passed\":0,\"failed\":1}"),
        ("controls", "{\"total\":0,\"passed\":0,\"failed\":0}"),
    ] {
        let mut mutated = value.clone();
        mutated[key] = serde_json::from_str(replacement).expect("mutation JSON");
        assert!(
            validate_ledger(mutated.to_string().as_bytes()).is_err(),
            "invalid {key}"
        );
    }
    let mut mutated = value;
    mutated["unknown"] = serde_json::Value::Bool(true);
    assert!(validate_ledger(mutated.to_string().as_bytes()).is_err());
}

#[test]
fn rejects_invalid_encoding_and_resource_limits() {
    for text in [
        format!("{VALID} null"),
        VALID.replace("100,", "100.0,"),
        VALID.replace("100,", "1e2,"),
        VALID.replace("100,", "18446744073709551616,"),
        format!("{}0{}", "[".repeat(200), "]".repeat(200)),
        " ".repeat(stele_bench::MAX_LEDGER_BYTES + 1),
    ] {
        assert!(validate_ledger(text.as_bytes()).is_err());
    }
    assert!(validate_ledger(&[255]).is_err());
}

#[test]
fn accepts_micro_record_without_inference_evidence() {
    let mut value: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    value["kind"] = "micro".into();
    value["workload"] = "micro/field-mul".into();
    value["proof_size_bytes"] = 0u64.into();
    value["verifier_time_ns"] = serde_json::json!({"rust":0,"python":0});
    value["controls"] = serde_json::json!({"total":0,"passed":0,"failed":0});
    assert_eq!(validate_ledger(value.to_string().as_bytes()), Ok(()));
    value["proof_size_bytes"] = 1u64.into();
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
    value["proof_size_bytes"] = 0u64.into();
    value["workload"] = "micro/".into();
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
    value["workload"] = "micro/field-mul".into();
    value["prompt_tokens"] = u64::MAX.into();
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
}

#[test]
fn matches_reference_documented_required_fields() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema.json")).expect("schema JSON");
    let fixture: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    let required: std::collections::BTreeSet<_> = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|key| key.as_str().expect("field"))
        .collect();
    assert_eq!(
        required,
        fixture
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect()
    );
    assert_eq!(
        required,
        schema["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .map(String::as_str)
            .collect()
    );
}

#[test]
fn rejects_invalid_files_through_cli() {
    use std::process::Command;
    let binary = env!("CARGO_BIN_EXE_stele-bench");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/valid.json");
    assert!(Command::new(binary)
        .args(["ledger", "validate"])
        .arg(&fixture)
        .output()
        .expect("run")
        .status
        .success());
    assert!(!Command::new(binary).output().expect("run").status.success());
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("stele-ledger-{}-{nonce}.json", std::process::id()));
    std::fs::write(
        &path,
        VALID.replace("\"bindings_all_on\": true", "\"bindings_all_on\": false"),
    )
    .expect("fixture");
    let result = Command::new(binary)
        .args(["ledger", "validate"])
        .arg(fixture)
        .arg(&path)
        .output()
        .expect("run");
    std::fs::remove_file(&path).expect("cleanup");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("bindings_all_on must be true"));
    assert!(!Command::new(binary)
        .args(["ledger", "validate"])
        .arg(path)
        .output()
        .expect("run")
        .status
        .success());
}

#[test]
fn rejects_escaped_duplicate_keys_and_batch_overflow() {
    let text = VALID.replace(
        "\"bindings_all_on\": true",
        r#""\u0062indings_all_on": false, "bindings_all_on": true"#,
    );
    assert!(validate_ledger(text.as_bytes()).is_err());
    let mut value: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    value["kernel_counters"]["synthetic_counter"] = u64::MAX.into();
    assert_eq!(validate_ledger(value.to_string().as_bytes()), Ok(()));
    value["prompt_tokens"] = (u64::MAX / 2 + 1).into();
    value["generated_tokens"] = 0u64.into();
    value["batch_size"] = 2u64.into();
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
}
