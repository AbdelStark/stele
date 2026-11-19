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

/// RFC-0018 A1, A2: a development record is an inference record on a `dev/` workload,
/// with a Rust verifier time, no Python verifier time, and a valid `model_config.rung`.
#[test]
fn accepts_development_record_without_python_verifier() {
    let mut value: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    value["profile"] = "development".into();
    value["workload"] = "dev/stories42m-t64".into();
    value["verifier_time_ns"] = serde_json::json!({"rust":1,"python":0});
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
    value["model_config"]["statement"] =
        serde_json::json!({"model":"ab","T":"64","tokens":"1,2","checked":"0..64"});
    // Post-E17-02 development records require `model_config.rung` (RFC-0018 A2).
    assert_eq!(
        validate_ledger(value.to_string().as_bytes()),
        Err("development record requires model_config.rung".into())
    );
    value["model_config"]["rung"] = "L99".into();
    assert_eq!(
        validate_ledger(value.to_string().as_bytes()),
        Err("unknown ladder rung in model_config.rung".into())
    );
    value["model_config"]["rung"] = "L2a".into();
    assert_eq!(validate_ledger(value.to_string().as_bytes()), Ok(()));
    for (key, replacement) in [
        ("verifier_time_ns", serde_json::json!({"rust":1,"python":1})),
        ("verifier_time_ns", serde_json::json!({"rust":0,"python":0})),
        ("workload", "W1".into()),
        ("workload", "dev/".into()),
        ("kind", "micro".into()),
        (
            "controls",
            serde_json::json!({"total":0,"passed":0,"failed":0}),
        ),
        ("proof_size_bytes", 0u64.into()),
        ("model_config", serde_json::json!({"statement":{"T":"64"}})),
    ] {
        let mut mutated = value.clone();
        mutated[key] = replacement;
        assert!(
            validate_ledger(mutated.to_string().as_bytes()).is_err(),
            "invalid {key}"
        );
    }
    // A standard record still needs both verifiers and a W or rung workload.
    value["profile"] = "standard".into();
    assert!(validate_ledger(value.to_string().as_bytes()).is_err());
}

/// RFC-0018 A2 (task E17-02): admit ladder rung IDs L0..L6 on standard/treaty records
/// and in `model_config.rung`, rejecting unknown rung names.
#[test]
fn accepts_ladder_rung_workloads_and_rejects_unknown_rungs() {
    let base: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    for &rung in stele_bench::RUNGS {
        for profile in ["standard", "treaty"] {
            let mut value = base.clone();
            value["profile"] = profile.into();
            value["workload"] = rung.into();
            assert_eq!(
                validate_ledger(value.to_string().as_bytes()),
                Ok(()),
                "profile={profile} rung={rung}"
            );
            value["model_config"]["rung"] = rung.into();
            assert_eq!(
                validate_ledger(value.to_string().as_bytes()),
                Ok(()),
                "profile={profile} model_config.rung={rung}"
            );
        }
    }
    for bad in ["L7", "L2d", "L0a", "l1", ""] {
        let mut value = base.clone();
        value["workload"] = bad.into();
        assert!(validate_ledger(value.to_string().as_bytes()).is_err());
        let mut value = base.clone();
        value["model_config"]["rung"] = bad.into();
        assert!(validate_ledger(value.to_string().as_bytes()).is_err());
    }
    let mut conflict = base.clone();
    conflict["workload"] = "L3a".into();
    conflict["model_config"]["rung"] = "L2a".into();
    assert!(validate_ledger(conflict.to_string().as_bytes()).is_err());

    // RFC-0018 A2 / RFC-0027 §3: W1->L3c, W3->L4, W4..W6->L6; W2/W7/W8 and micro carry no rung.
    for (w, expected_rung) in [
        ("W1", "L3c"),
        ("W3", "L4"),
        ("W4", "L6"),
        ("W5", "L6"),
        ("W6", "L6"),
    ] {
        let mut ok = base.clone();
        ok["workload"] = w.into();
        ok["model_config"]["rung"] = expected_rung.into();
        assert_eq!(validate_ledger(ok.to_string().as_bytes()), Ok(()), "w={w}");
        let mut bad = base.clone();
        bad["workload"] = w.into();
        bad["model_config"]["rung"] = "L0".into();
        assert!(
            validate_ledger(bad.to_string().as_bytes()).is_err(),
            "w={w} with mismatched rung"
        );
    }
    for non_ladder in ["W2", "W7", "W8"] {
        let mut bad = base.clone();
        bad["workload"] = non_ladder.into();
        bad["model_config"]["rung"] = "L3c".into();
        assert!(
            validate_ledger(bad.to_string().as_bytes()).is_err(),
            "non-ladder {non_ladder} must reject model_config.rung"
        );
    }
    let mut micro = base.clone();
    micro["kind"] = "micro".into();
    micro["workload"] = "micro/field-add".into();
    micro["proof_size_bytes"] = 0u64.into();
    micro["verifier_time_ns"] = serde_json::json!({"rust": 0, "python": 0});
    micro["controls"] = serde_json::json!({"total": 0, "passed": 0, "failed": 0});
    micro["model_config"]["rung"] = "L0".into();
    assert!(validate_ledger(micro.to_string().as_bytes()).is_err());
}

/// RFC-0018 A2 (task E17-02): a pre-E17-02 historical development ledger validates without
/// `model_config.rung` by exact BLAKE3 allowlist, and any 1-byte tamper is rejected.
#[test]
fn rejects_tampered_pre_e17_02_allowlisted_ledger_without_rung() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let raw = std::fs::read(root.join("bench/ledger/e16-11-dev-stories42m.json"))
        .expect("read historical pre-E17-02 ledger");
    assert_eq!(validate_ledger(&raw), Ok(()));
    let mut trailing_ws = raw.clone();
    trailing_ws.push(b' ');
    let err = validate_ledger(&trailing_ws).expect_err("trailing space must fail");
    assert_eq!(err, "development record requires model_config.rung");
    let text = String::from_utf8(raw).expect("utf-8");
    let mut parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
    let prev = parsed["prover_time_ns"].as_u64().expect("prover_time_ns");
    parsed["prover_time_ns"] = (prev + 1).into();
    let err = validate_ledger(parsed.to_string().as_bytes()).expect_err("tamper must fail");
    assert_eq!(err, "development record requires model_config.rung");
}

/// RFC-0018 A2, RFC-0027 §3 (task E17-02): `render_scoreboard` rejects invalid ledgers and
/// handles empty/full rung sets, W* standard/treaty rows, micro skipping, privacy tests,
/// profile_byte labels, fallback counters, and missing optional fields.
#[test]
fn rejects_invalid_ledgers_and_renders_scoreboard_edge_cases() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("stele-sb-edge-{}-{nonce}", std::process::id()));

    // 1. Empty directory lists all 11 rungs as missing.
    let empty_dir = dir.join("empty");
    std::fs::create_dir_all(&empty_dir).expect("mkdir empty");
    let empty_md = stele_bench::render_scoreboard(&empty_dir).expect("empty scoreboard");
    assert!(empty_md
        .contains("Rungs with no record: L0, L1, L2a, L2b, L2c, L3a, L3b, L3c, L4, L5, L6."));

    // 2. Invalid ledger cases in --ledger-dir are rejected.
    let base: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    let mut missing_rung_dev = base.clone();
    missing_rung_dev["profile"] = "development".into();
    missing_rung_dev["workload"] = "dev/new-no-rung".into();
    missing_rung_dev["verifier_time_ns"] = serde_json::json!({"rust": 50, "python": 0});
    missing_rung_dev["model_config"]["statement"] =
        serde_json::json!({"model":"ab","T":"16","tokens":"1","checked":"0..16"});
    let mut bad_micro = base.clone();
    bad_micro["kind"] = "micro".into();
    bad_micro["workload"] = "micro/bad".into();
    // leaves nonzero proof_size_bytes -> invalid micro record.
    let invalid_cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "disabled-bindings",
            VALID
                .replace("\"bindings_all_on\": true", "\"bindings_all_on\": false")
                .into_bytes(),
        ),
        ("malformed-json", b"{not valid json".to_vec()),
        ("oversized", vec![b' '; stele_bench::MAX_LEDGER_BYTES + 2]),
        ("invalid-micro", bad_micro.to_string().into_bytes()),
        (
            "dev-missing-rung",
            missing_rung_dev.to_string().into_bytes(),
        ),
    ];
    for (name, bytes) in invalid_cases {
        let bad_dir = dir.join(format!("bad-{name}"));
        std::fs::create_dir_all(&bad_dir).expect("mkdir bad");
        std::fs::write(bad_dir.join("case.json"), bytes).expect("write bad");
        assert!(
            stele_bench::render_scoreboard(&bad_dir).is_err(),
            "expected render_scoreboard failure for {name}"
        );
    }

    // 3. Rich rendering edge cases: all 11 rungs populated, W1->L3c, W3->L4, W4->L6, W8 non-ladder,
    // valid micro skipped, privacy workload, profile_byte 1 & 4, missing/zero/fallback counters.
    let rich_dir = dir.join("rich");
    std::fs::create_dir_all(&rich_dir).expect("mkdir rich");

    let mut valid_micro = base.clone();
    valid_micro["kind"] = "micro".into();
    valid_micro["workload"] = "micro/skipped".into();
    valid_micro["proof_size_bytes"] = 0u64.into();
    valid_micro["verifier_time_ns"] = serde_json::json!({"rust": 0, "python": 0});
    valid_micro["controls"] = serde_json::json!({"total": 0, "passed": 0, "failed": 0});
    std::fs::write(rich_dir.join("00-micro.json"), valid_micro.to_string()).expect("write micro");

    for (fname, workload, profile) in [
        ("01-w1.json", "W1", "standard"),
        ("02-w3.json", "W3", "treaty"),
        ("03-w4.json", "W4", "standard"),
        ("04-w8.json", "W8", "standard"),
    ] {
        let mut r = base.clone();
        r["workload"] = workload.into();
        r["profile"] = profile.into();
        std::fs::write(rich_dir.join(fname), r.to_string()).expect("write W*");
    }

    // Cover remaining rungs L0, L1, L2a, L2b, L2c, L3a, L3b, L5 via development records
    // exercising privacy, profile_byte 1 & 4, fallback counters, zero counters, and missing optionals.
    let dev_specs: &[(&str, &str, &str, Option<u64>, serde_json::Value)] = &[
        (
            "10-l0-privacy.json",
            "dev/privacy-test",
            "L0",
            Some(1),
            serde_json::json!({"stacked_source_cells_padded": 1600, "lookup_ledger_numerator_sum": 3200}),
        ),
        (
            "11-l1-a8.json",
            "dev/a8-run",
            "L1",
            Some(4),
            serde_json::json!({"committed_cells": 0, "lookup_positions": 0, "weight_reads": 2}),
        ),
        (
            "12-l2a.json",
            "dev/s42",
            "L2a",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
        (
            "13-l2b.json",
            "dev/s42-long",
            "L2b",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
        (
            "14-l2c.json",
            "dev/s110",
            "L2c",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
        (
            "15-l3a.json",
            "dev/8b-t64",
            "L3a",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
        (
            "16-l3b.json",
            "dev/8b-t1024",
            "L3b",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
        (
            "17-l5.json",
            "dev/maverick",
            "L5",
            None,
            serde_json::json!({"committed_cells": 1024}),
        ),
    ];
    for (fname, workload, rung, pbyte, counters) in dev_specs {
        let mut r = base.clone();
        r["profile"] = "development".into();
        r["workload"] = (*workload).into();
        r["verifier_time_ns"] = serde_json::json!({"rust": 50, "python": 0});
        r["model_config"]["rung"] = (*rung).into();
        r["model_config"]["statement"] =
            serde_json::json!({"model":"ab","T":"16","tokens":"1","checked":"0..16"});
        if let Some(b) = pbyte {
            r["model_config"]["profile_byte"] = (*b).into();
        }
        r["kernel_counters"] = counters.clone();
        std::fs::write(rich_dir.join(fname), r.to_string()).expect("write dev");
    }

    let md = stele_bench::render_scoreboard(&rich_dir).expect("rich scoreboard");
    assert!(!md.contains("00-micro"), "micro record must be skipped");
    assert!(md.contains("| L3c | standard |"));
    assert!(md.contains("| L4 | treaty |"));
    assert!(md.contains("| L6 | standard |"));
    assert!(md.contains("| W8 | standard |"));
    assert!(
        md.contains("| ? |"),
        "standard/treaty rows display ? for lambda"
    );
    assert!(md.contains("| L0 | development (dev-zk) privacy test, whole-test time |"));
    assert!(
        md.contains("| — |"),
        "missing optional fields and privacy tok/s render as em-dash"
    );
    assert!(md.contains("| L1 | development (dev-zk, A8 sources) |"));
    assert!(
        md.contains("Rungs with no record: ."),
        "all 11 rungs populated leaves no missing rungs: {md}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// RFC-0018 A2, RFC-0027 §3 (task E17-02): `stele-bench scoreboard` generates, writes,
/// and checks `bench/scoreboard.md`, listing every recorded rung and marking rungs with none.
#[test]
fn matches_reference_scoreboard_generation_and_check() {
    use std::process::Command;
    let binary = env!("CARGO_BIN_EXE_stele-bench");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let check_repo = Command::new(binary)
        .current_dir(&root)
        .args(["scoreboard", "--check"])
        .output()
        .expect("run scoreboard --check");
    assert!(
        check_repo.status.success(),
        "{}",
        String::from_utf8_lossy(&check_repo.stderr)
    );

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("stele-sb-{}-{nonce}", std::process::id()));
    let ledgers = dir.join("ledger");
    let out = dir.join("scoreboard.md");
    std::fs::create_dir_all(&ledgers).expect("mkdir");
    let mut rec: serde_json::Value = serde_json::from_str(VALID).expect("fixture JSON");
    rec["profile"] = "development".into();
    rec["workload"] = "dev/synthetic-1layer-t16".into();
    rec["verifier_time_ns"] = serde_json::json!({"rust": 50, "python": 0});
    rec["model_config"]["rung"] = "L0".into();
    rec["model_config"]["threads"] = 8u64.into();
    rec["model_config"]["statement"] =
        serde_json::json!({"model":"ab","T":"16","tokens":"1","checked":"0..16"});
    rec["kernel_counters"]["committed_cells"] = 1600u64.into();
    rec["kernel_counters"]["lookup_positions"] = 3200u64.into();
    rec["kernel_counters"]["weight_reads"] = 4u64.into();
    rec["kernel_counters"]["prove_peak_rss_bytes"] = 250_000_000u64.into();
    std::fs::write(ledgers.join("sample-l0.json"), rec.to_string()).expect("write ledger");

    // Missing file fails --check.
    let missing = Command::new(binary)
        .args(["scoreboard", "--check", "--ledger-dir"])
        .arg(&ledgers)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("check missing");
    assert!(!missing.status.success());

    // --write generates scoreboard listing L0 and marking L1..L6 missing.
    let write = Command::new(binary)
        .args(["scoreboard", "--write", "--ledger-dir"])
        .arg(&ledgers)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("write");
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let text = std::fs::read_to_string(&out).expect("read scoreboard");
    assert!(text.contains("| L0 | development |"));
    assert!(text.contains("Rungs with no record: L1, L2a, L2b, L2c, L3a, L3b, L3c, L4, L5, L6."));

    // Fresh file passes --check.
    let fresh = Command::new(binary)
        .args(["scoreboard", "--check", "--ledger-dir"])
        .arg(&ledgers)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("check fresh");
    assert!(
        fresh.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh.stderr)
    );

    // Tampered file fails --check.
    std::fs::write(&out, format!("{text}extra\n")).expect("tamper");
    let stale = Command::new(binary)
        .args(["scoreboard", "--check", "--ledger-dir"])
        .arg(&ledgers)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("check stale");
    assert!(!stale.status.success());

    // Passing both --write and --check is rejected.
    let both = Command::new(binary)
        .args(["scoreboard", "--write", "--check"])
        .output()
        .expect("both flags");
    assert!(!both.status.success());

    std::fs::remove_dir_all(&dir).ok();
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
