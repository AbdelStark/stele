//! RFC-0027 §3, RFC-0026 §5 — integration tests for `stele-bench accounting` and
//! static-accounting scoreboard rendering (task E22-01).
#![forbid(unsafe_code)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use stele_bench::accounting::{account_from_files, build_micro_ledger, format_report, LedgerMeta};
use stele_bench::{render_scoreboard, validate_ledger};
use stele_prover::accounting::{
    Accounting, ModuleAccounting, RelationKindAccounting, ShapeSummary,
};
use stele_prover::development::{bundle, prove_window_development_measured, Statement};

const FIXTURE_BIN: &[u8] = include_bytes!("../../stele-prover/tests/fixtures/synthetic-e2e.bin");
const FIXTURE_JSON: &str = include_str!("../../stele-prover/tests/fixtures/synthetic-e2e.json");

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("stele-bench-e22-01-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn write_fixture_case(dir: &Path, case_name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let parsed: Value = serde_json::from_str(FIXTURE_JSON).expect("fixture json");
    let case = parsed["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == case_name)
        .expect("case");
    let slice = |key: &str| {
        let o = case[key]["offset"].as_u64().expect("offset") as usize;
        let l = case[key]["length"].as_u64().expect("length") as usize;
        &FIXTURE_BIN[o..o + l]
    };
    let model = dir.join("model.bin");
    let prep = dir.join("preparation.bin");
    let scales = dir.join("scales.bin");
    let artifact = dir.join("artifact.bin");
    std::fs::write(&model, slice("model")).expect("write model");
    std::fs::write(&prep, slice("preparation")).expect("write prep");
    std::fs::write(&scales, slice("scales")).expect("write scales");
    std::fs::write(&artifact, slice("artifact")).expect("write artifact");
    (model, prep, scales, artifact)
}

#[test]
fn accepts_cli_accounting_and_validates_micro_ledger_round_trip() {
    let dir = temp_dir("cli-roundtrip");
    let (model, prep, scales, artifact) = write_fixture_case(&dir, "one-layer");
    let bin = env!("CARGO_BIN_EXE_stele-bench");

    // 1. Default run without --artifact (placeholder gain widths).
    let out = Command::new(bin)
        .args([
            "accounting",
            "--model",
            model.to_str().expect("utf8"),
            "--scales",
            scales.to_str().expect("utf8"),
            "--length",
            "4",
        ])
        .output()
        .expect("run default");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("exact_gain_widths=false"));
    assert!(stdout.contains("Per module (sorted by committed_cells desc):"));
    assert!(stdout.contains("Per relation kind:"));
    assert!(stdout.contains("Lookup positions by width / table (sorted desc):"));

    // 2. Prefix checked range (checked.end < length -> next = None).
    let out_prefix = Command::new(bin)
        .args([
            "accounting",
            "--model",
            model.to_str().expect("utf8"),
            "--scales",
            scales.to_str().expect("utf8"),
            "--artifact",
            artifact.to_str().expect("utf8"),
            "--length",
            "4",
            "--checked",
            "0..2",
        ])
        .output()
        .expect("run prefix");
    assert!(
        out_prefix.status.success(),
        "{}",
        String::from_utf8_lossy(&out_prefix.stderr)
    );
    assert!(String::from_utf8_lossy(&out_prefix.stdout).contains("exact_gain_widths=true"));

    // 3. --public path produces identical totals to --artifact.
    let (public, stmt, _, report) = prove_window_development_measured(
        &std::fs::read(&model).expect("m"),
        &std::fs::read(&prep).expect("p"),
        &std::fs::read(&scales).expect("s"),
        &std::fs::read(&artifact).expect("a"),
        Statement {
            tokens: vec![1u32],
            start: 0,
            end: 4,
            next: None,
        },
        4,
        3,
    )
    .expect("prove one-layer");
    let public_path = dir.join("public.bin");
    std::fs::write(&public_path, bundle::encode(&public, &stmt)).expect("write public");
    let (acc_art, shape_art, exact_art) =
        account_from_files(&model, &scales, Some(&artifact), None, 4, 0..4).expect("art");
    let (acc_pub, shape_pub, exact_pub) =
        account_from_files(&model, &scales, None, Some(&public_path), 4, 0..4).expect("pub");
    assert!(exact_art && exact_pub);
    assert_eq!(acc_art, acc_pub);
    assert_eq!(shape_art, shape_pub);
    assert_eq!(acc_art.committed_cells, report.engine.committed_cells);
    assert_eq!(acc_art.lookup_positions, report.engine.lookup_positions);
    assert!(format_report(&acc_art, &shape_art, true).contains("committed_cells="));

    // 4. --ledger-out emits a validated micro ledger whose sums balance exactly.
    let ledger_path = dir.join("e22-01-test-l0.json");
    let out_ledger = Command::new(bin)
        .args([
            "accounting",
            "--model",
            model.to_str().expect("utf8"),
            "--scales",
            scales.to_str().expect("utf8"),
            "--public",
            public_path.to_str().expect("utf8"),
            "--length",
            "4",
            "--checked",
            "0..4",
            "--ledger-out",
            ledger_path.to_str().expect("utf8"),
            "--rung",
            "L0",
            "--suffix",
            "l0-test",
            "--name",
            "one-layer (T=4)",
            "--commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--device",
            "test-cpu",
            "--toolchain",
            "rustc 1.90.0",
        ])
        .output()
        .expect("run ledger-out");
    assert!(
        out_ledger.status.success(),
        "{}",
        String::from_utf8_lossy(&out_ledger.stderr)
    );
    let raw = std::fs::read(&ledger_path).expect("read ledger");
    assert_eq!(validate_ledger(&raw), Ok(()));
    let parsed: Value = serde_json::from_slice(&raw).expect("parse");
    let kc = parsed["kernel_counters"].as_object().expect("kc");
    assert_eq!(
        kc["committed_cells"].as_u64(),
        Some(report.engine.committed_cells)
    );
    assert_eq!(
        kc["lookup_positions"].as_u64(),
        Some(report.engine.lookup_positions)
    );
    let per_mod = parsed["model_config"]["per_module"]
        .as_object()
        .expect("per_module");
    let mod_cells_sum: u64 = per_mod
        .values()
        .map(|m| m["committed_cells"].as_u64().expect("cells"))
        .sum();
    let mod_lookups_sum: u64 = per_mod
        .values()
        .map(|m| m["lookup_positions"].as_u64().expect("lookups"))
        .sum();
    assert_eq!(mod_cells_sum, report.engine.committed_cells);
    assert_eq!(mod_lookups_sum, report.engine.lookup_positions);
    assert!(parsed["note"]
        .as_str()
        .expect("note")
        .contains("not a profile admission"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rejects_invalid_cli_accounting_inputs_and_corrupted_artifacts() {
    let dir = temp_dir("cli-reject");
    let (model, _, scales, artifact) = write_fixture_case(&dir, "one-layer");
    let bin = env!("CARGO_BIN_EXE_stele-bench");
    let m = model.to_str().expect("utf8");
    let s = scales.to_str().expect("utf8");
    let a = artifact.to_str().expect("utf8");

    // Truncated artifact fails header/length check.
    let truncated = dir.join("truncated.bin");
    let full = std::fs::read(&artifact).expect("read");
    std::fs::write(&truncated, &full[..full.len() - 1]).expect("write");
    let bad_magic = dir.join("bad_magic.bin");
    let mut corrupted = full;
    corrupted[0] ^= 0xFF;
    std::fs::write(&bad_magic, &corrupted).expect("write");

    let out_json = dir.join("out.json");
    let cases: Vec<Vec<&str>> = vec![
        // Missing required flags.
        vec!["accounting", "--model", m, "--scales", s],
        // Both --artifact and --public.
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--artifact",
            a,
            "--public",
            a,
            "--length",
            "4",
        ],
        // Non-power-of-two length.
        vec!["accounting", "--model", m, "--scales", s, "--length", "3"],
        // Invalid checked ranges.
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--length",
            "4",
            "--checked",
            "bad",
        ],
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--length",
            "4",
            "--checked",
            "3..2",
        ],
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--length",
            "4",
            "--checked",
            "0..8",
        ],
        // Missing input file.
        vec![
            "accounting",
            "--model",
            "/nonexistent/stele-model.bin",
            "--scales",
            s,
            "--length",
            "4",
        ],
        // Corrupted / truncated artifact.
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--artifact",
            truncated.to_str().expect("utf8"),
            "--length",
            "4",
        ],
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--artifact",
            bad_magic.to_str().expect("utf8"),
            "--length",
            "4",
        ],
        // --ledger-out missing required companion flags.
        vec![
            "accounting",
            "--model",
            m,
            "--scales",
            s,
            "--length",
            "4",
            "--ledger-out",
            out_json.to_str().expect("utf8"),
        ],
    ];
    for args in cases {
        let out = Command::new(bin).args(&args).output().expect("run");
        assert!(
            !out.status.success(),
            "expected failure for args {args:?}, stdout={}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rejects_invalid_rung_and_duplicate_sanitized_counter_keys() {
    let shape = ShapeSummary {
        family: 1,
        layers: 1,
        d: 16,
        heads: 2,
        kv_heads: 2,
        head_width: 8,
        hidden: 32,
        vocabulary: 64,
        context: 16,
        wide_residual: false,
    };
    let mut by_module = BTreeMap::new();
    by_module.insert(
        "a/b".to_string(),
        ModuleAccounting {
            committed_cells: 16,
            lookup_positions: 16,
            ..ModuleAccounting::default()
        },
    );
    let acc = Accounting {
        tokens: 4,
        committed_cells: 16,
        lookup_positions: 16,
        weight_cells: 16,
        public_cells: 16,
        witness_columns: 1,
        groups: 1,
        by_module: by_module.clone(),
        by_relation_kind: RelationKindAccounting::default(),
        lookups_by_width: BTreeMap::new(),
        lookups_by_check: vec![("range_8".into(), 16)],
    };
    let bad_meta = LedgerMeta {
        workload_suffix: "bad",
        target_rung: "L99",
        model_name: "bad",
        commit: "0123456789abcdef0123456789abcdef01234567",
        device: "cpu",
        toolchain: "rustc 1.90.0",
        checked_label: "0..4",
        exact_vectors: true,
        elapsed_ns: 100,
        extra_note: "",
    };
    assert!(build_micro_ledger(&acc, &shape, &bad_meta).is_err());

    // Duplicate sanitized module key ("a/b" and "a:b" both sanitize to "a_b").
    by_module.insert(
        "a:b".to_string(),
        ModuleAccounting {
            committed_cells: 16,
            lookup_positions: 16,
            ..ModuleAccounting::default()
        },
    );
    let dup_acc = Accounting {
        by_module,
        committed_cells: 32,
        lookup_positions: 32,
        ..acc
    };
    let ok_meta = LedgerMeta {
        target_rung: "L0",
        ..bad_meta
    };
    let err = build_micro_ledger(&dup_acc, &shape, &ok_meta).expect_err("duplicate key");
    assert!(err.contains("duplicate sanitized counter key"), "{err}");
}

#[test]
fn renders_static_scoreboard_rows_and_rejects_malformed_static_ledgers() {
    let dir = temp_dir("scoreboard-static");
    let shape = ShapeSummary {
        family: 1,
        layers: 1,
        d: 16,
        heads: 2,
        kv_heads: 2,
        head_width: 8,
        hidden: 32,
        vocabulary: 64,
        context: 16,
        wide_residual: false,
    };
    let mut by_module = BTreeMap::new();
    by_module.insert(
        "attention".to_string(),
        ModuleAccounting {
            committed_cells: 640,
            lookup_positions: 320,
            ..ModuleAccounting::default()
        },
    );
    let acc = Accounting {
        tokens: 4,
        committed_cells: 640,
        lookup_positions: 320,
        weight_cells: 16,
        public_cells: 16,
        witness_columns: 2,
        groups: 1,
        by_module,
        by_relation_kind: RelationKindAccounting::default(),
        lookups_by_width: BTreeMap::from([("range:u8".into(), 320)]),
        lookups_by_check: vec![("range_8".into(), 320)],
    };
    let meta = LedgerMeta {
        workload_suffix: "l1-synth",
        target_rung: "L1",
        model_name: "synth (T=4)",
        commit: "0123456789abcdef0123456789abcdef01234567",
        device: "cpu",
        toolchain: "rustc 1.90.0",
        checked_label: "0..4",
        exact_vectors: true,
        elapsed_ns: 500,
        extra_note: "",
    };
    let valid_json = build_micro_ledger(&acc, &shape, &meta).expect("valid ledger");
    let path = dir.join("e22-01-static-accounting-l1-synth.json");
    std::fs::write(&path, &valid_json).expect("write");

    let rendered = render_scoreboard(&dir).expect("render");
    assert!(rendered.contains("## Static Accounting Baselines (RFC-0027 §3, E22-01)"));
    assert!(rendered.contains(
        "| L1 | synth (T=4) | 4 | 640 | 160 | 320 | 80 | attention (160) | attention (80) |"
    ));

    // Missing `top_module_*` renders em-dash fallback cleanly.
    let mut no_top: Value = serde_json::from_str(&valid_json).expect("parse");
    no_top["model_config"]
        .as_object_mut()
        .expect("mc")
        .remove("top_module_cells");
    no_top["model_config"]
        .as_object_mut()
        .expect("mc")
        .remove("top_module_lookups");
    std::fs::write(&path, serde_json::to_string_pretty(&no_top).expect("ser")).expect("write");
    let rendered_no_top = render_scoreboard(&dir).expect("render no_top");
    assert!(rendered_no_top.contains("| 80 | — | — |"));

    // Zero tokens must be rejected (no divide-by-zero).
    let mut zero_tok: Value = serde_json::from_str(&valid_json).expect("parse");
    zero_tok["kernel_counters"]["tokens"] = Value::from(0u64);
    std::fs::write(&path, serde_json::to_string_pretty(&zero_tok).expect("ser")).expect("write");
    assert!(render_scoreboard(&dir).is_err());

    // Missing target_rung must be rejected.
    let mut no_rung: Value = serde_json::from_str(&valid_json).expect("parse");
    no_rung["model_config"]
        .as_object_mut()
        .expect("mc")
        .remove("target_rung");
    std::fs::write(&path, serde_json::to_string_pretty(&no_rung).expect("ser")).expect("write");
    assert!(render_scoreboard(&dir).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}
