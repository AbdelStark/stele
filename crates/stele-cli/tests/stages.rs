//! RFC-0018 A2 (task E17-01): `stele prove-dev` emits in-process stage nanoseconds
//! and thread-count-independent counters while keeping proof bytes unchanged.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn parse_prefixed(stdout: &str, prefix: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let mut parts = rest.split_whitespace();
            let name = parts.next().expect("metric name");
            let val: u64 = parts
                .next()
                .expect("metric value")
                .parse()
                .expect("unsigned integer");
            assert!(parts.next().is_none(), "trailing tokens on {line}");
            assert!(
                map.insert(name.to_string(), val).is_none(),
                "duplicate metric {name}"
            );
        }
    }
    map
}

fn run_l0(dir: &Path, threads: &str) -> (Vec<u8>, BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../..");
    let extract = Command::new("python3")
        .arg(root.join("research/cqis-model-contract/synthetic_extract.py"))
        .arg(root.join("crates/stele-prover/tests/fixtures"))
        .arg("one-layer")
        .arg(dir)
        .output()
        .expect("extract synthetic fixture");
    assert!(extract.status.success(), "{extract:?}");
    let out = Command::new(env!("CARGO_BIN_EXE_stele"))
        .env("RAYON_NUM_THREADS", threads)
        .args(["prove-dev", "--model"])
        .arg(dir.join("model.bin"))
        .arg("--preparation")
        .arg(dir.join("preparation.bin"))
        .arg("--scales")
        .arg(dir.join("scales.bin"))
        .arg("--artifact")
        .arg(dir.join("artifact.bin"))
        .args(["--tokens", "1", "--length", "16", "--public"])
        .arg(dir.join("public.bin"))
        .arg("--proof")
        .arg(dir.join("proof.bin"))
        .output()
        .expect("run prove-dev");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().last(), Some("PROOF WRITTEN"));
    let stages = parse_prefixed(&stdout, "stage_ns ");
    let counters = parse_prefixed(&stdout, "counter ");
    let proof = std::fs::read(dir.join("proof.bin")).expect("proof bytes");
    (proof, stages, counters)
}

#[test]
fn accepts_l0_cli_stage_timers_and_thread_independent_counters() {
    let base = std::env::temp_dir().join(format!("stele-cli-stages-{}", std::process::id()));
    let dir1 = base.join("t1");
    let dir2 = base.join("t2");
    let (proof1, stages1, counters1) = run_l0(&dir1, "1");
    let (proof2, stages2, counters2) = run_l0(&dir2, "2");
    std::fs::remove_dir_all(&base).ok();

    assert_eq!(
        proof1, proof2,
        "proof bytes must be thread-count independent"
    );
    assert_eq!(
        counters1, counters2,
        "counters must be thread-count independent"
    );
    for stage in [
        "model_commitment",
        "witness",
        "plain_check",
        "plan",
        "commitment",
        "multiplicities",
        "zerochecks",
        "lookups",
        "reductions",
        "openings",
    ] {
        assert!(stages1.contains_key(stage), "missing stage {stage}");
        assert!(stages2.contains_key(stage), "missing stage {stage}");
    }
    for counter in [
        "committed_cells",
        "stacked_source_cells_padded",
        "lookup_positions",
        "proof_section_groups_bytes",
        "proof_section_multiplicities_bytes",
        "proof_section_identities_bytes",
        "proof_section_lookups_bytes",
        "proof_section_matmuls_bytes",
        "proof_section_openings_bytes",
        "weight_reads",
        "weight_elements_read",
    ] {
        assert!(counters1.contains_key(counter), "missing counter {counter}");
    }
    // Development-tier weights currently undergo 5 physical passes: materialising the
    // virtual matmul accumulators (RFC-0028 §2.1, task E18-05), Step 3 Range counts,
    // Step 5 Range originals, the Step 2.4 contraction reduction, and Step 7 model opening.
    assert_eq!(counters1["weight_reads"], 5);
    let per_check_sum: u64 = counters1
        .iter()
        .filter(|(k, _)| k.starts_with("lookup_positions_check_"))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(per_check_sum, counters1["lookup_positions"]);
}
