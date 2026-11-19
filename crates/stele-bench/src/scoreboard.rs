//! RFC-0018 A2, RFC-0027 §3 — scoreboard generator from `bench/ledger/` (task E17-02).
//!
//! Pure integer arithmetic (`u128` round-half-to-even, INV-12: no floats) producing
//! byte-identical Markdown output to `bench/scoreboard.py`.
use crate::json::IntegerJson;
use crate::{validate_ledger, MAX_LEDGER_BYTES};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Ladder rungs in RFC-0027 §3 / RFC-0018 A2 display order.
pub const RUNGS: &[&str] = &[
    "L0", "L1", "L2a", "L2b", "L2c", "L3a", "L3b", "L3c", "L4", "L5", "L6",
];

/// True iff `rung` is a valid RFC-0018 A2 / RFC-0027 §3 ladder rung identifier.
pub fn is_valid_rung(rung: &str) -> bool {
    RUNGS.contains(&rung)
}

/// Canonical RFC-0018 A2 / RFC-0027 §3 ladder rung for a `standard` or `treaty` workload id.
pub fn workload_rung(workload: &str) -> Option<&'static str> {
    match workload {
        "W1" => Some("L3c"),
        "W3" => Some("L4"),
        "W4" | "W5" | "W6" => Some("L6"),
        _ => RUNGS
            .iter()
            .copied()
            .find(|&candidate| candidate == workload),
    }
}

/// Legacy pre-E17-01 workload-to-rung mapping (matches `bench/scoreboard.py::RUNGS`).
fn legacy_rung(workload: &str) -> Option<&'static str> {
    match workload {
        "dev/synthetic-8layer-t64" => Some("L1"),
        "dev/stories42m-t64" => Some("L2a"),
        "dev/stories110m-t64" => Some("L2c"),
        _ => None,
    }
}

/// Format rational `num / den` (`den > 0`) to `decimals` fractional digits with
/// round-half-to-even (IEEE-754 ties-to-even) in pure `u128` integer arithmetic (INV-12).
fn fmt_fixed_u128(num: u128, den: u128, decimals: u32) -> Result<String, String> {
    if den == 0 {
        return Err("division by zero while formatting scoreboard".into());
    }
    let scale = 10u128.pow(decimals);
    let scaled = num
        .checked_mul(scale)
        .ok_or_else(|| "scoreboard ratio overflow".to_string())?;
    let mut q = scaled / den;
    let r = scaled % den;
    // Compare 2 * r against den without overflow: compare r against den - r.
    let cmp = r.cmp(&(den - r));
    if cmp == std::cmp::Ordering::Greater || (cmp == std::cmp::Ordering::Equal && (q & 1) == 1) {
        q = q
            .checked_add(1)
            .ok_or_else(|| "scoreboard rounding overflow".to_string())?;
    }
    let whole = q / scale;
    let frac = q % scale;
    let width = decimals as usize;
    Ok(format!("{whole}.{frac:0width$}"))
}

/// Format an unsigned integer with comma thousands separators (`f'{n:,}'`).
fn fmt_commas(n: u64) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn counter_u64(map: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    map.get(key).and_then(Value::as_u64)
}

fn format_threads(model_config: &serde_json::Map<String, Value>) -> String {
    match model_config.get("threads") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => {
            if *b {
                "True".into()
            } else {
                "False".into()
            }
        }
        Some(Value::Null) => "None".into(),
        Some(other) => other.to_string(),
        None => "—".into(),
    }
}

/// Render `bench/scoreboard.md` from all `*.json` inference ledgers in `ledger_dir`.
/// Every ledger is validated before entering the table.
pub fn render_scoreboard(ledger_dir: &Path) -> Result<String, String> {
    let entries =
        std::fs::read_dir(ledger_dir).map_err(|e| format!("read {}: {e}", ledger_dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") && path.is_file() {
            paths.push(path);
        }
    }
    paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    let mut rows: Vec<(usize, String, String, Vec<String>)> = Vec::new();
    for path in paths {
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("non-UTF-8 ledger filename: {}", path.display()))?
            .to_string();
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("non-UTF-8 ledger stem: {}", path.display()))?
            .to_string();
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|f| {
                f.take((MAX_LEDGER_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
            })
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        validate_ledger(&bytes).map_err(|e| format!("invalid ledger {}: {e}", path.display()))?;
        let IntegerJson(r) =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
        if r["kind"].as_str() != Some("inference") {
            continue;
        }
        let workload = r["workload"].as_str().ok_or("missing workload")?;
        let mc = r["model_config"]
            .as_object()
            .ok_or("missing model_config")?;
        let rung = mc
            .get("rung")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| workload_rung(workload))
            .or_else(|| legacy_rung(workload))
            .unwrap_or(workload)
            .to_string();
        let prompt = r["prompt_tokens"].as_u64().ok_or("missing prompt_tokens")?;
        let generated = r["generated_tokens"]
            .as_u64()
            .ok_or("missing generated_tokens")?;
        let batch = r["batch_size"].as_u64().ok_or("missing batch_size")?;
        let tokens = prompt
            .checked_add(generated)
            .and_then(|p| p.checked_mul(batch))
            .ok_or("token count overflow")?;
        let kc = r["kernel_counters"]
            .as_object()
            .ok_or("missing kernel_counters")?;
        let cells = counter_u64(kc, "committed_cells")
            .or_else(|| counter_u64(kc, "stacked_source_cells_padded"));
        let lookups = counter_u64(kc, "lookup_positions")
            .or_else(|| counter_u64(kc, "lookup_ledger_numerator_sum"));
        let prove_ns = r["prover_time_ns"]
            .as_u64()
            .ok_or("missing prover_time_ns")?;
        let verify_rust_ns = r["verifier_time_ns"]["rust"]
            .as_u64()
            .ok_or("missing verifier_time_ns.rust")?;
        let proof_bytes = r["proof_size_bytes"]
            .as_u64()
            .ok_or("missing proof_size_bytes")?;
        let profile_base = r["profile"].as_str().ok_or("missing profile")?;
        let profile_byte_suffix = match mc.get("profile_byte").and_then(Value::as_u64) {
            Some(1) => " (dev-zk)",
            Some(4) => " (dev-zk, A8 sources)",
            _ => "",
        };
        let is_privacy = workload.contains("privacy");
        let privacy_suffix = if is_privacy {
            " privacy test, whole-test time"
        } else {
            ""
        };
        let profile_col = format!("{profile_base}{profile_byte_suffix}{privacy_suffix}");
        let device = r["device"].as_str().ok_or("missing device")?.to_string();
        let threads = format_threads(mc);
        let prove_s = fmt_fixed_u128(u128::from(prove_ns), 1_000_000_000, 2)?;
        let tok_s = if is_privacy {
            "—".to_string()
        } else {
            fmt_fixed_u128(
                u128::from(tokens)
                    .checked_mul(1_000_000_000)
                    .ok_or("tok/s overflow")?,
                u128::from(prove_ns),
                3,
            )?
        };
        let verify_s = fmt_fixed_u128(u128::from(verify_rust_ns), 1_000_000_000, 2)?;
        let proof_mb = fmt_fixed_u128(u128::from(proof_bytes), 1_000_000, 1)?;
        let rss_gb = match counter_u64(kc, "prove_peak_rss_bytes") {
            Some(rss) => fmt_fixed_u128(u128::from(rss), 1_000_000_000, 1)?,
            None => "—".to_string(),
        };
        let cells_col = match cells {
            Some(c) if c > 0 => fmt_commas(c / tokens),
            _ => "—".to_string(),
        };
        let lookups_col = match lookups {
            Some(l) if l > 0 => fmt_commas(l / tokens),
            _ => "—".to_string(),
        };
        let weight_reads = match counter_u64(kc, "weight_reads") {
            Some(w) => w.to_string(),
            None => "—".to_string(),
        };
        let lambda = if profile_base == "development" {
            "none".to_string()
        } else {
            "?".to_string()
        };
        let passed = r["controls"]["passed"]
            .as_u64()
            .ok_or("missing controls.passed")?;
        let total = r["controls"]["total"]
            .as_u64()
            .ok_or("missing controls.total")?;
        let controls = format!("{passed}/{total}");
        let commit = r["commit"].as_str().ok_or("missing commit")?;
        let short_commit = &commit[..7.min(commit.len())];
        let ledger_link = format!("[{stem}](ledger/{filename}) @ `{short_commit}`");

        let order = RUNGS
            .iter()
            .position(|&candidate| candidate == rung)
            .unwrap_or(RUNGS.len());
        let cols = vec![
            rung.clone(),
            profile_col,
            device,
            threads,
            prove_s,
            tok_s,
            verify_s,
            proof_mb,
            rss_gb,
            cells_col,
            lookups_col,
            weight_reads,
            lambda,
            controls,
            ledger_link,
        ];
        rows.push((order, rung, filename, cols));
    }

    rows.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));

    let head = [
        "Rung",
        "Profile",
        "Device",
        "Threads",
        "Prove s",
        "Tok/s",
        "Verify s",
        "Proof MB",
        "RSS GB",
        "Cells/token",
        "Lookups/token",
        "Weight reads",
        "λ bits",
        "Controls",
        "Ledger",
    ];
    let seen: BTreeSet<&str> = rows.iter().map(|(_, rung, _, _)| rung.as_str()).collect();
    let missing: Vec<&str> = RUNGS
        .iter()
        .copied()
        .filter(|r| !seen.contains(*r))
        .collect();

    let mut lines: Vec<String> = vec![
        "# Scoreboard".into(),
        String::new(),
        "Generated by `python3 bench/scoreboard.py --write` from `bench/ledger/`. Do not edit."
            .into(),
        "Rungs and columns: RFC-0027 §3, RFC-0018 A2. One row per inference record.".into(),
        String::new(),
        format!("| {} |", head.join(" | ")),
        format!("|{}", "---|".repeat(head.len())),
    ];
    for (_, _, _, cols) in rows {
        lines.push(format!("| {} |", cols.join(" | ")));
    }
    lines.push(String::new());
    lines.push(format!("Rungs with no record: {}.", missing.join(", ")));
    lines.push(String::new());
    lines.push("- Cells/token and Lookups/token before task E17-01 are upper bounds read from the proof: the padded".into());
    lines.push("  stacked-source size and the sum of the verifier's LU numerators (tables included). A dash".into());
    lines.push("  means the record does not carry the counter.".into());
    lines.push("- λ is `none` for every development-profile record (RFC-0026 §1.2).".into());
    lines.push(
        "- Rows on different devices or thread counts are not a comparison (Workflow 04).".into(),
    );
    lines.push(String::new());
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_ties_to_even_and_extreme_u64_formatting() {
        assert_eq!(fmt_fixed_u128(0, 1_000_000_000, 2).expect("fmt"), "0.00");
        assert_eq!(
            fmt_fixed_u128(999_999_999, 1_000_000_000, 2).expect("fmt"),
            "1.00"
        );
        // Exact midpoint ties-to-even (including cases where IEEE-754 binary64 diverges).
        assert_eq!(
            fmt_fixed_u128(2_675_000_000, 1_000_000_000, 2).expect("fmt"),
            "2.68"
        );
        assert_eq!(
            fmt_fixed_u128(2_665_000_000, 1_000_000_000, 2).expect("fmt"),
            "2.66"
        );
        assert_eq!(
            fmt_fixed_u128(15_650_000, 1_000_000, 1).expect("fmt"),
            "15.6"
        );
        assert_eq!(
            fmt_fixed_u128(15_750_000, 1_000_000, 1).expect("fmt"),
            "15.8"
        );
        assert_eq!(
            fmt_fixed_u128(1_000_000_000, 80_000_000_000, 3).expect("fmt"),
            "0.012"
        );
        assert_eq!(
            fmt_fixed_u128(u128::from(u64::MAX), 1_000_000_000, 2).expect("fmt"),
            "18446744073.71"
        );
        assert_eq!(
            fmt_fixed_u128(u128::from(u64::MAX) * 1_000_000_000, 1, 3).expect("fmt"),
            "18446744073709551615000000000.000"
        );
        assert!(fmt_fixed_u128(1, 0, 2).is_err());
        assert_eq!(fmt_commas(0), "0");
        assert_eq!(fmt_commas(999), "999");
        assert_eq!(fmt_commas(1_000), "1,000");
        assert_eq!(fmt_commas(4_202_085), "4,202,085");
    }

    #[test]
    fn matches_reference_workload_rung_mapping() {
        assert_eq!(workload_rung("W1"), Some("L3c"));
        assert_eq!(workload_rung("W3"), Some("L4"));
        assert_eq!(workload_rung("W4"), Some("L6"));
        assert_eq!(workload_rung("W5"), Some("L6"));
        assert_eq!(workload_rung("W6"), Some("L6"));
        assert_eq!(workload_rung("W2"), None);
        assert_eq!(workload_rung("W7"), None);
        assert_eq!(workload_rung("W8"), None);
        for &rung in RUNGS {
            assert_eq!(workload_rung(rung), Some(rung));
        }
    }
}
