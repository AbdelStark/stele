//! RFC-0027 §3, RFC-0026 §5 — static accounting report and RFC-0018 micro ledger builder (task E22-01).
//!
//! Pure integer arithmetic (INV-12: no floats).
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use stele_prover::accounting::{
    account_frames, blake3_hex, inspect_model, validate_artifact_header, Accounting, ArtifactMeta,
    ShapeSummary, ARTIFACT_HEADER_LEN,
};
use stele_prover::development::bundle;

/// Metadata for emitting a validated RFC-0018 `kind: "micro"` static-accounting ledger.
pub struct LedgerMeta<'a> {
    pub workload_suffix: &'a str,
    pub target_rung: &'a str,
    pub model_name: &'a str,
    pub commit: &'a str,
    pub device: &'a str,
    pub toolchain: &'a str,
    pub checked_label: &'a str,
    pub exact_vectors: bool,
    pub elapsed_ns: u64,
    pub extra_note: &'a str,
}

/// Deterministic counter-key sanitizer matching `stele-cli::sanitize_counter_name` (E17-01).
fn sanitize_counter_key(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_sep = false;
    let push_sep = |out: &mut String, prev: &mut bool| {
        if !*prev && !out.is_empty() {
            out.push('_');
            *prev = true;
        }
    };
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if ch == '-' {
            push_sep(&mut out, &mut prev_sep);
            out.push_str("neg_");
            prev_sep = true;
        } else {
            push_sep(&mut out, &mut prev_sep);
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "unnamed".into()
    } else {
        out
    }
}

fn insert_unique(map: &mut Map<String, Value>, key: String, value: Value) -> Result<(), String> {
    if map.insert(key.clone(), value).is_some() {
        return Err(format!("duplicate sanitized counter key: {key}"));
    }
    Ok(())
}

/// Format an unsigned integer with comma thousands separators.
pub fn fmt_commas(n: u64) -> String {
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

/// Read only the 1-D norm-gain records from an `artifact.bin` file via seek + read_exact,
/// after validating the 49-byte CQIS artifact header (`cqis-weights-v1`, record count) and
/// total file byte length (RFC-0025 encoding §3).
pub fn read_vectors_from_artifact_file(
    path: &Path,
    meta: &ArtifactMeta,
) -> Result<Vec<(u16, Vec<i16>)>, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    let mut header = [0u8; ARTIFACT_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read header {}: {e}", path.display()))?;
    validate_artifact_header(&header, file_len, meta).map_err(|_| {
        format!(
            "artifact {} does not match model header/length (expected {} bytes, {} records)",
            path.display(),
            meta.byte_length,
            meta.record_count
        )
    })?;
    let mut out = Vec::with_capacity(meta.vector_spans.len());
    for &(ordinal, offset, elements) in &meta.vector_spans {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        let byte_len = elements
            .checked_mul(2)
            .ok_or_else(|| "vector byte length overflow".to_string())?;
        let mut raw = vec![0u8; byte_len];
        file.read_exact(&mut raw)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let codes: Vec<i16> = raw
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push((ordinal, codes));
    }
    Ok(out)
}

/// Read `model.bin` and `scales.bin` (plus optional `artifact.bin` or `public.bin` for exact
/// 1-D gain widths) and run static accounting without proving.
pub fn account_from_files(
    model_path: &Path,
    scales_path: &Path,
    artifact_path: Option<&Path>,
    public_path: Option<&Path>,
    length: usize,
    checked: core::ops::Range<usize>,
) -> Result<(Accounting, ShapeSummary, bool), String> {
    let model_raw =
        std::fs::read(model_path).map_err(|e| format!("read {}: {e}", model_path.display()))?;
    let scales_raw =
        std::fs::read(scales_path).map_err(|e| format!("read {}: {e}", scales_path.display()))?;
    let (shape, meta) = inspect_model(&model_raw).map_err(|e| format!("inspect model: {e:?}"))?;
    let vectors = match (artifact_path, public_path) {
        (Some(_), Some(_)) => return Err("pass at most one of --artifact or --public".into()),
        (Some(art), None) => Some(read_vectors_from_artifact_file(art, &meta)?),
        (None, Some(pub_path)) => {
            let pub_raw =
                std::fs::read(pub_path).map_err(|e| format!("read {}: {e}", pub_path.display()))?;
            let (public, _) =
                bundle::decode(&pub_raw).map_err(|e| format!("decode public: {e:?}"))?;
            Some(public.vectors)
        }
        (None, None) => None,
    };
    let exact_vectors = vectors.is_some();
    let acc = account_frames(&model_raw, &scales_raw, vectors.as_deref(), length, checked)
        .map_err(|e| format!("account: {e:?}"))?;
    Ok((acc, shape, exact_vectors))
}

/// Format a human-readable static accounting report (per module, relation kind, and lookup width).
pub fn format_report(acc: &Accounting, shape: &ShapeSummary, exact_vectors: bool) -> String {
    let t = acc.tokens;
    let mut lines = Vec::new();
    lines.push(format!(
        "shape: family={} layers={} d={} heads={} kv_heads={} head_width={} hidden={} vocab={} context={} wide_residual={}",
        shape.family,
        shape.layers,
        shape.d,
        shape.heads,
        shape.kv_heads,
        shape.head_width,
        shape.hidden,
        shape.vocabulary,
        shape.context,
        shape.wide_residual
    ));
    lines.push(format!(
        "window: T={t} exact_gain_widths={exact_vectors} groups={} witness_columns={}",
        acc.groups, acc.witness_columns
    ));
    lines.push(format!(
        "totals: committed_cells={} ({}/tok) lookup_positions={} ({}/tok) weight_cells={} public_cells={}",
        fmt_commas(acc.committed_cells),
        fmt_commas(acc.committed_cells / t),
        fmt_commas(acc.lookup_positions),
        fmt_commas(acc.lookup_positions / t),
        fmt_commas(acc.weight_cells),
        fmt_commas(acc.public_cells),
    ));

    lines.push(String::new());
    lines.push("Per module (sorted by committed_cells desc):".into());
    lines.push(
        "  module               committed_cells    cells/tok    lookup_positions  lookups/tok   cols   id  comp   mm"
            .into(),
    );
    let mut mods: Vec<(&String, &stele_prover::accounting::ModuleAccounting)> =
        acc.by_module.iter().collect();
    mods.sort_by(|a, b| {
        b.1.committed_cells
            .cmp(&a.1.committed_cells)
            .then_with(|| b.1.lookup_positions.cmp(&a.1.lookup_positions))
            .then_with(|| a.0.cmp(b.0))
    });
    for (name, m) in mods {
        lines.push(format!(
            "  {name:<20} {:>15} {:>12} {:>19} {:>12} {:>6} {:>4} {:>5} {:>4}",
            fmt_commas(m.committed_cells),
            fmt_commas(m.committed_cells / t),
            fmt_commas(m.lookup_positions),
            fmt_commas(m.lookup_positions / t),
            m.witness_columns,
            m.identities,
            m.composes,
            m.matmuls,
        ));
    }

    let k = &acc.by_relation_kind;
    lines.push(String::new());
    lines.push("Per relation kind:".into());
    lines.push(format!(
        "  identities: {:>8}  domain_points={}",
        k.identity_count,
        fmt_commas(k.identity_points)
    ));
    lines.push(format!(
        "  composes:   {:>8}  domain_points={}",
        k.compose_count,
        fmt_commas(k.compose_points)
    ));
    lines.push(format!(
        "  lookups:    {:>8}  positions={} ({}/tok)",
        k.lookup_count,
        fmt_commas(k.lookup_positions),
        fmt_commas(k.lookup_positions / t)
    ));
    lines.push(format!(
        "  ranges:     {:>8}  positions={} ({}/tok)",
        k.range_count,
        fmt_commas(k.range_positions),
        fmt_commas(k.range_positions / t)
    ));
    lines.push(format!(
        "  matmuls:    {:>8}  free_points={} domain_points={}",
        k.matmul_count,
        fmt_commas(k.matmul_free_points),
        fmt_commas(k.matmul_domain_points)
    ));

    lines.push(String::new());
    lines.push("Lookup positions by width / table (sorted desc):".into());
    let mut widths: Vec<(&String, &u64)> = acc.lookups_by_width.iter().collect();
    widths.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (label, &pos) in widths {
        lines.push(format!(
            "  {label:<36} {:>15} ({:>10}/tok)",
            fmt_commas(pos),
            fmt_commas(pos / t)
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

/// Build and validate an RFC-0018 `kind: "micro"` static-accounting ledger JSON string.
pub fn build_micro_ledger(
    acc: &Accounting,
    shape: &ShapeSummary,
    meta: &LedgerMeta<'_>,
) -> Result<String, String> {
    if !crate::is_valid_rung(meta.target_rung) {
        return Err(format!("unknown target rung: {}", meta.target_rung));
    }
    let t = acc.tokens;

    let mut per_module = Map::new();
    for (name, m) in &acc.by_module {
        let mut by_width = Map::new();
        for (w, &pos) in &m.lookups_by_width {
            by_width.insert(w.clone(), json!(pos));
        }
        per_module.insert(
            name.clone(),
            json!({
                "committed_cells": m.committed_cells,
                "committed_cells_per_token": m.committed_cells / t,
                "witness_columns": m.witness_columns,
                "weight_columns": m.weight_columns,
                "lookup_positions": m.lookup_positions,
                "lookup_positions_per_token": m.lookup_positions / t,
                "table_lookup_positions": m.table_lookup_positions,
                "range_lookup_positions": m.range_lookup_positions,
                "identities": m.identities,
                "composes": m.composes,
                "matmuls": m.matmuls,
                "lookups_by_width": Value::Object(by_width),
            }),
        );
    }

    let mut lookups_by_width = Map::new();
    for (w, &pos) in &acc.lookups_by_width {
        lookups_by_width.insert(w.clone(), json!(pos));
    }

    let top_cells = acc
        .by_module
        .iter()
        .max_by(|a, b| {
            a.1.committed_cells
                .cmp(&b.1.committed_cells)
                .then_with(|| b.0.cmp(a.0))
        })
        .map(|(k, v)| (k.clone(), v.committed_cells))
        .unwrap_or_else(|| ("none".into(), 0));
    let top_lookups = acc
        .by_module
        .iter()
        .max_by(|a, b| {
            a.1.lookup_positions
                .cmp(&b.1.lookup_positions)
                .then_with(|| b.0.cmp(a.0))
        })
        .map(|(k, v)| (k.clone(), v.lookup_positions))
        .unwrap_or_else(|| ("none".into(), 0));

    let k = &acc.by_relation_kind;
    let model_config = json!({
        "target_rung": meta.target_rung,
        "model_name": meta.model_name,
        "tokens": t,
        "checked": meta.checked_label,
        "exact_gain_widths": meta.exact_vectors,
        "shape": {
            "family": shape.family,
            "layers": shape.layers,
            "d": shape.d,
            "heads": shape.heads,
            "kv_heads": shape.kv_heads,
            "head_width": shape.head_width,
            "hidden": shape.hidden,
            "vocabulary": shape.vocabulary,
            "context": shape.context,
            "wide_residual": shape.wide_residual,
        },
        "top_module_cells": {
            "module": top_cells.0,
            "committed_cells": top_cells.1,
            "cells_per_token": top_cells.1 / t,
        },
        "top_module_lookups": {
            "module": top_lookups.0,
            "lookup_positions": top_lookups.1,
            "lookups_per_token": top_lookups.1 / t,
        },
        "per_relation_kind": {
            "identities": { "count": k.identity_count, "domain_points": k.identity_points },
            "composes": { "count": k.compose_count, "domain_points": k.compose_points },
            "lookups": { "count": k.lookup_count, "positions": k.lookup_positions },
            "ranges": { "count": k.range_count, "positions": k.range_positions },
            "matmuls": {
                "count": k.matmul_count,
                "free_points": k.matmul_free_points,
                "domain_points": k.matmul_domain_points,
            },
        },
        "per_module": Value::Object(per_module),
        "lookups_by_width": Value::Object(lookups_by_width),
    });

    let plan_bytes = serde_json::to_vec(&model_config).map_err(|e| e.to_string())?;
    let plan_digest = blake3_hex(&plan_bytes);

    let mut kernel_counters = Map::new();
    insert_unique(&mut kernel_counters, "tokens".into(), json!(t))?;
    insert_unique(
        &mut kernel_counters,
        "committed_cells".into(),
        json!(acc.committed_cells),
    )?;
    insert_unique(
        &mut kernel_counters,
        "committed_cells_per_token".into(),
        json!(acc.committed_cells / t),
    )?;
    insert_unique(
        &mut kernel_counters,
        "lookup_positions".into(),
        json!(acc.lookup_positions),
    )?;
    insert_unique(
        &mut kernel_counters,
        "lookup_positions_per_token".into(),
        json!(acc.lookup_positions / t),
    )?;
    insert_unique(
        &mut kernel_counters,
        "weight_cells".into(),
        json!(acc.weight_cells),
    )?;
    insert_unique(
        &mut kernel_counters,
        "public_cells".into(),
        json!(acc.public_cells),
    )?;
    insert_unique(
        &mut kernel_counters,
        "witness_columns".into(),
        json!(acc.witness_columns),
    )?;
    insert_unique(&mut kernel_counters, "groups".into(), json!(acc.groups))?;
    insert_unique(
        &mut kernel_counters,
        "identities".into(),
        json!(k.identity_count),
    )?;
    insert_unique(
        &mut kernel_counters,
        "composes".into(),
        json!(k.compose_count),
    )?;
    insert_unique(
        &mut kernel_counters,
        "lookups".into(),
        json!(k.lookup_count),
    )?;
    insert_unique(&mut kernel_counters, "ranges".into(), json!(k.range_count))?;
    insert_unique(
        &mut kernel_counters,
        "matmuls".into(),
        json!(k.matmul_count),
    )?;
    for (name, m) in &acc.by_module {
        let key = sanitize_counter_key(name);
        insert_unique(
            &mut kernel_counters,
            format!("module_{key}_committed_cells"),
            json!(m.committed_cells),
        )?;
        insert_unique(
            &mut kernel_counters,
            format!("module_{key}_lookup_positions"),
            json!(m.lookup_positions),
        )?;
    }
    for (label, &pos) in &acc.lookups_by_width {
        let key = sanitize_counter_key(label);
        insert_unique(
            &mut kernel_counters,
            format!("width_{key}_positions"),
            json!(pos),
        )?;
    }
    for (i, (check_name, pos)) in acc.lookups_by_check.iter().enumerate() {
        let key = sanitize_counter_key(check_name);
        insert_unique(
            &mut kernel_counters,
            format!("lookup_positions_check_{i}_{key}"),
            json!(*pos),
        )?;
    }

    let elapsed_ns = meta.elapsed_ns.max(1);
    let note = format!(
        "Static accounting baseline for {} (RFC-0027 §3, RFC-0026 §5, task E22-01): exact committed witness cells and unpadded lookup positions derived from Layout::declare without proving (exact_gain_widths={}). \"profile\": \"standard\" is a required RFC-0018 micro-schema field, not a profile admission (INV-13); micro proof/verifier/control fields are zero because no proof is produced.{}",
        meta.target_rung,
        meta.exact_vectors,
        if meta.extra_note.is_empty() {
            String::new()
        } else {
            format!(" {}", meta.extra_note)
        }
    );

    let ledger = json!({
        "schema_version": 1,
        "kind": "micro",
        "workload": format!("micro/static-accounting-{}", meta.workload_suffix),
        "commit": meta.commit,
        "toolchain": meta.toolchain,
        "device": meta.device,
        "driver": "not-applicable",
        "model_config": model_config,
        "plan_digest": plan_digest,
        "profile": "standard",
        "bindings_all_on": true,
        "batch_size": 1,
        "prompt_tokens": 0,
        "generated_tokens": 0,
        "prover_time_ns": elapsed_ns,
        "witness_recompute_ns": 0,
        "stage_times_ns": {
            "declare_and_account": elapsed_ns,
        },
        "kernel_counters": Value::Object(kernel_counters),
        "proof_size_bytes": 0,
        "verifier_time_ns": { "rust": 0, "python": 0 },
        "controls": { "total": 0, "passed": 0, "failed": 0 },
        "note": note,
    });

    let serialized = format!(
        "{}\n",
        serde_json::to_string_pretty(&ledger).map_err(|e| e.to_string())?
    );
    crate::validate_ledger(serialized.as_bytes())?;
    Ok(serialized)
}
