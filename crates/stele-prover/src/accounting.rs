//! Static accounting of committed cells and lookup positions per token (RFC-0027 §3, RFC-0026 §5, task E22-01).
//!
//! Declares a window's [`Relation`] from plan metadata (`Model`, `Scales`, and optional
//! 1-D norm gain vectors) without executing the model or producing a proof, and reports:
//! - committed witness cells (`sum 2^log_len` over `Kind::Witness`),
//! - lookup positions (`sum 2^vars` over `Lookup` + `sum 2^log_len` over `Range`),
//! - breakdown by RFC-0026 §5 module, by relation kind, by lookup/range width, and in exact
//!   E17-01 check order (`lookups_by_check`).
//!
//! Pure integer arithmetic only (INV-12: no floats).

use crate::development::{Error, Layout, PlanData, Statement};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use stele_reductions::stele_cqis::model::{ArtifactLayout, Model, Scales};
use stele_reductions::stele_ir::relation::{Kind, Relation, Width};

/// Per-module static accounting totals across all layers sharing the same module kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleAccounting {
    /// Committed witness cells (`sum 2^log_len` over `Kind::Witness` columns in this module).
    pub committed_cells: u64,
    /// Number of committed witness columns in this module.
    pub witness_columns: u64,
    /// Number of weight columns owned by this module.
    pub weight_columns: u64,
    /// Total unpadded lookup positions (table lookups + range checks) in this module.
    pub lookup_positions: u64,
    /// Unpadded table lookup positions (`Lookup`) in this module.
    pub table_lookup_positions: u64,
    /// Unpadded range check positions (`Range`) in this module.
    pub range_lookup_positions: u64,
    /// Count of identities owned by this module.
    pub identities: u64,
    /// Count of limb compositions owned by this module.
    pub composes: u64,
    /// Count of matmuls owned by this module.
    pub matmuls: u64,
    /// Lookup and range positions keyed by width/table label.
    pub lookups_by_width: BTreeMap<String, u64>,
}

/// Counts and domain-point totals grouped by IR relation kind (RFC-0026 §3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelationKindAccounting {
    pub identity_count: u64,
    pub identity_points: u64,
    pub compose_count: u64,
    pub compose_points: u64,
    pub lookup_count: u64,
    pub lookup_positions: u64,
    pub range_count: u64,
    pub range_positions: u64,
    pub matmul_count: u64,
    pub matmul_free_points: u64,
    pub matmul_domain_points: u64,
}

/// Complete static accounting report for one declared relation window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accounting {
    /// Window length `T` (tokens).
    pub tokens: u64,
    /// Total committed witness cells (`sum 2^log_len` over `Kind::Witness`), matching E17-01.
    pub committed_cells: u64,
    /// Total unpadded lookup positions (table lookups + ranges), matching E17-01.
    pub lookup_positions: u64,
    /// Total weight column cells (`sum 2^log_len` over `Kind::Weight`).
    pub weight_cells: u64,
    /// Total public column cells (`sum 2^log_len` over `Kind::Public`).
    pub public_cells: u64,
    /// Number of witness columns.
    pub witness_columns: u64,
    /// Number of commitment groups.
    pub groups: u64,
    /// Per-module breakdown keyed by normalized RFC-0026 §5 module name.
    pub by_module: BTreeMap<String, ModuleAccounting>,
    /// Breakdown by IR relation kind.
    pub by_relation_kind: RelationKindAccounting,
    /// Lookup and range positions grouped by width/table label (`range:s8`, `range:u16`, `table:<name>(<widths>)`).
    pub lookups_by_width: BTreeMap<String, u64>,
    /// Per-check `(check_name, unpadded_positions)` in exact E17-01 `plan.checks` order.
    pub lookups_by_check: Vec<(String, u64)>,
}

/// Format a [`Width`] as a concise signed/unsigned bit label (`s8`, `u16`, ...).
pub fn width_label(w: Width) -> String {
    let prefix = if w.signed { 's' } else { 'u' };
    format!("{prefix}{}", w.bits)
}

/// Normalize a column or constraint name to its RFC-0026 §5 module kind.
///
/// Strips leading `G/` or `L<layer>/` scope prefixes and takes the module segment
/// (e.g. `G/embedding/out` -> `embedding`, `L0/norm1/S_0` -> `norm1`, `L31/rope/q/x` -> `rope_q`,
/// `L0/attention/score` -> `attention`, `L0/gated/row/scale` -> `gated_row`, `G/argmax/m` -> `argmax`).
pub fn module_of(name: &str) -> String {
    let rest = if let Some(after) = name.strip_prefix("G/") {
        after
    } else if let Some(after) = name.strip_prefix('L') {
        match after.find('/') {
            Some(pos) if pos > 0 && after[..pos].bytes().all(|b| b.is_ascii_digit()) => {
                &after[pos + 1..]
            }
            _ => name,
        }
    } else {
        name
    };
    let mut parts = rest.split('/');
    let first = parts.next().unwrap_or("other");
    // Disambiguate `rope/q/...` vs `rope/k/...`, `residual/mid/...` vs `residual/out/...`,
    // and `gated/row/...` (`GatedConversion`) vs `gated/...` (`GatedProduct`), while keeping
    // single-segment modules (`norm1`, `row1`, `q`, `attention`, `argmax`, ...).
    match (first, parts.next()) {
        ("rope", Some(sub @ ("q" | "k"))) => format!("rope_{sub}"),
        ("residual", Some(sub @ ("mid" | "out"))) => format!("residual_{sub}"),
        ("gated", Some("row")) => "gated_row".to_string(),
        ("", _) => "other".to_string(),
        (m, _) => m.to_string(),
    }
}

/// Compute static accounting directly from any validated [`Relation`] (RFC-0027 §3, E22-01).
pub fn account_relation(relation: &Relation, tokens: u64) -> Result<Accounting, Error> {
    if tokens == 0 {
        return Err(Error::StatementMismatch);
    }
    relation.validate().map_err(|_| Error::StatementMismatch)?;

    let mut committed_cells = 0u64;
    let mut weight_cells = 0u64;
    let mut public_cells = 0u64;
    let mut witness_columns = 0u64;
    let mut by_module: BTreeMap<String, ModuleAccounting> = BTreeMap::new();
    let mut by_kind = RelationKindAccounting::default();
    let mut lookups_by_width: BTreeMap<String, u64> = BTreeMap::new();

    for col in &relation.columns {
        let cells = 1u64 << col.log_len;
        match &col.kind {
            Kind::Witness(_) => {
                committed_cells = committed_cells.saturating_add(cells);
                witness_columns += 1;
                let entry = by_module.entry(module_of(&col.name)).or_default();
                entry.committed_cells = entry.committed_cells.saturating_add(cells);
                entry.witness_columns += 1;
            }
            Kind::Weight => {
                weight_cells = weight_cells.saturating_add(cells);
                let entry = by_module.entry(module_of(&col.name)).or_default();
                entry.weight_columns += 1;
            }
            Kind::Public(_) => {
                public_cells = public_cells.saturating_add(cells);
            }
        }
    }

    // Exact E17-01 `plan.checks` grouping: keyed by `(TableId | Range(bits))` in first-use
    // order (matching `stele-reductions/src/relation.rs` `Target`), so distinct tables sharing
    // a name or a table named `range_{bits}` stay distinct checks.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CheckTarget {
        Table(u32),
        Range(u8),
    }
    let mut check_order: Vec<(CheckTarget, String, u64)> = Vec::new();
    let mut add_check = |target: CheckTarget, check_name: String, positions: u64| {
        if let Some((_, _, total)) = check_order.iter_mut().find(|(t, _, _)| *t == target) {
            *total = total.saturating_add(positions);
        } else {
            check_order.push((target, check_name, positions));
        }
    };

    for lookup in &relation.lookups {
        let positions = 1u64 << lookup.vars;
        let table = &relation.tables[lookup.table.0 as usize];
        by_kind.lookup_count += 1;
        by_kind.lookup_positions = by_kind.lookup_positions.saturating_add(positions);

        let widths: Vec<String> = table.widths.iter().map(|w| width_label(*w)).collect();
        let width_key = format!("table:{}({})", table.name, widths.join(","));
        lookups_by_width
            .entry(width_key.clone())
            .and_modify(|v| *v = v.saturating_add(positions))
            .or_insert(positions);
        add_check(
            CheckTarget::Table(lookup.table.0),
            table.name.clone(),
            positions,
        );

        let mod_name = module_of(&lookup.name);
        let entry = by_module.entry(mod_name).or_default();
        entry.lookup_positions = entry.lookup_positions.saturating_add(positions);
        entry.table_lookup_positions = entry.table_lookup_positions.saturating_add(positions);
        entry
            .lookups_by_width
            .entry(width_key)
            .and_modify(|v| *v = v.saturating_add(positions))
            .or_insert(positions);
    }

    for range in &relation.ranges {
        let col = &relation.columns[range.column.0 as usize];
        let positions = 1u64 << col.log_len;
        by_kind.range_count += 1;
        by_kind.range_positions = by_kind.range_positions.saturating_add(positions);

        let width_key = format!("range:{}", width_label(range.width));
        lookups_by_width
            .entry(width_key.clone())
            .and_modify(|v| *v = v.saturating_add(positions))
            .or_insert(positions);
        add_check(
            CheckTarget::Range(range.width.bits),
            format!("range_{}", range.width.bits),
            positions,
        );

        let mod_name = module_of(&col.name);
        let entry = by_module.entry(mod_name).or_default();
        entry.lookup_positions = entry.lookup_positions.saturating_add(positions);
        entry.range_lookup_positions = entry.range_lookup_positions.saturating_add(positions);
        entry
            .lookups_by_width
            .entry(width_key)
            .and_modify(|v| *v = v.saturating_add(positions))
            .or_insert(positions);
    }

    for identity in &relation.identities {
        by_kind.identity_count += 1;
        by_kind.identity_points = by_kind
            .identity_points
            .saturating_add(1u64 << identity.vars);
        let entry = by_module.entry(module_of(&identity.name)).or_default();
        entry.identities += 1;
    }

    for compose in &relation.composes {
        let col = &relation.columns[compose.column.0 as usize];
        by_kind.compose_count += 1;
        by_kind.compose_points = by_kind.compose_points.saturating_add(1u64 << col.log_len);
        let entry = by_module.entry(module_of(&compose.name)).or_default();
        entry.composes += 1;
    }

    for matmul in &relation.matmuls {
        by_kind.matmul_count += 1;
        by_kind.matmul_free_points = by_kind
            .matmul_free_points
            .saturating_add(1u64 << matmul.free);
        by_kind.matmul_domain_points = by_kind
            .matmul_domain_points
            .saturating_add(1u64 << (matmul.free + matmul.summed));
        let entry = by_module.entry(module_of(&matmul.name)).or_default();
        entry.matmuls += 1;
    }

    let lookup_positions = by_kind
        .lookup_positions
        .saturating_add(by_kind.range_positions);
    Ok(Accounting {
        tokens,
        committed_cells,
        lookup_positions,
        weight_cells,
        public_cells,
        witness_columns,
        groups: relation.groups.len() as u64,
        by_module,
        by_relation_kind: by_kind,
        lookups_by_width,
        lookups_by_check: check_order
            .into_iter()
            .map(|(_, name, pos)| (name, pos))
            .collect(),
    })
}

/// CQIS Artifact v1 header magic (`PREFIX` = 15 bytes, followed by 32-byte preparation id and 2-byte record count).
pub const ARTIFACT_HEADER_LEN: usize = 15 + 32 + 2;
const ARTIFACT_PREFIX: &[u8] = b"cqis-weights-v1";

/// Structural metadata needed to validate an Artifact file header and seek only 1-D vector records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactMeta {
    pub byte_length: u64,
    pub record_count: u16,
    pub vector_spans: Vec<VectorSpan>,
}

/// Validate the 49-byte CQIS Artifact header (`cqis-weights-v1`, record count) and total length.
pub fn validate_artifact_header(
    header: &[u8],
    actual_byte_len: u64,
    meta: &ArtifactMeta,
) -> Result<(), Error> {
    if header.len() < ARTIFACT_HEADER_LEN
        || &header[..ARTIFACT_PREFIX.len()] != ARTIFACT_PREFIX
        || actual_byte_len != meta.byte_length
    {
        return Err(Error::Witness);
    }
    let count = u16::from_le_bytes([
        header[ARTIFACT_PREFIX.len() + 32],
        header[ARTIFACT_PREFIX.len() + 33],
    ]);
    if count != meta.record_count {
        return Err(Error::Witness);
    }
    Ok(())
}

/// Extract only the 1-D gain vectors from an Artifact byte slice, without decoding 2-D weights.
pub fn extract_vectors_from_artifact(
    model: &Model,
    artifact: &[u8],
) -> Result<Vec<(u16, Vec<i16>)>, Error> {
    let meta = artifact_meta(model)?;
    validate_artifact_header(artifact, artifact.len() as u64, &meta)?;
    let mut vectors = Vec::with_capacity(meta.vector_spans.len());
    for &(ordinal, payload_offset, elements) in &meta.vector_spans {
        let start = usize::try_from(payload_offset).map_err(|_| Error::Witness)?;
        let len = elements.checked_mul(2).ok_or(Error::Witness)?;
        let raw = artifact
            .get(start..start.checked_add(len).ok_or(Error::Witness)?)
            .ok_or(Error::Witness)?;
        let codes: Vec<i16> = (0..elements)
            .map(|i| i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]))
            .collect();
        vectors.push((ordinal, codes));
    }
    Ok(vectors)
}

/// Byte span `(ordinal, payload_offset, elements)` of one 1-D gain vector record in an Artifact.
pub type VectorSpan = (u16, u64, usize);

/// Structural header expectations and 1-D vector record spans for an Artifact of `model`.
pub fn artifact_meta(model: &Model) -> Result<ArtifactMeta, Error> {
    let layout = ArtifactLayout::new(model).map_err(|_| Error::UnsupportedModel)?;
    let shape = model.shape();
    let record_count =
        u16::try_from(layout.records().len()).map_err(|_| Error::UnsupportedModel)?;
    let mut spans = Vec::new();
    for r in layout.records() {
        let physical = shape.physical(r.ordinal()).ok_or(Error::UnsupportedModel)?;
        if physical.dimensions().len() != 1 {
            continue;
        }
        let elements = usize::try_from(r.elements()).map_err(|_| Error::Witness)?;
        if r.bits() != 16 {
            return Err(Error::UnsupportedModel);
        }
        spans.push((r.ordinal(), r.payload_offset(), elements));
    }
    Ok(ArtifactMeta {
        byte_length: layout.byte_length(),
        record_count,
        vector_spans: spans,
    })
}

/// Byte offsets `(ordinal, payload_offset, elements)` of all 1-D gain records in an Artifact,
/// enabling callers with `std::fs::File` to seek and read only the tiny 1-D records.
pub fn vector_record_spans(model: &Model) -> Result<Vec<VectorSpan>, Error> {
    Ok(artifact_meta(model)?.vector_spans)
}

/// Synthesize canonical zero 1-D gain vectors for shape-only accounting (`fixed_widths = true`).
pub fn placeholder_vectors(model: &Model) -> Result<Vec<(u16, Vec<i16>)>, Error> {
    let shape = model.shape();
    let mut vectors = Vec::new();
    for ordinal in 0..shape.record_count() {
        let physical = shape.physical(ordinal).ok_or(Error::UnsupportedModel)?;
        if physical.dimensions().len() == 1 {
            let elements =
                usize::try_from(physical.dimensions()[0]).map_err(|_| Error::UnsupportedModel)?;
            vectors.push((ordinal, vec![0i16; elements]));
        }
    }
    Ok(vectors)
}

/// Declare a window's relation from decoded `Model` and `Scales` (without proving) and
/// return its static [`Accounting`] report (RFC-0027 §3, task E22-01).
///
/// When `vectors` is `Some`, uses the exact 1-D norm gain widths (`fixed_widths = false`),
/// matching `stele prove-dev` bit-for-bit. When `vectors` is `None`, synthesizes placeholder
/// vectors with canonical full widths (`fixed_widths = true`).
pub fn account_model(
    model: &Model,
    scales: &Scales,
    vectors: Option<&[(u16, Vec<i16>)]>,
    length: usize,
    checked: core::ops::Range<usize>,
) -> Result<Accounting, Error> {
    if length == 0
        || length > model.shape().context() as usize
        || checked.start >= checked.end
        || checked.end > length
    {
        return Err(Error::StatementMismatch);
    }
    if !length.is_power_of_two() {
        return Err(Error::UnsupportedModel);
    }
    let placeholder;
    let (vecs, zk) = match vectors {
        Some(v) => (v, false),
        None => {
            placeholder = placeholder_vectors(model)?;
            (placeholder.as_slice(), true)
        }
    };
    let plan = PlanData {
        model,
        scales,
        vectors: vecs,
        zk,
        segment_layers: 0,
    };
    let start = u32::try_from(checked.start).map_err(|_| Error::StatementMismatch)?;
    let end = u32::try_from(checked.end).map_err(|_| Error::StatementMismatch)?;
    let statement = Statement {
        tokens: vec![0u32; length],
        start,
        end,
        next: (checked.end == length).then_some(0),
    };
    let layout = Layout::declare(&plan, &statement)?;
    account_relation(&layout.relation, length as u64)
}

/// Decode `model.bin` and `scales.bin` and run [`account_model`].
pub fn account_frames(
    model_raw: &[u8],
    scales_raw: &[u8],
    vectors: Option<&[(u16, Vec<i16>)]>,
    length: usize,
    checked: core::ops::Range<usize>,
) -> Result<Accounting, Error> {
    let model = Model::decode(model_raw).map_err(|_| Error::StatementMismatch)?;
    let scales = Scales::decode(&model, scales_raw).map_err(|_| Error::StatementMismatch)?;
    account_model(&model, &scales, vectors, length, checked)
}

/// Lowercase 64-character BLAKE3 hex digest (for deterministic ledger `plan_digest`s).
pub fn blake3_hex(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    let mut out = String::with_capacity(64);
    for b in digest.as_bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Model shape summary extracted from a decoded `model.bin` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeSummary {
    pub family: u8,
    pub layers: u16,
    pub d: u16,
    pub heads: u16,
    pub kv_heads: u16,
    pub head_width: u16,
    pub hidden: u16,
    pub vocabulary: u32,
    pub context: u32,
    pub wide_residual: bool,
}

/// Decode `model.bin` and return its [`ShapeSummary`] plus Artifact header metadata.
pub fn inspect_model(model_raw: &[u8]) -> Result<(ShapeSummary, ArtifactMeta), Error> {
    let model = Model::decode(model_raw).map_err(|_| Error::StatementMismatch)?;
    let s = model.shape();
    let summary = ShapeSummary {
        family: s.family(),
        layers: s.layers(),
        d: s.width(),
        heads: s.heads(),
        kv_heads: s.groups(),
        head_width: s.head_width(),
        hidden: s.hidden(),
        vocabulary: s.vocabulary(),
        context: s.context(),
        wide_residual: model.wide(),
    };
    let meta = artifact_meta(&model)?;
    Ok((summary, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::development::prove_window_development_measured;

    #[test]
    fn accepts_normalized_module_names() {
        assert_eq!(module_of("G/embedding/out"), "embedding");
        assert_eq!(module_of("L0/norm1/S_0"), "norm1");
        assert_eq!(module_of("L31/q/acc"), "q");
        assert_eq!(module_of("L7/rope/q/x"), "rope_q");
        assert_eq!(module_of("L7/rope/k/y"), "rope_k");
        assert_eq!(module_of("L3/residual/mid/s"), "residual_mid");
        assert_eq!(module_of("L3/residual/out/s"), "residual_out");
        assert_eq!(module_of("L0/gated/up"), "gated");
        assert_eq!(module_of("L0/gated/row/scale"), "gated_row");
        assert_eq!(module_of("G/norm/S_0"), "norm");
        assert_eq!(module_of("G/row/scale"), "row");
        assert_eq!(module_of("G/head/acc"), "head");
        assert_eq!(module_of("G/argmax/m"), "argmax");
    }

    #[test]
    fn accepts_distinct_checks_for_duplicate_table_names_and_range_collision() {
        use stele_reductions::stele_ir::relation::{Lookup, Range, Ref, Table};

        let mut rel = Relation::default();
        let g = rel.add_group("g", 2);
        let c0 = rel.add_column("L0/gated/x", Kind::Witness(g), Width::unsigned(4), 2);
        let c1 = rel.add_column("L1/gated/x", Kind::Witness(g), Width::unsigned(4), 2);
        let c2 = rel.add_column("L0/q/byte", Kind::Witness(g), Width::unsigned(8), 2);
        let t0 = rel.add_table(Table {
            name: "silu_q".into(),
            widths: vec![Width::unsigned(4)],
            rows: vec![vec![0], vec![1]],
        });
        let t1 = rel.add_table(Table {
            name: "silu_q".into(),
            widths: vec![Width::unsigned(4)],
            rows: vec![vec![0], vec![2]],
        });
        let t_range_name = rel.add_table(Table {
            name: "range_8".into(),
            widths: vec![Width::unsigned(4)],
            rows: vec![vec![0], vec![3]],
        });
        rel.lookups.push(Lookup {
            name: "L0/gated/l".into(),
            vars: 2,
            selector: None,
            tuple: vec![Ref {
                column: c0,
                vars: vec![0, 1],
            }],
            table: t0,
        });
        rel.lookups.push(Lookup {
            name: "L1/gated/l".into(),
            vars: 2,
            selector: None,
            tuple: vec![Ref {
                column: c1,
                vars: vec![0, 1],
            }],
            table: t1,
        });
        rel.lookups.push(Lookup {
            name: "L0/gated/r".into(),
            vars: 2,
            selector: None,
            tuple: vec![Ref {
                column: c0,
                vars: vec![0, 1],
            }],
            table: t_range_name,
        });
        rel.ranges.push(Range {
            name: "L0/q/byte/range".into(),
            column: c2,
            width: Width::unsigned(8),
        });
        let acc = account_relation(&rel, 4).expect("account");
        assert_eq!(
            acc.lookups_by_check,
            vec![
                ("silu_q".into(), 4),
                ("silu_q".into(), 4),
                ("range_8".into(), 4),
                ("range_8".into(), 4),
            ]
        );
        assert_eq!(acc.lookup_positions, 16);
    }

    #[test]
    fn matches_reference_e17_01_engine_counters_on_l0_and_l1_fixtures() {
        const RAW: &[u8] = include_bytes!("../tests/fixtures/synthetic-e2e.bin");
        const JSON: &str = include_str!("../tests/fixtures/synthetic-e2e.json");
        let parsed: serde_json::Value = serde_json::from_str(JSON).expect("fixture json");
        let cases = parsed["cases"].as_array().expect("cases");
        let span = |case: &serde_json::Value, key: &str| {
            let o = case[key]["offset"].as_u64().expect("offset") as usize;
            let l = case[key]["length"].as_u64().expect("length") as usize;
            &RAW[o..o + l]
        };

        // Exact parity with live E17-01 prove_window_development_measured on `one-layer` (L0).
        let one = cases
            .iter()
            .find(|c| c["name"] == "one-layer")
            .expect("one-layer");
        let m_raw = span(one, "model");
        let p_raw = span(one, "preparation");
        let s_raw = span(one, "scales");
        let a_raw = span(one, "artifact");
        let model = Model::decode(m_raw).expect("model");
        let scales = Scales::decode(&model, s_raw).expect("scales");
        let vecs = extract_vectors_from_artifact(&model, a_raw).expect("vectors");
        let stmt = Statement {
            tokens: vec![1u32],
            start: 0,
            end: 4,
            next: None,
        };
        let (_, _, _, report) =
            prove_window_development_measured(m_raw, p_raw, s_raw, a_raw, stmt, 4, 3)
                .expect("prove one-layer");
        let acc = account_model(&model, &scales, Some(&vecs), 4, 0..4).expect("acc");
        assert_eq!(acc.committed_cells, report.engine.committed_cells);
        assert_eq!(acc.lookup_positions, report.engine.lookup_positions);
        assert_eq!(acc.lookups_by_check, report.engine.lookup_checks);

        // Exact parity with the pinned E17-01 L1 ledger (`eight-layer`, T = 64, checked 0..64).
        let eight = cases
            .iter()
            .find(|c| c["name"] == "eight-layer")
            .expect("eight-layer");
        let m8 = Model::decode(span(eight, "model")).expect("model8");
        let s8 = Scales::decode(&m8, span(eight, "scales")).expect("scales8");
        let v8 = extract_vectors_from_artifact(&m8, span(eight, "artifact")).expect("vecs8");
        let acc8 = account_model(&m8, &s8, Some(&v8), 64, 0..64).expect("acc8");
        // Verify exact totals match `bench/ledger/e17-01-dev-synthetic-8layer-24t.json`.
        let l1_ledger: serde_json::Value = serde_json::from_str(include_str!(
            "../../../bench/ledger/e17-01-dev-synthetic-8layer-24t.json"
        ))
        .expect("l1 ledger");
        let kc = &l1_ledger["kernel_counters"];
        assert_eq!(
            acc8.committed_cells,
            kc["committed_cells"].as_u64().expect("committed_cells")
        );
        assert_eq!(
            acc8.lookup_positions,
            kc["lookup_positions"].as_u64().expect("lookup_positions")
        );
        // Also verify every per-check counter matches E17-01 in exact check order and count.
        let kc_check_count = kc
            .as_object()
            .expect("kc object")
            .keys()
            .filter(|k| k.starts_with("lookup_positions_check_"))
            .count();
        assert_eq!(acc8.lookups_by_check.len(), 21);
        assert_eq!(acc8.lookups_by_check.len(), kc_check_count);
        for (i, (name, pos)) in acc8.lookups_by_check.iter().enumerate() {
            let mut sanitized = String::with_capacity(name.len());
            let mut prev_sep = false;
            let push_sep = |out: &mut String, prev: &mut bool| {
                if !*prev && !out.is_empty() {
                    out.push('_');
                    *prev = true;
                }
            };
            for ch in name.chars() {
                if ch.is_ascii_alphanumeric() {
                    sanitized.push(ch.to_ascii_lowercase());
                    prev_sep = false;
                } else if ch == '-' {
                    push_sep(&mut sanitized, &mut prev_sep);
                    sanitized.push_str("neg_");
                    prev_sep = true;
                } else {
                    push_sep(&mut sanitized, &mut prev_sep);
                }
            }
            while sanitized.ends_with('_') {
                sanitized.pop();
            }
            let suffix = if sanitized.is_empty() {
                "unnamed"
            } else {
                &sanitized
            };
            let key = format!("lookup_positions_check_{i}_{suffix}");
            assert_eq!(
                Some(*pos),
                kc[&key].as_u64(),
                "mismatch on E17-01 check counter {key}"
            );
        }
        // Prefix checked window (checked.end < length -> next = None) is accepted (F3).
        let acc_prefix = account_model(&m8, &s8, Some(&v8), 64, 4..32).expect("prefix checked");
        assert_eq!(acc_prefix.tokens, 64);
        assert!(acc_prefix.committed_cells > 0);
        // Compose attribution: GatedProduct's `L{l}/gated/up` belongs to `gated`, not `up` (F4).
        assert_eq!(acc8.by_module["up"].composes, 0);
        assert!(acc8.by_module["gated"].composes >= 8);
        assert!(acc8.by_module.contains_key("gated_row"));
        assert_eq!(
            acc8.by_module["gated"].composes + acc8.by_module["gated_row"].composes,
            24
        );
        // Artifact header and length validation rejects wrong magic, short header,
        // wrong record count, or truncated slice (N2/F3).
        let mut bad_magic = a_raw.to_vec();
        bad_magic[0] ^= 0xFF;
        assert!(extract_vectors_from_artifact(&model, &bad_magic).is_err());
        assert!(extract_vectors_from_artifact(&model, &a_raw[..a_raw.len() - 1]).is_err());
        let meta = artifact_meta(&model).expect("meta");
        assert!(validate_artifact_header(
            &a_raw[..ARTIFACT_HEADER_LEN - 1],
            meta.byte_length,
            &meta
        )
        .is_err());
        let mut bad_count = a_raw[..ARTIFACT_HEADER_LEN].to_vec();
        bad_count[ARTIFACT_HEADER_LEN - 1] ^= 0x01;
        assert!(validate_artifact_header(&bad_count, meta.byte_length, &meta).is_err());
        // Placeholder (vectors = None) mode and context overflow rejection (F2/F3).
        let acc_placeholder = account_model(&model, &scales, None, 4, 0..4).expect("placeholder");
        assert!(acc_placeholder.committed_cells >= acc.committed_cells);
        let over_ctx = (model.shape().context() as usize).next_power_of_two() * 2;
        assert!(matches!(
            account_model(&model, &scales, Some(&vecs), over_ctx, 0..over_ctx),
            Err(Error::StatementMismatch)
        ));
        // Non-power-of-two window length is rejected per RFC-0026 §1.3.
        assert!(matches!(
            account_model(&m8, &s8, Some(&v8), 5, 1..5),
            Err(Error::UnsupportedModel)
        ));
        // Smaller power-of-two window (T = 16) is accounted without proving.
        let acc16 = account_model(&m8, &s8, Some(&v8), 16, 4..16).expect("acc16");
        assert_eq!(acc16.tokens, 16);
        assert!(acc16.committed_cells < acc8.committed_cells);
        // Wide int24 + GQA + grouped gated FFN fixture is accounted cleanly.
        let wide = cases
            .iter()
            .find(|c| c["name"] == "one-layer-wide-gqa")
            .expect("one-layer-wide-gqa");
        let mw = Model::decode(span(wide, "model")).expect("wide model");
        let sw = Scales::decode(&mw, span(wide, "scales")).expect("wide scales");
        let vw = extract_vectors_from_artifact(&mw, span(wide, "artifact")).expect("wide vecs");
        let accw = account_model(&mw, &sw, Some(&vw), 4, 0..4).expect("wide acc");
        assert_eq!(
            accw.by_module
                .values()
                .map(|m| m.committed_cells)
                .sum::<u64>(),
            accw.committed_cells
        );
        // Sum of per-module cells and lookups must equal the global totals exactly.
        let mod_cells: u64 = acc8.by_module.values().map(|m| m.committed_cells).sum();
        let mod_lookups: u64 = acc8.by_module.values().map(|m| m.lookup_positions).sum();
        let width_lookups: u64 = acc8.lookups_by_width.values().sum();
        assert_eq!(mod_cells, acc8.committed_cells);
        assert_eq!(mod_lookups, acc8.lookup_positions);
        assert_eq!(width_lookups, acc8.lookup_positions);
    }
}
