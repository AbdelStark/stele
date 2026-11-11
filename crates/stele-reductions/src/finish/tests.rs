//! Model boundary tests: the composed final norm, final row conversion, head and
//! greedy check against `Executor::capture`, a false claim and a tampered logit, and
//! static validity at the E16-10 shape.

use super::*;
use crate::residual::tests::{executor_captures, Fixture};
use alloc::vec;
use stele_cqis::model::{ArtifactLayout, Model, Role};
use stele_ir::relation::{check, Kind, Range, Width};

fn log2_ceil(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}

/// Signed codes of the artifact record `(role, layer)`, rows of `columns`, as the
/// executor's `Data::code` reads them; with its ordinal and bit width.
fn record(model: &Model, artifact: &[u8], role: Role) -> (u16, u8, Vec<i64>) {
    let layout = ArtifactLayout::new(model).expect("layout");
    let r = layout
        .records()
        .iter()
        .find(|r| {
            let p = model.shape().physical(r.ordinal()).expect("physical");
            p.role() == role && p.layer().is_none()
        })
        .expect("record");
    let raw = &artifact[r.payload_offset() as usize..][..r.payload_length() as usize];
    let codes = (0..r.elements() as usize)
        .map(|i| match r.bits() {
            16 => i64::from(i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]])),
            8 => i64::from(raw[i] as i8),
            _ => {
                let n = i64::from((raw[i / 2] >> (4 * (i % 2))) & 15);
                n - if n >= 8 { 16 } else { 0 }
            }
        })
        .collect();
    (r.ordinal(), r.bits(), codes)
}

fn policy(p: stele_cqis::model::Policy) -> Policy {
    match p.mode() {
        0 => Policy::Dynamic,
        1 => Policy::Static(p.scale()),
        _ => Policy::Grouped(p.scale()),
    }
}

/// `rows` padded to `2^log_rows × 2^log_lanes`, row-major.
fn padded(rows: &[Vec<i64>], log_lanes: u8) -> Vec<i64> {
    let mut out = vec![0; rows.len().next_power_of_two() << log_lanes];
    for (i, row) in rows.iter().enumerate() {
        out[i << log_lanes..][..row.len()].copy_from_slice(row);
    }
    out
}

struct Case {
    relation: Relation,
    values: Values,
    finish: Finish,
}

/// The model boundary of one fixture: `R_L` and the head weight assigned, the module
/// declared from Model/Scales plan data and assigned from the capture, claiming
/// `claims` (row `i` claims `claims[i]`).
fn case(f: &Fixture, claims: &[u32]) -> Option<Case> {
    let (model, capture) = (&f.model, &f.capture);
    let t = f.tokens.len();
    let d = usize::from(model.shape().width());
    let vocabulary = model.shape().vocabulary() as usize;
    let descriptor = *model.final_norm().function();
    let (_, _, gains) = record(model, f.artifact, Role::FinalGain);
    let gains: Vec<i16> = gains.iter().map(|g| *g as i16).collect();
    let (ordinal, bits, weights) = record(model, f.artifact, Role::Head);
    let matrix = f.scales.matrix(ordinal).expect("matrix");
    let fraction = descriptor.parameters()[4];
    let last: Vec<Vec<i32>> = capture.full().cuts().last().expect("cut").clone();
    let norm: Vec<RmsNormRow> = last
        .iter()
        .map(|x| {
            let e = descriptor.evaluate_rmsnorm_wide(x, &gains).expect("norm");
            RmsNormRow::new(x, &e)
        })
        .collect();
    for (row, head) in norm.iter().zip(&capture.head) {
        let output: Vec<i64> = row.output.iter().map(|v| i64::from(*v)).collect();
        assert_eq!(output, head.norm.output.quotient, "capture norm output");
    }
    let row = ConversionCapture {
        inputs: capture.head.iter().map(|h| h.row.input.clone()).collect(),
        codes: capture.head.iter().map(|h| h.row.codes.clone()).collect(),
        scales: capture.head.iter().map(|h| h.row.scales.clone()).collect(),
    };
    let head = ProjectionCapture {
        codes: row.codes.clone(),
        scales: row.scales.clone(),
        weights: weights.chunks(d).map(<[i64]>::to_vec).collect(),
        outputs: capture
            .head
            .iter()
            .map(|h| h.logits.output.quotient.clone())
            .collect(),
    };
    let plan = FinishPlan {
        norm: RmsNormPlan {
            descriptor,
            gains,
            rows: t,
            fixed_widths: false,
        },
        policy: policy(model.final_policy()),
        head: ProjectionPlan {
            rows: t,
            inner: d,
            outputs: vocabulary,
            weight_bits: bits,
            mantissas: matrix.mantissas().to_vec(),
            shift: i32::from(matrix.exponent()) - i32::from(fraction)
                + i32::from(model.logits_fraction()),
        },
        tied: None,
        tokens: core::iter::once(0)
            .chain(claims[..t - 1].iter().copied())
            .collect(),
        checked: (0, t),
        next: Some(claims[t - 1]),
    };
    let mut relation = Relation::default();
    let n = log2_ceil(t) + log2_ceil(d);
    let group = relation.add_group("L/residual/test", n);
    let input = relation.add_column("R_L", Kind::Witness(group), Width::signed(16), n);
    relation.ranges.push(Range {
        name: "R_L".into(),
        column: input,
        width: Width::signed(16),
    });
    let mut finish = Finish::new(plan, input, &relation).ok()?;
    finish.declare(&mut relation);
    let mut values = Values::new(&relation);
    let r: Vec<Vec<i64>> = last
        .iter()
        .map(|x| x.iter().map(|v| i64::from(*v)).collect())
        .collect();
    values
        .set(&relation, input, padded(&r, log2_ceil(d)))
        .expect("R_L");
    let weight = finish.columns().expect("declared").weight;
    values
        .set(&relation, weight, padded(&head.weights, log2_ceil(d)))
        .expect("weight");
    finish
        .assign(&relation, &FinishCapture { norm, row, head }, &mut values)
        .expect("assign");
    Some(Case {
        relation,
        values,
        finish,
    })
}

/// Every family-1 fixture with `T` a power of two: the executor's boundary passes
/// with its own greedy choices; claiming any other id on any row, or moving one logit,
/// is rejected.
#[test]
fn matches_executor_capture_fixtures() {
    let mut checked = 0;
    for f in executor_captures() {
        if !f.tokens.len().is_power_of_two() {
            continue;
        }
        let greedy: Vec<u32> = f.capture.head.iter().map(|h| h.argmax).collect();
        let case = case(&f, &greedy).expect("supported plan");
        assert_eq!(check(&case.relation, &case.values), Ok(()));
        let vocabulary = f.model.shape().vocabulary();
        for i in 0..greedy.len() {
            let mut claims = greedy.clone();
            claims[i] = (greedy[i] + 1) % vocabulary;
            if vocabulary > 1 {
                let wrong = self::case(&f, &claims).expect("plan");
                assert!(check(&wrong.relation, &wrong.values).is_err(), "row {i}");
            }
        }
        let logits = case.finish.columns().expect("declared").logits;
        let mut values = case.values.clone();
        let mut column = values.get(&case.relation, logits).expect("logits").to_vec();
        column[0] += 1;
        values.set(&case.relation, logits, column).expect("set");
        assert!(check(&case.relation, &values).is_err(), "tampered logit");
        checked += 1;
    }
    assert!(checked > 0, "a power-of-two family-1 fixture");
}

/// A tied head reads the embedding source declared by the E16-04 `Embedding` module
/// (`E`, V×d, untransposed) with the token embedding's codes and row mantissas
/// (RFC-0025 §2.5): no head weight is declared, and validate and check pass on the
/// executor's `R_L`, final norm and final row, with executor-equivalent logits.
#[test]
fn accepts_tied_head_on_embedding_source() {
    use crate::development::embedding::{Embedding, EmbeddingCapture, EmbeddingPlan};
    use crate::development::tests::affine;
    use stele_cqis::model::Role;
    let mut checked = 0;
    for f in executor_captures() {
        let t = f.tokens.len();
        if !t.is_power_of_two() {
            continue;
        }
        let (model, capture) = (&f.model, &f.capture);
        let (d, vocabulary) = (
            usize::from(model.shape().width()),
            model.shape().vocabulary() as usize,
        );
        let (token, bits, codes) = record(model, f.artifact, Role::Token);
        let embedding = f.scales.matrix(token).expect("token scale");
        let rows: Vec<Vec<i64>> = codes.chunks(d).map(<[i64]>::to_vec).collect();
        let descriptor = *model.final_norm().function();
        let fraction = descriptor.parameters()[4];
        let shift = i32::from(embedding.exponent()) - i32::from(fraction)
            + i32::from(model.logits_fraction());
        let row = ConversionCapture {
            inputs: capture.head.iter().map(|h| h.row.input.clone()).collect(),
            codes: capture.head.iter().map(|h| h.row.codes.clone()).collect(),
            scales: capture.head.iter().map(|h| h.row.scales.clone()).collect(),
        };
        // Executor-equivalent tied logits (`Data::affine` on the embedding source).
        let Some(logits) = affine(&row.codes, &row.scales, &rows, embedding.mantissas(), shift)
        else {
            continue;
        };
        let greedy: Vec<u32> = logits
            .iter()
            .map(|l| {
                let max = l.iter().max().expect("row");
                l.iter().position(|v| v == max).expect("max") as u32
            })
            .collect();

        let mut relation = Relation::default();
        let mut embed = Embedding::new(
            EmbeddingPlan {
                tokens: f.tokens.clone(),
                vocabulary: vocabulary as u32,
                width: model.shape().width(),
                code_bits: bits,
                mantissas: embedding.mantissas().to_vec(),
                exponent: embedding.exponent(),
                fraction: model.initial_fraction(),
            },
            "G/embedding",
        )
        .expect("embedding plan");
        embed.declare(&mut relation);
        let source = embed.weight().expect("E");
        let n = log2_ceil(t) + log2_ceil(d);
        let group = relation.add_group("L/residual/test", n);
        let input = relation.add_column("R_L", Kind::Witness(group), Width::signed(16), n);
        relation.ranges.push(Range {
            name: "R_L".into(),
            column: input,
            width: Width::signed(16),
        });
        let (_, _, gains) = record(model, f.artifact, Role::FinalGain);
        let gains: Vec<i16> = gains.iter().map(|g| *g as i16).collect();
        let plan = FinishPlan {
            norm: RmsNormPlan {
                descriptor,
                gains: gains.clone(),
                rows: t,
                fixed_widths: false,
            },
            policy: policy(model.final_policy()),
            head: ProjectionPlan {
                rows: t,
                inner: d,
                outputs: vocabulary,
                weight_bits: bits,
                mantissas: embedding.mantissas().to_vec(),
                shift,
            },
            tied: Some(source),
            tokens: core::iter::once(0)
                .chain(greedy[..t - 1].iter().copied())
                .collect(),
            checked: (0, t),
            next: Some(greedy[t - 1]),
        };
        let weights = relation
            .columns
            .iter()
            .filter(|c| c.kind == Kind::Weight)
            .count();
        let mut finish = Finish::new(plan, input, &relation).expect("tied plan");
        finish.declare(&mut relation);
        assert_eq!(finish.columns().expect("declared").weight, source);
        let after = relation
            .columns
            .iter()
            .filter(|c| c.kind == Kind::Weight)
            .count();
        assert_eq!(after, weights, "a tied head declares no weight source");
        relation.validate().expect("valid");

        let mut values = Values::new(&relation);
        let cut = |c: usize| -> Vec<Vec<i64>> {
            capture.full().cuts()[c]
                .iter()
                .map(|r| r.iter().map(|v| i64::from(*v)).collect())
                .collect()
        };
        values
            .set(&relation, source, {
                let mut e = padded(&rows, log2_ceil(d));
                e.resize(vocabulary.next_power_of_two() << log2_ceil(d), 0);
                e
            })
            .expect("E");
        embed
            .assign(
                &relation,
                &EmbeddingCapture {
                    codes: f
                        .tokens
                        .iter()
                        .map(|&x| rows[x as usize].iter().map(|&v| v as i16).collect())
                        .collect(),
                    output: cut(0)
                        .iter()
                        .map(|r| r.iter().map(|&v| v as i16).collect())
                        .collect(),
                },
                &mut values,
            )
            .expect("embedding");
        let last = capture.full().cuts().len() - 1;
        values
            .set(&relation, input, padded(&cut(last), log2_ceil(d)))
            .expect("R_L");
        let norm = capture.full().cuts()[last]
            .iter()
            .map(|x| {
                let e = descriptor.evaluate_rmsnorm_wide(x, &gains).expect("norm");
                RmsNormRow::new(x, &e)
            })
            .collect();
        let head = ProjectionCapture {
            codes: row.codes.clone(),
            scales: row.scales.clone(),
            weights: rows.clone(),
            outputs: logits,
        };
        finish
            .assign(&relation, &FinishCapture { norm, row, head }, &mut values)
            .expect("assign");
        assert_eq!(check(&relation, &values), Ok(()), "tied head");
        checked += 1;
    }
    assert!(checked > 0, "a fixture with in-range tied logits");
}

/// The E16-10 target shape validates: T = 64, d = 512, V = 256, from a fixture Model's
/// final norm descriptor resized to d.
#[test]
fn accepts_static_validity_e2e_shape() {
    let f = executor_captures().remove(0);
    let (t, d, vocabulary) = (64usize, 512usize, 256usize);
    let mut p = f.model.final_norm().function().parameters().to_vec();
    p[..2].copy_from_slice(&(d as u16).to_le_bytes());
    let descriptor =
        stele_cqis::functions::Descriptor::new("rmsnorm_q", 1, &p).expect("rmsnorm descriptor");
    let plan = FinishPlan {
        norm: RmsNormPlan {
            descriptor,
            gains: vec![1 << 8; d],
            rows: t,
            fixed_widths: false,
        },
        policy: Policy::Dynamic,
        head: ProjectionPlan {
            rows: t,
            inner: d,
            outputs: vocabulary,
            weight_bits: 8,
            mantissas: vec![1 << 15; vocabulary],
            shift: -20,
        },
        tied: None,
        tokens: vec![1; t],
        checked: (0, t),
        next: Some(2),
    };
    let mut relation = Relation::default();
    let n = log2_ceil(t) + log2_ceil(d);
    let group = relation.add_group("L/residual/test", n);
    let input = relation.add_column("R_L", Kind::Witness(group), Width::signed(16), n);
    relation.ranges.push(Range {
        name: "R_L".into(),
        column: input,
        width: Width::signed(16),
    });
    let mut finish = Finish::new(plan.clone(), input, &relation).expect("plan");
    finish.declare(&mut relation);
    relation.validate().expect("valid");
    // A token outside the vocabulary is a statement error, before any relation.
    // So is a token count that is not the row count, or not a power of two: 60 tokens
    // against 64 rows share log2 and would move the row checked against y.
    let mut short = plan.clone();
    short.tokens.truncate(60);
    let mut rows = plan.clone();
    rows.head.rows = 32;
    let bad = FinishPlan {
        next: Some(vocabulary as u32),
        ..plan
    };
    for bad in [bad, short, rows] {
        assert!(matches!(
            Finish::new(bad, input, &relation),
            Err(FinishError::Statement(_))
        ));
    }
}
