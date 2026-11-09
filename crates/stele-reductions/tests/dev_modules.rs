//! RFC-0026 §5 rows 1-2 on the stele-cqis model-execution fixtures: honest values come
//! from `Executor::capture` (task E16-03). The embedding module accepts the captured `R0`
//! and the rmsnorm_q module accepts every captured first, second and final norm row,
//! for every family-1 fixture.
use stele_cqis::execution::capture::{Norm, Quantised};
use stele_cqis::execution::Executor;
use stele_cqis::functions::Descriptor;
use stele_cqis::model::{ArtifactLayout, Model, Preparation, Role, Scales};
use stele_ir::relation::{check, Kind, Module, Relation, Values, Width};
use stele_reductions::development::embedding::{Embedding, EmbeddingCapture, EmbeddingPlan};
use stele_reductions::development::rmsnorm::{RmsNorm, RmsNormPlan, RmsNormRow};

const RAW: &[u8] = include_bytes!("../../stele-cqis/tests/fixtures/model-execution.bin");
const JSON: &str = include_str!("../../stele-cqis/tests/fixtures/model-execution.json");

/// The text after `"key":` in one fixture case (the fixture JSON is compact).
fn after<'a>(case: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{key}\":");
    &case[case.find(&pattern).expect("key") + pattern.len()..]
}

fn number(text: &str) -> usize {
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("number")
}

fn bytes(case: &str, key: &str) -> &'static [u8] {
    let span = after(case, key);
    let offset = number(after(span, "offset"));
    let length = number(after(span, "length"));
    &RAW[offset..offset + length]
}

fn hex32(s: &str) -> [u8; 32] {
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("digest"))
}

/// Decoded codes of every artifact record, by (role, layer), as `Data::code` reads them.
fn records(model: &Model, artifact: &[u8]) -> Vec<(Role, Option<u16>, u8, Vec<i16>)> {
    let layout = ArtifactLayout::new(model).expect("layout");
    layout
        .records()
        .iter()
        .map(|r| {
            let physical = model.shape().physical(r.ordinal()).expect("physical");
            let raw = &artifact[r.payload_offset() as usize..][..r.payload_length() as usize];
            let codes = (0..r.elements() as usize)
                .map(|i| match r.bits() {
                    16 => i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]),
                    8 => i16::from(raw[i] as i8),
                    _ => {
                        let n = (raw[i / 2] >> (4 * (i % 2))) & 15;
                        i16::from(n) - if n >= 8 { 16 } else { 0 }
                    }
                })
                .collect();
            (physical.role(), physical.layer(), r.bits(), codes)
        })
        .collect()
}

fn padded(rows: &[Vec<i64>], width: usize) -> Vec<i64> {
    let stride = width.next_power_of_two();
    let mut out = vec![0; rows.len() * stride];
    for (t, row) in rows.iter().enumerate() {
        out[t * stride..t * stride + row.len()].copy_from_slice(row);
    }
    out
}

#[test]
fn accepts_executor_embedding_and_rmsnorm_on_family_one_fixtures() {
    let mut checked = 0;
    for case in JSON.split("{\"model\":").skip(1) {
        let case = format!("{{\"model\":{case}");
        let case = case.as_str();
        let model = Model::decode(bytes(case, "model")).expect("Model");
        // An oracle rejection has a string reason instead of expected cuts.
        if model.shape().family() != 1 || after(case, "expected").starts_with('"') {
            continue;
        }
        let prep = Preparation::decode(&model, bytes(case, "preparation")).expect("Preparation");
        let scales = Scales::decode(&model, bytes(case, "scales")).expect("Scales");
        let artifact = bytes(case, "artifact");
        let expected = hex32(&after(case, "artifact_id")[1..65]);
        let mut executor =
            Executor::new(&model, &prep, &scales, artifact, &expected, 1 << 30).expect("load");
        let list = after(case, "tokens");
        let tokens: Vec<u32> = list[1..list.find(']').expect("tokens")]
            .split(',')
            .map(|v| v.parse().expect("token"))
            .collect();
        // Rows are causal and position-independent here, so a power-of-two prefix suffices.
        let tokens = &tokens[..1 << tokens.len().ilog2()];
        let capture = executor.capture(tokens).expect("evaluation");
        let records = records(&model, artifact);
        let shape = model.shape();
        let d = usize::from(shape.width());
        let xbits = if model.wide() { 24 } else { 16 };

        // Row 1: the embedding against the captured R_0 (token code x mantissa, rounded).
        let (_, _, bits, embedding) = &records[0];
        let matrix = scales.matrix(0).expect("token scale");
        let plan = EmbeddingPlan {
            tokens: tokens.to_vec(),
            vocabulary: shape.vocabulary(),
            width: shape.width(),
            code_bits: *bits,
            mantissas: matrix.mantissas().to_vec(),
            exponent: matrix.exponent(),
            fraction: model.initial_fraction(),
        };
        let gathered = EmbeddingCapture {
            codes: capture
                .embedding
                .iter()
                .map(|e| {
                    let m = i128::from(matrix.mantissas()[e.token as usize]);
                    e.token_term.iter().map(|&p| (p / m) as i16).collect()
                })
                .collect(),
            output: capture
                .embedding
                .iter()
                .map(|e| e.output.quotient.iter().map(|&v| v as i16).collect())
                .collect(),
        };
        let mut relation = Relation::default();
        let mut module = Embedding::new(plan, "G/embedding").expect("plan");
        module.declare(&mut relation);
        let mut values = Values::new(&relation);
        let weights: Vec<Vec<i64>> = embedding
            .chunks(d)
            .map(|r| r.iter().map(|&v| i64::from(v)).collect())
            .collect();
        let mut weights = padded(&weights, d);
        weights.resize(
            d.next_power_of_two() * (shape.vocabulary() as usize).next_power_of_two(),
            0,
        );
        values
            .set(&relation, module.weight().expect("E"), weights)
            .expect("weights");
        module
            .assign(&relation, &gathered, &mut values)
            .expect("assign");
        check(&relation, &values).expect("embedding fixture passes");
        assert_eq!(capture.embedding.len(), tokens.len());
        // The captured codes are the committed embedding rows.
        for (t, row) in gathered.codes.iter().enumerate() {
            assert_eq!(row[..], embedding[tokens[t] as usize * d..][..d]);
        }

        // Row 2: every first, second and final norm, from the captured columns.
        let mut norms: Vec<(Descriptor, Vec<(&Norm, &Quantised)>)> = Vec::new();
        for (l, block) in model.blocks().iter().enumerate() {
            let rows = &capture.blocks[l];
            norms.push((
                *block.first_norm().function(),
                rows.iter().map(|b| (&b.first_norm, &b.first_row)).collect(),
            ));
            norms.push((
                *block.second_norm().function(),
                rows.iter()
                    .map(|b| (&b.second_norm, &b.second_row))
                    .collect(),
            ));
        }
        norms.push((
            *model.final_norm().function(),
            capture.head.iter().map(|h| (&h.norm, &h.row)).collect(),
        ));
        for (descriptor, captured) in norms {
            let rows: Vec<RmsNormRow> = captured
                .iter()
                .map(|(n, y)| RmsNormRow {
                    input: n.input.iter().map(|&x| x as i32).collect(),
                    exponent: n.exponent as i8,
                    mantissa: n.mantissa.quotient[0] as u16,
                    reciprocal: n.reciprocal.output[0] as u16,
                    divisor: n.mantissa.divisor[0] as i128,
                    remainder: n.mantissa.remainder[0],
                    output: y.input.iter().map(|&v| v as i16).collect(),
                })
                .collect();
            let gains: Vec<i16> = captured[0].0.gain.iter().map(|&h| h as i16).collect();
            let mut relation = Relation::default();
            let log = (tokens.len() * d.next_power_of_two()).trailing_zeros() as u8;
            let group = relation.add_group("L0/residual", log);
            let x = relation.add_column("R", Kind::Witness(group), Width::signed(xbits), log);
            let plan = RmsNormPlan {
                descriptor,
                gains,
                rows: tokens.len(),
            };
            let mut module = RmsNorm::new(plan, x, "L0/norm1").expect("plan");
            module.declare(&mut relation);
            let mut values = Values::new(&relation);
            let input: Vec<Vec<i64>> = rows
                .iter()
                .map(|r| r.input.iter().map(|&v| i64::from(v)).collect())
                .collect();
            values.set(&relation, x, padded(&input, d)).expect("input");
            module
                .assign(&relation, &rows, &mut values)
                .expect("assign");
            check(&relation, &values).expect("norm fixture passes");
        }
        checked += 1;
    }
    assert!(checked > 0, "at least one family-1 fixture");
    eprintln!("family-1 fixtures checked: {checked}");
}
