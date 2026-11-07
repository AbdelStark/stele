//! RFC-0004 A15 / RFC-0025 A2: native grouped activation rows against the research reference.
use serde_json::Value;
use stele_cqis::{
    bounds::arithmetic::{self, Affine, Record, Row, Weight},
    execution::{Error, Executor, Request},
    model::{self, Bounds, Model, Preparation, Registry, Scales},
    row::{self, Quantiser},
};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/grouped-rows.json")).expect("fixtures")
}
fn bytes(span: &Value) -> &'static [u8] {
    let raw = include_bytes!("fixtures/grouped-rows.bin");
    let offset = span["offset"].as_u64().expect("offset") as usize;
    let length = span["length"].as_u64().expect("length") as usize;
    &raw[offset..offset + length]
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn numbers(v: &Value) -> Vec<i64> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_i64().expect("integer"))
        .collect()
}
fn grouped(dimension: u16, kind: u8, group: u32) -> Row {
    Row {
        dimension,
        kind,
        fraction: 7,
        policy: 2,
        scale: group,
    }
}

#[test]
fn matches_reference_grouped_conversions() {
    for c in fixtures()["conversions"].as_array().expect("conversions") {
        let input = numbers(&c["input"]);
        let kind = c["kind"].as_u64().expect("kind") as u8;
        let q = Quantiser::new(grouped(
            input.len() as u16,
            kind,
            c["group"].as_u64().expect("g") as u32,
        ))
        .expect("grouped parameters");
        let row = if kind == 0 {
            let x: Vec<i16> = input.iter().map(|v| *v as i16).collect();
            q.convert_wide(&x)
        } else {
            let x: Vec<i32> = input.iter().map(|v| *v as i32).collect();
            q.convert_gated(&x)
        }
        .expect("reference accepts");
        let codes: Vec<i64> = row.codes().iter().map(|v| i64::from(*v)).collect();
        let scales: Vec<i64> = row.scales().iter().map(|v| i64::from(*v)).collect();
        assert_eq!(codes, numbers(&c["codes"]));
        assert_eq!(scales, numbers(&c["scales"]));
        assert_eq!(row.maximum(), None);
    }
    // g must be a power of two below n that divides n (research `Scale`).
    for c in fixtures()["bad_conversions"].as_array().expect("bad") {
        let p = grouped(
            c["dimension"].as_u64().expect("n") as u16,
            0,
            c["group"].as_u64().expect("g") as u32,
        );
        assert_eq!(
            Quantiser::new(p).err(),
            Some(row::Error::Bounds(arithmetic::Error::Parameters))
        );
    }
    // Ungrouped rows keep one scale.
    let q = Quantiser::new(Row {
        policy: 0,
        scale: 0,
        ..grouped(4, 0, 0)
    })
    .expect("dynamic");
    let r = q.convert_wide(&[254, -1, 0, 3]).expect("row");
    assert_eq!((r.scales(), r.scale()), (&[2][..], 2));
}

#[test]
fn matches_reference_schema_23_24_25_records() {
    for r in fixtures()["records"].as_array().expect("records") {
        let p = numbers(&r["parameters"]);
        let record = if r["kind"] == "Row" {
            Record::row(Row {
                dimension: p[0] as u16,
                kind: p[1] as u8,
                fraction: p[2] as u8,
                policy: p[3] as u8,
                scale: p[4] as u32,
            })
        } else {
            let affine = Affine {
                source: Row {
                    dimension: p[0] as u16,
                    kind: p[4] as u8,
                    fraction: p[5] as u8,
                    policy: p[7] as u8,
                    scale: p[8] as u32,
                },
                weight: Weight {
                    bits: p[1] as u8,
                    exponent: p[2] as i16,
                    mantissa: p[3] as u16,
                },
                output_fraction: p[6] as u8,
                bias_fraction: (p[9] >= 0).then_some(p[9] as u8),
            };
            if p[10] == 24 {
                Record::wide_affine(affine)
            } else {
                Record::affine(affine)
            }
        }
        .expect("reference record");
        let raw = record.as_bytes();
        assert_eq!(raw.len() as u64, r["length"].as_u64().expect("length"));
        assert_eq!(u64::from(raw[36]), r["schema"].as_u64().expect("schema"));
        assert_eq!(
            blake3::hash(raw).to_hex().as_str(),
            r["digest"].as_str().expect("digest")
        );
    }
    // A single group is mode 0: g = n has no grouped encoding.
    assert_eq!(
        Record::row(grouped(4, 0, 4)),
        Err(arithmetic::Error::Parameters)
    );
    let affine = Affine {
        source: grouped(6, 0, 4),
        weight: Weight {
            bits: 8,
            exponent: 0,
            mantissa: 1,
        },
        output_fraction: 0,
        bias_fraction: None,
    };
    assert_eq!(Record::affine(affine), Err(arithmetic::Error::Parameters));
}

#[test]
fn rejects_invalid_grouped_policies() {
    let data = fixtures();
    let invalid = data["invalid"].as_array().expect("invalid");
    assert_eq!(invalid.len(), 8);
    for case in invalid {
        assert_eq!(
            Model::decode(bytes(&case["model"])),
            Err(model::Error::Policy),
            "{}",
            case["reason"]
        );
    }
}

#[test]
fn matches_reference_grouped_registry_bounds_and_execution() {
    let data = fixtures();
    let (mut static_cases, mut accepted, mut rejected) = (0, 0, 0);
    for case in data["cases"].as_array().expect("cases") {
        let model = Model::decode(bytes(&case["model"])).expect("Model");
        assert_ne!(
            model.identity().as_slice(),
            hex(case["ungrouped_model_id"].as_str().expect("id"))
        );
        let prep = Preparation::decode(&model, bytes(&case["preparation"])).expect("Preparation");
        let scales = Scales::decode(&model, bytes(&case["scales"])).expect("Scales");
        if !case["registry"].is_null() {
            let registry = Registry::new(&model).expect("Registry");
            assert_eq!(registry.as_bytes(), bytes(&case["registry"]));
            let b = Bounds::new(&model, &scales, &registry).expect("grouped Bounds");
            assert_eq!(
                b.identity().as_slice(),
                hex(case["bounds_id"].as_str().expect("Bounds id"))
            );
            assert_eq!(
                b.byte_length(),
                case["bounds_length"].as_u64().expect("len")
            );
            static_cases += 1;
        }
        let expected = hex(case["artifact_id"].as_str().expect("Artifact id"));
        let expected: [u8; 32] = expected.try_into().expect("digest");
        let raw = bytes(&case["artifact"]);
        let mut executor =
            Executor::new(&model, &prep, &scales, raw, &expected, 1 << 30).expect("complete load");
        let tokens: Vec<u32> = numbers(&case["tokens"]).iter().map(|v| *v as u32).collect();
        let full = executor.full(&tokens);
        if let Some(reason) = case["expected"].as_str() {
            let expected = match reason {
                "Range" => Some(Error::Range),
                "RowRange" => Some(Error::Row(row::Error::Range)),
                "ExpDomain" => Some(Error::ExpDomain),
                _ => None,
            };
            assert_eq!(Some(full.expect_err("reference rejection")), expected);
            rejected += 1;
            continue;
        }
        let full = full.expect("complete evaluation");
        accepted += 1;
        let cuts: Vec<u8> = full
            .cuts()
            .iter()
            .flatten()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let logits: Vec<u8> = full
            .logits()
            .iter()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(cuts, bytes(&case["expected"]["cuts"]));
        assert_eq!(logits, bytes(&case["expected"]["logits"]));
        let cache: Vec<u8> = full
            .cache()
            .layers()
            .iter()
            .flatten()
            .flat_map(|(k, v)| [k, v])
            .flat_map(|row| {
                let mut raw = row.scale().to_le_bytes().to_vec();
                raw.push(row.fraction());
                raw.extend(row.codes().iter().map(|v| *v as u8));
                raw
            })
            .collect();
        assert_eq!(cache, bytes(&case["expected"]["cache"]));
        let mut state = None;
        for (position, token) in tokens.iter().enumerate() {
            let (step, next) = executor.step(*token, state.as_ref()).expect("step");
            for (layer, row) in step.cuts().iter().enumerate() {
                assert_eq!(*row, full.cuts()[layer][position]);
            }
            assert_eq!(step.logits(), full.logits()[position]);
            state = Some(next);
        }
        assert_eq!(state.as_ref(), Some(full.cache()));
        for g in case["generations"].as_array().expect("generations") {
            let request = Request::decode(&model, bytes(&g["request"])).expect("request");
            let prompt: Vec<u32> = numbers(&g["prompt"]).iter().map(|v| *v as u32).collect();
            let seed = g["seed"].as_str().map(hex);
            let result = executor.generate(&request, &prompt, seed.as_deref());
            if let Some(reason) = g["expected"].as_str() {
                assert!(result.is_err(), "reference rejection {reason}");
                continue;
            }
            let result = result.expect("complete generation");
            let sequence: Vec<u32> = numbers(&g["expected"]["tokens"])
                .iter()
                .map(|v| *v as u32)
                .collect();
            assert_eq!(result.cache().tokens(), sequence);
            assert_eq!(
                u64::from(result.reason()),
                g["expected"]["reason"].as_u64().expect("reason")
            );
            assert_eq!(
                result.cache(),
                executor.full(&sequence).expect("replay").cache()
            );
        }
    }
    assert!(static_cases == 6 && accepted >= 24 && rejected > 0);
}
