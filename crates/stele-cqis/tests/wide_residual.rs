//! RFC-0004 A14 / RFC-0021 A4: native wide int24 residual against the research reference.
use serde_json::Value;
use stele_cqis::{
    bounds::arithmetic::{Affine, Record, Residual, Row, Weight},
    execution::{Error, Executor, Request},
    functions::{self, Descriptor, NormError},
    model::{self, Bounds, Model, Preparation, Registry, Scales},
};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/wide-residual.json")).expect("fixtures")
}
fn bytes(span: &Value) -> &'static [u8] {
    let raw = include_bytes!("fixtures/wide-residual.bin");
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
fn norm(p: &[i64], version: u32) -> Result<Descriptor, functions::Error> {
    let mut raw = (p[0] as u16).to_le_bytes().to_vec();
    raw.extend([p[1] as u8, p[2] as u8, p[3] as u8]);
    raw.extend((p[4] as u32).to_le_bytes());
    raw.extend((p[5] as u32).to_le_bytes());
    Descriptor::new("rmsnorm_q", version, &raw)
}

#[test]
fn matches_reference_version_two_function_identities() {
    for f in fixtures()["functions"].as_array().expect("functions") {
        let raw = hex(f["descriptor"].as_str().expect("descriptor"));
        let d = Descriptor::decode(&raw).expect("rmsnorm_q");
        assert_eq!(
            u64::from(d.version()),
            f["version"].as_u64().expect("version")
        );
        assert_eq!(
            d.parameters(),
            hex(f["parameters"].as_str().expect("params"))
        );
        assert_eq!(d.encode().expect("bytes").as_bytes(), raw);
        assert_eq!(
            d.identity().expect("id").as_slice(),
            hex(f["function_id"].as_str().expect("id"))
        );
    }
    // Version 2 admits d <= 8192 only; there is no version 3 or other version 2.
    assert!(norm(&[8192, 0, 0, 0, 1, 1], 2).is_ok());
    assert_eq!(
        norm(&[8193, 0, 0, 0, 1, 1], 2),
        Err(functions::Error::Parameters)
    );
    assert!(norm(&[16384, 0, 0, 0, 1, 1], 1).is_ok());
    assert_eq!(norm(&[1, 0, 0, 0, 1, 1], 3), Err(functions::Error::Version));
    assert_eq!(
        Descriptor::new("range_8", 2, &[]),
        Err(functions::Error::Version)
    );
}

#[test]
fn matches_reference_version_two_rows_and_rejects_domains() {
    for row in fixtures()["rows"].as_array().expect("rows") {
        let d = norm(&numbers(&row["parameters"]), 2).expect("descriptor");
        let input: Vec<i32> = numbers(&row["input"]).iter().map(|v| *v as i32).collect();
        let gain: Vec<i16> = numbers(&row["gain"]).iter().map(|v| *v as i16).collect();
        let result = d.evaluate_rmsnorm_wide(&input, &gain);
        let expected = &row["expected"];
        match expected.as_str() {
            Some(reason) => {
                assert_eq!(reason, "Overflow");
                assert_eq!(result, Err(NormError::Overflow));
            }
            None => {
                let r = result.expect("reference accepts");
                let out: Vec<i64> = r.outputs().iter().map(|v| i64::from(*v)).collect();
                assert_eq!(out, numbers(&expected["output"]));
                assert_eq!(r.statistic(), expected["statistic"].as_u64().expect("S"));
                assert_eq!(
                    i64::from(r.exponent()),
                    expected["exponent"].as_i64().expect("a")
                );
                assert_eq!(
                    u64::from(r.mantissa()),
                    expected["mantissa"].as_u64().expect("M")
                );
                assert_eq!(
                    u64::from(r.reciprocal()),
                    expected["reciprocal"].as_u64().expect("J")
                );
                assert_eq!(i64::from(r.shift()), expected["shift"].as_i64().expect("e"));
                let (a, d, rem) = r.normalized_ratio();
                assert_eq!(a, u128::from(r.mantissa()) * d + rem);
            }
        }
    }
    let p = [1, 0, 0, 0, 1, 1];
    let (v1, v2) = (norm(&p, 1).expect("v1"), norm(&p, 2).expect("v2"));
    // int24 X only at version 2; the int16 entry point is the same row at version 1.
    assert_eq!(
        v1.evaluate_rmsnorm_wide(&[32768], &[1]),
        Err(NormError::Domain)
    );
    assert_eq!(
        v2.evaluate_rmsnorm_wide(&[1 << 23], &[1]),
        Err(NormError::Domain)
    );
    assert_eq!(
        v2.evaluate_rmsnorm_wide(&[-(1 << 23) - 1], &[1]),
        Err(NormError::Domain)
    );
    assert!(v2.evaluate_rmsnorm_wide(&[-(1 << 23)], &[1]).is_ok());
    assert_eq!(
        v1.evaluate_rmsnorm_wide(&[-32768], &[7]),
        v1.evaluate_rmsnorm(&[-32768], &[7])
    );
    // RFC-0022's int16-only record has no version-2 form.
    assert_eq!(
        stele_cqis::bounds::Record::rmsnorm(v2),
        Err(stele_cqis::bounds::Error::Parameters)
    );
}

#[test]
fn matches_reference_schema_20_21_22_records() {
    for r in fixtures()["records"].as_array().expect("records") {
        let p = numbers(&r["parameters"]);
        let record = match r["kind"].as_str().expect("kind") {
            "RMSNorm" => Record::rmsnorm(norm(&p, p[6] as u32).expect("norm")),
            "Affine" => {
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
                    bias_fraction: None,
                };
                if p[9] == 24 {
                    Record::wide_affine(affine)
                } else {
                    Record::affine(affine)
                }
            }
            _ => {
                let residual = Residual {
                    dimension: p[0] as u16,
                    input_fractions: [p[1] as u8, p[2] as u8],
                    output_fraction: p[3] as u8,
                };
                if p[4] == 24 {
                    Record::wide_residual(residual)
                } else {
                    Record::residual(residual)
                }
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
    // A wide affine carries no bias: Llama projections have none.
    let biased = Affine {
        source: Row {
            dimension: 16,
            kind: 0,
            fraction: 0,
            policy: 0,
            scale: 0,
        },
        weight: Weight {
            bits: 8,
            exponent: 0,
            mantissa: 1,
        },
        output_fraction: 0,
        bias_fraction: Some(0),
    };
    assert!(Record::affine(biased).is_ok());
    assert_eq!(
        Record::wide_affine(biased),
        Err(stele_cqis::bounds::arithmetic::Error::Parameters)
    );
}

#[test]
fn rejects_mixed_norm_versions_with_width() {
    let data = fixtures();
    assert_eq!(
        Model::decode(bytes(&data["mixed"])),
        Err(model::Error::Width)
    );
    let wide = Model::decode(bytes(&data["cases"][0]["model"])).expect("wide Model");
    assert!(wide.wide());
}

#[test]
fn matches_reference_wide_registry_bounds_and_execution() {
    let data = fixtures();
    let (mut static_cases, mut accepted, mut beyond) = (0, 0, 0);
    for case in data["cases"].as_array().expect("cases") {
        let model = Model::decode(bytes(&case["model"])).expect("Model");
        assert!(model.wide());
        let prep = Preparation::decode(&model, bytes(&case["preparation"])).expect("Preparation");
        let scales = Scales::decode(&model, bytes(&case["scales"])).expect("Scales");
        if !case["registry"].is_null() {
            let registry = Registry::new(&model).expect("Registry");
            assert_eq!(registry.as_bytes(), bytes(&case["registry"]));
            let b = Bounds::new(&model, &scales, &registry).expect("wide Bounds");
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
                "RowRange" => Some(Error::Row(stele_cqis::row::Error::Range)),
                "ExpDomain" => Some(Error::ExpDomain),
                _ => None,
            };
            assert_eq!(Some(full.expect_err("reference rejection")), expected);
            continue;
        }
        let full = full.expect("complete evaluation");
        accepted += 1;
        // R_0 stays int16; every cut is within int24.
        assert!(full.cuts()[0]
            .iter()
            .flatten()
            .all(|v| i16::try_from(*v).is_ok()));
        assert!(full
            .cuts()
            .iter()
            .flatten()
            .flatten()
            .all(|v| (-(1 << 23)..1 << 23).contains(v)));
        beyond += usize::from(
            full.cuts()
                .iter()
                .flatten()
                .flatten()
                .any(|v| i16::try_from(*v).is_err()),
        );
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
    assert!(static_cases > 0 && accepted > 0 && beyond > 0);
}
