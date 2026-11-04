//! RFC-0025 static §§1–5 and flow §§1–3: exact native records from separate parameters.
use serde_json::Value;
use stele_cqis::bounds::{
    arithmetic::{Affine, Embedding, Gated, Record, Residual, Row, Weight},
    Error,
};
use stele_cqis::functions::Descriptor;

fn derive(kind: &str, p: &Value) -> Result<Record, Error> {
    let n = |key: &str| p[key].as_u64().expect("unsigned parameter");
    let row = || Row {
        dimension: n(if kind == "Affine" { "inner" } else { "d" }) as u16,
        kind: n("kind") as u8,
        fraction: n("fraction") as u8,
        policy: n("policy") as u8,
        scale: n("scale") as u32,
    };
    match kind {
        "LayerNorm" | "RMSNorm" => {
            let mut params = (n("d") as u16).to_le_bytes().to_vec();
            params.extend([n("F") as u8, n("G") as u8, n("E") as u8]);
            if kind == "LayerNorm" {
                params.push(n("Gb") as u8);
            }
            params.extend((n("en") as u32).to_le_bytes());
            params.extend((n("ed") as u32).to_le_bytes());
            let name = if kind == "LayerNorm" {
                "layernorm_q"
            } else {
                "rmsnorm_q"
            };
            let descriptor = Descriptor::new(name, 1, &params).map_err(|_| Error::Parameters)?;
            if kind == "LayerNorm" {
                Record::layernorm(descriptor)
            } else {
                Record::rmsnorm(descriptor)
            }
        }
        "Affine" => Record::affine(Affine {
            source: row(),
            weight: Weight {
                bits: n("bits") as u8,
                exponent: p["exponent"].as_i64().expect("exponent") as i16,
                mantissa: n("mantissa") as u16,
            },
            output_fraction: n("output_fraction") as u8,
            bias_fraction: p["bias_fraction"].as_u64().map(|v| v as u8),
        }),
        "Embedding" => Record::embedding(Embedding {
            vocabulary: n("vocabulary") as u32,
            context: n("context") as u32,
            output_fraction: n("output_fraction") as u8,
            token: Weight {
                bits: n("bits") as u8,
                exponent: p["exponent"].as_i64().expect("exponent") as i16,
                mantissa: n("mantissa") as u16,
            },
            position: p["position"].as_array().map(|v| Weight {
                bits: v[0].as_u64().expect("bits") as u8,
                exponent: v[1].as_i64().expect("exponent") as i16,
                mantissa: v[2].as_u64().expect("mantissa") as u16,
            }),
        }),
        "Row" => Record::row(row()),
        "Residual" => Record::residual(Residual {
            dimension: n("d") as u16,
            input_fractions: [n("fx") as u8, n("fy") as u8],
            output_fraction: n("fo") as u8,
        }),
        "Gated" => Record::gated(Gated {
            dimension: n("d") as u16,
            up_fraction: n("fu") as u8,
            activation_fraction: n("E") as u8,
        }),
        _ => unreachable!("fixture kind"),
    }
}

#[test]
fn matches_reference_random_shapes_and_complete_boundary_records() {
    let data: Value = serde_json::from_str(include_str!("fixtures/arithmetic-records.json"))
        .expect("independent reference");
    let mut complete = include_bytes!("fixtures/arithmetic-records.bin").as_slice();
    let cases = data["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 1565);
    for case in cases {
        let record =
            derive(case["kind"].as_str().expect("kind"), &case["parameters"]).expect("record");
        let raw = record.as_bytes();
        assert_eq!(raw.len() as u64, case["length"].as_u64().expect("length"));
        assert_eq!(
            blake3::hash(raw).to_hex().as_str(),
            case["digest"].as_str().expect("digest")
        );
        if case["complete"].as_bool().expect("complete") {
            let length = u32::from_le_bytes(complete[..4].try_into().expect("length")) as usize;
            assert_eq!(raw, &complete[4..4 + length]);
            complete = &complete[4 + length..];
            // Exact regenerated comparison rejects every byte/length mutation,
            // including schema, prime, high zeros, all caps and final carries.
            let mut changed = raw.to_vec();
            for i in 0..raw.len() {
                changed[i] ^= 1;
                assert_eq!(record.validate_encoding(&changed), Err(Error::Encoding));
                changed[i] ^= 1;
                assert_eq!(record.validate_encoding(&raw[..i]), Err(Error::Encoding));
            }
            changed.push(0);
            assert_eq!(record.validate_encoding(&changed), Err(Error::Encoding));
            assert_eq!(record.validate_encoding(raw), Ok(()));
        }
    }
    assert!(complete.is_empty());
}

#[test]
fn rejects_invalid_domains_and_other_valid_parameter_authority() {
    let data: Value = serde_json::from_str(include_str!("fixtures/arithmetic-records.json"))
        .expect("independent reference");
    let cases = data["cases"].as_array().expect("cases");
    for case in cases.iter().filter(|c| c["complete"] == true) {
        let kind = case["kind"].as_str().expect("kind");
        let p = &case["parameters"];
        let expected = derive(kind, p).expect("expected");
        let key = match kind {
            "Affine" => "inner",
            "Embedding" => "vocabulary",
            _ => "d",
        };
        for bad in [
            0,
            if kind == "Embedding" {
                (1 << 20) + 1
            } else {
                16385
            },
        ] {
            let mut changed = p.clone();
            changed[key] = bad.into();
            assert_eq!(derive(kind, &changed), Err(Error::Parameters));
        }
        let mut changed = p.clone();
        changed[key] = if p[key] == 1 { 2.into() } else { 1.into() };
        let other = derive(kind, &changed).expect("other valid shape");
        assert_eq!(
            expected.validate_encoding(other.as_bytes()),
            Err(Error::Encoding)
        );
        assert_eq!(
            other.validate_encoding(expected.as_bytes()),
            Err(Error::Encoding)
        );
    }
    for (kind, key, value) in [
        ("Affine", "bits", 5),
        ("Affine", "exponent", -1100),
        ("Affine", "exponent", 1025),
        ("Affine", "mantissa", 0),
        ("Affine", "output_fraction", 31),
        ("Affine", "bias_fraction", 31),
        ("Embedding", "context", 0),
        ("Embedding", "output_fraction", 31),
        ("Row", "kind", 2),
        ("Row", "fraction", 31),
        ("Row", "policy", 2),
        ("Row", "scale", 1),
        ("Residual", "fx", 31),
        ("Residual", "fy", 31),
        ("Residual", "fo", 31),
        ("Gated", "fu", 31),
        ("Gated", "E", 15),
        ("LayerNorm", "F", 31),
        ("LayerNorm", "G", 31),
        ("LayerNorm", "E", 15),
        ("LayerNorm", "Gb", 31),
        ("LayerNorm", "en", 0),
        ("RMSNorm", "ed", 0),
    ] {
        let mut p = cases.iter().find(|c| c["kind"] == kind).expect("kind")["parameters"].clone();
        p[key] = value.into();
        assert_eq!(derive(kind, &p), Err(Error::Parameters), "{kind} {key}");
    }
    let wrong = Descriptor::new("range_16", 1, &[]).expect("different function");
    assert_eq!(Record::layernorm(wrong), Err(Error::Parameters));
    assert_eq!(Record::rmsnorm(wrong), Err(Error::Parameters));
}
