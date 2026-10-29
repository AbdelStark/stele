//! RFC-0021 §4: component metadata is not table-data or proof admission.
use stele_cqis::tables::{Descriptor, Error};

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex fixture"))
        .collect()
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../research/cqis-tables/table-identity-candidates.json"
    ))
    .expect("independent Python vectors")
}

#[test]
fn matches_reference_all_component_descriptors_and_identities() {
    let vectors = vectors();
    let cases = vectors["descriptors"].as_array().expect("cases");
    assert_eq!(cases.len(), 13);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let raw = hex(case["descriptor"].as_str().expect("descriptor"));
        let d = Descriptor::decode(&raw).expect("canonical descriptor");
        assert_eq!(d.name(), name);
        assert_eq!(d.version(), 1);
        assert_eq!(d.encode().expect("encoding").as_bytes(), raw);
        assert_eq!(
            d.identity().expect("identity").as_slice(),
            hex(case["table_id"].as_str().expect("identity"))
        );
        assert_eq!(Descriptor::new(name, 1, d.parameters()), Ok(d));
        if let Some(data) = vectors["data"]
            .as_array()
            .expect("data cases")
            .iter()
            .find(|data| data["name"] == name)
        {
            let shape = d.shape();
            assert_eq!(
                u64::from(shape.rows()),
                data["rows"].as_u64().expect("rows")
            );
            assert_eq!(
                u64::from(shape.padded()),
                data["padded"].as_u64().expect("padded")
            );
            assert_eq!(
                u64::from(shape.columns()),
                data["columns"].as_u64().expect("columns")
            );
        }
    }
}

#[test]
fn rejects_truncations_lengths_unknown_versions_and_trailing_bytes() {
    let vectors = vectors();
    for case in vectors["descriptors"].as_array().expect("cases") {
        let raw = hex(case["descriptor"].as_str().expect("bytes"));
        for length in 0..raw.len() {
            assert!(Descriptor::decode(&raw[..length]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(Descriptor::decode(&trailing), Err(Error::Encoding));
        let name_length = case["name"].as_str().expect("name").len();
        let name_start = b"stele/v0.1/table/identity".len() + 2;
        let mut changed = raw.clone();
        changed[name_start + name_length] = 2;
        assert_eq!(Descriptor::decode(&changed), Err(Error::Version));
        for offset in [name_start - 2, name_start + name_length + 4] {
            let mut changed = raw.clone();
            changed[offset..offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
            assert_eq!(Descriptor::decode(&changed), Err(Error::Encoding));
        }
        let mut changed = raw.clone();
        changed[name_start] = 0xff;
        assert_eq!(Descriptor::decode(&changed), Err(Error::Encoding));
        let mut changed = raw.clone();
        changed[0] ^= 1;
        assert_eq!(Descriptor::decode(&changed), Err(Error::Encoding));
    }
    assert_eq!(Descriptor::decode(&[0; 129]), Err(Error::Encoding));
    for name in ["", "exp_q", "range_7", "rope_q", "SIGMOID_Q"] {
        assert_eq!(Descriptor::new(name, 1, &[]), Err(Error::Name));
    }
    for version in [0, 2, u32::MAX] {
        assert_eq!(
            Descriptor::new("range_8", version, &[]),
            Err(Error::Version)
        );
    }
}

#[test]
fn accepts_exact_exponential_parameter_grid_and_maximum_shapes() {
    for b in 0u8..=32 {
        for k in 0u8..=18 {
            let product = (7..=31).contains(&b) && (1..=16).contains(&k) && b >= k && b - k <= 15;
            for name in ["exp_q/hi", "exp_q/lo", "exp_q/correction"] {
                for (f, e) in [(0, 0), (30, 14), (31, 14), (30, 15)] {
                    let actual = Descriptor::new(name, 1, &[b, f, e, k]);
                    let expected =
                        product && (name != "exp_q/correction" || b <= 15) && f <= 30 && e <= 14;
                    assert_eq!(actual.is_ok(), expected, "{name}, {b}/{f}/{e}/{k}");
                    if let Ok(d) = actual {
                        let n = match name {
                            "exp_q/hi" => (1u32 << (b - k)) + 1,
                            "exp_q/lo" => 1u32 << k,
                            _ => (1u32 << b) + 1,
                        };
                        assert_eq!(d.shape().rows(), n);
                        assert_eq!(d.shape().padded(), n.next_power_of_two());
                        assert!(d.shape().padded() <= 65536);
                        assert_eq!(
                            Descriptor::decode(d.encode().expect("bytes").as_bytes()),
                            Ok(d)
                        );
                    }
                }
            }
        }
        assert_eq!(
            Descriptor::new("exp_q/direct", 1, &[b, 30, 14]).is_ok(),
            (7..=15).contains(&b)
        );
    }
    let high = Descriptor::new("exp_q/hi", 1, &[7, 0, 0, 7]).expect("two-row component");
    assert_eq!((high.shape().rows(), high.shape().padded()), (2, 2));
}

#[test]
fn rejects_noncanonical_parameters_and_binds_each_semantic_choice() {
    for name in ["silu_q", "sigmoid_q", "gelu_q", "gelu_tanh_q"] {
        for params in [vec![], vec![0], vec![0, 0, 0], vec![31, 0], vec![0, 15]] {
            assert_eq!(Descriptor::new(name, 1, &params), Err(Error::Parameters));
        }
        let a = Descriptor::new(name, 1, &[0, 0]).expect("metadata, not generation");
        let b = Descriptor::new(name, 1, &[30, 14]).expect("metadata");
        assert_eq!(a.shape().rows(), 65536);
        assert_ne!(a.identity(), b.identity());
    }
    for params in [
        [0, 0, 0, 0, 0],
        [0, 0, 2, 0, 1],
        [0, 0, 1, 0, 31],
        [31, 0, 1, 0, 0],
    ] {
        assert_eq!(
            Descriptor::new("softcap_q", 1, &params),
            Err(Error::Parameters)
        );
    }
    for params in [[0, 0, 2, 0, 0], [30, 14, 255, 255, 30], [0, 0, 1, 0, 30]] {
        assert!(Descriptor::new("softcap_q", 1, &params).is_ok());
    }
    for name in ["rsqrt_q", "range_8", "range_12", "range_16"] {
        assert_eq!(Descriptor::new(name, 1, &[0]), Err(Error::Parameters));
    }
    let hi = Descriptor::new("exp_q/hi", 1, &[14, 10, 12, 7]).expect("high");
    for params in [
        [15, 10, 12, 7],
        [14, 11, 12, 7],
        [14, 10, 13, 7],
        [14, 10, 12, 6],
    ] {
        assert_ne!(
            hi.identity(),
            Descriptor::new("exp_q/hi", 1, &params)
                .expect("changed")
                .identity()
        );
    }
    assert_ne!(
        hi.identity(),
        Descriptor::new("exp_q/lo", 1, hi.parameters())
            .expect("low")
            .identity()
    );
    assert_ne!(
        Descriptor::new("gelu_q", 1, &[10, 12])
            .expect("exact")
            .identity(),
        Descriptor::new("gelu_tanh_q", 1, &[10, 12])
            .expect("tanh")
            .identity()
    );
}
