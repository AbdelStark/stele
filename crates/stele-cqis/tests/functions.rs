//! RFC-0021 §4: semantic identities and expected representation choices.
use stele_cqis::functions::{Descriptor, Error, Representation};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../research/cqis-tables/function-identity-candidates.json"
    ))
    .expect("Python function/representation vectors")
}

#[test]
fn matches_reference_all_committed_function_and_representation_bytes() {
    let vectors = fixtures();
    for row in vectors["functions"].as_array().expect("functions") {
        let raw = hex(row["descriptor"].as_str().expect("descriptor"));
        let f = Descriptor::decode(&raw).expect("function");
        assert_eq!(f.name(), row["name"].as_str().expect("name"));
        assert_eq!(f.version(), 1);
        assert_eq!(f.encode().expect("encoding").as_bytes(), raw);
        assert_eq!(
            &f.identity().expect("identity")[..],
            hex(row["function_id"].as_str().expect("id"))
        );
        for end in 0..raw.len() {
            assert!(Descriptor::decode(&raw[..end]).is_err());
        }
        let mut bad = raw.clone();
        bad.push(0);
        assert_eq!(Descriptor::decode(&bad), Err(Error::Encoding));
    }
    for row in vectors["representations"]
        .as_array()
        .expect("representations")
    {
        let function = vectors["functions"]
            .as_array()
            .expect("functions")
            .iter()
            .find(|f| f["name"] == row["function"])
            .expect("expected function");
        let f = Descriptor::decode(&hex(function["descriptor"].as_str().expect("function")))
            .expect("descriptor");
        let r = Representation::new(
            f,
            row["mode"].as_u64().expect("mode") as u8,
            &hex(row["parameters"].as_str().expect("params")),
        )
        .expect("representation");
        let raw = hex(row["encoding"].as_str().expect("encoding"));
        assert_eq!(r.encode().expect("bytes").as_bytes(), raw);
        assert_eq!(Representation::decode(f, &raw), Ok(r));
        assert_eq!(r.validate_encoding(&raw), Ok(()));
        assert_eq!(
            &r.identity().expect("id")[..],
            hex(row["representation_id"].as_str().expect("id"))
        );
        for end in 0..raw.len() {
            assert!(r.validate_encoding(&raw[..end]).is_err());
        }
        // Every supplied byte is constrained by the expected selection and closure.
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 1;
            assert!(
                r.validate_encoding(&bad).is_err(),
                "unbound representation byte {i}"
            );
        }
        let mut bad = raw.clone();
        bad.push(0);
        assert!(r.validate_encoding(&bad).is_err());
        if r.components().len() > 1 {
            let start = raw.len() - 32 * r.components().len();
            let mut bad = raw.clone();
            bad[start..start + 32].copy_from_slice(&raw[start + 32..start + 64]);
            bad[start + 32..start + 64].copy_from_slice(&raw[start..start + 32]);
            assert_eq!(r.validate_encoding(&bad), Err(Error::Representation));
        }
    }
}

#[test]
fn accepts_every_closed_function_and_derives_canonical_components() {
    let cases = [
        ("exp_q/product", &[31, 30, 14, 16][..], 1),
        ("exp_q/nearest", &[15, 30, 14][..], 0),
        (
            "rmsnorm_q",
            &[0, 64, 30, 30, 14, 255, 255, 255, 255, 254, 255, 255, 255][..],
            3,
        ),
        ("sigmoid_q", &[30, 14][..], 0),
        ("silu_q", &[0, 14][..], 0),
        ("gelu_q", &[30, 14][..], 0),
        ("gelu_tanh_q", &[30, 14][..], 0),
        ("softcap_q", &[30, 14, 255, 255, 30][..], 0),
        ("range_8", &[][..], 0),
        ("range_12", &[][..], 0),
        ("range_16", &[][..], 0),
    ];
    let mut identities = Vec::new();
    for (name, p, mode) in cases {
        let f = Descriptor::new(name, 1, p).expect("closed function");
        let r = Representation::new(f, mode, &[]).expect("closed mode");
        assert_eq!(
            Descriptor::decode(f.encode().expect("bytes").as_bytes()),
            Ok(f)
        );
        assert_eq!(r.mode(), mode);
        assert!(r.parameters().is_empty());
        assert_eq!(
            r.validate_encoding(r.encode().expect("bytes").as_bytes()),
            Ok(())
        );
        assert!(!identities.contains(&f.identity().expect("id")));
        identities.push(f.identity().expect("id"));
        assert_eq!(Descriptor::new(name, 2, p), Err(Error::Version));
        assert_eq!(Descriptor::new(name, 2, &[255; 14]), Err(Error::Version));
        for wrong in 0..=4 {
            if wrong != mode && !(name == "exp_q/nearest" && wrong == 2) {
                assert_eq!(
                    Representation::new(f, wrong, &[]),
                    Err(Error::Representation)
                );
            }
        }
        assert_eq!(
            Representation::new(f, mode, &[0, 0]),
            Err(Error::Representation)
        );
    }
    for (b, k, expected) in [
        (7, 7, true),
        (7, 8, false),
        (15, 1, true),
        (15, 15, true),
        (15, 16, false),
    ] {
        let f = Descriptor::new("exp_q/nearest", 1, &[b, 30, 14]).expect("nearest");
        assert_eq!(Representation::new(f, 2, &[k]).is_ok(), expected);
    }
    let f = Descriptor::new("range_8", 1, &[]).expect("range");
    let d = stele_cqis::tables::Descriptor::new("range_8", 1, &[]).expect("component");
    assert_ne!(
        f.identity().expect("function"),
        d.identity().expect("component")
    );
}

#[test]
fn rejects_norm_boundaries_malformed_framing_and_identity_substitution() {
    let p = [8, 0, 8, 8, 8, 1, 0, 0, 0, 160, 134, 1, 0];
    let f = Descriptor::new("rmsnorm_q", 1, &p).expect("norm");
    for i in 0..13 {
        let mut changed = p;
        changed[i] ^= 1;
        if let Ok(other) = Descriptor::new("rmsnorm_q", 1, &changed) {
            assert_ne!(f.identity(), other.identity());
        }
    }
    for (offset, bytes) in [
        (0, &0u16.to_le_bytes()[..]),
        (0, &16385u16.to_le_bytes()[..]),
        (2, &[31][..]),
        (3, &[31][..]),
        (4, &[15][..]),
        (5, &0u32.to_le_bytes()[..]),
        (9, &0u32.to_le_bytes()[..]),
    ] {
        let mut bad = p;
        bad[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            Descriptor::new("rmsnorm_q", 1, &bad),
            Err(Error::Parameters)
        );
    }
    let raw = f.encode().expect("bytes").as_bytes().to_vec();
    let prefix = b"stele/v0.1/function/identity".len();
    for count in [0u16, 33, 65535] {
        let mut bad = raw.clone();
        bad[prefix..prefix + 2].copy_from_slice(&count.to_le_bytes());
        assert_eq!(Descriptor::decode(&bad), Err(Error::Encoding));
    }
    let mut bad = raw.clone();
    bad[prefix + 2] = 255;
    assert_eq!(Descriptor::decode(&bad), Err(Error::Encoding));
    let mut bad = raw.clone();
    let offset = prefix + 2 + f.name().len() + 4;
    bad[offset..offset + 2].copy_from_slice(&65u16.to_le_bytes());
    assert_eq!(Descriptor::decode(&bad), Err(Error::Encoding));
    assert_eq!(Descriptor::decode(&[0; 129]), Err(Error::Encoding));
    assert_eq!(Representation::decode(f, &[0; 193]), Err(Error::Encoding));
    let r = Representation::new(f, 3, &[]).expect("norm representation");
    let other = Descriptor::new("range_8", 1, &[]).expect("other function");
    assert_eq!(
        Representation::decode(other, r.encode().expect("bytes").as_bytes()),
        Err(Error::Identity)
    );
}

#[test]
fn rejects_changed_expected_representation_for_the_same_function() {
    let f = Descriptor::new("exp_q/nearest", 1, &[7, 10, 12]).expect("nearest function");
    let direct = Representation::new(f, 0, &[]).expect("direct");
    let corrected = Representation::new(f, 2, &[6]).expect("corrected");
    assert_eq!(direct.function(), corrected.function());
    assert_ne!(direct.identity(), corrected.identity());
    assert_eq!(
        direct.validate_encoding(corrected.encode().expect("bytes").as_bytes()),
        Err(Error::Representation)
    );
    let other_split = Representation::new(f, 2, &[7]).expect("another legal split");
    assert_eq!(
        corrected.validate_encoding(other_split.encode().expect("bytes").as_bytes()),
        Err(Error::Representation)
    );
    assert_eq!(
        corrected
            .components()
            .iter()
            .map(|d| d.name())
            .collect::<Vec<_>>(),
        ["exp_q/hi", "exp_q/lo", "exp_q/correction"]
    );
}

#[test]
fn rejects_noncanonical_norm_epsilon_and_component_names() {
    let mut p = [8, 0, 8, 8, 8, 1, 0, 0, 0, 160, 134, 1, 0];
    assert!(Descriptor::new("rmsnorm_q", 1, &p).is_ok());
    p[5..9].copy_from_slice(&2u32.to_le_bytes());
    p[9..13].copy_from_slice(&200000u32.to_le_bytes());
    assert_eq!(Descriptor::new("rmsnorm_q", 1, &p), Err(Error::Parameters));
    assert_eq!(
        Descriptor::new("exp_q/hi", 1, &[7, 10, 12, 6]),
        Err(Error::Name)
    );
    assert_eq!(Descriptor::new("rsqrt_q", 1, &[]), Err(Error::Name));
}
