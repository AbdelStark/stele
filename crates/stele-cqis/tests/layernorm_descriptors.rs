//! RFC-0021 A3 / RFC-0025 encoding §4: LayerNorm identity and shared rsqrt closure.
use stele_cqis::{
    bounds,
    functions::{Descriptor, Error, Manifest, NormError, Representation},
};

fn hex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/layernorm-descriptors.json"))
        .expect("independent Python descriptor vectors")
}

fn parameters() -> [u8; 14] {
    [0, 3, 8, 8, 8, 8, 1, 0, 0, 0, 160, 134, 1, 0]
}

#[test]
fn matches_reference_layernorm_function_and_representation_bytes() {
    for row in fixtures()["vectors"].as_array().expect("vectors") {
        let params = hex(row["parameters"].as_str().expect("parameters"));
        let expected = hex(row["descriptor"].as_str().expect("descriptor"));
        let function = Descriptor::new("layernorm_q", 1, &params).expect("LayerNorm");
        assert_eq!(function.name(), "layernorm_q");
        assert_eq!(function.parameters(), params);
        assert_eq!(function.encode().expect("bytes").as_bytes(), expected);
        assert_eq!(Descriptor::decode(&expected), Ok(function));
        assert_eq!(
            function.identity().expect("identity").as_slice(),
            hex(row["function_id"].as_str().expect("function id"))
        );
        let representation = Representation::new(function, 4, &[]).expect("LayerNorm mode");
        let raw = hex(row["representation"].as_str().expect("representation"));
        assert_eq!(representation.encode().expect("bytes").as_bytes(), raw);
        assert_eq!(Representation::decode(function, &raw), Ok(representation));
        assert_eq!(
            representation.identity().expect("identity").as_slice(),
            hex(row["representation_id"]
                .as_str()
                .expect("representation id"))
        );
        assert_eq!(representation.components().len(), 1);
        assert_eq!(representation.components()[0].name(), "rsqrt_q");
        for end in 0..expected.len() {
            assert!(Descriptor::decode(&expected[..end]).is_err());
        }
        let mut extra = expected;
        extra.push(0);
        assert_eq!(Descriptor::decode(&extra), Err(Error::Encoding));
        for i in 0..raw.len() {
            let mut changed = raw.clone();
            changed[i] ^= 1;
            assert!(representation.validate_encoding(&changed).is_err());
        }
    }
}

#[test]
fn rejects_layernorm_parameter_boundaries_and_noncanonical_epsilon() {
    let p = parameters();
    for (offset, bytes) in [
        (0, &0u16.to_le_bytes()[..]),
        (0, &16385u16.to_le_bytes()[..]),
        (2, &[31][..]),
        (3, &[31][..]),
        (4, &[15][..]),
        (5, &[31][..]),
        (6, &0u32.to_le_bytes()[..]),
        (10, &0u32.to_le_bytes()[..]),
    ] {
        let mut bad = p;
        bad[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            Descriptor::new("layernorm_q", 1, &bad),
            Err(Error::Parameters)
        );
    }
    let mut bad = p;
    bad[6..10].copy_from_slice(&2u32.to_le_bytes());
    bad[10..14].copy_from_slice(&200000u32.to_le_bytes());
    assert_eq!(
        Descriptor::new("layernorm_q", 1, &bad),
        Err(Error::Parameters)
    );
    assert_eq!(Descriptor::new("layernorm_q", 2, &p), Err(Error::Version));
    for raw in [&p[..13], &[0; 15][..]] {
        assert_eq!(
            Descriptor::new("layernorm_q", 1, raw),
            Err(Error::Parameters)
        );
    }
}

#[test]
fn rejects_layernorm_bias_fraction_and_rmsnorm_substitution() {
    let p = parameters();
    let function = Descriptor::new("layernorm_q", 1, &p).expect("LayerNorm");
    let selected = Representation::new(function, 4, &[]).expect("mode 4");
    let mut changed = p;
    changed[5] += 1;
    let other = Descriptor::new("layernorm_q", 1, &changed).expect("different bias fraction");
    assert_ne!(function.identity(), other.identity());
    let other = Representation::new(other, 4, &[]).expect("different function");
    assert_eq!(
        selected.validate_encoding(other.encode().expect("bytes").as_bytes()),
        Err(Error::Identity)
    );
    for mode in [0, 1, 2, 3, 5, 255] {
        assert_eq!(
            Representation::new(function, mode, &[]),
            Err(Error::Representation)
        );
    }
    assert_eq!(
        Representation::new(function, 4, &[0]),
        Err(Error::Representation)
    );
    assert_eq!(
        function.evaluate_rmsnorm(&[], &[]),
        Err(NormError::Function)
    );
    assert_eq!(
        bounds::Record::rmsnorm(function),
        Err(bounds::Error::Parameters)
    );

    let rms_parameters: Vec<_> = p[..5].iter().chain(&p[6..]).copied().collect();
    let rms = Descriptor::new("rmsnorm_q", 1, &rms_parameters).expect("RMSNorm");
    assert_eq!(Representation::new(rms, 4, &[]), Err(Error::Representation));
    let rms = Representation::new(rms, 3, &[]).expect("mode 3");
    assert_eq!(rms.components(), selected.components());
    assert_eq!(
        selected.validate_encoding(rms.encode().expect("bytes").as_bytes()),
        Err(Error::Identity)
    );
    let manifest = Manifest::new(&[rms, selected]).expect("regenerated shared rsqrt");
    assert_eq!(
        manifest.as_bytes(),
        hex(fixtures()["manifest"].as_str().expect("manifest"))
    );
    let omitted = Manifest::new(&[rms]).expect("RMSNorm only");
    assert_eq!(
        manifest.validate_encoding(omitted.as_bytes()),
        Err(Error::Manifest)
    );
}
