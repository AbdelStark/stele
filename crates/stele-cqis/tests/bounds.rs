//! RFC-0022 §§4,6: complete static record bytes and rejection boundaries.
use stele_cqis::{
    bounds::{Error, Record},
    functions::Descriptor,
    Format, Requant,
};

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}

fn record(kind: u64, p: &[u8]) -> Record {
    if kind == 1 {
        Record::requant(
            Requant::new(u32::from(u16::from_le_bytes([p[0], p[1]])), u32::from(p[2]))
                .expect("Requant"),
            if p[3] == 8 {
                Format::Int8
            } else {
                Format::Int16
            },
        )
        .expect("static record")
    } else {
        Record::rmsnorm(Descriptor::new("rmsnorm_q", 1, p).expect("RMSNorm"))
            .expect("static record")
    }
}

#[test]
fn matches_reference_complete_records_and_rejects_every_changed_byte() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../research/cqis-bounds/encoding.json"))
            .expect("independent exact byte vectors");
    let cases = data["goldens"].as_array().expect("cases");
    assert_eq!(cases.len(), 7);
    for case in cases {
        let kind = case["schema"].as_u64().expect("schema");
        let params = hex(case["parameters"].as_str().expect("parameters"));
        let raw = hex(case["bytes"].as_str().expect("complete bytes"));
        let expected = record(kind, &params);
        assert_eq!(expected.as_bytes(), raw);
        assert!(raw.len() <= 4386);
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 1;
            assert_eq!(expected.validate_encoding(&bad), Err(Error::Encoding));
            assert_eq!(expected.validate_encoding(&raw[..i]), Err(Error::Encoding));
        }
        let mut bad = raw.clone();
        bad.push(0);
        assert_eq!(expected.validate_encoding(&bad), Err(Error::Encoding));
        assert_eq!(
            expected.validate_encoding(&vec![0; 8193]),
            Err(Error::Encoding)
        );
        // Add p to a wide scalar without changing its M31 residue.
        let start = 22 + 4 + 1 + 2 + params.len() + 4 + 1 + 1;
        let scalar = u128::from_le_bytes(raw[start..start + 16].try_into().expect("low scalar"));
        let mut bad = raw.clone();
        bad[start..start + 16].copy_from_slice(&(scalar + 2u128.pow(31) - 1).to_le_bytes());
        assert_eq!(expected.validate_encoding(&bad), Err(Error::Encoding));
        let mut other = params.clone();
        if kind == 1 {
            let m = u16::from_le_bytes([other[0], other[1]]) % 65535 + 1;
            other[..2].copy_from_slice(&m.to_le_bytes());
        } else {
            other[4] = (other[4] + 1) % 15;
        }
        assert_eq!(
            record(kind, &other).validate_encoding(&raw),
            Err(Error::Encoding)
        );
        assert_eq!(
            expected.validate_encoding(record(kind, &other).as_bytes()),
            Err(Error::Encoding)
        );
        let scalars = usize::from(raw[start - 1]);
        let shifts = start + 20 * scalars;
        let first = shifts + 1 + 2 * usize::from(raw[shifts]) + 1;
        let length = |at: usize| {
            72 + usize::from(raw[at + 65])
                + usize::from(raw[at + 66])
                + 13 * usize::from(raw[at + 67])
        };
        let second = first + length(first);
        let end = second + length(second);
        let mut bad = raw[..first].to_vec();
        bad.extend(&raw[second..end]);
        bad.extend(&raw[first..second]);
        bad.extend(&raw[end..]);
        assert_eq!(expected.validate_encoding(&bad), Err(Error::Encoding));
        assert_eq!(expected.validate_encoding(&raw), Ok(()));
        assert_eq!(expected.as_bytes(), raw);
    }
}

#[test]
fn rejects_wrong_semantic_function_and_preserves_wide_static_bounds() {
    let wrong = Descriptor::new("range_16", 1, &[]).expect("different function");
    assert_eq!(Record::rmsnorm(wrong), Err(Error::Parameters));
    let mut p = vec![0, 64, 30, 30, 14];
    p.extend(u32::MAX.to_le_bytes());
    p.extend((u32::MAX - 1).to_le_bytes());
    let record = record(2, &p);
    let a_max = 22 + 4 + 1 + 2 + 13 + 4 + 1 + 1 + 4 * 20;
    assert!(record.as_bytes()[a_max + 16..a_max + 20]
        .iter()
        .any(|v| *v != 0));
}
