//! RFC-0021 §§2.2,3,4: strict finite tails and whole-table activation admission.
use stele_cqis::tables::{Descriptor, Error, Table};

fn generate(name: &str, parameters: &[u8]) -> Result<Table, Error> {
    Table::activation(Descriptor::new(name, 1, parameters).expect("descriptor"))
}

#[test]
fn matches_reference_complete_activation_data_and_rejects_mutations() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/native-activation-entries.json"
    ))
    .expect("independent complete tables");
    for case in vectors["tables"].as_array().expect("tables") {
        let hex = case["parameters"].as_str().expect("parameters");
        let parameters: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let table = generate(case["name"].as_str().expect("name"), &parameters).expect("table");
        assert_eq!(table.entries().len(), 65536 * 2);
        for (i, row) in table.entries().chunks_exact(2).enumerate() {
            assert_eq!(row[0], i as i32 - 32768);
            assert!(i16::try_from(row[1]).is_ok());
        }
        let raw = table.encode().expect("bytes");
        assert_eq!(
            blake3::hash(&raw).to_hex().as_str(),
            case["data_digest"].as_str().expect("digest")
        );
        assert_eq!(table.validate_encoding(&raw), Ok(()));
        let hex = case["numpy_gathers"].as_str().expect("integer gathers");
        let gathers: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        assert_eq!(gathers.len(), 10000 * 4);
        for row in gathers.chunks_exact(4) {
            let t = i32::from(i16::from_le_bytes(row[..2].try_into().expect("input")));
            let expected = i32::from(i16::from_le_bytes(row[2..].try_into().expect("output")));
            assert_eq!(table.entries()[(t + 32768) as usize * 2 + 1], expected);
        }
        let header = b"stele/v0.1/table/data".len() + 41;
        let mut bad = raw.clone();
        bad[header + 4] ^= 1;
        assert_eq!(table.validate_encoding(&bad), Err(Error::Entry));
        bad = raw.clone();
        bad[header..header + 4].copy_from_slice(&(-32768i32 + i32::MAX).to_le_bytes());
        assert_eq!(table.validate_encoding(&bad), Err(Error::Entry));
        assert_eq!(
            table.validate_encoding(&raw[..raw.len() - 1]),
            Err(Error::Length)
        );
        bad = raw.clone();
        bad.push(0);
        assert_eq!(table.validate_encoding(&bad), Err(Error::Length));
        bad = raw.clone();
        bad[b"stele/v0.1/table/data".len()] ^= 1;
        assert_eq!(table.validate_encoding(&bad), Err(Error::Identity));
    }
}

#[test]
fn accepts_strict_finite_tail_rounding_and_exact_zero() {
    let sigmoid = generate("sigmoid_q", &[0, 0]).expect("sigmoid");
    assert_eq!(sigmoid.entries()[32768 * 2 + 1], 1);
    let silu = generate("silu_q", &[1, 0]).expect("SiLU");
    assert_eq!(silu.entries()[65535 * 2 + 1], 16383);
    assert_eq!(silu.entries()[32768 * 2 + 1], 0);
    let cap = generate("softcap_q", &[0, 0, 1, 0, 1]).expect("half limit");
    assert!(cap.entries().chunks_exact(2).all(|row| row[1] == 0));
}

#[test]
fn rejects_whole_table_output_overflow_and_unimplemented_kinds() {
    assert_eq!(generate("silu_q", &[0, 14]), Err(Error::Overflow));
    assert_eq!(
        generate("softcap_q", &[0, 14, 3, 0, 0]),
        Err(Error::Overflow)
    );
    for (name, p) in [("range_8", &[][..]), ("gelu_q", &[8, 8][..])] {
        assert_eq!(generate(name, p), Err(Error::Parameters));
    }
}
