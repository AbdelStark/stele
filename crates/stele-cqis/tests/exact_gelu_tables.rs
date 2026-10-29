//! RFC-0021 §§2.2,3: exact GeLU is a distinct function with strict finite tails.
use stele_cqis::tables::{Descriptor, Error, Table};

#[test]
fn matches_reference_complete_exact_gelu_bytes_and_numpy_gathers() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/native-exact-gelu.json"
    ))
    .expect("oracle");
    let d = Descriptor::new("gelu_q", 1, &[8, 8]).expect("descriptor");
    let table = Table::activation(d).expect("complete table");
    let raw = table.encode().expect("data");
    assert_eq!(
        blake3::hash(&raw).to_hex().as_str(),
        fixture["data_digest"].as_str().expect("digest")
    );
    assert_eq!(table.validate_encoding(&raw), Ok(()));
    let hex = fixture["numpy_gathers"].as_str().expect("gathers");
    let rows: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(rows.len(), 10000 * 4);
    for row in rows.chunks_exact(4) {
        let t = i32::from(i16::from_le_bytes(row[..2].try_into().expect("input")));
        let y = i32::from(i16::from_le_bytes(row[2..].try_into().expect("output")));
        assert_eq!(table.entries()[(t + 32768) as usize * 2 + 1], y);
    }
    let mut bad = raw.clone();
    bad[b"stele/v0.1/table/data".len() + 41 + 4] ^= 1;
    assert_eq!(table.validate_encoding(&bad), Err(Error::Entry));
    let mut bad = raw.clone();
    let input = b"stele/v0.1/table/data".len() + 41;
    bad[input..input + 4].copy_from_slice(&(-32768i32 + i32::MAX).to_le_bytes());
    assert_eq!(table.validate_encoding(&bad), Err(Error::Entry));
    let alternative =
        Table::activation(Descriptor::new("gelu_tanh_q", 1, &[8, 8]).expect("other function"))
            .expect("complete tanh variant");
    assert_ne!(table.entries(), alternative.entries());
    assert_eq!(alternative.validate_encoding(&raw), Err(Error::Identity));
}

#[test]
fn accepts_exact_gelu_zero_and_strict_half_limit() {
    let d = Descriptor::new("gelu_q", 1, &[1, 0]).expect("descriptor");
    let table = Table::activation(d).expect("complete exact GeLU");
    assert_eq!(table.entries()[32768 * 2 + 1], 0);
    assert_eq!(table.entries()[65535 * 2 + 1], 16383);
    assert_eq!(table.entries()[1], 0);
}

#[test]
fn rejects_whole_exact_gelu_table_overflow() {
    let d = Descriptor::new("gelu_q", 1, &[0, 14]).expect("descriptor");
    assert_eq!(Table::activation(d), Err(Error::Overflow));
}
