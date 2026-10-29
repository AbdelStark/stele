//! RFC-0021 §§2.2-2.3,4: fixed generators and complete canonical integer data.
use stele_cqis::tables::{Error, Table};

fn tables() -> Vec<Table> {
    [8, 12, 16]
        .into_iter()
        .map(|bits| Table::range(bits).expect("registered range"))
        .chain([Table::rsqrt().expect("certified rsqrt")])
        .collect()
}

#[test]
fn matches_reference_complete_fixed_table_bytes() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/table-identity-candidates.json"
    ))
    .expect("independent Python full-table vectors");
    for table in tables() {
        let expected = vectors["data"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|v| v["name"] == table.descriptor().name())
            .expect("case");
        let encoded = table.encode().expect("canonical full table");
        assert_eq!(
            encoded.len() as u64,
            expected["byte_length"].as_u64().expect("length")
        );
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            expected["data_digest"].as_str().expect("digest")
        );
        assert_eq!(table.validate_encoding(&encoded), Ok(()));
        let shape = table.descriptor().shape();
        let c = usize::from(shape.columns());
        assert_eq!(table.entries().len(), shape.padded() as usize * c);
        assert!(table.entries()[shape.rows() as usize * c..]
            .iter()
            .all(|v| *v == 0));
        // Independently assemble every header field and every signed entry.
        let mut independent = b"stele/v0.1/table/data".to_vec();
        independent.extend(table.descriptor().identity().expect("id"));
        independent.extend(shape.rows().to_le_bytes());
        independent.extend(shape.padded().to_le_bytes());
        independent.push(shape.columns());
        for value in table.entries() {
            independent.extend(value.to_le_bytes());
        }
        assert_eq!(independent, encoded);
    }
}

#[test]
fn accepts_all_range_values_and_certifies_every_rsqrt_entry() {
    for bits in [8, 12, 16] {
        let table = Table::range(bits).expect("range");
        for (i, value) in table.entries().iter().enumerate() {
            assert_eq!(*value, i as i32);
        }
    }
    let table = Table::rsqrt().expect("rsqrt");
    for (i, row) in table.entries().chunks_exact(2).take(49152).enumerate() {
        let m = 16384 + i as u64;
        assert_eq!(row[0] as u64, m);
        // Independent bisection of the final rounding cell, not the generator's isqrt.
        let (mut low, mut high) = (8192u64, 16384u64);
        while low < high {
            let middle = (low + high).div_ceil(2);
            if m * (2 * middle - 1).pow(2) <= 1 << 44 {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        assert_eq!(row[1] as u64, low);
        assert!(m * (2 * low - 1).pow(2) <= 1 << 44);
        assert!(1 << 44 < m * (2 * low + 1).pow(2));
    }
    for bits in [0, 7, 9, 15, 17, 32, 255] {
        assert!(matches!(Table::range(bits), Err(Error::Parameters)));
    }
}

#[test]
fn matches_reference_numpy_integer_fixed_table_gathers() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/native-fixed-gathers.json"
    ))
    .expect("NumPy fixed gathers");
    for (table, case) in tables()
        .iter()
        .zip(vectors["cases"].as_array().expect("cases"))
    {
        assert_eq!(case["name"], table.descriptor().name());
        assert_eq!(case["count"], 10000);
        assert_eq!(
            blake3::hash(&table.encode().expect("canonical data"))
                .to_hex()
                .as_str(),
            case["data_digest"].as_str().expect("full data digest")
        );
        let hex = case["records"].as_str().expect("gathers");
        let records: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("byte"))
            .collect();
        assert_eq!(records.len(), 10000 * 8);
        let width = usize::from(table.descriptor().shape().columns());
        let start = if width == 2 { 16384 } else { 0 };
        for record in records.chunks_exact(8) {
            let input = u32::from_le_bytes(record[..4].try_into().expect("input"));
            let expected = i32::from_le_bytes(record[4..].try_into().expect("output"));
            let index = usize::try_from(input.checked_sub(start).expect("domain")).expect("index");
            assert!(index < table.descriptor().shape().rows() as usize);
            assert_eq!(table.entries()[index * width + width - 1], expected);
        }
    }
    assert_eq!(vectors["cases"].as_array().expect("cases").len(), 4);
}

#[test]
fn rejects_changed_data_identity_shape_padding_and_integer_aliases() {
    for table in tables() {
        let honest = table.encode().expect("encoding");
        let prefix = b"stele/v0.1/table/data".len();
        let data = prefix + 32 + 9;
        for (offset, expected) in [
            (0, Error::DataHeader),
            (prefix, Error::Identity),
            (prefix + 32, Error::Shape),
            (prefix + 36, Error::Shape),
            (prefix + 40, Error::Shape),
            (data, Error::Entry),
            (data + 4, Error::Entry),
        ] {
            let mut changed = honest.clone();
            changed[offset] ^= 1;
            assert_eq!(table.validate_encoding(&changed), Err(expected));
        }
        for length in [0, 1, data - 1, data, honest.len() - 1] {
            assert_eq!(
                table.validate_encoding(&honest[..length]),
                Err(Error::Length)
            );
        }
        let mut changed = honest.clone();
        changed.push(0);
        assert_eq!(table.validate_encoding(&changed), Err(Error::Length));
        let shape = table.descriptor().shape();
        if shape.rows() < shape.padded() {
            let mut changed = honest.clone();
            changed[data + shape.rows() as usize * usize::from(shape.columns()) * 4] = 1;
            assert_eq!(table.validate_encoding(&changed), Err(Error::Padding));
        } else {
            let mut alias = honest.clone();
            alias[data..data + 4].copy_from_slice(&i32::MAX.to_le_bytes());
            assert_eq!(table.validate_encoding(&alias), Err(Error::Entry));
        }
        assert_eq!(table.validate_encoding(&honest), Ok(()));
        assert_eq!(table.encode().expect("unchanged after rejection"), honest);
    }
}
