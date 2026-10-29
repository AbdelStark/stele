//! RFC-0021 §§2.1,3,4: complete exponential components, not lookup admission.
use stele_cqis::tables::{Descriptor, Error, Table};

#[test]
fn matches_reference_complete_exponential_component_bytes() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/table-identity-candidates.json"
    ))
    .expect("Python table vectors");
    for (name, parameters) in [
        ("exp_q/hi", &[14, 10, 12, 7][..]),
        ("exp_q/lo", &[14, 10, 12, 7][..]),
        ("exp_q/direct", &[7, 10, 12][..]),
        ("exp_q/correction", &[7, 10, 12, 7][..]),
    ] {
        let table = Table::exponential(Descriptor::new(name, 1, parameters).expect("descriptor"))
            .expect("certified table");
        let raw = table.encode().expect("bytes");
        let expected = vectors["data"]
            .as_array()
            .expect("vectors")
            .iter()
            .find(|r| r["name"] == name)
            .expect("case");
        assert_eq!(
            blake3::hash(&raw).to_hex().as_str(),
            expected["data_digest"].as_str().expect("digest")
        );
        assert_eq!(table.validate_encoding(&raw), Ok(()));
        let mut bad = raw.clone();
        bad[b"stele/v0.1/table/data".len() + 41 + 4] ^= 1;
        assert_eq!(table.validate_encoding(&bad), Err(Error::Entry));
    }
}

#[test]
fn accepts_full_correction_and_maximum_component_shapes() {
    let table = Table::exponential(
        Descriptor::new("exp_q/correction", 1, &[14, 10, 12, 7]).expect("descriptor"),
    )
    .expect("corrections");
    let mut counts = [0; 4];
    for (i, row) in table.entries().chunks_exact(2).take(16385).enumerate() {
        assert_eq!(row[0], i as i32 - 16384);
        counts[usize::try_from(row[1] + 1).expect("correction range")] += 1;
    }
    assert_eq!(counts, [3, 10868, 5501, 13]);
    assert!(table.entries()[16385 * 2..].iter().all(|v| *v == 0));
    for name in ["exp_q/hi", "exp_q/lo"] {
        let table =
            Table::exponential(Descriptor::new(name, 1, &[31, 0, 14, 16]).expect("maximal shape"))
                .expect("wide table");
        assert_eq!(table.descriptor().shape().padded(), 65536);
        assert_eq!(table.entries()[1], 16384);
        assert!(table
            .entries()
            .chunks_exact(2)
            .skip(1)
            .all(|row| (0..=16384).contains(&row[1])));
    }
    assert!(matches!(
        Table::exponential(Descriptor::new("rsqrt_q", 1, &[]).expect("other kind")),
        Err(Error::Parameters)
    ));
}
