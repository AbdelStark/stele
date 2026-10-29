//! RFC-0021 §2.1,§6: function composition using actual native-generated tables.
use stele_cqis::tables::{Descriptor, Table};

fn unhex(value: &serde_json::Value) -> Vec<u8> {
    let hex = value.as_str().expect("hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("byte"))
        .collect()
}

#[test]
fn matches_reference_varied_exponential_functions_and_numpy_gathers() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/native-exp-functions.json"
    ))
    .expect("independent positive-series full tables and NumPy gathers");
    let mut counts = [0, 0];
    let mut components = 0;
    for case in vectors["cases"].as_array().expect("cases") {
        let p: Vec<u32> = case["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .map(|v| u32::try_from(v.as_u64().expect("integer")).expect("u32"))
            .collect();
        let tables: Vec<Table> = case["components"]
            .as_array()
            .expect("components")
            .iter()
            .map(|c| {
                let d = Descriptor::new(
                    c["name"].as_str().expect("name"),
                    1,
                    &unhex(&c["parameters"]),
                )
                .expect("descriptor");
                let table = Table::exponential(d).expect("complete table");
                assert_eq!(
                    blake3::hash(&table.encode().expect("canonical data"))
                        .to_hex()
                        .as_str(),
                    c["data_digest"]
                        .as_str()
                        .expect("full independent data digest")
                );
                components += 1;
                table
            })
            .collect();
        let nearest = case["mode"] == "nearest";
        assert_eq!(tables.len(), if nearest { 4 } else { 2 });
        let records = unhex(&case["records"]);
        let stride = if nearest { 12 } else { 8 };
        let count = usize::try_from(case["count"].as_u64().expect("count")).expect("usize");
        assert_eq!(records.len(), count * stride);
        for record in records.chunks_exact(stride) {
            let t = i64::from(i32::from_le_bytes(record[..4].try_into().expect("input")));
            assert!(-(1i64 << p[0]) <= t && t <= 0);
            // Promote before negating: the inclusive B=31 endpoint is i32::MIN.
            let u = u64::try_from(-t).expect("nonnegative");
            let h = usize::try_from(u >> p[3]).expect("high index");
            let l = usize::try_from(u & ((1 << p[3]) - 1)).expect("low index");
            let high = tables[0].entries()[2 * h + 1];
            let low = tables[1].entries()[2 * l + 1];
            let product = i64::from(high) * i64::from(low) / (1i64 << p[2]);
            let expected = i64::from(u32::from_le_bytes(record[4..8].try_into().expect("output")));
            if nearest {
                let i = usize::try_from(t + (1i64 << p[0])).expect("signed input index");
                let correction = i32::from_le_bytes(record[8..].try_into().expect("correction"));
                assert!((-1..=2).contains(&correction));
                assert_eq!(tables[2].entries()[2 * i], i32::try_from(t).expect("i32"));
                assert_eq!(tables[3].entries()[2 * i + 1], correction);
                assert_eq!(i64::from(tables[2].entries()[2 * i + 1]), expected);
                assert_eq!(product + i64::from(correction), expected);
            } else {
                assert_eq!(product, expected);
            }
        }
        counts[usize::from(nearest)] += count;
    }
    assert_eq!(counts, [10000, 10000]);
    assert_eq!(components, 192);
}
