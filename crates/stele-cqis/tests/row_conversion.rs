//! RFC-0025 §2.2/2.5 and flow §1: complete numerical rows and static certificates.
use serde_json::Value;
use stele_cqis::{
    bounds::arithmetic::{self, Row},
    row::{Error, Quantiser},
};

fn take<const N: usize>(input: &mut &[u8]) -> [u8; N] {
    let (value, rest) = input.split_at(N);
    *input = rest;
    value.try_into().expect("fixture word")
}
fn hex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("hex"))
        .collect()
}
#[test]
fn matches_reference_complete_rows_and_static_certificates() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/row-conversion.json")).expect("fixtures");
    let bytes = include_bytes!("fixtures/row-conversion.bin");
    let mut counts = [0; 4];
    for group in fixtures["groups"].as_array().expect("groups") {
        let label = group["label"].as_str().expect("label");
        let raw = hex(group["parameters"].as_str().expect("parameters"));
        let p = Row {
            dimension: u16::from_le_bytes(raw[..2].try_into().expect("dimension")),
            kind: raw[2],
            fraction: raw[3],
            policy: raw[4],
            scale: u32::from_le_bytes(raw[5..].try_into().expect("scale")),
        };
        let quantiser = Quantiser::new(p).expect("checked static parameters");
        assert_eq!(quantiser.parameters(), p);
        assert_eq!(
            blake3::hash(quantiser.certificate().as_bytes())
                .to_hex()
                .as_str(),
            group["record_id"]
                .as_str()
                .expect("independent certificate")
        );
        let start = group["offset"].as_u64().expect("offset") as usize;
        let length = group["length"].as_u64().expect("length") as usize;
        let mut input = &bytes[start..start + length];
        let randomized = group["randomized"] == true;
        let mut state = group["seed"].as_u64().unwrap_or(0);
        let mut input_hash = blake3::Hasher::new();
        for case in 0..group["count"].as_u64().expect("count") {
            let values: Vec<_> = if randomized {
                let h = if p.kind == 0 { 32768i64 } else { 1 << 30 };
                let bound = if p.policy == 1 && case % 4 != 0 {
                    h.min((255 * i64::from(p.scale) - 1) / 2)
                } else {
                    h
                };
                let high = bound.min(if p.kind == 0 { h - 1 } else { h });
                let width = (high + bound + 1) as u64;
                (0..p.dimension)
                    .map(|_| {
                        // Public deterministic test inputs only, never a proof challenge.
                        state = state
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        (-bound + ((state >> 32) % width) as i64) as i32
                    })
                    .collect()
            } else {
                (0..p.dimension)
                    .map(|_| i32::from_le_bytes(take(&mut input)))
                    .collect()
            };
            for value in &values {
                input_hash.update(&value.to_le_bytes());
            }
            let result = if p.kind == 0 {
                let wide: Vec<_> = values
                    .iter()
                    .map(|v| i16::try_from(*v).expect("int16 fixture"))
                    .collect();
                quantiser.convert_wide(&wide)
            } else {
                quantiser.convert_gated(&values)
            };
            match take::<1>(&mut input)[0] {
                0 => {
                    let row = result.expect(label);
                    let scale = u32::from_le_bytes(take(&mut input));
                    let index = u16::from_le_bytes(take(&mut input));
                    let maximum = u32::from_le_bytes(take(&mut input));
                    let (codes, rest) = input.split_at(usize::from(p.dimension));
                    input = rest;
                    assert_eq!(row.parameters(), p);
                    assert_eq!(row.scale(), scale, "{label}");
                    assert_eq!(row.fraction(), p.fraction);
                    assert_eq!(
                        row.maximum(),
                        if p.policy == 0 {
                            Some((index, maximum))
                        } else {
                            None
                        }
                    );
                    assert_eq!(
                        row.codes().iter().map(|v| *v as u8).collect::<Vec<_>>(),
                        codes,
                        "{label}"
                    );
                }
                1 => assert_eq!(result.err(), Some(Error::Range), "{label}"),
                2 => assert_eq!(result.err(), Some(Error::Input), "{label}"),
                _ => unreachable!(),
            }
            if randomized {
                counts[usize::from(2 * p.kind + p.policy)] += 1;
            }
        }
        assert!(input.is_empty(), "{label}");
        assert_eq!(
            input_hash.finalize().to_hex().as_str(),
            group["input_id"].as_str().expect("complete input digest"),
            "{label}"
        );
    }
    assert_eq!(counts, [10000; 4]);
}

#[test]
fn rejects_wrong_scope_parameters_and_truncated_gated_scale() {
    let p = Row {
        dimension: 3,
        kind: 0,
        fraction: 30,
        policy: 0,
        scale: 0,
    };
    for bad in [
        Row { dimension: 0, ..p },
        Row {
            dimension: 16385,
            ..p
        },
        Row { kind: 2, ..p },
        Row { fraction: 31, ..p },
        Row {
            kind: 1,
            fraction: 45,
            ..p
        },
        Row { policy: 2, ..p },
        Row { scale: 1, ..p },
        Row {
            policy: 1,
            scale: 0,
            ..p
        },
        Row {
            policy: 1,
            scale: 65536,
            ..p
        },
        Row {
            kind: 1,
            policy: 1,
            scale: 8454662,
            ..p
        },
    ] {
        assert_eq!(
            Quantiser::new(bad).err(),
            Some(Error::Bounds(arithmetic::Error::Parameters))
        );
    }
    let q = Quantiser::new(p).expect("wide");
    assert_eq!(q.convert_wide(&[]).err(), Some(Error::Shape));
    assert_eq!(q.convert_wide(&[0; 2]).err(), Some(Error::Shape));
    assert_eq!(q.convert_wide(&[0; 4]).err(), Some(Error::Shape));
    assert_eq!(q.convert_gated(&[0; 3]).err(), Some(Error::Kind));
    let p = Row {
        kind: 1,
        fraction: 44,
        policy: 1,
        scale: 65537,
        ..p
    };
    let q = Quantiser::new(p).expect("gated");
    let values = [65537 * 127, -65537 * 127, 65537];
    let row = q.convert_gated(&values).expect("full scale");
    assert_eq!(row.codes(), &[127, -127, 1]);
    assert_eq!(row.scale(), 65537);
    assert_eq!(row.maximum(), None);
    assert_eq!(q.convert_wide(&[0; 3]).err(), Some(Error::Kind));
    let truncated = Quantiser::new(Row {
        scale: u32::from(p.scale as u16),
        ..p
    })
    .expect("different valid parameters");
    assert_eq!(truncated.convert_gated(&values).err(), Some(Error::Range));
    // A late out-of-range static code never exposes an earlier partial row.
    let small = Quantiser::new(Row {
        kind: 0,
        fraction: 0,
        scale: 2,
        ..p
    })
    .expect("static wide");
    assert_eq!(small.convert_wide(&[0, 1, 255]).err(), Some(Error::Range));
    assert_eq!(
        small.convert_wide(&[0, -1, 254]).expect("ties").codes(),
        &[0, -1, 127]
    );
    let other = Quantiser::new(Row { fraction: 0, ..p }).expect("different fraction");
    assert_eq!(
        other
            .convert_gated(&values)
            .expect("same integer codes")
            .codes(),
        row.codes()
    );
    assert_ne!(other.certificate().as_bytes(), q.certificate().as_bytes());
}
