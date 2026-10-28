//! RFC-0010 A4 — independent fixed setup framing vectors, no proof challenges.
use stele_hash::setup::{expander_block, InvalidSetupRecord};
#[test]
fn matches_reference_setup_blocks_and_rejects_invalid_coordinates() {
    let mut seed = [0; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let cases = [
        (
            [0; 32],
            4,
            0,
            0,
            0,
            0,
            "346389466b02adb85223edfa91727571d10e9dbfee5853c624db9b643b565926",
        ),
        (
            [0; 32],
            4,
            0,
            0,
            1,
            0,
            "a70f198ae77f2146f11738318b1d3733b552336e21d9e7bdc43b6929e8d2e421",
        ),
        (
            seed,
            15,
            1,
            (1 << 29) - 1,
            1,
            31,
            "7052d62ef64d40099a39f56621d1d6510b1bc4bccfb55f0a326472ff7c1d5063",
        ),
    ];
    for (seed, level, kind, row, stream, counter, hex) in cases {
        let bytes = expander_block(&seed, level, kind, row, stream, counter).expect("record");
        let expected: Vec<_> = (0..32)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect();
        assert_eq!(bytes.as_slice(), expected);
    }
    for (level, kind, row, stream, counter) in [
        (3, 0, 0, 0, 0),
        (16, 0, 0, 0, 0),
        (4, 2, 0, 0, 0),
        (4, 0, 256, 0, 0),
        (4, 1, 128, 0, 0),
        (4, 0, 0, 2, 0),
        (4, 0, 0, 0, 32),
    ] {
        assert_eq!(
            expander_block(&seed, level, kind, row, stream, counter),
            Err(InvalidSetupRecord)
        );
    }
}
