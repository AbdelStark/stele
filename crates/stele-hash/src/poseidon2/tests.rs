//! RFC-0012 A2 — exact parity with an executed, pinned upstream reference.
use super::*;
use serde_json::Value;

#[test]
fn matches_reference_poseidon2_constants_and_vectors() {
    let mut records = include_str!("../../tests/fixtures/poseidon2.jsonl").lines();
    let parameters: Value =
        serde_json::from_str(records.next().expect("parameters")).expect("JSON");
    for (name, rounds) in [("initial", INITIAL.as_slice()), ("final", FINAL.as_slice())] {
        for (i, round) in rounds.iter().enumerate() {
            for (j, value) in round.iter().enumerate() {
                assert_eq!(Some(u64::from(*value)), parameters[name][i][j].as_u64());
                assert!(*value < M31::MODULUS);
            }
        }
    }
    for (i, value) in INTERNAL.iter().enumerate() {
        assert_eq!(Some(u64::from(*value)), parameters["internal"][i].as_u64());
        assert!(*value < M31::MODULUS);
    }
    let mut count = 0;
    for record in records {
        let vector: Value = serde_json::from_str(record).expect("JSON vector");
        let decode = |name: &str| -> [M31; 16] {
            let limbs = vector[name].as_array().expect("array");
            assert_eq!(limbs.len(), 16);
            core::array::from_fn(|i| {
                M31::from_canonical(u32::try_from(limbs[i].as_u64().expect("u32")).expect("fits"))
                    .expect("canonical")
            })
        };
        let mut state = decode("input");
        permute(&mut state);
        assert_eq!(state, decode("output"), "vector {count}");
        count += 1;
    }
    assert_eq!(count, 35);
}
