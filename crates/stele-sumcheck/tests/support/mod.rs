//! RFC-0006 A2: shared fixture decoding and A1 continuation checks.
use serde_json::Value;
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{Dense, Instance, Proof, Term};
pub fn array(v: &Value) -> &[Value] {
    v.as_array().expect("fixture array")
}
pub fn number(v: &Value) -> u64 {
    v.as_u64().expect("fixture integer")
}
pub fn field<K: ChallengeField>(v: &Value) -> K
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes: Vec<u8> = array(v)
        .iter()
        .flat_map(|v| (number(v) as u32).to_le_bytes())
        .collect();
    K::from_le_bytes(bytes.try_into().ok().expect("field width")).expect("canonical field")
}
pub fn values<K: ChallengeField>(v: &Value) -> Vec<K>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v).iter().map(field).collect()
}
pub fn proof<K: ChallengeField>(v: &Value) -> Proof<K>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    Proof {
        rounds: array(&v["rounds"]).iter().map(values).collect(),
        final_values: array(&v["final"]).iter().flat_map(values).collect(),
    }
}
pub fn continuation<K: ChallengeField + Eq + core::fmt::Debug>(
    v: &Value,
    pt: &mut Transcript<K>,
    vt: &mut Transcript<K>,
) where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let next = Instance {
        id: 99,
        num_vars: 1,
        inputs: vec![11],
        terms: vec![
            Term {
                coefficient: K::from_i64(2),
                factors: vec![0],
            },
            Term {
                coefficient: K::from_i64(-3),
                factors: vec![],
            },
        ],
        claimed_sum: K::from_i64(10),
    };
    let data = vec![vec![K::from_i64(3), K::from_i64(5)]];
    let continued =
        stele_sumcheck::prove(&next, Dense::new(&next, data.clone()).expect("shape"), pt)
            .expect("continuation");
    let expected = Proof {
        rounds: array(&v["continuation"]["rounds"])
            .iter()
            .map(values)
            .collect(),
        final_values: values(&v["continuation"]["final"]),
    };
    assert_eq!(continued, expected);
    let _ = stele_sumcheck::verify_public(&next, &continued, &data, vt).expect("same continuation");
}
