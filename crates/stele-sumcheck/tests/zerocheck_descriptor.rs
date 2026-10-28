//! RFC-0006 A3: static descriptor bytes and rejected configurations.
use serde_json::Value;
use stele_field::{Field, OM31, QM31};
use stele_hash::ChallengeField;
use stele_sumcheck::{zerocheck::Zerocheck, Error, Instance, Term};
pub mod support;
fn check<K: ChallengeField + Eq>(v: &Value)
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let instance = support::zerocheck_instance::<K>(&v["instance"]);
    let z = Zerocheck {
        instance: &instance,
        skip: support::number(&v["instance"]["k"]) as u8,
    };
    let hex: String = z
        .encode()
        .expect("descriptor")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, v["descriptor_hex"].as_str().expect("hex"));
}
#[test]
fn matches_reference_zerocheck_descriptors() {
    let vectors = include_str!("../../../research/zerocheck/vectors.jsonl");
    assert_eq!(vectors.lines().count(), 130);
    for line in vectors.lines() {
        let v: Value = serde_json::from_str(line).expect("fixture");
        if v["field"] == 4 {
            check::<QM31>(&v);
        } else {
            check::<OM31>(&v);
        }
    }
}
#[test]
fn rejects_invalid_zerocheck_descriptors() {
    let (zero, one) = (QM31::from_i64(0), QM31::from_i64(1));
    let mut i = Instance {
        id: 1,
        num_vars: 2,
        inputs: vec![],
        terms: vec![],
        claimed_sum: zero,
    };
    let error = |i: &Instance<QM31>, skip| Zerocheck { instance: i, skip }.encode().err();
    for skip in [1, 3, 5] {
        assert_eq!(error(&i, skip), Some(Error::InvalidZerocheck));
    }
    i.claimed_sum = one;
    assert_eq!(error(&i, 0), Some(Error::InvalidZerocheck));
    i.claimed_sum = zero;
    i.inputs = vec![1, 1];
    assert_eq!(error(&i, 0), Some(Error::InvalidZerocheck));
    i.inputs = vec![1];
    i.terms = vec![Term {
        coefficient: zero,
        factors: vec![0; 5],
    }];
    assert_eq!(error(&i, 0), Some(Error::InvalidZerocheck));
    i.terms[0].factors = vec![1];
    assert_eq!(error(&i, 0), Some(Error::InvalidZerocheck));
}
