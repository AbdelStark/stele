//! RFC-0006 A3: both-field protocol bytes, every slice claim and phased SC records.
use serde_json::Value;
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    zerocheck::{Proof, Zerocheck},
    Error, Instance, Term,
};
pub mod support;
use support::{array, field, number, values};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"zerocheck").expect("public")
}
fn rows<K: ChallengeField>(v: &Value) -> Vec<Vec<K>>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    v.as_array().expect("fixture").iter().map(values).collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(v: &Value)
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let i = &v["instance"];
    let instance = support::zerocheck_instance::<K>(i);
    let z = Zerocheck {
        instance: &instance,
        skip: number(&i["k"]) as u8,
    };
    let tables = rows::<K>(&v["tables"]);
    let expected = Proof {
        skip_values: values(&v["proof"]["skip"]),
        rounds: rows(&v["proof"]["rounds"]),
        final_values: rows::<K>(&v["proof"]["final"])
            .into_iter()
            .flatten()
            .collect(),
    };
    let new = transcript::<K>;
    let mut pt = new();
    let proof = z.prove(&tables, &mut pt).expect("fixture");
    assert_eq!(proof, expected);
    assert_eq!(
        hex(&z.encode().expect("fixture")),
        v["descriptor_hex"].as_str().expect("fixture")
    );
    let mut vt = new();
    let result = z.verify_public(&proof, &tables, &mut vt).expect("fixture");
    assert_eq!(result.claims.len(), array(&v["receipt"]["claims"]).len());
    for (actual, expected) in result.claims.iter().zip(array(&v["receipt"]["claims"])) {
        assert_eq!(actual.tensor, number(&expected[0]));
        assert_eq!(actual.point, values(&expected[1]));
        assert_eq!(actual.value, field(&expected[2]));
    }
    for (phase, (record, expected)) in result.sc.iter().zip(array(&v["receipt"]["sc"])).enumerate()
    {
        assert_eq!(number(&expected["phase"]), phase as u64);
        assert_eq!(record.id, instance.id);
        assert_eq!(record.m as u64, number(&expected["m"]));
        assert_eq!(record.degree as u64, number(&expected["degree"]));
        assert_eq!(record.field_degree as u64, number(&v["field"]));
        assert_eq!(record.numerator, number(&expected["numerator"]));
    }
    for t in [&mut pt, &mut vt] {
        assert_eq!(
            hex(t
                .challenge(ChallengeLabel::Sumcheck)
                .expect("fixture")
                .to_le_bytes()
                .as_ref()),
            v["continuation_challenge"].as_str().expect("fixture")
        );
    }
    let mut bad = proof.clone();
    *bad.final_values.last_mut().expect("fixture") =
        *bad.final_values.last().expect("fixture") + K::from_i64(1);
    assert!(z.verify(&bad, &mut new()).is_ok());
    assert_eq!(
        z.verify_public(&bad, &tables, &mut new()).err(),
        Some(Error::ClaimMismatch)
    );
    for part in 0..3 {
        let mut bad = proof.clone();
        match part {
            0 => bad.skip_values.push(K::from_i64(0)),
            1 => bad.rounds.push(vec![]),
            _ => bad.final_values.pop().map(|_| ()).expect("fixture"),
        }
        let mut t = new();
        assert_eq!(z.verify(&bad, &mut t).err(), Some(Error::ProofShape));
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck).expect("fixture"),
            new().challenge(ChallengeLabel::Sumcheck).expect("fixture")
        );
    }
}
#[test]
fn matches_reference_zerocheck_bytes_and_accounting() {
    let lines = include_str!("../../../research/zerocheck/vectors.jsonl");
    assert_eq!(lines.lines().count(), 130);
    for line in lines.lines() {
        let v: Value = serde_json::from_str(line).expect("fixture");
        if v["field"] == 4 {
            check::<QM31>(&v)
        } else {
            check::<OM31>(&v)
        }
    }
}

#[test]
fn rejects_invalid_zero_descriptors_and_accepts_empty_relations() {
    use stele_field::Field;
    let (zero, one) = (QM31::from_i64(0), QM31::from_i64(1));
    for m in [0, 2] {
        let mut i = Instance {
            id: 1,
            num_vars: m,
            inputs: vec![],
            terms: vec![],
            claimed_sum: zero,
        };
        let z = Zerocheck {
            instance: &i,
            skip: 0,
        };
        let p = z
            .prove(&[], &mut transcript())
            .expect("empty zero relation");
        let r = z
            .verify_public(&p, &[], &mut transcript())
            .expect("closed empty relation");
        assert!(r.claims.is_empty());
        assert_eq!(r.sc.map(|r| r.numerator), [u64::from(m), 0, 0]);
        for skip in [1, 3, 5] {
            assert_eq!(
                Zerocheck { instance: &i, skip }.encode(),
                Err(Error::InvalidZerocheck)
            );
        }
        i.terms.push(Term {
            coefficient: one,
            factors: vec![],
        });
        let expected = if m == 0 {
            Error::FinalEvaluationMismatch
        } else {
            Error::RoundSumMismatch
        };
        assert_eq!(
            Zerocheck {
                instance: &i,
                skip: 0
            }
            .prove(&[], &mut transcript()),
            Err(expected)
        );
        i.claimed_sum = one;
        assert_eq!(
            Zerocheck {
                instance: &i,
                skip: 0
            }
            .encode(),
            Err(Error::InvalidZerocheck)
        );
    }
}
