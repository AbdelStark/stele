//! RFC-0006 A2: actual instance batching, byte parity, obligations and accounting.
use serde_json::Value;
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{batch::Batch, Dense, Error, Instance, Proof, Term};
fn array(v: &Value) -> &[Value] {
    v.as_array().expect("fixture array")
}
fn number(v: &Value) -> u64 {
    v.as_u64().expect("fixture integer")
}
fn field<K: ChallengeField>(v: &Value) -> K
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes: Vec<u8> = array(v)
        .iter()
        .flat_map(|v| (number(v) as u32).to_le_bytes())
        .collect();
    K::from_le_bytes(bytes.try_into().ok().expect("field width")).expect("canonical field")
}
fn values<K: ChallengeField>(v: &Value) -> Vec<K>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v).iter().map(field).collect()
}
fn proof<K: ChallengeField>(v: &Value) -> Proof<K>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    Proof {
        rounds: array(&v["rounds"]).iter().map(values).collect(),
        final_values: array(&v["final"]).iter().flat_map(values).collect(),
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(v: &Value)
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let members: Vec<_> = array(&v["batch"]["instances"])
        .iter()
        .map(|i| Instance {
            id: number(&i["id"]),
            num_vars: number(&i["m"]) as u32,
            inputs: array(&i["ids"]).iter().map(number).collect(),
            terms: array(&i["terms"])
                .iter()
                .map(|term| Term {
                    coefficient: field(&term[0]),
                    factors: array(&term[1]).iter().map(|v| number(v) as u32).collect(),
                })
                .collect(),
            claimed_sum: field(&i["sum"]),
        })
        .collect();
    let b = Batch {
        id: number(&v["batch"]["id"]),
        instances: &members,
    };
    let tables: Vec<Vec<Vec<K>>> = array(&v["tables"])
        .iter()
        .map(|g| array(g).iter().map(values).collect())
        .collect();
    let mut pt = Transcript::new(b"batch study").expect("public");
    let actual = b.prove(tables.clone(), &mut pt).expect("honest batch");
    assert_eq!(actual, proof(&v["proof"]));
    let encoded: String = b
        .encode()
        .expect("descriptor")
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    assert_eq!(encoded, v["context_hex"].as_str().expect("hex"));
    let mut vt = Transcript::new(b"batch study").expect("public");
    let r = b
        .verify_public(&actual, &tables, &mut vt)
        .expect("public batch");
    assert_eq!(r.point, values(&v["point"]));
    assert_eq!(r.sc.numerator, number(&v["receipt"]["sc"]));
    assert_eq!(r.rlc.numerator, number(&v["receipt"]["rlc"]));
    assert_eq!(r.sc.id, b.id);
    assert_eq!(r.rlc.id, b.id);
    assert_eq!(r.sc.m as usize, r.point.len());
    assert_eq!(r.sc.degree as u64, number(&v["receipt"]["degree"]));
    assert_eq!(r.rlc.t as usize, members.len());
    assert_eq!(r.sc.field_degree as u64, number(&v["degree"]));
    assert_eq!(r.rlc.field_degree, r.sc.field_degree);
    let mut at = 0;
    for i in &members {
        for id in &i.inputs {
            assert_eq!(r.claims[at].tensor, *id);
            assert_eq!(
                r.claims[at].point,
                r.point[r.point.len() - i.num_vars as usize..]
            );
            assert_eq!(r.claims[at].value, actual.final_values[at]);
            at += 1;
        }
    }
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
    let continued = stele_sumcheck::prove(
        &next,
        Dense::new(&next, data.clone()).expect("shape"),
        &mut pt,
    )
    .expect("continuation");
    let expected = Proof {
        rounds: array(&v["continuation"]["rounds"])
            .iter()
            .map(values)
            .collect(),
        final_values: values(&v["continuation"]["final"]),
    };
    assert_eq!(continued, expected);
    let _ = stele_sumcheck::verify_public(&next, &continued, &data, &mut vt)
        .expect("same continuation");
    let mut changed = actual.clone();
    if changed.final_values.pop().is_none() {
        changed.final_values.push(K::from_i64(0));
    }
    assert_eq!(
        b.verify(
            &changed,
            &mut Transcript::new(b"batch study").expect("public")
        )
        .err(),
        Some(Error::ProofShape)
    );
}
#[test]
fn matches_reference_batch_bytes_and_accounting() {
    for line in include_str!("fixtures/batch-instances.jsonl").lines() {
        let v: Value = serde_json::from_str(line).expect("fixture");
        if number(&v["degree"]) == 4 {
            check::<QM31>(&v)
        } else {
            check::<OM31>(&v)
        }
    }
}
#[test]
fn rejects_invalid_batches_and_alias_tables() {
    let i = Instance {
        id: 1,
        num_vars: 0,
        inputs: vec![11],
        terms: vec![],
        claimed_sum: QM31::from_i64(0),
    };
    let invalid = |id, instances: &[Instance<QM31>]| {
        assert_eq!(Batch { id, instances }.encode(), Err(Error::InvalidBatch));
    };
    invalid(3, &[]);
    invalid(1, std::slice::from_ref(&i));
    invalid(3, &[i.clone(), i.clone()]);
    let mut other = i.clone();
    other.id = 2;
    other.num_vars = 1;
    invalid(3, &[i.clone(), other.clone()]);
    other.num_vars = 0;
    let instances = [i, other];
    let b = Batch {
        id: 3,
        instances: &instances,
    };
    let mut tables = vec![vec![vec![QM31::from_i64(3)]]; 2];
    let proof = b
        .prove(
            tables.clone(),
            &mut Transcript::new(b"public").expect("public"),
        )
        .expect("zero polynomial");
    tables[1][0][0] = QM31::from_i64(4);
    assert_eq!(
        b.verify_public(
            &proof,
            &tables,
            &mut Transcript::new(b"public").expect("public")
        )
        .err(),
        Some(Error::PublicShape)
    );
}
