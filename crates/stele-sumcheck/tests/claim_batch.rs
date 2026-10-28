//! RFC-0006 A2 mode 1: byte/accounting parity and independent coefficient evaluation.
use serde_json::Value;
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{claim_batch::Batch, Error};
pub mod support;
use support::*;
fn check<K: ChallengeField + Eq + core::fmt::Debug>(v: &Value)
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let claims: Vec<_> = array(&v["batch"]["claims"])
        .iter()
        .map(|c| (values(&c[0]), field::<K>(&c[1])))
        .collect();
    let b = Batch {
        id: number(&v["batch"]["id"]),
        tensor: number(&v["batch"]["tensor"]),
        num_vars: number(&v["batch"]["m"]) as u32,
        claims: &claims,
    };
    let table = values::<K>(&v["tables"]);
    let mut pt = Transcript::new(b"batch study").expect("public");
    let actual = b.prove(table.clone(), &mut pt).expect("honest claims");
    assert_eq!(actual, proof(&v["proof"]));
    let hex: String = b
        .encode()
        .expect("descriptor")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, v["context_hex"].as_str().expect("hex"));
    let mut vt = Transcript::new(b"batch study").expect("public");
    let r = b
        .verify_public(&actual, &table, &mut vt)
        .expect("public claims");
    assert_eq!(r.point, values(&v["point"]));
    assert_eq!(r.claims.len(), 1);
    assert_eq!(r.claims[0].tensor, b.tensor);
    assert_eq!(r.claims[0].point, r.point);
    assert_eq!(r.claims[0].value, actual.final_values[0]);
    assert_eq!(r.sc.id, b.id);
    assert_eq!(r.rlc.id, b.id);
    assert_eq!(r.sc.m, b.num_vars);
    assert_eq!(r.sc.degree, 2);
    assert_eq!(r.sc.numerator, number(&v["receipt"]["sc"]));
    assert_eq!(r.rlc.numerator, number(&v["receipt"]["rlc"]));
    assert_eq!(r.rlc.t as usize, claims.len());
    assert_eq!(r.sc.field_degree as u64, number(&v["degree"]));
    assert_eq!(r.rlc.field_degree, r.sc.field_degree);
    continuation(v, &mut pt, &mut vt);
    let mut changed = actual.clone();
    changed.final_values[0] = changed.final_values[0] + K::from_i64(1);
    assert_eq!(
        b.verify_public(
            &changed,
            &table,
            &mut Transcript::new(b"batch study").expect("public")
        )
        .err(),
        Some(Error::FinalEvaluationMismatch)
    );
    changed.final_values.push(K::from_i64(1));
    assert_eq!(
        b.verify(&changed, &mut Transcript::new(b"public").expect("public"))
            .err(),
        Some(Error::ProofShape)
    );
}
#[test]
fn matches_reference_claim_bytes_and_accounting() {
    let records = include_str!("fixtures/batch-claims.jsonl");
    assert_eq!(records.lines().count(), 6);
    for line in records.lines() {
        let v: Value = serde_json::from_str(line).expect("fixture");
        if number(&v["degree"]) == 4 {
            check::<QM31>(&v)
        } else {
            check::<OM31>(&v)
        }
    }
}
fn random<K: ChallengeField>(seed: &mut u64) -> K
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes: Vec<u8> = (0..K::from_i64(0).to_le_bytes().as_ref().len() / 4)
        .flat_map(|_| {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((*seed >> 32) as u32 % K::MODULUS).to_le_bytes()
        })
        .collect();
    K::from_le_bytes(bytes.try_into().ok().expect("width")).expect("canonical")
}
fn coefficient_checks<K: ChallengeField + Eq + core::fmt::Debug>()
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut seed = 920u64;
    for case in 0..10_000 {
        let m = case % 6;
        let mut claims = Vec::new();
        for c in 0..3 {
            let point = (0..m)
                .map(|j| {
                    if j < (case + c) % (m + 1) {
                        K::from_i64(((case + j + c) % 2) as i64)
                    } else {
                        random(&mut seed)
                    }
                })
                .collect();
            claims.push((point, K::from_i64(0)));
        }
        if case % 3 == 0 {
            claims[1] = claims[0].clone();
        }
        let b = Batch {
            id: 1,
            tensor: 2,
            num_vars: m as u32,
            claims: &claims,
        };
        let gamma = match case % 7 {
            0 => K::from_i64(0),
            1 => K::from_i64(1),
            2 => K::from_i64(-1),
            _ => random(&mut seed),
        };
        let point: Vec<K> = (0..m).map(|_| random(&mut seed)).collect();
        let mut table = b.coefficient_table(gamma).expect("sparse table");
        // Independent leading-coordinate folds, rather than the direct verifier eq formula.
        for r in &point {
            let half = table.len() / 2;
            for j in 0..half {
                table[j] = table[j] + *r * (table[j + half] - table[j]);
            }
            table.truncate(half);
        }
        assert_eq!(
            table[0],
            b.coefficient(&point, gamma).expect("verifier coefficient")
        );
    }
    let repeated = vec![(vec![K::from_i64(0)], K::from_i64(0)); 2];
    let b = Batch {
        id: 1,
        tensor: 2,
        num_vars: 1,
        claims: &repeated,
    };
    assert_eq!(
        b.coefficient_table(K::from_i64(-1)).expect("cancellation"),
        vec![K::from_i64(0); 2]
    );
    assert_eq!(
        b.coefficient(&[K::from_i64(2)], K::from_i64(-1))
            .expect("zero coefficient"),
        K::from_i64(0)
    );
}
#[test]
fn matches_reference_coefficients_at_ten_thousand_points_per_field() {
    coefficient_checks::<QM31>();
    coefficient_checks::<OM31>();
}
#[test]
fn rejects_invalid_claim_descriptors_and_table_shapes() {
    let empty = Batch::<QM31> {
        id: 1,
        tensor: 2,
        num_vars: 0,
        claims: &[],
    };
    assert_eq!(empty.encode(), Err(Error::InvalidBatch));
    let claims = [(vec![], QM31::from_i64(3))];
    let mut b = Batch {
        id: 1,
        tensor: 2,
        num_vars: 1,
        claims: &claims,
    };
    assert_eq!(b.encode(), Err(Error::InvalidBatch));
    b.num_vars = 0;
    assert_eq!(
        b.prove(vec![], &mut Transcript::new(b"public").expect("public")),
        Err(Error::PublicShape)
    );
}
