//! RFC-0018 §1 / RFC-0006 A2: every warmup and measured batch is publicly verified.
use serde_json::{json, Value};
use std::{hint::black_box, time::Instant};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{batch, claim_batch, Error, Instance, Proof, Term};

fn transcript<K: ChallengeField>() -> Result<Transcript<K>, Error> {
    Ok(Transcript::new(b"synthetic batching baseline")?)
}
fn measure<K: ChallengeField + Eq>(
    mut prove: impl FnMut() -> Result<Proof<K>, Error>,
    mut verify: impl FnMut(&Proof<K>) -> Result<batch::Reduction<K>, Error>,
    expected: (u32, u8, u32, usize),
    iterations: usize,
) -> Result<Value, Error> {
    let (m, degree, count, claims) = expected;
    let (mut elapsed, mut canonical) = (0u128, Vec::new());
    for iteration in 0..=iterations {
        let start = Instant::now();
        let proof = prove()?;
        black_box(&proof);
        let time = start.elapsed().as_nanos();
        if iteration != 0 {
            elapsed += time;
        }
        let r = verify(&proof)?;
        assert_eq!(
            (r.sc.id, r.sc.m, r.sc.degree, r.sc.numerator),
            (1, m, degree, u64::from(m) * u64::from(degree))
        );
        assert_eq!(
            (r.rlc.id, r.rlc.t, r.rlc.numerator),
            (1, count, u64::from(count))
        );
        assert_eq!(r.claims.len(), claims);
        assert_eq!(
            usize::from(r.sc.field_degree),
            K::from_i64(0).to_le_bytes().as_ref().len() / 4
        );
        assert_eq!(r.rlc.field_degree, r.sc.field_degree);
        let encoded: Vec<u8> = proof
            .rounds
            .iter()
            .flatten()
            .chain(&proof.final_values)
            .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
            .collect();
        if iteration == 0 {
            canonical = encoded;
        } else {
            assert_eq!(encoded, canonical);
        }
    }
    Ok(
        json!({"time_ns": u64::try_from(elapsed).expect("nanoseconds fit"),
        "output": canonical.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "m": m, "degree": degree, "count": count, "claims": claims}),
    )
}
fn run<K: ChallengeField + Eq>(case: usize, m: u32, iterations: usize) -> Result<Value, Error> {
    assert!(case < 9 && m >= 4 && iterations > 0);
    let field_bytes = K::from_i64(0).to_le_bytes().as_ref().len();
    let (mut result, points, elements) = if case < 6 {
        let degree = 2 * (case / 2);
        let mut instances = Vec::new();
        let mut tables = Vec::new();
        let mut points = 0usize;
        for member in 0..3u32 {
            let dim = if case.is_multiple_of(2) {
                m
            } else {
                m - 2 * member
            };
            let data: Vec<Vec<K>> = [(73, 19, 31), (29, 7, 17)]
                .into_iter()
                .map(|(a, b, q)| {
                    (0..1usize << dim)
                        .map(|j| K::from_i64((j as i64 * a + b + member as i64) % q - q / 2))
                        .collect()
                })
                .collect();
            let sum = data[0]
                .iter()
                .zip(&data[1])
                .fold(K::from_i64(0), |sum, (a, b)| {
                    let left = (0..degree).fold(K::from_i64(1), |p, _| p * *a);
                    let right = (0..degree.saturating_sub(1)).fold(K::from_i64(2), |p, _| p * *b);
                    sum + left + right
                });
            instances.push(Instance {
                id: 10 + u64::from(member),
                num_vars: dim,
                inputs: vec![100 + 2 * u64::from(member), 101 + 2 * u64::from(member)],
                terms: vec![
                    Term {
                        coefficient: K::from_i64(1),
                        factors: vec![0; degree],
                    },
                    Term {
                        coefficient: K::from_i64(2),
                        factors: vec![1; degree.saturating_sub(1)],
                    },
                ],
                claimed_sum: sum,
            });
            points += 1usize << dim;
            tables.push(data);
        }
        let b = batch::Batch {
            id: 1,
            instances: &instances,
        };
        (
            measure(
                || b.prove(black_box(&tables).clone(), &mut transcript()?),
                |p| b.verify_public(p, &tables, &mut transcript()?),
                (m, degree.max(case % 2) as u8, 3, 6),
                iterations,
            )?,
            points,
            2 * points,
        )
    } else {
        let table: Vec<K> = (0..1usize << m)
            .map(|j| K::from_i64((j as i64 * 73 + 19) % 31 - 15))
            .collect();
        let mut claims = Vec::new();
        for claim in 0..4 {
            let point: Vec<K> = (0..m)
                .map(|j| {
                    if j < 2 && case != 8 {
                        let block = if case == 7 { claim % 2 } else { claim };
                        K::from_i64((block >> (1 - j)) & 1)
                    } else {
                        K::from_i64(2 + i64::from(j) + claim)
                    }
                })
                .collect();
            let eq = stele_poly::eq_table(&point).map_err(|_| Error::Capacity)?;
            let value = table
                .iter()
                .zip(eq)
                .fold(K::from_i64(0), |sum, (v, w)| sum + *v * w);
            claims.push((point, value));
        }
        let b = claim_batch::Batch {
            id: 1,
            tensor: 77,
            num_vars: m,
            claims: &claims,
        };
        (
            measure(
                || b.prove(black_box(&table).clone(), &mut transcript()?),
                |p| b.verify_public(p, &table, &mut transcript()?),
                (m, 2, 4, 1),
                iterations,
            )?,
            1usize << m,
            2 * (1usize << m),
        )
    };
    result["points"] = json!(points);
    result["working_table_payload_bytes"] = json!(elements * field_bytes);
    Ok(result)
}
fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("expected QM31|OM31 and case 0..8".into());
    }
    let case: usize = args[1].parse().map_err(|_| "invalid case")?;
    if case >= 9 {
        return Err("invalid case".into());
    }
    let result = match args[0].as_str() {
        "QM31" => run::<QM31>(case, 12, 3),
        "OM31" => run::<OM31>(case, 12, 3),
        _ => return Err("invalid field".into()),
    }
    .map_err(|e| format!("{e:?}"))?;
    println!("{result}");
    Ok(())
}
#[test]
fn accepts_all_benchmark_cases() {
    for case in 0..9 {
        for r in [run::<QM31>(case, 4, 1), run::<OM31>(case, 4, 1)] {
            let result = r.expect("verified benchmark");
            assert!(result["time_ns"].as_u64().expect("time") > 0);
            assert_eq!(
                result["points"],
                if case < 6 {
                    if case.is_multiple_of(2) {
                        48
                    } else {
                        21
                    }
                } else {
                    16
                }
            );
        }
    }
}
#[test]
fn rejects_unverified_sample() {
    assert_eq!(
        measure::<QM31>(
            || Ok(Proof {
                rounds: vec![],
                final_values: vec![]
            }),
            |_| Err(Error::ClaimMismatch),
            (0, 0, 1, 0),
            1
        ),
        Err(Error::ClaimMismatch)
    );
}
