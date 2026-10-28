//! RFC-0006 A3 / RFC-0018 §1: complete CPU zerocheck/public-consumer microbenchmark.
use serde_json::{json, Value};
use std::{hint::black_box, time::Instant};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{zerocheck::Zerocheck, Instance, Term};
#[path = "../tests/support/zero_reference.rs"]
mod reference;
fn measure<K: ChallengeField + Eq>(
    degree: usize,
    skip: usize,
    m: usize,
    naive: bool,
) -> Result<Value, String> {
    if degree > 4 || skip > 4 || skip > m || m > 8 || (degree == 0 && skip != 0) {
        return Err("invalid benchmark shape".into());
    }
    let (n, s, j, a) = (1usize << m, 1usize << skip, m - skip, 4usize);
    let left: Vec<_> = (0..n)
        .map(|x| K::from_i64(((x * 73 + 19) % 31) as i64 - 15))
        .collect();
    let right = left
        .iter()
        .map(|x| (0..degree).fold(K::from_i64(1), |v, _| v * *x))
        .collect();
    let tables = vec![left.clone(), right, left.clone(), left];
    let terms = if degree == 0 {
        vec![]
    } else {
        vec![
            Term {
                coefficient: K::from_i64(1),
                factors: vec![0; degree],
            },
            Term {
                coefficient: K::from_i64(-1),
                factors: vec![1],
            },
        ]
    };
    let i = Instance {
        id: 100,
        num_vars: m as u32,
        inputs: vec![11, 12, 13, 14],
        terms,
        claimed_sum: K::from_i64(0),
    };
    let z = Zerocheck {
        instance: &i,
        skip: skip as u8,
    };
    let new =
        || Transcript::<K>::new(b"synthetic zerocheck baseline").map_err(|e| format!("{e:?}"));
    let (mut prover_ns, mut consumer_ns, mut canonical) = (0u128, 0u128, vec![]);
    let mut sc = vec![];
    for iteration in 0..4 {
        let start = Instant::now();
        let mut prover = new()?;
        let proof = if naive {
            reference::prove(black_box(&z), black_box(&tables), &mut prover)
        } else {
            z.prove(black_box(&tables), &mut prover)
                .map_err(|e| format!("{e:?}"))?
        };
        black_box(&proof);
        let pt = start.elapsed().as_nanos();
        let start = Instant::now();
        let mut verifier = new()?;
        let result = z
            .verify_public(black_box(&proof), black_box(&tables), &mut verifier)
            .map_err(|e| format!("{e:?}"))?;
        black_box(&result);
        let vt = start.elapsed().as_nanos();
        if iteration > 0 {
            prover_ns += pt;
            consumer_ns += vt;
        }
        assert_eq!(result.claims.len(), a * s);
        assert_eq!(
            result.sc.map(|r| r.numerator),
            [j as u64, (degree * (s - 1)) as u64, (j * degree) as u64]
        );
        sc = result
            .sc
            .iter()
            .enumerate()
            .map(|(phase, r)| {
                json!({"id":r.id,"phase":phase,"m":r.m,
            "degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
            })
            .collect();
        let pnext = prover
            .challenge(ChallengeLabel::Sumcheck)
            .map_err(|e| format!("{e:?}"))?;
        let vnext = verifier
            .challenge(ChallengeLabel::Sumcheck)
            .map_err(|e| format!("{e:?}"))?;
        assert!(pnext == vnext);
        let encoded: Vec<u8> = proof
            .skip_values
            .iter()
            .chain(proof.rounds.iter().flatten())
            .chain(&proof.final_values)
            .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
            .collect();
        if iteration == 0 {
            canonical = encoded;
        } else {
            assert_eq!(canonical, encoded);
        }
    }
    let (width, d, l) = (n / s, degree * (s - 1), degree.saturating_sub(1) * (s - 1));
    let storage = std::mem::size_of::<K>();
    let wire = K::from_i64(0).to_le_bytes().as_ref().len();
    let proof_fields = l + j * (degree + 1) + a * s;
    assert_eq!(canonical.len(), proof_fields * wire);
    // A3: conservative sum of all scratch field-buffer maxima, not isolated measured RSS.
    let scratch_fields = if naive {
        width + 2 * a * s + 2 * a + 4 * j + 2 * s
    } else {
        2 * a * width + 3 * width + 3 * a + 3 * s + 2 * (d + degree + 2) + 3 * j
    };
    // Includes descriptor/A1 suffix capacity and every message buffer; excludes Vec/allocator headers.
    let framing = z.encode().map_err(|e| format!("{e:?}"))?.len()
        + wire
        + 40
        + (l + degree + 1 + a * s) * wire;
    let consumer_fields = n + a * s * (m + 1) + 3 * j + 3 * s + 2 * (d + degree + 2) + 3 * a;
    let output: String = canonical.iter().map(|b| format!("{b:02x}")).collect();
    Ok(
        json!({"prover_ns":u64::try_from(prover_ns).map_err(|_|"time overflow")?,
        "consumer_ns":u64::try_from(consumer_ns).map_err(|_|"time overflow")?,
        "output":output,"sc":sc,"points":n,"m":m,"degree":degree,"skip":skip,"claims":a*s,
        "caller_input_payload_bytes":a*n*storage,"proof_payload_bytes":proof_fields*storage,
        "prover_scratch_payload_bound_bytes":scratch_fields*storage+framing,
        "consumer_scratch_payload_bound_bytes":consumer_fields*storage+framing}),
    )
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("expected QM31|OM31 degree skip dense|reference".into());
    }
    let degree = args[1].parse().map_err(|_| "invalid degree")?;
    let skip = args[2].parse().map_err(|_| "invalid skip")?;
    let naive = match args[3].as_str() {
        "dense" => false,
        "reference" => true,
        _ => return Err("invalid strategy".into()),
    };
    let result = match args[0].as_str() {
        "QM31" => measure::<QM31>(degree, skip, 8, naive)?,
        "OM31" => measure::<OM31>(degree, skip, 8, naive)?,
        _ => return Err("invalid field".into()),
    };
    println!("{result}");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn check<K: ChallengeField + Eq>() {
        for degree in 0..=4 {
            for skip in 0..=if degree == 0 { 0 } else { 4 } {
                let dense = measure::<K>(degree, skip, 5, false).expect("dense");
                let naive = measure::<K>(degree, skip, 5, true).expect("reference");
                for key in [
                    "output",
                    "claims",
                    "points",
                    "caller_input_payload_bytes",
                    "proof_payload_bytes",
                ] {
                    assert_eq!(dense[key], naive[key]);
                }
                assert!(dense["prover_ns"].as_u64().expect("integer") > 0);
                assert!(dense["consumer_ns"].as_u64().expect("integer") > 0);
            }
        }
    }
    #[test]
    fn matches_reference_benchmark_cases() {
        check::<QM31>();
        check::<OM31>();
    }
    #[test]
    fn rejects_invalid_benchmark_shapes() {
        for (d, k, m) in [(5, 0, 8), (0, 1, 8), (1, 5, 8), (1, 2, 1), (1, 0, 9)] {
            assert!(measure::<QM31>(d, k, m, false).is_err());
        }
    }
}
