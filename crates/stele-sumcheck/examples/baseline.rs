//! RFC-0018 §1 / RFC-0006 A1: verified dense QM31 sumcheck microbenchmark.
use std::{hint::black_box, time::Instant};
use stele_field::{Field, Serialize, QM31};
use stele_hash::Transcript;
use stele_sumcheck::{prove, verify_public, Dense, Instance, Term};

fn main() -> Result<(), String> {
    let degree: usize = std::env::args()
        .nth(1)
        .ok_or("expected degree 0..4")?
        .parse()
        .map_err(|_| "invalid degree")?;
    if degree > 4 {
        return Err("invalid degree".into());
    }
    let tables: Vec<Vec<QM31>> = [(73, 19, 31), (29, 7, 17)]
        .into_iter()
        .map(|(a, b, q)| {
            (0..16384)
                .map(|j| QM31::from_i64((j * a + b) % q - q / 2))
                .collect()
        })
        .collect();
    let mut sum = QM31::from_i64(0);
    for j in 0..16384 {
        let left = (0..degree).fold(QM31::from_i64(1), |p, _| p * tables[0][j]);
        let right = (0..degree.saturating_sub(1)).fold(QM31::from_i64(2), |p, _| p * tables[1][j]);
        sum = sum + left + right;
    }
    let i = Instance {
        id: 100,
        num_vars: 14,
        inputs: vec![11, 12],
        terms: vec![
            Term {
                coefficient: QM31::from_i64(1),
                factors: vec![0; degree],
            },
            Term {
                coefficient: QM31::from_i64(2),
                factors: vec![1; degree.saturating_sub(1)],
            },
        ],
        claimed_sum: sum,
    };
    let mut total = 0u128;
    let mut canonical = Vec::new();
    for iteration in 0..4 {
        let start = Instant::now();
        let mut transcript =
            Transcript::new(b"synthetic sumcheck baseline").map_err(|e| format!("{e:?}"))?;
        let dense =
            Dense::new(black_box(&i), black_box(&tables).clone()).map_err(|e| format!("{e:?}"))?;
        let proof = prove(&i, dense, &mut transcript).map_err(|e| format!("{e:?}"))?;
        black_box(&proof);
        let elapsed = start.elapsed().as_nanos();
        if iteration != 0 {
            total += elapsed;
        }
        let mut verifier =
            Transcript::new(b"synthetic sumcheck baseline").map_err(|e| format!("{e:?}"))?;
        let receipt =
            verify_public(&i, &proof, &tables, &mut verifier).map_err(|e| format!("{e:?}"))?;
        assert_eq!(receipt.sc.numerator, 14 * degree as u64);
        let encoded: Vec<u8> = proof
            .rounds
            .iter()
            .flatten()
            .chain(&proof.final_values)
            .flat_map(|v| v.to_le_bytes())
            .collect();
        if iteration == 0 {
            canonical = encoded;
        } else {
            assert_eq!(encoded, canonical);
        }
    }
    println!("time_ns {total}");
    println!("dense_table_payload_bytes {}", 2 * 16384 * 16);
    print!("output ");
    for byte in canonical {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}
