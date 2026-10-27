//! Scalar multiplication measurements for RFC-0018 §1 / task E1-02.
use std::{hint::black_box, ops::Mul, time::Instant};
use stele_field::{Field, CM31, M31, QM31};

fn measure<F: Copy + Mul<Output = F>>(mut value: F, factor: F, iterations: u64) -> u128 {
    let factor = black_box(factor);
    let start = Instant::now();
    for _ in 0..iterations {
        value = black_box(value * factor);
    }
    black_box(value);
    start.elapsed().as_nanos()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .map(|x| x.parse::<u64>())
        .transpose()?
        .unwrap_or(1_000_000);
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let a = M31::from_i64(1729);
    let b = M31::from_i64(7919);
    let c = QM31(
        CM31(M31::from_i64(3), M31::from_i64(5)),
        CM31(M31::from_i64(7), M31::from_i64(11)),
    );
    let d = QM31(
        CM31(M31::from_i64(13), M31::from_i64(17)),
        CM31(M31::from_i64(19), M31::from_i64(23)),
    );
    measure(a, b, 10_000);
    measure(c, d, 10_000);
    let start = Instant::now();
    let mut samples = [[0u128; 2]; 5];
    for (index, sample) in samples.iter_mut().enumerate() {
        if index % 2 == 0 {
            sample[0] = measure(a, b, iterations);
            sample[1] = measure(c, d, iterations);
        } else {
            sample[1] = measure(c, d, iterations);
            sample[0] = measure(a, b, iterations);
        }
    }
    let total = start.elapsed().as_nanos();
    println!("total {total}");
    for [m31, qm31] in samples {
        println!("sample {m31} {qm31}");
    }
    Ok(())
}
