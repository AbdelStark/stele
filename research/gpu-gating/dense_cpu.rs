//! E16-21 GPU gating micro-benchmark (RFC-0014 §1, §5): the real stele-sumcheck `Dense`
//! strategy on the same tables and challenges as `dense_gpu.cu`. Research code; nothing in
//! `crates/` imports it. Ledger: `bench/ledger/e16-21-gpu-gating.json`.
//!
//! Run: copy to `crates/stele-sumcheck/examples/dense_cpu.rs`, then
//! `cargo run --release -p stele-sumcheck --features std --example dense_cpu <K> <logn>`.
use std::time::Instant;
use stele_field::{Field, Serialize, CM31, M31, QM31};
use stele_sumcheck::{Dense, Instance, Summand, Term};

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).map(|a| a.parse().unwrap()).collect();
    let (k, logn) = (args[0], args[1]);
    let n = 1usize << logn;
    let (a, b, q) = ([73i64, 29, 41, 13], [19i64, 7, 3, 23], [1048573i64, 1048571, 999983, 1000003]);
    let tables: Vec<Vec<QM31>> = (0..k)
        .map(|t| (0..n as i64).map(|j| QM31::from_i64((j * a[t] + b[t]) % q[t] - q[t] / 2)).collect())
        .collect();
    let instance = Instance {
        id: 1,
        num_vars: logn as u32,
        inputs: (0..k as u64).collect(),
        terms: vec![Term { coefficient: QM31::from_i64(1), factors: (0..k as u32).collect() }],
        claimed_sum: QM31::from_i64(0),
    };
    let m = |v: i64| M31::from_i64(v);
    let challenge = |i: i64| {
        QM31(CM31(m(1000003 * i + 17), m(7919 * i + 5)), CM31(m(104729 * i + 3), m(31337 * i + 11)))
    };
    let start = Instant::now();
    let mut dense = Dense::new(&instance, tables).unwrap();
    let mut fnv: u64 = 0xcbf29ce484222325;
    let mut put = |v: QM31| {
        for byte in v.to_le_bytes() {
            fnv ^= byte as u64;
            fnv = fnv.wrapping_mul(0x100000001b3);
        }
    };
    for i in 0..logn {
        for v in dense.round(&instance).unwrap() {
            put(v);
        }
        dense.fold(challenge(i as i64)).unwrap();
    }
    for v in dense.final_values().unwrap() {
        put(v);
    }
    println!(
        "cpu K={k} logn={logn} threads={} total_s={:.4} fnv={fnv:016x}",
        rayon::current_num_threads(),
        start.elapsed().as_secs_f64()
    );
}
