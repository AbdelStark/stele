//! Cache-resident packed field throughput (RFC-0018 §1, task E1-04).
use std::{hint::black_box, time::Instant};
use stele_simd::{Backend, Op, PackedM31, PackedQM31};

fn time<T>(iterations: u64, mut operation: impl FnMut() -> T) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    start.elapsed().as_nanos()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(100_000);
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let backends: Vec<_> = [
        Backend::Scalar,
        Backend::Neon,
        Backend::Avx2,
        Backend::Avx512,
    ]
    .into_iter()
    .filter(|b| b.available())
    .collect();
    let a = std::array::from_fn(|c| std::array::from_fn(|i| ((c * 16 + i + 1) * 8191) as u32));
    let b = std::array::from_fn(|c| std::array::from_fn(|i| ((c * 16 + i + 17) * 65521) as u32));
    let ma = PackedM31::from_lazy(a[0]).ok_or("invalid input")?;
    let mb = PackedM31::from_lazy(b[0]).ok_or("invalid input")?;
    let qa = PackedQM31::from_lazy(a).ok_or("invalid input")?;
    let qb = PackedQM31::from_lazy(b).ok_or("invalid input")?;
    for backend in &backends {
        for op in [Op::Add, Op::Sub, Op::Mul] {
            backend.m31(op, ma, mb)?;
            backend.qm31(op, qa, qb)?;
            time(1000, || {
                backend
                    .m31(op, black_box(ma), black_box(mb))
                    .expect("checked backend")
            });
            time(1000, || {
                backend
                    .qm31(op, black_box(qa), black_box(qb))
                    .expect("checked backend")
            });
        }
    }
    let mut samples = Vec::with_capacity(backends.len() * 18);
    let start = Instant::now();
    for round in 0..3 {
        for index in 0..backends.len() {
            let backend = backends[(index + round) % backends.len()];
            for op in [Op::Add, Op::Sub, Op::Mul] {
                let m = time(iterations, || {
                    backend
                        .m31(op, black_box(ma), black_box(mb))
                        .expect("checked backend")
                });
                let q = time(iterations, || {
                    backend
                        .qm31(op, black_box(qa), black_box(qb))
                        .expect("checked backend")
                });
                samples.push((backend, "m31", op, m));
                samples.push((backend, "qm31", op, q));
            }
        }
    }
    let total = start.elapsed().as_nanos();
    println!("total {total}");
    for (backend, field, op, ns) in samples {
        println!("sample {backend:?}/{field}/{op:?} {ns}");
    }
    Ok(())
}
