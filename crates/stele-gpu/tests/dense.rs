//! RFC-0014 A2. The CUDA gate requires real hardware and the field-only reference.
#![cfg(feature = "cuda")]
use stele_gpu::{Cuda, Error, Session};
use stele_kernels::{Backend, Field, Scalar, SourceGeometry, WeightedClaim, CM31, M31, QM31};
struct Seed(u64);
impl Seed {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
    fn field(&mut self) -> QM31 {
        let mut limb = || M31::from_u64(self.next().into());
        QM31(CM31(limb(), limb()), CM31(limb(), limb()))
    }
}
#[test]
#[ignore = "requires a real CUDA device; invoked explicitly by the hardware gate"]
fn matches_reference_cuda_dense_batches() {
    let cuda = Cuda::new().expect("required CUDA device");
    let mut rounds = 0;
    for case in 0..1000 {
        let session = cuda.session();
        let reference = Scalar::new();
        let mut seed = Seed(0x68cc0a48u64 + case);
        let g = SourceGeometry {
            id: 7,
            rows: 2usize << (seed.next() % 3),
            columns: 2usize << (seed.next() % 7),
        };
        let n = g.word_count().expect("valid seeded batch");
        let half = n / 4;
        let message: Vec<_> = (0..n)
            .map(|j| match (case + j as u64) % 6 {
                0 => M31::ZERO,
                1 => M31::ONE,
                2 => M31::from_i64(-1),
                3 => M31::from_lazy(M31::MODULUS).expect("valid seeded batch"),
                4 => M31::from_lazy(2 * M31::MODULUS - 1).expect("valid seeded batch"),
                _ => M31::from_u64(seed.next().into()),
            })
            .collect();
        let a = reference.original(g, &message).expect("valid seeded batch");
        let b = session.original(g, &message).expect("valid seeded batch");
        let mut pairs: Vec<_> = (0..half.min((seed.next() % 300) as usize))
            .map(|i| (i, seed.field()))
            .collect();
        pairs.extend([
            (half - 1, seed.field()),
            (half - 1, seed.field()),
            (0, seed.field()),
        ]);
        let claims = [
            WeightedClaim {
                weights: &pairs,
                value: seed.field(),
                gamma: seed.field(),
            },
            WeightedClaim {
                weights: &[],
                value: seed.field(),
                gamma: seed.field(),
            },
        ];
        let claims = if case % 17 == 0 {
            &claims[..0]
        } else {
            &claims[..]
        };
        let (mut cpu, v) = reference
            .dense_batch(g, &a, claims)
            .expect("valid seeded batch");
        let (mut gpu, w) = session
            .dense_batch(g, &b, claims)
            .expect("valid seeded batch");
        assert_eq!(v, w);
        for _ in 0..(2 * half).ilog2() {
            assert_eq!(
                Scalar::dense_round(&mut cpu).expect("valid seeded batch"),
                Session::dense_round(&mut gpu).expect("valid seeded batch")
            );
            let r = seed.field();
            Scalar::dense_fold(&mut cpu, r).expect("valid seeded batch");
            Session::dense_fold(&mut gpu, r).expect("valid seeded batch");
        }
        assert_eq!(
            Scalar::dense_finals(&cpu).expect("valid seeded batch"),
            Session::dense_finals(&gpu).expect("valid seeded batch")
        );
        let c = session.counts();
        assert_eq!(
            (c.originals, c.batches, c.rounds, c.folds, c.finals),
            (
                1,
                1,
                (2 * half).ilog2() as usize,
                (2 * half).ilog2() as usize,
                1
            )
        );
        assert_eq!(c.downloaded_bytes, 48 * c.rounds as u64 + 32);
        rounds += c.rounds;
    }
    println!("cuda_dense_cases=1000 rounds={rounds} folds={rounds} finals=1000");
}

#[test]
#[ignore = "requires a real CUDA device; invoked explicitly by the hardware gate"]
fn rejects_foreign_source_and_invalid_dense_transitions() {
    let cuda = Cuda::new().expect("required CUDA");
    let a = cuda.session();
    let b = cuda.session();
    let g = SourceGeometry {
        id: 7,
        rows: 2,
        columns: 2,
    };
    let message = [M31::ONE; 4];
    let owner = a.original(g, &message).expect("valid seeded batch");
    b.original(g, &message).expect("valid seeded batch");
    assert!(matches!(a.original(g, &message), Err(Error::Source)));
    assert!(matches!(
        a.original(SourceGeometry { id: 8, ..g }, &message[..3]),
        Err(Error::Geometry)
    ));
    assert!(matches!(b.dense_batch(g, &owner, &[]), Err(Error::Source)));
    assert!(matches!(
        a.dense_batch(SourceGeometry { id: 9, ..g }, &owner, &[]),
        Err(Error::Source)
    ));
    let invalid = [WeightedClaim {
        weights: &[(1, QM31::ZERO)],
        value: QM31::ONE,
        gamma: QM31::ZERO,
    }];
    assert!(matches!(
        a.dense_batch(g, &owner, &invalid),
        Err(Error::Geometry)
    ));
    let (mut state, _) = a.dense_batch(g, &owner, &[]).expect("valid seeded batch");
    assert!(matches!(
        Session::dense_fold(&mut state, QM31::ONE),
        Err(Error::Phase)
    ));
    assert!(matches!(Session::dense_finals(&state), Err(Error::Phase)));
    Session::dense_round(&mut state).expect("valid seeded batch");
    assert!(matches!(
        Session::dense_round(&mut state),
        Err(Error::Phase)
    ));
    Session::dense_fold(&mut state, QM31::ONE).expect("valid seeded batch");
    assert!(matches!(
        Session::dense_fold(&mut state, QM31::ONE),
        Err(Error::Phase)
    ));
    assert!(matches!(
        Session::dense_round(&mut state),
        Err(Error::Phase)
    ));
}
