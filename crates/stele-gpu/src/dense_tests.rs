//! RFC-0014 A2 and NC-1000. Inject true lazy limbs into the same DMA and kernel paths.
use super::*;
use stele_kernels::{Field, CM31};

#[test]
#[ignore = "requires an actual CUDA device; invoked explicitly by the parity gate"]
fn matches_reference_raw_lazy_device_boundaries() {
    let cuda = Cuda::new().expect("required CUDA");
    let p = M31::MODULUS;
    let mut seed = 0x5354_454c_4521_3289u64;
    for i in 0..1000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let raw = match i % 5 {
            0 => p,
            1 => 2 * p - 1,
            2 => p + 1,
            3 => 0,
            _ => p + (seed as u32 % p),
        };
        let limb = M31::from_lazy(raw).expect("lazy representative");
        let q = QM31(CM31(limb, M31::ONE), CM31(M31::ZERO, limb));
        let message = [limb, M31::ONE, M31::ZERO, limb];
        let session = cuda.session();
        let g = SourceGeometry {
            id: 1,
            rows: 2,
            columns: 2,
        };
        let mut owner = session.original(g, &message).expect("four input limbs");
        let stream = &cuda.stream;
        assert_eq!(
            cuda.complete_transfer(stream.clone_dtoh(&owner.words))
                .expect("original DMA"),
            message.map(|x| x.as_u32())
        );
        cuda.complete_transfer(stream.memcpy_htod(&[raw, p + 1, p, raw][..], &mut owner.words))
            .expect("lazy original input");
        let pairs = [(0, q)];
        let claims = [WeightedClaim {
            weights: &pairs,
            value: q,
            gamma: q,
        }];
        let mut packed = Packed::new(&claims, 1).expect("valid ordered claim");
        packed.weights[0] = [raw, p + 1, p, raw];
        packed.gammas[0] = [raw, p + 1, p, raw];
        let (mut state, sum) = session
            .build_dense(&owner, packed)
            .expect("raw CUDA construction");
        let weight = q * q;
        let x = QM31::from_i64(i64::from(limb.as_u32()));
        assert_eq!(sum, weight);
        assert_eq!(
            cuda.complete_transfer(stream.clone_dtoh(&state.weights))
                .expect("weight DMA"),
            [words(weight), [0; 4]]
        );
        let Face::Base(ref mut face) = state.face else {
            unreachable!()
        };
        assert_eq!(
            cuda.complete_transfer(stream.clone_dtoh(face))
                .expect("face DMA"),
            [limb.as_u32(), 0]
        );
        cuda.complete_transfer(stream.memcpy_htod(&[raw, p][..], face))
            .expect("lazy first face");
        let lazy_weight = words(weight).map(|v| v + p);
        cuda.complete_transfer(stream.memcpy_htod(&[lazy_weight, [p; 4]][..], &mut state.weights))
            .expect("lazy first weights");
        let multiply = weight * x;
        assert_eq!(
            Session::dense_round(&mut state).expect("canonical polynomial"),
            [multiply, QM31::ZERO, multiply]
        );
        Session::dense_fold(&mut state, q).expect("fold");
        let finals = Session::dense_finals(&state).expect("canonical compact fields");
        assert_eq!(finals, [weight * (QM31::ONE - q), x * (QM31::ONE - q)]);
        assert_eq!(session.counts().finals, 1);
    }
    println!("cuda_dense_lazy_cases=1000");
}

#[test]
#[ignore = "requires CUDA hardware"]
fn matches_reference_original_across_staging_chunks() {
    let cuda = Cuda::new().expect("CUDA required");
    let session = cuda.session();
    let geometry = SourceGeometry {
        id: 17,
        rows: 1 << 11,
        columns: 1 << 10,
    };
    let words: Vec<_> = (0..geometry.word_count().expect("valid geometry"))
        .map(|i| M31::from_u64((167 * i + i / (1 << 20)) as u64))
        .collect();
    let owner = session
        .original(geometry, &words)
        .expect("two staging chunks");
    for offset in [0, (1 << 20) - 16, words.len() - 32] {
        let slice = owner.words.slice(offset..offset + 32);
        let copied = cuda
            .complete_transfer(cuda.stream.clone_dtoh(&slice))
            .expect("completed transfer");
        assert!(copied
            .iter()
            .zip(&words[offset..])
            .all(|(&x, y)| x == y.as_u32()));
    }
}
