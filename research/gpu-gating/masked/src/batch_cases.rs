//! RFC-0013 A5 item 5: real batch tables, ordinary Dense and near-miss controls.
use crate::{Field, Rng, K, M31};
use stele_reductions::stele_hash::{HashUsage, Transcript};
use stele_reductions::stele_pcs::{hiding_message, Policy, PreparedSource, Source};
use stele_reductions::zk::claims::{bench::BatchInputs, Claim};
use stele_sumcheck::{Dense, Summand};

pub(crate) const CASES: usize = 1000;
pub(crate) const SEED: u64 = 0x40_2000_0001;
pub(crate) const ELL: u8 = 3;
pub(crate) const M: u8 = 9;

pub(crate) fn message() -> Vec<M31> {
    let mut rng = Rng::new(SEED);
    let mut data: Vec<_> = (0..1usize << (ELL + M)).map(|_| rng.m31()).collect();
    data[..3].copy_from_slice(&[M31::ZERO, M31::ONE, -M31::ONE]);
    hiding_message(73, ELL, M, &data, &[17; 32]).unwrap()
}

pub(crate) fn prepared(message: &[M31]) -> PreparedSource<'_, K> {
    PreparedSource::hiding_with(
        73,
        ELL,
        M,
        2,
        message,
        &[17; 32],
        &mut HashUsage::default(),
        Policy::Two,
    )
    .unwrap()
}

pub(crate) fn claims(message: &[M31], seed: u64) -> (Vec<Claim<K>>, Vec<K>) {
    let mut rng = Rng::new(seed);
    let half = message.len() / 4;
    let cols = 1usize << M;
    let count = if seed.is_multiple_of(17) {
        0
    } else {
        1 + seed as usize % 5
    };
    let mut claims = Vec::new();
    let mut gammas = Vec::new();
    for c in 0..count {
        let mut weights = vec![
            (0, K::ZERO),
            (0, K::ONE),
            (0, -K::ONE),
            (half - 1, rng.qm31()),
            (cols - 1, rng.qm31()),
            (cols, rng.qm31()),
        ];
        weights
            .extend((0..1 + seed % 13).map(|_| ((rng.next() % half as u64) as usize, rng.qm31())));
        let value = weights.iter().fold(K::ZERO, |sum, (p, w)| {
            sum + *w * K::from_i64(i64::from(message[p / cols * 2 * cols + p % cols].as_u32()))
        });
        claims.push(Claim { value, weights });
        gammas.push(if seed.is_multiple_of(19) {
            K::ZERO
        } else if c == 0 {
            K::ONE
        } else {
            rng.qm31()
        });
    }
    (claims, gammas)
}

#[test]
fn accepts_batch_staging_and_rejects_outside_data_face() {
    let message = message();
    let prepared = prepared(&message);
    let (claims, gammas) = claims(&message, SEED);
    let p = crate::batch::Prepared::new(prepared.source(), &message, &claims, &gammas)
        .expect("staging");
    let reference = BatchInputs::new(7, &prepared, &claims, &gammas).unwrap();
    assert_eq!(p.len, reference.face.len());
    assert_eq!(p.claimed_sum, reference.instance.claimed_sum);
    for change in 0..3 {
        let mut claims = claims.clone();
        let mut gammas = gammas.clone();
        if change == 0 {
            gammas.pop();
        } else {
            claims[0]
                .weights
                .push((if change == 1 { p.len / 2 } else { usize::MAX }, K::ZERO));
        }
        assert!(
            crate::batch::Prepared::new(prepared.source(), &message, &claims, &gammas).is_none()
        );
        assert!(matches!(
            BatchInputs::new(7, &prepared, &claims, &gammas),
            Err(stele_reductions::zk::Error::Statement)
        ));
    }
    assert!(crate::batch::Prepared::new(
        prepared.source(),
        &message[..message.len() - 1],
        &claims,
        &gammas
    )
    .is_none());
    let plain = Source::<K>::new(73, ELL + 1, M + 1, 2, [0; 32]).unwrap();
    assert!(crate::batch::Prepared::new(&plain, &message, &claims, &gammas).is_none());
}

#[test]
fn rejects_batch_claim_near_miss_by_ordinary_round_sum() {
    let message = message();
    let prepared = prepared(&message);
    let (mut claims, gammas) = claims(&message, SEED);
    let honest = BatchInputs::new(7, &prepared, &claims, &gammas).unwrap();
    let dense = Dense::new(
        &honest.instance,
        vec![honest.weights.clone(), honest.face.clone()],
    )
    .unwrap();
    let round = dense.round(&honest.instance).unwrap();
    assert_eq!(round[0] + round[1], honest.instance.claimed_sum);
    claims[0].value = claims[0].value + K::ONE;
    let near = BatchInputs::new(7, &prepared, &claims, &gammas).unwrap();
    assert_eq!(near.weights, honest.weights);
    assert_eq!(near.face, honest.face);
    let p = crate::batch::Prepared::new(prepared.source(), &message, &claims, &gammas).unwrap();
    assert_ne!(p.claimed_sum, round[0] + round[1]);
    let dense = Dense::new(&near.instance, vec![near.weights, near.face]).unwrap();
    assert_eq!(
        stele_sumcheck::prove(
            &near.instance,
            dense,
            &mut Transcript::new(b"batch near miss").unwrap()
        )
        .err(),
        Some(stele_sumcheck::Error::RoundSumMismatch)
    );
}

#[test]
fn matches_reference_batch_kernels_on_host() {
    let message = message();
    let prepared = prepared(&message);
    let mut input = Vec::new();
    for case in 0..CASES {
        let (claims, gammas) = claims(&message, SEED + 2 * case as u64);
        let p = crate::batch::Prepared::new(prepared.source(), &message, &claims, &gammas).unwrap();
        assert_eq!(
            p.upload_bytes(),
            4 * (p.message.len() + p.pairs.len()) + 8 * p.offsets.len()
        );
        for raw in [0, 1] {
            input.extend([p.len as u32, p.columns as u32, p.pairs.len() as u32, raw]);
            input.extend(
                p.offsets
                    .iter()
                    .flat_map(|x| [*x as u32, (*x >> 32) as u32]),
            );
            input.extend_from_slice(&p.message);
            input.extend_from_slice(&p.pairs);
        }
    }
    let source = format!("#include <cstdio>\n#include <vector>\n#define __device__\n#define __global__\n#define __forceinline__ inline\n{}\n#define GRID_STRIDE(j,n) for(u64 j=0;j<(n);++j)\n{}\n{}", crate::host_probe::helpers(), include_str!("batch.cu"), include_str!("batch_host.cuh"));
    let output = crate::host_probe::run(&source, &input);
    let len = message.len() / 2;
    assert_eq!(output.len(), CASES * 2 * len * 5);
    for case in 0..CASES {
        let (claims, gammas) = claims(&message, SEED + 2 * case as u64);
        let reference = BatchInputs::new(7, &prepared, &claims, &gammas).unwrap();
        let expected: Vec<u32> = reference
            .weights
            .iter()
            .flat_map(|v| crate::lookup::words(*v))
            .chain(reference.face.iter().map(|x| crate::lookup::words(*x)[0]))
            .collect();
        for raw in 0..2 {
            let at = (2 * case + raw) * len * 5;
            assert_eq!(output[at..at + len * 5], expected, "case {case} raw={raw}");
        }
    }
}
