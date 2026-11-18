//! RFC-0014 §5: require actual H100 construction, rounds, folds and canonical finals.
use super::*;
use crate::batch_cases::{claims, message, prepared, CASES, SEED};
use crate::M31;
use stele_reductions::zk::claims::bench::BatchInputs;
use stele_sumcheck::{Dense, Summand};

#[test]
#[ignore = "requires an explicitly allocated H100 and CUDA/NVRTC"]
fn matches_reference_batch_on_h100() {
    assert!(
        crate::gpu::available(),
        "required CUDA driver and NVRTC absent"
    );
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required: {}", dev.name);
    let mut sources = std::collections::BTreeSet::new();
    for case in 0..CASES {
        let seed = SEED + 2 * case as u64;
        let message = message(seed);
        assert!(sources.insert(message[3].as_u32()), "duplicate face input");
        let source = prepared(&message, seed);
        let (claims, gammas) = claims(&message, seed);
        let reference = BatchInputs::new(7, &source, &claims, &gammas).unwrap();
        for raw in [false, true] {
            let (mut state, sum, timing) = if raw {
                let mut p = Prepared::new(source.source(), &message, &claims, &gammas).unwrap();
                for word in p
                    .message
                    .iter_mut()
                    .chain(p.weights.iter_mut().flatten())
                    .chain(p.gammas.iter_mut().flatten())
                {
                    *word += M31::MODULUS;
                }
                let (state, time) = build(&dev, &p, None).unwrap();
                (state, p.claimed_sum, time)
            } else {
                prepare(&dev, &source, &claims, &gammas).unwrap()
            };
            assert_eq!(sum, reference.instance.claimed_sum);
            let mut tables = vec![reference.weights.clone(), reference.face.clone()];
            assert_eq!(
                state.tables().unwrap(),
                tables
                    .iter()
                    .map(|v| (v.clone(), vec![]))
                    .collect::<Vec<_>>()
            );
            let scratch = timing.initial_round_buffer_bytes - 20 * reference.face.len();
            assert_eq!(
                timing.first_fold_peak_bytes,
                scratch + 28 * reference.face.len()
            );
            assert_eq!(
                timing.retained_after_first_fold_bytes,
                scratch + 24 * reference.face.len()
            );
            let mut dense = Dense::new(&reference.instance, tables.clone()).unwrap();
            for round in 0..reference.instance.num_vars {
                if raw {
                    for factor in &mut state.factors {
                        let base = factor.x.is_base();
                        let mut words = dev.stream.clone_dtoh(factor.x.slice()).unwrap();
                        for word in &mut words[..state.len * if base { 1 } else { 4 }] {
                            assert!(*word < M31::MODULUS);
                            *word += M31::MODULUS;
                        }
                        let slice = match &mut factor.x {
                            Buf::Base(s) | Buf::Ext(s) => s,
                        };
                        dev.stream.memcpy_htod(&words, slice).unwrap();
                    }
                }
                assert_eq!(
                    state.round().unwrap(),
                    dense.round(&reference.instance).unwrap(),
                    "case {case} round {round} raw={raw}"
                );
                let challenge = crate::challenge(round as usize);
                state.fold(challenge).unwrap();
                dense.fold(challenge).unwrap();
                for table in &mut tables {
                    stele_sumcheck::parallel::fold(table, challenge);
                }
                assert_eq!(
                    state.tables().unwrap(),
                    tables
                        .iter()
                        .map(|v| (v.clone(), vec![]))
                        .collect::<Vec<_>>(),
                    "case {case} fold {round} raw={raw}"
                );
            }
            assert_eq!(
                dense.final_values().unwrap(),
                state
                    .tables()
                    .unwrap()
                    .iter()
                    .map(|(x, _)| x[0])
                    .collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(sources.len(), CASES);
    let message = message(SEED);
    let source = prepared(&message, SEED);
    let (mut claims, gammas) = claims(&message, SEED);
    claims[0].value = claims[0].value + K::from_i64(1);
    let (mut state, sum, _) = prepare(&dev, &source, &claims, &gammas).unwrap();
    let round = state.round().unwrap();
    assert_ne!(sum, round[0] + round[1], "one claimed value near miss");
    eprintln!("batch_device_cases={CASES} source_cases={CASES} raw_weight_cases={CASES} raw_face_cases={CASES} dense_cases={CASES} raw_dense_cases={CASES} near_miss_cases=1 seed={SEED} device={}", dev.name);
}
