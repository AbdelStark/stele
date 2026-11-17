//! RFC-0014 §5: raw lazy descriptors/tables through the actual launch and fold path.
use super::*;
use crate::{challenge, cpu, round_cases::synthetic, Rng};

pub(super) fn lift(dev: &Device, words: &mut CudaSlice<u32>, used: usize) {
    let mut host = dev.stream.clone_dtoh(words).unwrap();
    for word in &mut host[..used] {
        assert!(*word < M31::MODULUS);
        *word += M31::MODULUS;
    }
    dev.stream.memcpy_htod(&host, words).unwrap();
}

#[test]
#[ignore = "requires an explicitly allocated H100 and an external deadline"]
fn matches_reference_descriptor_rounds_on_h100() {
    assert!(available(), "required CUDA driver and NVRTC absent");
    let dev = Device::new().expect("CUDA device");
    assert!(dev.name.contains("H100"), "H100 required");
    let mut rng = Rng::new(0x40_1001);
    for case in 0..1000 {
        let shape = synthetic(case, &mut rng);
        for raw in [false, true] {
            let (mut state, _, _) = dev.build(&shape).unwrap();
            let mut reference = cpu(&shape);
            if raw {
                let used = state.coef.len();
                lift(&dev, &mut state.coef, used);
            }
            for round in 0..shape.n {
                if raw {
                    for factor in &mut state.factors {
                        for table in std::iter::once(&mut factor.x).chain(factor.r.iter_mut()) {
                            let used = state.len * if table.is_base() { 1 } else { 4 };
                            let (Buf::Base(words) | Buf::Ext(words)) = table;
                            lift(&dev, words, used);
                        }
                    }
                }
                assert_eq!(
                    state.round().unwrap(),
                    reference.round().unwrap(),
                    "case={case} round={round} raw={raw}"
                );
                state.fold(challenge(round)).unwrap();
                reference.fold(challenge(round)).unwrap();
                assert_eq!(
                    state.tables().unwrap(),
                    reference
                        .tables()
                        .map(|(x, r)| (x.to_vec(), r.to_vec()))
                        .collect::<Vec<_>>()
                );
            }
            assert!(matches!(
                state.round(),
                Err(Error::Shape("round exhausted"))
            ));
        }
    }
    eprintln!(
        "descriptor_device_cases=1000 raw_descriptor_cases=1000 seed=4198401 device={}",
        dev.name
    );
}
