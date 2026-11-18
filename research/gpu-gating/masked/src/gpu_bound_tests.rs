//! RFC-0013 A4 and RFC-0014 §5: the checked prover consumes device polynomials before Fiat–Shamir.
use super::{batch, Device, DeviceMasked};
use crate::batch_cases::{claims, message, prepared, CASES, SEED};
use crate::K;
use std::cell::{Cell, RefCell};
use stele_reductions::parallel::eq_table;
use stele_reductions::stele_hash::{blake3_digest, ChallengeLabel, Transcript};
use stele_reductions::zk::{self, claims::bench::BatchInputs};
use stele_sumcheck::{Dense, Error, Instance, Summand};

struct DeviceSummand<'a> {
    state: RefCell<DeviceMasked<'a>>,
    calls: &'a Cell<usize>,
}

impl Summand<K> for DeviceSummand<'_> {
    fn shape(&self) -> (u32, usize) {
        let state = self.state.borrow();
        (state.len.ilog2(), state.factors.len())
    }

    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, Error> {
        let result = self.state.borrow_mut().round().map_err(|_| Error::Source)?;
        self.calls.set(self.calls.get() + 1);
        Ok(result)
    }

    fn fold(&mut self, point: K) -> Result<(), Error> {
        self.state.get_mut().fold(point).map_err(|_| Error::Source)
    }

    fn final_values(&self) -> Result<Vec<K>, Error> {
        self.state
            .borrow()
            .final_values()
            .map_err(|_| Error::Source)
    }
}

#[test]
#[ignore = "requires an explicitly allocated H100 and CUDA/NVRTC"]
fn matches_reference_bound_masked_proofs_on_h100() {
    let dev = Device::new().expect("required CUDA device");
    assert!(dev.name.contains("H100"));
    let calls = Cell::new(0);
    let mut expected_calls = 0;
    for case in 0..CASES {
        let seed = SEED + 2 * case as u64;
        let message = message(seed);
        let source = prepared(&message, seed);
        let (claims, gammas) = claims(&message, seed);
        let reference = BatchInputs::new(7, &source, &claims, &gammas).expect("reference instance");
        let (state, sum, _) =
            batch::prepare(&dev, &source, &claims, &gammas).expect("device batch");
        let i = &reference.instance;
        assert_eq!(sum, i.claimed_sum);
        let auth = [
            b"stele/research/bound-device/".as_slice(),
            &seed.to_le_bytes(),
        ]
        .concat();
        // Synthetic public fixtures only. Each pair is the same statement, seed and transcript.
        let mask_seed = blake3_digest(&auth);
        let transcript = || Transcript::<K>::new(&auth).expect("fixture transcript");
        let mut device_t = transcript();
        let gpu = zk::prove(
            i,
            DeviceSummand {
                state: RefCell::new(state),
                calls: &calls,
            },
            zk::Seed::new(mask_seed),
            &mut device_t,
        )
        .expect("checked device-produced masked proof");
        expected_calls += i.num_vars as usize;
        assert_eq!(calls.get(), expected_calls);

        let mut verify_t = transcript();
        let (obligations, _) = zk::verify(i, &gpu, &mut verify_t).expect("verify A4 opening");
        let eq = eq_table(&obligations.point).expect("CPU equality weights");
        let tables = vec![reference.weights, reference.face];
        assert_eq!(obligations.claims.len(), tables.len());
        for ((id, value), (expected_id, table)) in
            obligations.claims.iter().zip(i.inputs.iter().zip(&tables))
        {
            assert_eq!(id, expected_id);
            assert_eq!(table.len(), eq.len());
            assert_eq!(
                *value,
                eq.iter()
                    .zip(table)
                    .fold(K::ZERO, |acc, (w, x)| acc + *w * *x)
            );
        }

        let mut cpu_t = transcript();
        let cpu = zk::prove(
            i,
            Dense::new(i, tables).expect("CPU tables"),
            zk::Seed::new(mask_seed),
            &mut cpu_t,
        )
        .expect("checked CPU reference");
        // Eq covers the binding bytes, complete certificate, every field, and the entire opening.
        assert_eq!(gpu, cpu, "bound proof case {case}");
        assert_eq!(device_t.usage(), cpu_t.usage());
        let next = device_t
            .challenge(ChallengeLabel::Sumcheck)
            .expect("continuation");
        assert_eq!(next, cpu_t.challenge(ChallengeLabel::Sumcheck).unwrap());
        assert_eq!(next, verify_t.challenge(ChallengeLabel::Sumcheck).unwrap());
        if case == 0 {
            let mut changed = gpu;
            changed.sumcheck.rounds[0][0] = changed.sumcheck.rounds[0][0] + K::ONE;
            assert_eq!(
                zk::verify(i, &changed, &mut transcript()),
                Err(zk::Error::Sumcheck(Error::RoundSumMismatch))
            );
        }
    }
    eprintln!("bound_masked_cases={CASES} device_rounds={expected_calls} changed_round_controls=1");
}
