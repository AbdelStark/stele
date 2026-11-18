//! RFC-0014 A2. A genuine device round with one changed field must fail the ordinary prover.
#![forbid(unsafe_code)]
use std::{env, fs, path::PathBuf};
use stele_gpu::{Cuda, Error, Session};
use stele_kernels::{Backend, SourceGeometry, WeightedClaim, M31, QM31};
use stele_prover::development::{prove_window_with_backend, zk, Statement};

// Only this rejection binary can replace the first field. The selected source, construction,
// challenge-independent round and all other operations are the production CUDA implementation.
struct ChangedRound<'d>(Session<'d>);

impl<'d> Backend<QM31> for ChangedRound<'d> {
    type Error = Error;
    type Original<'s>
        = <Session<'d> as Backend<QM31>>::Original<'s>
    where
        Self: 's;
    type Dense<'s>
        = <Session<'d> as Backend<QM31>>::Dense<'s>
    where
        Self: 's;

    fn original<'s>(
        &'s self,
        geometry: SourceGeometry,
        words: &'s [M31],
    ) -> Result<Self::Original<'s>, Error> {
        self.0.original(geometry, words)
    }

    fn dense_batch<'s>(
        &'s self,
        g: SourceGeometry,
        o: &'s Self::Original<'_>,
        claims: &[WeightedClaim<'_, QM31>],
    ) -> Result<(Self::Dense<'s>, QM31), Error> {
        self.0.dense_batch(g, o, claims)
    }

    fn dense_round<'s>(state: &mut Self::Dense<'s>) -> Result<[QM31; 3], Error>
    where
        Self: 's,
    {
        let mut fields = Session::dense_round(state)?;
        fields[0] = fields[0] + QM31::ONE;
        Ok(fields)
    }

    fn dense_fold<'s>(state: &mut Self::Dense<'s>, point: QM31) -> Result<(), Error>
    where
        Self: 's,
    {
        Session::dense_fold(state, point)
    }

    fn dense_finals<'s>(state: &Self::Dense<'s>) -> Result<[QM31; 2], Error>
    where
        Self: 's,
    {
        Session::dense_finals(state)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).map(PathBuf::from).collect();
    let [case, model_commitment, model_secret] = args.as_slice() else {
        return Err("expected first parity case, model commitment and original state".into());
    };
    let commitment =
        zk::ModelCommitment::decode(&fs::read(model_commitment)?).map_err(|e| format!("{e:?}"))?;
    let before = fs::read(model_secret)?;
    let mut state = zk::ModelState::decode(&before).map_err(|e| format!("{e:?}"))?;
    if state.next != 0
        || !state.revealed.is_empty()
        || commitment.proofs != 1
        || commitment.profile != zk::PROFILE_BALANCED
    {
        return Err("control requires the unused balanced model commitment".into());
    }
    let mut writes = Vec::new();
    let mut index = u32::MAX;
    let seed = fs::read(case.join("proof-seed.bin"))?
        .try_into()
        .map_err(|_| "invalid fixture seed")?;
    let device = Cuda::new()?;
    let changed = ChangedRound(device.session());
    let result = prove_window_with_backend(
        &fs::read(case.join("model.bin"))?,
        &fs::read(case.join("preparation.bin"))?,
        &fs::read(case.join("scales.bin"))?,
        &fs::read(case.join("artifact.bin"))?,
        Statement {
            tokens: vec![1],
            start: 0,
            end: 1,
            next: None,
        },
        2,
        zk::Window::Prove {
            seed: zk::Seed::new(seed),
            commitment: &commitment,
            state: &mut state,
            persist: &mut |s| {
                writes.push((s.next, s.encode()));
                Ok(())
            },
            index: &mut index,
        },
        zk::BatchExecution::new(&changed),
    );
    let error = result.err().ok_or("changed CUDA round was accepted")?;
    // The inner error belongs to the reductions crate. Avoid adding a protocol dependency to
    // this field backend just to match its nested variants in this rejection binary.
    let claimed = "Zk(Sumcheck(RoundSumMismatch))";
    if format!("{error:?}") != claimed {
        return Err(format!("expected {claimed}, got {error:?}").into());
    }
    let counts = changed.0.counts();
    if (
        counts.originals,
        counts.batches,
        counts.rounds,
        counts.folds,
        counts.finals,
    ) != (1, 1, 1, 0, 0)
        || counts.downloaded_bytes != 48
    {
        return Err("changed round did not stop at the first real device polynomial".into());
    }
    if !matches!(&writes[..], [(1, reserved), (0, restored)] if reserved != &before && restored == &before)
        || state.encode() != before
    {
        return Err("failed round did not restore the reservation".into());
    }
    println!("rejected_cuda_round=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1");
    Ok(())
}
