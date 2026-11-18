//! RFC-0014 A2–A7. A single changed device field, reconstructed root or sibling must reject.
#![forbid(unsafe_code)]
use std::{cell::Cell, env, fs, path::PathBuf};
use stele_gpu::{Cuda, Error, Session};
use stele_kernels::gkr::{GkrBackend, GkrConstruction, RelationBackend, RelationConstruction};
use stele_kernels::lookup::{Input, Key, LookupBackend, Visit};
use stele_kernels::{
    Backend, HidingBackend, SourceColumn, SourceGeometry, WeightedClaim, M31, QM31,
};
use stele_prover::development::{prove_window_with_backend, zk, Statement};

// Only this rejection binary can replace the first field. The selected source, construction,
// challenge-independent round and all other operations are the production CUDA implementation.
#[derive(Clone, Copy, PartialEq)]
enum Change {
    Round,
    Root,
    Sibling,
    LookupDenominator,
    SharedRound,
    StandaloneRoot,
    StandaloneSibling,
}
impl Change {
    fn shared_path(self) -> bool {
        matches!(
            self,
            Self::SharedRound | Self::StandaloneRoot | Self::StandaloneSibling
        )
    }
}
struct Dense<'s, 'd: 's> {
    state: <Session<'d> as Backend<QM31>>::Dense<'s>,
    inject_first: Option<&'s Cell<bool>>,
}
struct Changed<'d, const ROUND: bool> {
    device: Session<'d>,
    target: Change,
    first_id: Cell<Option<u64>>,
    shared_id: Cell<Option<u64>>,
    standalone_id: Cell<Option<u64>>,
    standalone_visits: Cell<usize>,
    shared_start: Cell<Option<(usize, usize, usize)>>,
    injected: Cell<bool>,
}
impl<'d, const ROUND: bool> Changed<'d, ROUND> {
    fn new(device: Session<'d>, target: Change) -> Self {
        Self {
            device,
            target,
            first_id: Cell::new(None),
            shared_id: Cell::new(None),
            standalone_id: Cell::new(None),
            standalone_visits: Cell::new(0),
            shared_start: Cell::new(None),
            injected: Cell::new(false),
        }
    }
}

impl<'d, const ROUND: bool> Backend<QM31> for Changed<'d, ROUND> {
    type Error = Error;
    type Original<'s>
        = <Session<'d> as Backend<QM31>>::Original<'s>
    where
        Self: 's;
    type Dense<'s>
        = Dense<'s, 'd>
    where
        Self: 's;

    fn original<'s>(
        &'s self,
        geometry: SourceGeometry,
        words: &'s [M31],
    ) -> Result<Self::Original<'s>, Error> {
        let result = self.device.original(geometry, words)?;
        if self.target.shared_path() {
            // The pinned complete fixture has three ordinary originals, then the shared
            // original, then A4's standalone owner after the ordinary batches finish.
            let c = self.device.counts();
            match c.originals {
                4 => self.shared_id.set(Some(geometry.id)),
                5 if c.finals == 3 && self.shared_id.get() != Some(geometry.id) => {
                    self.standalone_id.set(Some(geometry.id))
                }
                _ => {}
            }
        }
        Ok(result)
    }

    fn dense_batch<'s>(
        &'s self,
        g: SourceGeometry,
        o: &'s Self::Original<'_>,
        claims: &[WeightedClaim<'_, QM31>],
    ) -> Result<(Self::Dense<'s>, QM31), Error> {
        let (state, value) = self.device.dense_batch(g, o, claims)?;
        let c = self.device.counts();
        let shared = self.target.shared_path()
            && self.shared_id.get() == Some(g.id)
            && c.batches == 4
            && c.finals == 3;
        if shared {
            self.shared_start.set(Some((c.rounds, c.folds, c.finals)));
        }
        Ok((
            Dense {
                state,
                inject_first: (shared && self.target == Change::SharedRound)
                    .then_some(&self.injected),
            },
            value,
        ))
    }

    fn dense_round<'s>(state: &mut Self::Dense<'s>) -> Result<[QM31; 3], Error>
    where
        Self: 's,
    {
        let mut fields = Session::dense_round(&mut state.state)?;
        if ROUND || state.inject_first.is_some_and(|flag| !flag.replace(true)) {
            fields[0] = fields[0] + QM31::ONE;
        }
        Ok(fields)
    }

    fn dense_fold<'s>(state: &mut Self::Dense<'s>, point: QM31) -> Result<(), Error>
    where
        Self: 's,
    {
        Session::dense_fold(&mut state.state, point)
    }

    fn dense_finals<'s>(state: &Self::Dense<'s>) -> Result<[QM31; 2], Error>
    where
        Self: 's,
    {
        Session::dense_finals(&state.state)
    }
}

impl<'d, const ROUND: bool> GkrBackend<QM31> for Changed<'d, ROUND> {
    type Gkr<'s>
        = <Session<'d> as GkrBackend<QM31>>::Gkr<'s>
    where
        Self: 's;
    fn gkr_start<'s>(&'s self, input: &GkrConstruction<'_, QM31>) -> Result<Self::Gkr<'s>, Error> {
        self.device.gkr_start(input)
    }
    fn gkr_round<'s>(state: &mut Self::Gkr<'s>) -> Result<Vec<QM31>, Error>
    where
        Self: 's,
    {
        let mut fields = Session::gkr_round(state)?;
        if ROUND {
            let first = fields.first_mut().ok_or(Error::Geometry)?;
            *first = *first + QM31::ONE;
        }
        Ok(fields)
    }
    fn gkr_fold<'s>(s: &mut Self::Gkr<'s>, c: QM31) -> Result<(), Error>
    where
        Self: 's,
    {
        Session::gkr_fold(s, c)
    }
    fn gkr_finals<'s>(s: &Self::Gkr<'s>) -> Result<Vec<QM31>, Error>
    where
        Self: 's,
    {
        Session::gkr_finals(s)
    }
}
impl<const ROUND: bool> RelationBackend<QM31> for Changed<'_, ROUND> {
    fn relation_start<'s>(
        &'s self,
        input: &RelationConstruction<'_, QM31>,
    ) -> Result<Self::Gkr<'s>, Error> {
        self.device.relation_start(input)
    }
}

impl<'d> LookupBackend for Changed<'d, false> {
    type Tree<'s>
        = <Session<'d> as LookupBackend>::Tree<'s>
    where
        Self: 's;
    fn lookup_top(
        &self,
        input: &Input<'_>,
        owners: &[&Self::Original<'_>],
    ) -> Result<Vec<[QM31; 2]>, Error> {
        let mut pairs = self.device.lookup_top(input, owners)?;
        if self.target == Change::LookupDenominator && !self.injected.replace(true) {
            pairs.first_mut().ok_or(Error::Geometry)?[1] = QM31::ZERO;
        }
        Ok(pairs)
    }
    fn lookup_tree<'s>(
        &'s self,
        input: &Input<'_>,
        owners: &[&Self::Original<'_>],
    ) -> Result<Self::Tree<'s>, Error> {
        self.device.lookup_tree(input, owners)
    }
    fn lookup_gkr<'s>(
        &'s self,
        key: Key,
        visit: Visit<'_, Self::Tree<'_>>,
        input: &GkrConstruction<'_, QM31>,
    ) -> Result<Self::Gkr<'s>, Error> {
        self.device.lookup_gkr(key, visit, input)
    }
}

impl<'d> HidingBackend for Changed<'d, false> {
    type Columns<'s>
        = <Session<'d> as HidingBackend>::Columns<'s>
    where
        Self: 's;

    fn prepare_columns<'s>(
        &'s self,
        g: SourceGeometry,
        original: &Self::Original<'_>,
        seed: &[u8; 32],
        hashes: &mut u64,
    ) -> Result<(Self::Columns<'s>, [u8; 32]), Error> {
        let (tree, mut root) = self.device.prepare_columns(g, original, seed, hashes)?;
        if self.first_id.get().is_none() {
            self.first_id.set(Some(g.id));
        } else if self.target == Change::Root
            && self.first_id.get() == Some(g.id)
            && !self.injected.replace(true)
        {
            root[0] ^= 1;
        }
        if self.standalone_id.get() == Some(g.id) {
            let visit = self.standalone_visits.get() + 1;
            self.standalone_visits.set(visit);
            if self.target == Change::StandaloneRoot && visit == 2 && !self.injected.replace(true) {
                root[0] ^= 1;
            }
        }
        Ok((tree, root))
    }
    fn selected_column(
        &self,
        g: SourceGeometry,
        tree: &Self::Columns<'_>,
        index: usize,
    ) -> Result<SourceColumn, Error> {
        let mut col = self.device.selected_column(g, tree, index)?;
        let standalone = self.target == Change::StandaloneSibling
            && self.standalone_id.get() == Some(g.id)
            && self.standalone_visits.get() == 1;
        if (self.target == Change::Sibling || standalone) && !self.injected.replace(true) {
            col.siblings.first_mut().ok_or(Error::Geometry)?[0] ^= 1;
        }
        Ok(col)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).map(PathBuf::from).collect();
    let (case, model_commitment, model_secret, stage) = match args.as_slice() {
        [case, commitment, secret] => (case, commitment, secret, "batch"),
        [case, commitment, secret, stage] => {
            let mode = stage.to_str().ok_or("invalid control name")?;
            if !matches!(
                mode,
                "gkr"
                    | "relation"
                    | "source-root"
                    | "source-sibling"
                    | "lookup-denominator"
                    | "shared"
                    | "standalone-root"
                    | "standalone-sibling"
            ) {
                return Err("unknown device control".into());
            }
            (case, commitment, secret, mode)
        }
        [case, commitment, secret, stage] if stage.as_os_str() == "source-root" => (case,commitment,secret,"source-root"),
        [case, commitment, secret, stage] if stage.as_os_str() == "source-sibling" => (case,commitment,secret,"source-sibling"),
        _ => {
            return Err(
                "expected first parity case, commitment, state and optional device control".into(),
            )
        }
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
    let device = Cuda::new()?;
    let relation = stage == "relation";
    let mut writes = Vec::new();
    let mut index = u32::MAX;
    let seed = fs::read(case.join("proof-seed.bin"))?
        .try_into()
        .map_err(|_| "invalid fixture seed")?;
    let target = match stage {
        "lookup-denominator" => Change::LookupDenominator,
        "shared" => Change::SharedRound,
        "standalone-root" => Change::StandaloneRoot,
        "standalone-sibling" => Change::StandaloneSibling,
        "source-root" => Change::Root,
        "source-sibling" => Change::Sibling,
        _ => Change::Round,
    };
    let changed = Changed::<true>::new(device.session(), Change::Round);
    let material = Changed::<false>::new(device.session(), target);
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
        if target.shared_path() {
            zk::BatchExecution::with_shared(&material)
        } else if target == Change::LookupDenominator {
            zk::BatchExecution::with_lookup(&material)
        } else if target != Change::Round {
            zk::BatchExecution::with_sources(&material)
        } else if relation {
            zk::BatchExecution::with_relations(&changed)
        } else if stage == "gkr" {
            zk::BatchExecution::with_gkr(&changed)
        } else {
            zk::BatchExecution::new(&changed)
        },
    );
    let error = result.err().ok_or("changed CUDA round was accepted")?;
    // The inner error belongs to the reductions crate. Avoid adding a protocol dependency to
    // this field backend just to match its nested variants in this rejection binary.
    let claimed = if matches!(target, Change::Round | Change::SharedRound) {
        "Zk(Sumcheck(RoundSumMismatch))"
    } else if target == Change::LookupDenominator {
        "Zk(DenominatorZero)"
    } else {
        "Zk(Pcs(Merkle(RootMismatch)))"
    };
    if format!("{error:?}") != claimed {
        return Err(format!("expected {claimed}, got {error:?}").into());
    }
    let counts = if target == Change::Round {
        changed.device.counts()
    } else {
        material.device.counts()
    };
    if target.shared_path() {
        if !material.injected.get()
            || counts.originals != 5
            || counts.source_responses == 0
            || material.standalone_id.get().is_none()
            || material.shared_id.get().is_none()
            || material.standalone_id.get() == material.shared_id.get()
        {
            return Err(
                "A7 fault did not use distinct shared and standalone original owners".into(),
            );
        }
        match target {
            Change::SharedRound => {
                let (rounds, folds, finals) = material
                    .shared_start
                    .get()
                    .ok_or("shared batch not dispatched")?;
                if (counts.rounds, counts.folds, counts.finals) != (rounds + 1, folds, finals)
                    || material.standalone_visits.get() != 1
                    || counts.batches != 4
                {
                    return Err("changed shared round did not reject before its first fold".into());
                }
            }
            Change::StandaloneRoot
                if material.standalone_visits.get() == 2
                    && counts.finals == 4
                    && counts.rounds == counts.folds => {}
            Change::StandaloneSibling
                if material.standalone_visits.get() == 1 && counts.finals == 3 => {}
            _ => return Err("standalone fault did not reach the intended A4 visit".into()),
        }
    } else if target == Change::LookupDenominator {
        if !material.injected.get()
            || counts.lookup_tops != 1
            || counts.gkr_steps != 0
            || counts.lookup_rebuilds != 0
        {
            return Err("invalid abort point after changed top denominator".into());
        }
    } else if target != Change::Round {
        if !material.injected.get()
            || counts.source_responses == 0
            || counts.source_visits == 0
            || (target == Change::Root && counts.source_visits <= counts.originals)
            || (target == Change::Sibling && (counts.source_visits != 1 || counts.batches != 0))
        {
            return Err("source fault did not reach its intended proof visit".into());
        }
    } else if relation {
        if (
            counts.relation_steps,
            counts.relation_rounds,
            counts.relation_folds,
            counts.relation_finals,
            counts.gkr_steps,
            counts.batches,
        ) != (1, 1, 0, 0, 0, 0)
            || counts.relation_downloaded_bytes == 0
            || counts.relation_downloaded_bytes != counts.downloaded_bytes
        {
            return Err("changed relation did not stop at the first real device polynomial".into());
        }
    } else if stage == "gkr" {
        if (
            counts.gkr_steps,
            counts.gkr_rounds,
            counts.gkr_folds,
            counts.gkr_finals,
            counts.relation_steps,
            counts.batches,
        ) != (1, 1, 0, 0, 0, 0)
            || counts.gkr_downloaded_bytes == 0
            || counts.gkr_downloaded_bytes != counts.downloaded_bytes
        {
            return Err(
                "changed GKR round did not stop at the first real device polynomial".into(),
            );
        }
    } else if (
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
    if target == Change::SharedRound {
        println!("rejected_cuda_shared=RoundSumMismatch target_rounds=1 target_folds=0 reservation_restored=1");
    } else if target == Change::LookupDenominator {
        println!("rejected_cuda_{stage}=DenominatorZero injected=1 reservation_restored=1");
    } else if target != Change::Round {
        println!("rejected_cuda_{stage}=RootMismatch injected=1 reservation_restored=1");
    } else if relation {
        println!("rejected_cuda_relation=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1");
    } else if stage == "gkr" {
        println!("rejected_cuda_gkr_round=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1");
    } else {
        println!(
            "rejected_cuda_round=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1"
        );
    }
    Ok(())
}
