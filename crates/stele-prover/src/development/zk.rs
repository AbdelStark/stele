//! The dev-zk profile through the development orchestrator (RFC-0013 A5 items 6–8,
//! RFC-0013 A6 (Proposed), RFC-0026 A9; tasks E12-14b, E12-25).
//!
//! - **Model commitment** ([`ModelCommitment`], `stele-dev-zk-model-v1`). The model
//!   owner commits the weights once ([`commit`]), from a secret model seed, as one
//!   lifetime hiding source (A6). It reserves claim-mask blocks for `P` proofs, `t`
//!   per weight column per proof (`blocks`, from the reference window of `length`
//!   tokens). The published file holds the root, `P`, `blocks` and `length`; its
//!   digest ([`model_digest`]) is what `verify-dev --expect-model` pins.
//! - **Model state** ([`ModelState`], `stele-dev-zk-model-secret-v1`, secret). It
//!   holds the seed, the next proof index and the row-coefficient vectors that earlier
//!   openings revealed. [`ModelState::take`] hands out each index once and refuses past
//!   `P` (`MaskBudget`). The CLI persists the state before it proves.
//! - **Public input.** RFC-0026 §1.1 (as amended by A2), then the A9 profile byte `1`,
//!   the proof index `u32` and the commitment bytes. The development public input keeps
//!   its pre-A9 bytes, so a development proof is unchanged. `Public::commitment` holds
//!   the one root; the source's certificate travels in each proof.
//! - **Proof.** `stele-dev-zk-v1`: magic, `cqis_id`, the statement digest, then the
//!   claims proof bytes (`zk::claims::encode`). The header digest fails fast only; the
//!   transcript binds the public input (NC-0912).
//!
//! Each proof's own seed is move-only and serves one proof. The CLI draws it from the
//! OS RNG (`/dev/urandom`).
use super::{
    decode, layout_for, public_input as development_input, statement_digest, Error, Public,
    Statement, Weights, K,
};
use alloc::vec::Vec;
use stele_reductions::relation;
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_field::Serialize;
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{check, Relation, Values};
use stele_reductions::zk::claims::{Lifetime, ModelSecret};
pub use stele_reductions::zk::Seed;
use stele_reductions::zk::{claims, relation as zk_relation};

/// The RFC-0026 A9 profile byte of dev-zk.
pub const PROFILE: u8 = 1;

const MAGIC: &[u8] = b"stele-dev-zk-v1";
const MODEL_MAGIC: &[u8] = b"stele-dev-zk-model-v1";
const STATE_MAGIC: &[u8] = b"stele-dev-zk-model-secret-v1";
const DIGEST_TAG: &[u8] = b"stele/v0.1/dev-zk/model";

/// The published dev-zk model commitment (RFC-0013 A6, Proposed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCommitment {
    /// The lifetime weight source's root.
    pub root: [u8; 32],
    /// The proof budget `P`.
    pub proofs: u32,
    /// Per-proof claim-mask blocks `t` of each weight column, in column order.
    pub blocks: Vec<u32>,
    /// The reference window length the blocks were counted on.
    pub length: u32,
}

fn u32_at(bytes: &[u8], at: &mut usize) -> Result<u32, Error> {
    let b = bytes.get(*at..*at + 4).ok_or(Error::StatementMismatch)?;
    *at += 4;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

impl ModelCommitment {
    /// Canonical bytes: magic, root, `P`, `length`, the block count and each block.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MODEL_MAGIC.to_vec();
        out.extend_from_slice(&self.root);
        for x in [self.proofs, self.length, self.blocks.len() as u32] {
            out.extend_from_slice(&x.to_le_bytes());
        }
        for b in &self.blocks {
            out.extend_from_slice(&b.to_le_bytes());
        }
        out
    }

    /// Parse [`Self::encode`]'s bytes; anything else is `StatementMismatch`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = bytes
            .strip_prefix(MODEL_MAGIC)
            .ok_or(Error::StatementMismatch)?;
        let mut root = [0; 32];
        root.copy_from_slice(body.get(..32).ok_or(Error::StatementMismatch)?);
        let mut at = 32;
        let proofs = u32_at(body, &mut at)?;
        let length = u32_at(body, &mut at)?;
        let count = u32_at(body, &mut at)? as usize;
        if body.len() != at + 4 * count || proofs == 0 {
            return Err(Error::StatementMismatch);
        }
        let blocks = (0..count)
            .map(|_| u32_at(body, &mut at))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            root,
            proofs,
            blocks,
            length,
        })
    }

    fn lifetime(&self, index: u32) -> Lifetime {
        Lifetime {
            source: zk_relation::WEIGHTS,
            proofs: self.proofs as usize,
            index: index as usize,
            blocks: self.blocks.iter().map(|b| *b as usize).collect(),
        }
    }
}

/// The model owner's secret state (RFC-0013 A6): never published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelState {
    /// The model seed the weight source was committed from.
    pub seed: [u8; 32],
    /// The next proof index.
    pub next: u32,
    /// The row-coefficient vector each earlier opening revealed, in index order.
    pub revealed: Vec<Vec<K>>,
}

impl ModelState {
    /// Canonical bytes: magic, seed, `next`, then each revealed vector (count, values).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = STATE_MAGIC.to_vec();
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.next.to_le_bytes());
        out.extend_from_slice(&(self.revealed.len() as u32).to_le_bytes());
        for a in &self.revealed {
            out.extend_from_slice(&(a.len() as u32).to_le_bytes());
            for x in a {
                out.extend_from_slice(x.to_le_bytes().as_ref());
            }
        }
        out
    }

    /// Parse [`Self::encode`]'s bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = bytes
            .strip_prefix(STATE_MAGIC)
            .ok_or(Error::StatementMismatch)?;
        let mut seed = [0; 32];
        seed.copy_from_slice(body.get(..32).ok_or(Error::StatementMismatch)?);
        let mut at = 32;
        let next = u32_at(body, &mut at)?;
        let count = u32_at(body, &mut at)? as usize;
        let mut revealed = Vec::new();
        for _ in 0..count.min(body.len()) {
            let n = u32_at(body, &mut at)? as usize;
            let mut a = Vec::new();
            for _ in 0..n.min(body.len()) {
                let raw = body.get(at..at + 16).ok_or(Error::StatementMismatch)?;
                at += 16;
                let bytes: [u8; 16] = raw.try_into().map_err(|_| Error::StatementMismatch)?;
                a.push(K::from_le_bytes(bytes).ok_or(Error::StatementMismatch)?);
            }
            revealed.push(a);
        }
        if at != body.len() || revealed.len() != count {
            return Err(Error::StatementMismatch);
        }
        Ok(Self {
            seed,
            next,
            revealed,
        })
    }

    /// Hand out the next proof index once (RFC-0013 A6 lifetime counter). The
    /// caller persists the advanced state before proving; past `P` it refuses
    /// (`MaskBudget`), and so it does when earlier openings are missing from the
    /// state (an index taken but its opening never recorded).
    pub fn take(&mut self, commitment: &ModelCommitment) -> Result<u32, Error> {
        if self.next >= commitment.proofs || self.revealed.len() != self.next as usize {
            return Err(budget());
        }
        self.next += 1;
        Ok(self.next - 1)
    }
}

/// What [`super::prove_window_profile`] does under dev-zk: commit the model once
/// (the window's `length` is the reference), or prove one window against it.
pub enum Window<'a> {
    /// [`commit`] with budget `proofs` from the model seed; the result lands in `out`.
    Commit {
        proofs: u32,
        seed: [u8; 32],
        out: &'a mut Option<(ModelCommitment, ModelState)>,
    },
    /// [`prove_next`]: the next index of `state`, persisted through `persist`; the
    /// index lands in `index`.
    Prove {
        seed: Seed,
        commitment: &'a ModelCommitment,
        state: &'a mut ModelState,
        persist: &'a mut Persist<'a>,
        index: &'a mut u32,
    },
}

/// Saves the model state (the CLI writes the secret file).
pub type Persist<'a> = dyn FnMut(&ModelState) -> Result<(), Error> + 'a;

/// Prove the next index of `state` against `commitment` (RFC-0013 A6 item 5),
/// after every input was read and validated by the caller:
/// - take the index and persist the advanced state before proving;
/// - prove, then verify the proof itself;
/// - on any error, no proof bytes left the process, so restore and persist the
///   prior state (the index is not spent);
/// - on success, record the opening and persist.
#[allow(clippy::too_many_arguments)]
pub fn prove_next(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
    seed: Seed,
    commitment: &ModelCommitment,
    state: &mut ModelState,
    persist: &mut Persist<'_>,
) -> Result<(Vec<u8>, u32), Error> {
    let prior = state.clone();
    let index = state.take(commitment)?;
    persist(state)?;
    let result = prove(
        public, executor, weights, statement, seed, commitment, state, index,
    )
    .and_then(|(proof, revealed)| {
        verify(public, statement, &proof, commitment, index)?;
        Ok((proof, revealed))
    });
    match result {
        Ok((proof, revealed)) => {
            state.revealed.push(revealed);
            persist(state)?;
            Ok((proof, index))
        }
        Err(e) => {
            *state = prior;
            persist(state)?;
            Err(e)
        }
    }
}

fn budget() -> Error {
    Error::Zk(stele_reductions::zk::Error::Pcs(
        stele_reductions::stele_pcs::Error::MaskBudget,
    ))
}

/// What an accepted dev-zk proof leaves: the masked instances it verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Relation instances (identities per domain size, contractions, top identities).
    pub relations: usize,
    /// ZK-GKR steps over every check.
    pub gkr: usize,
    /// Claim-source batches, then the shared-source batch.
    pub batches: usize,
    /// Proof bytes.
    pub bytes: usize,
}

impl core::fmt::Display for Verified {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "dev-zk: {} relation instances, {} GKR steps, {} batches, {} proof bytes",
            self.relations, self.gkr, self.batches, self.bytes
        )
    }
}

/// The dev-zk public input: the development bytes, the profile byte, the proof
/// index and the model commitment.
pub fn public_input(
    public: &Public,
    cqis_id: &[u8; 32],
    statement: &Statement,
    commitment: &ModelCommitment,
    index: u32,
) -> Vec<u8> {
    let mut out = development_input(public, cqis_id, statement);
    out.push(PROFILE);
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&commitment.encode());
    out
}

/// What `--expect-model` pins under dev-zk: BLAKE3 of the tag, `cqis_id`, the
/// commitment bytes and the 1-D records (ordinal, length, codes) in record order.
pub fn model_digest(public: &Public, commitment: &ModelCommitment) -> Result<[u8; 32], Error> {
    let d = decode(public)?;
    let mut h = blake3::Hasher::new();
    h.update(DIGEST_TAG);
    h.update(&d.cqis_id);
    h.update(&commitment.encode());
    h.update(&(public.vectors.len() as u32).to_le_bytes());
    for (ordinal, codes) in &public.vectors {
        h.update(&ordinal.to_le_bytes());
        h.update(&(codes.len() as u32).to_le_bytes());
        for c in codes {
            h.update(&c.to_le_bytes());
        }
    }
    Ok(*h.finalize().as_bytes())
}

fn engine(e: stele_reductions::zk::Error) -> Error {
    Error::Zk(e)
}

/// The window's relation and values (the plain checker passed).
fn window(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
) -> Result<(Relation, Values), Error> {
    let d = decode(public)?;
    let layout = layout_for(&d, public, statement, true)?;
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    let values = layout.assign(&capture, &weights.codes)?;
    check(&layout.relation, &values).map_err(Error::Check)?;
    Ok((layout.relation, values))
}

/// Commit the model once (RFC-0013 A6): count the per-proof blocks on a reference
/// window of `length` tokens, then commit the lifetime weight source from `seed`.
/// Returns the published commitment and the owner's secret state.
pub fn commit(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    length: usize,
    proofs: u32,
    seed: [u8; 32],
) -> Result<(ModelCommitment, ModelState), Error> {
    if proofs == 0 || length == 0 {
        return Err(Error::StatementMismatch);
    }
    let reference = Statement {
        tokens: alloc::vec![1; length],
        start: 0,
        end: length as u32,
        next: Some(1),
    };
    let mut public = public.clone();
    public.commitment = alloc::vec![([0; 32], Vec::new())];
    let d = decode(&public)?;
    let layout = layout_for(&d, &public, &reference, true)?;
    let capture = executor
        .capture(&reference.tokens)
        .map_err(|_| Error::Witness)?;
    let values = layout.assign(&capture, &weights.codes)?;
    let blocks = zk_relation::weight_blocks(&layout.relation).map_err(engine)?;
    let mut commitment = ModelCommitment {
        root: [0; 32],
        proofs,
        blocks: blocks.iter().map(|b| *b as u32).collect(),
        length: length as u32,
    };
    commitment.root = zk_relation::lifetime_root(
        &layout.relation,
        &values,
        &commitment.lifetime(0),
        &Seed::new(seed),
    )
    .map_err(engine)?;
    Ok((
        commitment,
        ModelState {
            seed,
            next: 0,
            revealed: Vec::new(),
        },
    ))
}

/// Prove one window under dev-zk as proof `index` against `commitment`. `public`
/// carries the commitment's root; `state` must hold the `index` earlier openings
/// (from [`ModelState::take`]). Returns the proof and this opening's revealed
/// vector, which the caller appends to `state.revealed` and persists.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
    seed: Seed,
    commitment: &ModelCommitment,
    state: &ModelState,
    index: u32,
) -> Result<(Vec<u8>, Vec<K>), Error> {
    if index >= commitment.proofs
        || index >= state.next
        || state.revealed.len() != index as usize
        || public.commitment.first().map(|(r, _)| *r) != Some(commitment.root)
    {
        return Err(budget());
    }
    let d = decode(public)?;
    let (relation, values) = window(public, executor, weights, statement)?;
    let input = public_input(public, &d.cqis_id, statement, commitment, index);
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let model = ModelSecret {
        seed: &state.seed,
        revealed: state.revealed.clone(),
        root: commitment.root,
    };
    let (proof, revealed) = zk_relation::prove_lifetime(
        &mut t,
        &relation,
        &values,
        seed,
        &commitment.lifetime(index),
        model,
    )
    .map_err(engine)?;
    let digest = statement_digest(&input, &relation::digest(&relation));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&d.cqis_id);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&claims::encode(&proof));
    Ok((out, revealed))
}

/// The statement digest of `(public, statement)` under `profile` (0 development,
/// 1 dev-zk), over the dev-zk relation: the value a dev-zk container carries for
/// profile 1. NC-0912 restamps a dev-zk proof with profile 0.
pub fn statement_digest_for(
    public: &Public,
    statement: &Statement,
    commitment: &ModelCommitment,
    index: u32,
    profile: u8,
) -> Result<[u8; 32], Error> {
    let d = decode(public)?;
    let layout = layout_for(&d, public, statement, true)?;
    let input = match profile {
        PROFILE => public_input(public, &d.cqis_id, statement, commitment, index),
        _ => development_input(public, &d.cqis_id, statement),
    };
    Ok(statement_digest(
        &input,
        &relation::digest(&layout.relation),
    ))
}

/// Verify one dev-zk window (RFC-0026 §8 with A9) as proof `index` against the
/// published `commitment`: rebuild the relation from plan data and the statement,
/// then replay the claims verifier on the lifetime source.
pub fn verify(
    public: &Public,
    statement: &Statement,
    proof: &[u8],
    commitment: &ModelCommitment,
    index: u32,
) -> Result<Verified, Error> {
    let header = MAGIC.len() + 64;
    if proof.len() < header || !proof.starts_with(MAGIC) {
        return Err(Error::StatementMismatch);
    }
    let d = decode(public)?;
    if proof[MAGIC.len()..MAGIC.len() + 32] != d.cqis_id
        || public.commitment.len() != 1
        || public.commitment[0].0 != commitment.root
        || index >= commitment.proofs
    {
        return Err(Error::StatementMismatch);
    }
    let layout = layout_for(&d, public, statement, true)?;
    layout
        .relation
        .validate()
        .map_err(|_| Error::StatementMismatch)?;
    let input = public_input(public, &d.cqis_id, statement, commitment, index);
    // Fail fast only: the binding is the transcript over `input` (NC-0912).
    if proof[MAGIC.len() + 32..header]
        != statement_digest(&input, &relation::digest(&layout.relation))
    {
        return Err(Error::StatementMismatch);
    }
    let decoded = claims::decode::<K>(&proof[header..]).map_err(engine)?;
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let verified = zk_relation::verify_lifetime(
        &mut t,
        &layout.relation,
        commitment.root,
        &commitment.lifetime(index),
        &decoded,
    )
    .map_err(engine)?;
    Ok(Verified {
        relations: decoded.relations.len(),
        gkr: decoded.gkr.len(),
        batches: verified.reductions.len() - decoded.relations.len() - decoded.gkr.len(),
        bytes: proof.len(),
    })
}
