//! The dev-zk profile through the development orchestrator (RFC-0013 A5 items 6–8,
//! RFC-0013 A6, RFC-0026 A9; tasks E12-14b, E12-25).
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
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use stele_reductions::relation;
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_field::Serialize;
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{
    check, ColumnId, Identity, Kind, Range, Ref, Relation, Term as IdentityTerm, Values, Width,
};
use stele_reductions::zk::claims::{Lifetime, ModelSecret};
pub use stele_reductions::zk::Seed;
use stele_reductions::zk::{claims, relation as zk_relation};

/// The RFC-0026 A9 profile byte of dev-zk.
pub const PROFILE: u8 = 1;

const MAGIC: &[u8] = b"stele-dev-zk-v1";
const MODEL_MAGIC: &[u8] = b"stele-dev-zk-model-v1";
const STATE_MAGIC: &[u8] = b"stele-dev-zk-model-secret-v1";
const DIGEST_TAG: &[u8] = b"stele/v0.1/dev-zk/model";

/// The published dev-zk model commitment (RFC-0013 A6).
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
/// commitment bytes and the public 1-D records (ordinal, length, codes) in record
/// order. Under RFC-0013 A7 those records are the fixed per-format pattern
/// ([`published`]), not the gains; the gains are bound only through
/// `commitment.root`.
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

/// The RMSNorm gain-derived columns a dev-zk proof commits (E12-27, RFC-0013 A6):
/// the gain's low byte `H0`, its high byte `H1`, its sign `σH` and `flipH = 1 −
/// 2σH`, by name suffix, with their fixed widths.
const RECORDS: [(&str, Width); 4] = [
    ("/H0", Width::unsigned(8)),
    ("/H1", Width::signed(8)),
    ("/sigmaH", Width::unsigned(1)),
    ("/flipH", Width::signed(2)),
];

/// The published 1-D records of `model` (canonical Model bytes): every code
/// replaced by the fixed pattern `min, max, −1, 0, …` of the record's format,
/// lengths kept. Under dev-zk the gains are committed weights; the public input
/// names only their shapes. The pattern reaches the format's extremes of `H0, H1,
/// σH, flipH`, so the plan's static bounds (RFC-0026 §3.6) hold for any gain the
/// format admits.
pub fn published(model: &[u8], vectors: &[(u16, Vec<i16>)]) -> Result<Vec<(u16, Vec<i16>)>, Error> {
    let m = stele_reductions::stele_cqis::model::Model::decode(model)
        .map_err(|_| Error::StatementMismatch)?;
    vectors
        .iter()
        .map(|(o, codes)| {
            let bits = m
                .formats()
                .get(usize::from(*o))
                .ok_or(Error::StatementMismatch)?
                .bits()
                .min(16);
            let (min, max) = (-(1i32 << (bits - 1)), (1i32 << (bits - 1)) - 1);
            let pattern = [min as i16, max as i16, -1, 0];
            Ok((*o, (0..codes.len()).map(|k| pattern[k % 4]).collect()))
        })
        .collect()
}

/// Commit the 1-D records (E12-27): turn every gain-derived public column into a
/// weight column of fixed width, and add the relations that make each group a CQIS
/// int16 gain encoding `h = H0 + 256·H1` with `σH = [h < 0]`:
/// - ranges `H0 ∈ [0, 256)`, `H1 ∈ [−128, 128)`, `σH ∈ {0, 1}`, `flipH ∈ [−2, 2)`
///   and `L = H1 + 128·σH ∈ [0, 128)` (a new weight column), so `σH` is `H1`'s
///   two's-complement sign;
/// - identities `flipH − 1 + 2σH = 0` and `L − H1 − 128·σH = 0`;
/// - padding past the model width `d` is zero: `x·(1 − gainvalid) = 0` for `H0, H1, σH`.
///
/// `values` (the prover's, or empty for the verifier) gets the converted columns'
/// values. The result's structure depends on no gain value.
pub fn commit_records(
    relation: &Relation,
    values: Option<(&Values, &Relation)>,
    d: usize,
) -> Result<(Relation, Option<Values>), Error> {
    // The real gain columns come from `values`' own relation (same column ids).
    let source = values.map_or(relation, |(_, r)| r);
    let mut rel = relation.clone();
    let mut converted: Vec<(ColumnId, Vec<i64>)> = Vec::new();
    // Groups by module prefix: (prefix, [H0, H1, σH, flipH]).
    let mut groups: Vec<(String, [Option<ColumnId>; 4])> = Vec::new();
    for (i, column) in rel.columns.iter_mut().enumerate() {
        let Some(slot) = RECORDS.iter().position(|(s, _)| column.name.ends_with(s)) else {
            continue;
        };
        let Some(Kind::Public(data)) = source.columns.get(i).map(|c| &c.kind) else {
            return Err(Error::UnsupportedModel);
        };
        if !matches!(column.kind, Kind::Public(_)) {
            return Err(Error::UnsupportedModel);
        }
        converted.push((ColumnId(i as u32), data.clone()));
        column.kind = Kind::Weight;
        column.width = RECORDS[slot].1;
        let prefix = column.name[..column.name.len() - RECORDS[slot].0.len()].to_string();
        match groups.iter_mut().find(|(p, _)| *p == prefix) {
            Some((_, ids)) => ids[slot] = Some(ColumnId(i as u32)),
            None => {
                let mut ids = [None; 4];
                ids[slot] = Some(ColumnId(i as u32));
                groups.push((prefix, ids));
            }
        }
    }
    let mut derived: Vec<(ColumnId, ColumnId, ColumnId)> = Vec::new();
    for (prefix, ids) in &groups {
        let [Some(h0), Some(h1), Some(sigma), Some(flip)] = *ids else {
            return Err(Error::UnsupportedModel);
        };
        let log_len = rel.columns[h0.0 as usize].log_len;
        let read = |id| Ref::identity(id, log_len);
        let low = rel.add_column(
            &alloc::format!("{prefix}/H1low"),
            Kind::Weight,
            Width::unsigned(7),
            log_len,
        );
        let valid: Vec<i64> = (0..1usize << log_len).map(|k| i64::from(k < d)).collect();
        let mask = rel.add_column(
            &alloc::format!("{prefix}/gainvalid"),
            Kind::Public(valid),
            Width::unsigned(1),
            log_len,
        );
        for (id, width) in [
            (h0, Width::unsigned(8)),
            (h1, Width::signed(8)),
            (sigma, Width::unsigned(1)),
            (flip, Width::signed(2)),
            (low, Width::unsigned(7)),
        ] {
            rel.ranges.push(Range {
                name: alloc::format!("{}/range", rel.columns[id.0 as usize].name),
                column: id,
                width,
            });
        }
        let term = |coeff, factors| IdentityTerm { coeff, factors };
        let mut identities = alloc::vec![
            (
                "flip",
                alloc::vec![
                    term(1, alloc::vec![read(flip)]),
                    term(-1, Vec::new()),
                    term(2, alloc::vec![read(sigma)]),
                ],
            ),
            (
                "sign",
                alloc::vec![
                    term(1, alloc::vec![read(low)]),
                    term(-1, alloc::vec![read(h1)]),
                    term(-128, alloc::vec![read(sigma)]),
                ],
            ),
        ];
        for (name, id) in [("pad0", h0), ("pad1", h1), ("padsigma", sigma)] {
            identities.push((
                name,
                alloc::vec![
                    term(1, alloc::vec![read(id)]),
                    term(-1, alloc::vec![read(mask), read(id)]),
                ],
            ));
        }
        for (name, terms) in identities {
            rel.identities.push(Identity {
                name: alloc::format!("{prefix}/records/{name}"),
                vars: log_len,
                terms,
            });
        }
        derived.push((low, h1, sigma));
    }
    rel.validate().map_err(|_| Error::UnsupportedModel)?;
    let Some((values, real)) = values else {
        return Ok((rel, None));
    };
    let mut out = Values::new(&rel);
    for i in 0..relation.columns.len() {
        let id = ColumnId(i as u32);
        if matches!(relation.columns[i].kind, Kind::Public(_)) {
            continue;
        }
        let v = values.get(real, id).ok_or(Error::Witness)?.to_vec();
        out.set(&rel, id, v).map_err(|_| Error::Witness)?;
    }
    for (id, v) in &converted {
        out.set(&rel, *id, v.clone()).map_err(|_| Error::Witness)?;
    }
    for (low, h1, sigma) in derived {
        let get = |id| out.get(&rel, id).map(<[i64]>::to_vec).ok_or(Error::Witness);
        let (h1v, sv) = (get(h1)?, get(sigma)?);
        let lv = h1v.iter().zip(&sv).map(|(h, s)| h + 128 * s).collect();
        out.set(&rel, low, lv).map_err(|_| Error::Witness)?;
    }
    Ok((rel, Some(out)))
}

/// The dev-zk relation the verifier derives (E12-27): the development plan on the
/// published (zeroed) 1-D records, with the records committed. A public input whose
/// records are not zeroed is refused (`StatementMismatch`).
fn zk_relation_of(public: &Public, statement: &Statement) -> Result<Relation, Error> {
    if public.vectors != published(&public.model, &public.vectors)? {
        return Err(Error::StatementMismatch);
    }
    let d = decode(public)?;
    let layout = layout_for(&d, public, statement, true)?;
    let width = usize::from(d.model.shape().width());
    Ok(commit_records(&layout.relation, None, width)?.0)
}

/// The window's committed relation and values from the real 1-D records in
/// `weights` (the plain checker passed when `checked`). The relation equals the
/// verifier's [`zk_relation_of`] or the window is refused.
fn window_values(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
    checked: bool,
) -> Result<(Relation, Values), Error> {
    if public.vectors != published(&public.model, &weights.vectors)? {
        return Err(Error::StatementMismatch);
    }
    let published_relation = zk_relation_of(public, statement)?;
    let real = Public {
        vectors: weights.vectors.clone(),
        ..public.clone()
    };
    let d = decode(&real)?;
    let layout = layout_for(&d, &real, statement, true)?;
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    let values = layout.assign(&capture, &weights.codes)?;
    if checked {
        check(&layout.relation, &values).map_err(Error::Check)?;
    }
    let width = usize::from(d.model.shape().width());
    let (relation, values) =
        commit_records(&layout.relation, Some((&values, &layout.relation)), width)?;
    let values = values.ok_or(Error::Witness)?;
    if checked {
        check(&relation, &values).map_err(Error::Check)?;
    }
    // The committed relation depends on no gain value: it is the verifier's.
    if relation::digest(&relation) != relation::digest(&published_relation) {
        return Err(Error::StatementMismatch);
    }
    Ok((relation, values))
}

/// The window's committed dev-zk relation and values (the plain checker passed),
/// as [`prove`] uses them; `public` carries the published records.
pub fn window(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
) -> Result<(Relation, Values), Error> {
    window_values(public, executor, weights, statement, true)
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
    // RFC-0026 A11: dev-zk uses its hiding sources; an A11 source set is rejected.
    if proofs == 0 || length == 0 || public.sources != relation::Sources::Expander {
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
    // The reference window need not be greedy: only its shape and weights count.
    let (relation, values) = window_values(&public, executor, weights, &reference, false)?;
    let blocks = zk_relation::weight_blocks(&relation).map_err(engine)?;
    let mut commitment = ModelCommitment {
        root: [0; 32],
        proofs,
        blocks: blocks.iter().map(|b| *b as u32).collect(),
        length: length as u32,
    };
    commitment.root = zk_relation::lifetime_root(
        &relation,
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
    if public.sources != relation::Sources::Expander {
        return Err(Error::StatementMismatch); // RFC-0026 A11: not a dev-zk input.
    }
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
    let relation_zk = zk_relation_of(public, statement)?;
    let input = match profile {
        PROFILE => public_input(public, &d.cqis_id, statement, commitment, index),
        _ => development_input(public, &d.cqis_id, statement),
    };
    Ok(statement_digest(&input, &relation::digest(&relation_zk)))
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
    // RFC-0026 A11: a dev-zk input carries no source-set byte.
    if proof.len() < header
        || !proof.starts_with(MAGIC)
        || public.sources != relation::Sources::Expander
    {
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
    let relation_zk = zk_relation_of(public, statement)?;
    let input = public_input(public, &d.cqis_id, statement, commitment, index);
    // Fail fast only: the binding is the transcript over `input` (NC-0912).
    if proof[MAGIC.len() + 32..header] != statement_digest(&input, &relation::digest(&relation_zk))
    {
        return Err(Error::StatementMismatch);
    }
    let decoded = claims::decode::<K>(&proof[header..]).map_err(engine)?;
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let verified = zk_relation::verify_lifetime(
        &mut t,
        &relation_zk,
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
