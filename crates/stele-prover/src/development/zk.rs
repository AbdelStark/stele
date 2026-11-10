//! The dev-zk profile through the development orchestrator (RFC-0013 A5 items 6–8,
//! RFC-0026 A9; task E12-14b).
//!
//! - **Public input.** RFC-0026 §1.1 (as amended by A2), then the A9 profile byte
//!   `1`. The development public input keeps its pre-A9 bytes (the byte is
//!   implied `0`), so a development proof is unchanged. The model commitment is one
//!   root: the proof's hiding weight source (A5 item 7, `P = 1`), whose certificate
//!   travels in the proof.
//! - **Proof.** `stele-dev-zk-v1`: magic, `cqis_id`, the statement digest (over the
//!   profiled public input and the relation digest), then the claims proof bytes
//!   (`zk::claims::encode`). The header digest fails fast only; the transcript binds
//!   the public input, profile byte included (NC-0912).
//! - **Order.** `Transcript::new(public input)`, then `zk::relation::prove`:
//!   `relation/statement`, the claim sources, checks, relations, GKR steps and
//!   batches (A5 item 6).
//!
//! The seed is move-only and serves one proof; [`prove`] takes it from its caller,
//! which draws it from the OS RNG (the CLI reads `/dev/urandom`).
use super::{
    decode, layout_for, public_input as development_input, statement_digest, Error, Public,
    Statement, Weights, K,
};
use alloc::vec::Vec;
use stele_reductions::relation;
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::check;
pub use stele_reductions::zk::Seed;
use stele_reductions::zk::{claims, relation as zk_relation};

/// The RFC-0026 A9 profile byte of dev-zk.
pub const PROFILE: u8 = 1;

const MAGIC: &[u8] = b"stele-dev-zk-v1";

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

/// The dev-zk public input: the development bytes, then the profile byte.
pub fn public_input(public: &Public, cqis_id: &[u8; 32], statement: &Statement) -> Vec<u8> {
    let mut out = development_input(public, cqis_id, statement);
    out.push(PROFILE);
    out
}

fn engine(e: stele_reductions::zk::Error) -> Error {
    Error::Zk(e)
}

/// Prove one window under dev-zk. `public` carries no commitment; the returned
/// [`Public`] carries the weight-source root this proof's seed commits.
pub fn prove(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
    seed: Seed,
) -> Result<(Public, Vec<u8>), Error> {
    let d = decode(public)?;
    let mut public = public.clone();
    // The layout checks one weight source; its root is not yet known.
    public.commitment = alloc::vec![([0; 32], Vec::new())];
    let layout = layout_for(&d, &public, statement, true)?;
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    let values = layout.assign(&capture, &weights.codes)?;
    check(&layout.relation, &values).map_err(Error::Check)?;
    let root = zk_relation::weight_root(&layout.relation, &values, &seed)
        .map_err(engine)?
        .ok_or(Error::UnsupportedModel)?;
    public.commitment = alloc::vec![(root, Vec::new())];
    let input = public_input(&public, &d.cqis_id, statement);
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let proof = zk_relation::prove(&mut t, &layout.relation, &values, seed).map_err(engine)?;
    let digest = statement_digest(&input, &relation::digest(&layout.relation));
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&d.cqis_id);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&claims::encode(&proof));
    Ok((public, out))
}

/// The statement digest of `(public, statement)` under `profile` (0 development,
/// 1 dev-zk), over the dev-zk relation: the value a dev-zk container carries for
/// profile 1. NC-0912 restamps a dev-zk proof with profile 0.
pub fn statement_digest_for(
    public: &Public,
    statement: &Statement,
    profile: u8,
) -> Result<[u8; 32], Error> {
    let d = decode(public)?;
    let layout = layout_for(&d, public, statement, true)?;
    let input = match profile {
        PROFILE => public_input(public, &d.cqis_id, statement),
        _ => development_input(public, &d.cqis_id, statement),
    };
    Ok(statement_digest(
        &input,
        &relation::digest(&layout.relation),
    ))
}

/// Verify one dev-zk window (RFC-0026 §8 with A9): rebuild the relation from plan
/// data and the statement, then replay the claims verifier.
pub fn verify(public: &Public, statement: &Statement, proof: &[u8]) -> Result<Verified, Error> {
    let header = MAGIC.len() + 64;
    if proof.len() < header || !proof.starts_with(MAGIC) {
        return Err(Error::StatementMismatch);
    }
    let d = decode(public)?;
    if proof[MAGIC.len()..MAGIC.len() + 32] != d.cqis_id {
        return Err(Error::StatementMismatch);
    }
    let layout = layout_for(&d, public, statement, true)?;
    layout
        .relation
        .validate()
        .map_err(|_| Error::StatementMismatch)?;
    let input = public_input(public, &d.cqis_id, statement);
    // Fail fast only: the binding is the transcript over `input` (NC-0912).
    if proof[MAGIC.len() + 32..header]
        != statement_digest(&input, &relation::digest(&layout.relation))
    {
        return Err(Error::StatementMismatch);
    }
    let decoded = claims::decode::<K>(&proof[header..]).map_err(engine)?;
    let root = public.commitment.first().map(|(root, _)| *root);
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let verified = zk_relation::verify(&mut t, &layout.relation, root, &decoded).map_err(engine)?;
    Ok(Verified {
        relations: decoded.relations.len(),
        gkr: decoded.gkr.len(),
        batches: verified.reductions.len() - decoded.relations.len() - decoded.gkr.len(),
        bytes: proof.len(),
    })
}
