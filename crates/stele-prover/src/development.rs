//! Development-profile end-to-end prefill prover and verifier (RFC-0026 §1, §4.1, §8).
//!
//! - [`Weights`] reads the weight codes and the public 1-D records of an Artifact.
//! - [`Committed`] is the model commitment (RFC-0026 §2.2): one RFC-0010 v2 source per
//!   weight tensor in plan order, prepared once and reused across proofs.
//! - [`prove`] runs the executor capture, declares and assigns the relation, runs the
//!   plain checker and the relation engine, and emits a `stele-dev-e2e-v1` container.
//! - [`verify`] rebuilds the relation from plan data and the statement and replays the
//!   engine; it returns the RFC-0026 §6 ledger.
//!
//! Public inputs (RFC-0026 §1.1 as amended by A2) are encoded by [`public_input`].
use alloc::string::String;
use alloc::vec::Vec;
use stele_proof::development::{self as container, Container};
use stele_reductions::relation::{self, Ledger, Proof};
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{
    ArtifactLayout, Bounds, Model, NumericalIdentity, Registry, Role, Scales,
};
use stele_reductions::stele_field::{Field, M31};
use stele_reductions::stele_hash::{HashUsage, Transcript};
use stele_reductions::stele_ir::relation::{check, Relation, Values, Violation};
use stele_reductions::stele_pcs::{
    verify_certificate, PreparedSource, ProofKind, Source, VerifiedCertificate,
};

pub mod bundle;
mod plan;
pub use plan::{Layout, PlanData};

/// Challenge field of the development profile.
type K = relation::K;

/// A rejected statement, witness or proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The Model is outside the RFC-0026 §1.3 class, or a plan module rejects it.
    UnsupportedModel,
    /// The statement is malformed, or the plan-derived relation or digest differs
    /// (RFC-0026 §2.2, §4 step 1, §8 step 2).
    StatementMismatch,
    /// The executor rejected the window, or a capture does not fit its column.
    Witness,
    /// A module rejected its capture.
    Assign(String),
    /// The honest relation failed the plain checker (RFC-0026 §3.7).
    Check(Violation),
    /// The container does not parse.
    Container(container::Error),
    /// A model-commitment certificate does not verify.
    Commitment(stele_reductions::stele_pcs::Error),
    /// The relation engine rejected (RFC-0026 §8 step 3-4).
    Engine(relation::Error),
}

/// The proven window (RFC-0026 §1.1 items 3-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// `x_0..x_{T-1}`; `T` is a power of two.
    pub tokens: Vec<u32>,
    /// Checked range `[start, end)`.
    pub start: u32,
    pub end: u32,
    /// The next token `y`, present exactly when `end = T`.
    pub next: Option<u32>,
}

impl Statement {
    fn validate(&self, vocabulary: u32) -> Result<(), Error> {
        let t = self.tokens.len();
        let ok = t.is_power_of_two()
            && self.start < self.end
            && self.end as usize <= t
            && (self.end as usize == t) == self.next.is_some()
            && self
                .tokens
                .iter()
                .chain(&self.next)
                .all(|&x| x < vocabulary);
        ok.then_some(()).ok_or(Error::StatementMismatch)
    }
}

/// The verifier's model data: canonical Model, Scales and Preparation bytes, the 1-D
/// records (RFC-0026 A2) and the model-commitment roots with their certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub model: Vec<u8>,
    pub scales: Vec<u8>,
    pub preparation: Vec<u8>,
    /// `(ordinal, codes)` of every 1-D artifact record, in record order.
    pub vectors: Vec<(u16, Vec<i16>)>,
    /// One `(root, certificate)` per weight source in plan order.
    pub commitment: Vec<([u8; 32], Vec<u8>)>,
}

struct Decoded {
    model: Model,
    scales: Scales,
    cqis_id: [u8; 32],
}

fn decode(public: &Public) -> Result<Decoded, Error> {
    let model = Model::decode(&public.model).map_err(|_| Error::StatementMismatch)?;
    let scales = Scales::decode(&model, &public.scales).map_err(|_| Error::StatementMismatch)?;
    stele_reductions::stele_cqis::model::Preparation::decode(&model, &public.preparation)
        .map_err(|_| Error::StatementMismatch)?;
    let registry = Registry::new(&model).map_err(|_| Error::UnsupportedModel)?;
    let bounds = Bounds::new(&model, &scales, &registry).map_err(|_| Error::UnsupportedModel)?;
    let cqis_id = NumericalIdentity::new(&model, &scales, &registry, &bounds)
        .map_err(|_| Error::StatementMismatch)?
        .identity();
    Ok(Decoded {
        model,
        scales,
        cqis_id,
    })
}

fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

const PUBLIC_TAG: &[u8] = b"stele/v0.1/dev-e2e/public-input";
const STATEMENT_TAG: &[u8] = b"stele/v0.1/dev-e2e/statement";

/// Canonical RFC-0026 §1.1 public input (as amended by A2), the transcript's first frame.
pub fn public_input(public: &Public, cqis_id: &[u8; 32], statement: &Statement) -> Vec<u8> {
    let mut out = PUBLIC_TAG.to_vec();
    out.extend_from_slice(cqis_id);
    blob(&mut out, &public.model);
    blob(&mut out, &public.scales);
    blob(&mut out, &public.preparation);
    out.extend_from_slice(&(public.vectors.len() as u32).to_le_bytes());
    for (ordinal, codes) in &public.vectors {
        out.extend_from_slice(&ordinal.to_le_bytes());
        let raw: Vec<u8> = codes.iter().flat_map(|c| c.to_le_bytes()).collect();
        blob(&mut out, &raw);
    }
    out.extend_from_slice(&(public.commitment.len() as u32).to_le_bytes());
    for (root, _) in &public.commitment {
        out.extend_from_slice(root);
    }
    out.extend_from_slice(&(statement.tokens.len() as u32).to_le_bytes());
    for x in &statement.tokens {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.extend_from_slice(&statement.start.to_le_bytes());
    out.extend_from_slice(&statement.end.to_le_bytes());
    match statement.next {
        Some(y) => {
            out.push(1);
            out.extend_from_slice(&y.to_le_bytes());
        }
        None => out.push(0),
    }
    out
}

/// Container statement digest: BLAKE3 over the public input and the relation digest.
fn statement_digest(public_input: &[u8], relation: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(STATEMENT_TAG);
    h.update(&(public_input.len() as u64).to_le_bytes());
    h.update(public_input);
    h.update(relation);
    *h.finalize().as_bytes()
}

/// The `(role, layer)` of every weight source in RFC-0026 §2.2 plan order.
pub fn weight_roles(model: &Model) -> Vec<(Role, Option<u16>)> {
    let mut out = alloc::vec![(Role::Token, None)];
    for l in 0..model.shape().layers() {
        for role in [
            Role::Query,
            Role::Key,
            Role::Value,
            Role::Output,
            Role::Gate,
            Role::Up,
            Role::Down,
        ] {
            out.push((role, Some(l)));
        }
    }
    out.push((Role::Head, None));
    out
}

/// Declare the window and check the RFC-0026 §2.2 plan obligation.
fn layout(d: &Decoded, public: &Public, statement: &Statement) -> Result<Layout, Error> {
    statement.validate(d.model.shape().vocabulary())?;
    let plan = PlanData {
        model: &d.model,
        scales: &d.scales,
        vectors: &public.vectors,
    };
    let layout = Layout::declare(&plan, statement)?;
    let roles = weight_roles(&d.model);
    let declared = plan::weight_columns(&layout.relation);
    let same =
        declared.len() == roles.len()
            && layout.weights.len() == roles.len()
            && layout.weights.iter().zip(&declared).zip(&roles).all(
                |(((id, role, layer), column), (r, l))| id == column && role == r && layer == l,
            );
    if !same || public.commitment.len() != roles.len() {
        return Err(Error::StatementMismatch);
    }
    Ok(layout)
}

/// Weight codes of an Artifact in plan order, and its public 1-D records.
pub struct Weights {
    /// `[source][channel][lane]` codes.
    pub codes: Vec<Vec<Vec<i64>>>,
    pub vectors: Vec<(u16, Vec<i16>)>,
    messages: Vec<Vec<M31>>,
}

impl Weights {
    pub fn from_artifact(model: &Model, artifact: &[u8]) -> Result<Self, Error> {
        let layout = ArtifactLayout::new(model).map_err(|_| Error::UnsupportedModel)?;
        let shape = model.shape();
        let mut records = Vec::new();
        for r in layout.records() {
            let start = usize::try_from(r.payload_offset()).map_err(|_| Error::Witness)?;
            let len = usize::try_from(r.payload_length()).map_err(|_| Error::Witness)?;
            let raw = artifact.get(start..start + len).ok_or(Error::Witness)?;
            let codes: Vec<i16> = (0..r.elements() as usize)
                .map(|i| match r.bits() {
                    16 => i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]),
                    8 => i16::from(raw[i] as i8),
                    _ => {
                        let n = (raw[i / 2] >> (4 * (i % 2))) & 15;
                        i16::from(n) - if n >= 8 { 16 } else { 0 }
                    }
                })
                .collect();
            let physical = shape.physical(r.ordinal()).ok_or(Error::UnsupportedModel)?;
            records.push((physical, codes));
        }
        let vectors = records
            .iter()
            .filter(|(p, _)| p.dimensions().len() == 1)
            .map(|(p, c)| (p.ordinal(), c.clone()))
            .collect();
        let mut codes = Vec::new();
        let mut messages = Vec::new();
        for (role, layer) in weight_roles(model) {
            let (p, c) = records
                .iter()
                .find(|(p, _)| p.role() == role && p.layer() == layer)
                .ok_or(Error::UnsupportedModel)?;
            let lanes = p.dimensions()[1] as usize;
            let rows: Vec<Vec<i64>> = c
                .chunks(lanes)
                .map(|r| r.iter().map(|&v| i64::from(v)).collect())
                .collect();
            messages.push(
                plan::pad(&rows, lanes)
                    .into_iter()
                    .map(M31::from_i64)
                    .collect(),
            );
            codes.push(rows);
        }
        Ok(Self {
            codes,
            vectors,
            messages,
        })
    }
}

/// Smallest v2 expander exponent; RFC-0010 A3 item 2.
const MIN_J: u8 = 3;
const MAX_J: u8 = 14;
/// Weight-source ids sit above every engine group and multiplicity id.
const WEIGHT_ID: u64 = 1 << 40;

fn v2_code(j: u8) -> Vec<u8> {
    let mut code = b"stele/expander-seed/v2".to_vec();
    code.push(j);
    code.extend_from_slice(&[0; 32]);
    code
}

/// Geometry `(id, ell, code)` of weight source `i` with `2^bits` entries: the v2
/// exponent minimising certificate plus opening bytes (ties: smallest J).
fn geometry(i: usize, bits: u8) -> Result<(u64, u8, Vec<u8>), Error> {
    let id = WEIGHT_ID + i as u64;
    let mut best: Option<(usize, u8)> = None;
    for j in MIN_J..=MAX_J.min(bits / 2) {
        let Ok(s) = Source::<K>::from_code_id(id, bits - 2 * j, &v2_code(j), [0; 32]) else {
            continue;
        };
        let size = s
            .proof_size(ProofKind::Certificate)
            .and_then(|c| Ok(c + s.proof_size(ProofKind::Opening)?))
            .map_err(Error::Commitment)?;
        if best.is_none_or(|(b, _)| size < b) {
            best = Some((size, j));
        }
    }
    let (_, j) = best.ok_or(Error::UnsupportedModel)?;
    Ok((id, bits - 2 * j, v2_code(j)))
}

/// The prepared model commitment, built once per model (RFC-0026 §2.2).
pub struct Committed<'a> {
    prepared: Vec<PreparedSource<'a, K>>,
    certificates: Vec<VerifiedCertificate<K>>,
    /// `(root, certificate)` per source, for [`Public::commitment`].
    pub commitment: Vec<([u8; 32], Vec<u8>)>,
}

impl<'a> Committed<'a> {
    pub fn new(weights: &'a Weights) -> Result<Self, Error> {
        let mut prepared = Vec::new();
        let mut certificates = Vec::new();
        let mut commitment = Vec::new();
        for (i, message) in weights.messages.iter().enumerate() {
            let bits = message.len().trailing_zeros() as u8;
            let (id, ell, code) = geometry(i, bits)?;
            let p =
                PreparedSource::from_code_id(id, ell, &code, message, &mut HashUsage::default())
                    .map_err(Error::Commitment)?;
            let (bytes, _) = p
                .certificate()
                .map_err(|_| Error::Commitment(stele_reductions::stele_pcs::Error::Capacity))?;
            let (verified, _) =
                verify_certificate(*p.source(), &bytes).map_err(|f| Error::Commitment(f.cause))?;
            commitment.push((p.source().root(), bytes));
            certificates.push(verified);
            prepared.push(p);
        }
        Ok(Self {
            prepared,
            certificates,
            commitment,
        })
    }
}

/// Verify every model-commitment certificate against its plan-derived source.
fn certificates(public: &Public, bits: &[u8]) -> Result<Vec<VerifiedCertificate<K>>, Error> {
    public
        .commitment
        .iter()
        .zip(bits)
        .enumerate()
        .map(|(i, ((root, bytes), &b))| {
            let (id, ell, code) = geometry(i, b)?;
            let source = Source::from_code_id(id, ell, &code, *root).map_err(Error::Commitment)?;
            verify_certificate(source, bytes)
                .map(|(v, _)| v)
                .map_err(|f| Error::Commitment(f.cause))
        })
        .collect()
}

fn sections(proof: Proof, cqis_id: [u8; 32], statement: [u8; 32]) -> Container {
    Container {
        cqis_id,
        statement,
        groups: proof.groups,
        multiplicities: proof.multiplicities,
        identities: proof.identities,
        lookups: proof.lookups,
        matmuls: proof.matmuls,
        openings: proof.openings,
    }
}

/// Prove one window. `executor` must be loaded from the same Model, Scales,
/// Preparation and Artifact as `public` and `weights`.
pub fn prove(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
) -> Result<Vec<u8>, Error> {
    prove_inner(public, executor, weights, committed, statement, None)
}

/// A prover-side tamper for negative controls (RFC-0026 §9): it edits the prover's
/// relation or values after assignment.
pub type Hook<'h> = &'h mut dyn FnMut(&mut Relation, &mut Values);

/// Negative controls only: [`prove`] with `hook` applied to the prover's relation
/// and values, and without the plain checker, so a false witness reaches the proof.
/// The verifier is unchanged and must reject the result.
pub fn prove_tampered(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    hook: Hook<'_>,
) -> Result<Vec<u8>, Error> {
    prove_inner(public, executor, weights, committed, statement, Some(hook))
}

fn prove_inner(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    hook: Option<Hook<'_>>,
) -> Result<Vec<u8>, Error> {
    let d = decode(public)?;
    let mut layout = layout(&d, public, statement)?;
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    let mut values = layout.assign(&capture, &weights.codes)?;
    match hook {
        Some(hook) => hook(&mut layout.relation, &mut values),
        None => check(&layout.relation, &values).map_err(Error::Check)?,
    }
    let input = public_input(public, &d.cqis_id, statement);
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    let proof = relation::prove(
        &mut t,
        &layout.relation,
        &values,
        &committed.prepared.iter().collect::<Vec<_>>(),
        &committed.certificates.iter().collect::<Vec<_>>(),
    )
    .map_err(Error::Engine)?;
    let digest = statement_digest(&input, &relation::digest(&layout.relation));
    Ok(sections(proof, d.cqis_id, digest).encode())
}

/// Verify one window (RFC-0026 §8) and return its ledger.
pub fn verify(public: &Public, statement: &Statement, proof: &[u8]) -> Result<Ledger, Error> {
    let c = container::decode(proof).map_err(Error::Container)?;
    let d = decode(public)?;
    if c.cqis_id != d.cqis_id {
        return Err(Error::StatementMismatch);
    }
    let layout = layout(&d, public, statement)?;
    layout
        .relation
        .validate()
        .map_err(|_| Error::StatementMismatch)?;
    let input = public_input(public, &d.cqis_id, statement);
    if c.statement != statement_digest(&input, &relation::digest(&layout.relation)) {
        return Err(Error::StatementMismatch);
    }
    let bits: Vec<u8> = layout
        .weights
        .iter()
        .map(|(id, _, _)| layout.relation.columns[id.0 as usize].log_len)
        .collect();
    let certs = certificates(public, &bits)?;
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    // The engine derives every section count and length (RFC-0026 §4.1).
    let sections = Proof {
        groups: c.groups,
        multiplicities: c.multiplicities,
        identities: c.identities,
        lookups: c.lookups,
        matmuls: c.matmuls,
        openings: c.openings,
    };
    relation::verify(
        &mut t,
        &layout.relation,
        &certs.iter().collect::<Vec<_>>(),
        &sections,
    )
    .map_err(Error::Engine)
}

/// Prove one window from canonical Model, Preparation, Scales and Artifact bytes,
/// committing the model on the way; returns the verifier's [`Public`] data and the
/// container. When `statement.next` is `None` and `end = T`, `y` is the executor's
/// greedy choice at `T - 1` (RFC-0025 §2.6). A window shorter than `length` is first
/// extended by greedy decoding; `end` then defaults to the new `T`.
pub fn prove_window(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    mut statement: Statement,
    length: usize,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    let m = Model::decode(model).map_err(|_| Error::StatementMismatch)?;
    let p = stele_reductions::stele_cqis::model::Preparation::decode(&m, preparation)
        .map_err(|_| Error::StatementMismatch)?;
    let s = Scales::decode(&m, scales).map_err(|_| Error::StatementMismatch)?;
    let id = artifact_id(artifact);
    let mut executor =
        Executor::new(&m, &p, &s, artifact, &id, 1 << 36).map_err(|_| Error::Witness)?;
    if statement.tokens.len() < length {
        let whole = statement.end as usize == statement.tokens.len();
        let (mut cache, mut logits) = (None, Vec::new());
        for i in 0..length {
            if i == statement.tokens.len() {
                let max = logits.iter().max().ok_or(Error::Witness)?;
                let y = logits.iter().position(|v| v == max).ok_or(Error::Witness)?;
                statement.tokens.push(y as u32);
            }
            let (step, next) = executor
                .step(statement.tokens[i], cache.as_ref())
                .map_err(|_| Error::Witness)?;
            logits = step.logits().to_vec();
            cache = Some(next);
        }
        if whole {
            statement.end = length as u32;
        }
    }
    if statement.next.is_none() && statement.end as usize == statement.tokens.len() {
        let full = executor
            .full(&statement.tokens)
            .map_err(|_| Error::Witness)?;
        let last = full.logits().last().ok_or(Error::Witness)?;
        let max = last.iter().max().ok_or(Error::Witness)?;
        statement.next = last.iter().position(|v| v == max).map(|i| i as u32);
    }
    let weights = Weights::from_artifact(&m, artifact)?;
    let committed = Committed::new(&weights)?;
    let public = Public {
        model: model.to_vec(),
        scales: scales.to_vec(),
        preparation: preparation.to_vec(),
        vectors: weights.vectors.clone(),
        commitment: committed.commitment.clone(),
    };
    let proof = prove(&public, &mut executor, &weights, &committed, &statement)?;
    Ok((public, statement, proof))
}

/// The Artifact identity the executor expects: BLAKE3 of its canonical bytes.
pub fn artifact_id(artifact: &[u8]) -> [u8; 32] {
    *blake3::hash(artifact).as_bytes()
}
