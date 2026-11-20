//! Development-profile end-to-end prefill prover and verifier (RFC-0026 §1, §4.1, §8).
//!
//! - [`Weights`] reads the weight codes and the public 1-D records of an Artifact.
//! - [`Committed`] is the model commitment (RFC-0026 §2.2 as amended by A5): every
//!   weight tensor stacked, in plan order, into model sources of at most 2^30 entries,
//!   prepared once and reused across proofs.
//! - [`prove`] runs the executor capture, declares and assigns the relation, runs the
//!   plain checker and the relation engine, and emits a `stele-dev-e2e-v1` container.
//! - [`verify`] rebuilds the relation from plan data and the statement and replays the
//!   engine; it returns the RFC-0026 §6 ledger.
//!
//! Public inputs (RFC-0026 §1.1 as amended by A2) are encoded by [`public_input`].
use alloc::string::String;
use alloc::vec::Vec;
/// The `stele-dev-e2e-v1` / `stele-dev-e2e-v2` codec (RFC-0026 §4.1, A26), re-exported for verifier callers.
pub use stele_proof::development as container;
use stele_proof::development::{Container, ContainerV2, SegmentSections};
use stele_reductions::parallel;
use stele_reductions::relation::{self, Proof, ProofV2, SegmentProof, Sources};
/// The RFC-0026 §6 ledger and its enumerated rounds (E8-05c), for verifier callers.
pub use stele_reductions::relation::{Entry, Ledger, Line, Round, RoundError};
use stele_reductions::stele_cqis::execution::capture::Capture;
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{
    ArtifactLayout, Bounds, Model, NumericalIdentity, Registry, Role, Scales,
};
use stele_reductions::stele_field::{Field, M31};
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{check, check_segment, Relation, Values, Violation};
use stele_reductions::stele_pcs::{verify_certificate, PreparedSource, VerifiedCertificate};

pub mod bundle;
mod plan;
pub mod registry;
pub mod zk;
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
    /// The dev-zk claims prover or verifier rejected (RFC-0013 A5, RFC-0026 A9).
    Zk(stele_reductions::zk::Error),
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
    /// `T` is a power of two within the Model's context (RFC-0025 §2.6).
    fn validate(&self, vocabulary: u32, context: u32) -> Result<(), Error> {
        let t = self.tokens.len();
        let ok = t.is_power_of_two()
            && t <= context as usize
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
    /// The source parameter set (RFC-0026 A11), bound by [`public_input`]. dev-zk
    /// inputs carry `Expander`: their hiding sources do not read it.
    pub sources: Sources,
    /// RFC-0026 A27: `0` for unsegmented v1 proofs; `> 0` splits layers into segments of at most
    /// `segment_layers` layers each (with `Finish` in its own segment) and emits `stele-dev-e2e-v2`.
    pub segment_layers: u16,
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
    // RFC-0026 A2: exactly the Model's 1-D records, in record order, at their lengths.
    let shape = model.shape();
    let records: Vec<(u16, usize)> = (0..shape.record_count())
        .filter_map(|i| shape.physical(i))
        .filter(|p| p.dimensions().len() == 1)
        .map(|p| (p.ordinal(), p.dimensions()[0] as usize))
        .collect();
    let canonical = records.len() == public.vectors.len()
        && records
            .iter()
            .zip(&public.vectors)
            .all(|(&(o, n), (ordinal, codes))| {
                let bits = model.formats()[usize::from(o)].bits();
                o == *ordinal
                    && n == codes.len()
                    && codes
                        .iter()
                        .all(|&c| bits >= 16 || matches!(i32::from(c) >> (bits - 1), -1 | 0))
            });
    if !canonical {
        return Err(Error::StatementMismatch);
    }
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
/// RFC-0026 A11: the profile byte of a development proof on Circle Policy 2 sources.
/// `Expander` omits the byte, so pre-A11 inputs and proofs are unchanged; dev-zk
/// appends `1` (A9).
pub const CIRCLE_PROFILE: u8 = 2;
/// RFC-0026 A12: the profile byte of a development proof whose multiplicity sources
/// are Circle rate 1/4 too (`Sources::CircleAll`).
pub const CIRCLE_ALL_PROFILE: u8 = 3;
/// RFC-0026 A14 (Draft): the profile byte of a development proof on A12 sources whose
/// lookup `(β, α)` rounds grind (`Sources::CircleAllGrind`).
pub const GRIND_PROFILE: u8 = 5;
/// RFC-0026 A29 / RFC-0029: joined recursive openings (`Sources::CircleRecursive`).
pub const RECURSIVE_PROFILE: u8 = 6;
const STATEMENT_TAG: &[u8] = b"stele/v0.1/dev-e2e/statement";
const SEGMENTED_INPUT_TAG: &[u8] = b"stele/v0.1/dev-e2e/segmented";

/// Canonical RFC-0026 §1.1 public input (as amended by A2, A27), the transcript's first frame.
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
    match public.sources {
        Sources::Expander => {}
        Sources::Circle => out.push(CIRCLE_PROFILE),
        Sources::CircleAll => out.push(CIRCLE_ALL_PROFILE),
        Sources::CircleAllGrind => out.push(GRIND_PROFILE),
        Sources::CircleRecursive => out.push(RECURSIVE_PROFILE),
    }
    if public.segment_layers > 0 {
        out.extend_from_slice(SEGMENTED_INPUT_TAG);
        out.extend_from_slice(&public.segment_layers.to_le_bytes());
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

/// Declare the window and check the RFC-0026 §2.2 plan obligation. A dev-zk
/// window has one weight source (RFC-0013 A5 item 7), bound by its proof.
fn layout(d: &Decoded, public: &Public, statement: &Statement) -> Result<Layout, Error> {
    layout_for(d, public, statement, false)
}

fn layout_for(
    d: &Decoded,
    public: &Public,
    statement: &Statement,
    zk: bool,
) -> Result<Layout, Error> {
    if zk && public.segment_layers > 0 {
        return Err(Error::StatementMismatch);
    }
    let shape = d.model.shape();
    statement.validate(shape.vocabulary(), shape.context())?;
    let plan = PlanData {
        model: &d.model,
        scales: &d.scales,
        vectors: &public.vectors,
        zk,
        segment_layers: public.segment_layers,
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
    let sources = match zk {
        true => 1,
        false if public.sources == Sources::CircleRecursive => {
            relation::recursive_model_layout(&layout.relation)
                .map_err(Error::Engine)?
                .len()
        }
        false => relation::model_layout(&layout.relation, public.sources)
            .map_err(Error::Engine)?
            .len(),
    };
    if !same || public.commitment.len() != sources {
        return Err(Error::StatementMismatch);
    }
    Ok(layout)
}

const M31_P: u32 = (1u32 << 31) - 1;

#[inline]
fn m31_to_i64(v: M31) -> i64 {
    let u = v.as_u32();
    if u > M31_P / 2 {
        i64::from(u) - i64::from(M31_P)
    } else {
        i64::from(u)
    }
}

/// Location and logical dimensions of one weight role inside `Weights::stacked`.
struct RoleLayout {
    source: usize,
    offset: usize,
    rows: usize,
    lanes: usize,
}

enum WeightLayouts {
    Standard(Vec<relation::ModelLayout>),
    Recursive(Vec<relation::RecursiveModelLayout>),
}

/// Weight codes of an Artifact in plan order, and its public 1-D records.
/// Weight matrices are streamed directly into `stacked` (M31) without retaining
/// duplicate `i16`/`i64` copies, and decoded per role on demand (RFC-0026 A27, task E18-06).
pub struct Weights {
    pub vectors: Vec<(u16, Vec<i16>)>,
    /// The model sources and their stacked messages (RFC-0026 A5, A29).
    layouts: WeightLayouts,
    stacked: Vec<Vec<M31>>,
    roles: Vec<RoleLayout>,
    sources: Sources,
}

impl Weights {
    /// The weights under the default source set: every source Circle rate 1/4 under
    /// Policy 2 (RFC-0026 A12).
    pub fn from_artifact(model: &Model, artifact: &[u8]) -> Result<Self, Error> {
        Self::from_artifact_sources(model, artifact, Sources::CircleAll)
    }

    /// The source set the model commitment uses; [`Public::sources`] must equal it.
    pub fn sources(&self) -> Sources {
        self.sources
    }

    /// Decode one logical row `[0..lanes]` of weight role `index` from `stacked`.
    pub fn role_row(&self, index: usize, row: usize) -> Vec<i64> {
        let loc = &self.roles[index];
        let stride = loc.lanes.next_power_of_two();
        let start = loc.offset + row * stride;
        self.stacked[loc.source][start..start + loc.lanes]
            .iter()
            .map(|&v| m31_to_i64(v))
            .collect()
    }

    /// Decode logical `[rows][lanes]` `i64` codes of weight role `index` on demand.
    pub fn role_rows(&self, index: usize) -> Vec<Vec<i64>> {
        let loc = &self.roles[index];
        let stride = loc.lanes.next_power_of_two();
        (0..loc.rows)
            .map(|r| {
                let start = loc.offset + r * stride;
                self.stacked[loc.source][start..start + loc.lanes]
                    .iter()
                    .map(|&v| m31_to_i64(v))
                    .collect()
            })
            .collect()
    }

    /// Decode the padded `2^log_len` `i64` column of weight role `index` on demand.
    pub fn role_padded_i64(&self, index: usize, log_len: u8) -> Vec<i64> {
        let loc = &self.roles[index];
        let len = 1usize << log_len;
        self.stacked[loc.source][loc.offset..loc.offset + len]
            .iter()
            .map(|&v| m31_to_i64(v))
            .collect()
    }

    /// The weights under an explicit source set; `Expander` reproduces pre-A11 proofs
    /// and `Circle` A11 (profile byte 2) proofs.
    pub fn from_artifact_sources(
        model: &Model,
        artifact: &[u8],
        sources: Sources,
    ) -> Result<Self, Error> {
        let layout = ArtifactLayout::new(model).map_err(|_| Error::UnsupportedModel)?;
        let shape = model.shape();
        let mut vectors = Vec::new();
        // Record slices validated up front (payload bounds only; 2-D weights streamed below).
        struct RawRecord<'a> {
            role: Role,
            layer: Option<u16>,
            rows: usize,
            lanes: usize,
            bits: u8,
            elements: usize,
            raw: &'a [u8],
        }
        let mut matrices = Vec::new();
        for r in layout.records() {
            let start = usize::try_from(r.payload_offset()).map_err(|_| Error::Witness)?;
            let len = usize::try_from(r.payload_length()).map_err(|_| Error::Witness)?;
            let raw = artifact
                .get(start..start.checked_add(len).ok_or(Error::Witness)?)
                .ok_or(Error::Witness)?;
            let elements = usize::try_from(r.elements()).map_err(|_| Error::Witness)?;
            // Bytes the codes need: 2, 1 or 1/2 per element.
            let need = match r.bits() {
                16 => elements.checked_mul(2),
                8 => Some(elements),
                _ => Some(elements.div_ceil(2)),
            };
            if need.is_none_or(|n| raw.len() < n) {
                return Err(Error::Witness);
            }
            let physical = shape.physical(r.ordinal()).ok_or(Error::UnsupportedModel)?;
            let dims = physical.dimensions();
            if dims.len() == 1 {
                let codes: Vec<i16> = (0..elements)
                    .map(|i| match r.bits() {
                        16 => i16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]),
                        8 => i16::from(raw[i] as i8),
                        _ => {
                            let n = (raw[i / 2] >> (4 * (i % 2))) & 15;
                            i16::from(n) - if n >= 8 { 16 } else { 0 }
                        }
                    })
                    .collect();
                vectors.push((physical.ordinal(), codes));
            } else if dims.len() == 2 {
                matrices.push(RawRecord {
                    role: physical.role(),
                    layer: physical.layer(),
                    rows: dims[0] as usize,
                    lanes: dims[1] as usize,
                    bits: r.bits(),
                    elements,
                    raw,
                });
            }
        }
        let plan_roles = weight_roles(model);
        let mut matched: Vec<&RawRecord<'_>> = Vec::with_capacity(plan_roles.len());
        let mut lengths: Vec<u8> = Vec::with_capacity(plan_roles.len());
        for (role, layer) in plan_roles {
            let rec = matrices
                .iter()
                .find(|m| m.role == role && m.layer == layer)
                .ok_or(Error::UnsupportedModel)?;
            let padded = rec
                .rows
                .next_power_of_two()
                .checked_mul(rec.lanes.next_power_of_two())
                .ok_or(Error::UnsupportedModel)?;
            lengths.push(padded.trailing_zeros() as u8);
            matched.push(rec);
        }
        let layouts = if sources == Sources::CircleRecursive {
            WeightLayouts::Recursive(
                relation::recursive_model_layout_for(&lengths).map_err(Error::Engine)?,
            )
        } else {
            WeightLayouts::Standard(
                relation::model_layout_for(&lengths, sources).map_err(Error::Engine)?,
            )
        };
        let source_bits: Vec<u8> = match &layouts {
            WeightLayouts::Standard(ls) => ls.iter().map(|l| l.bits).collect(),
            WeightLayouts::Recursive(ls) => ls.iter().map(|l| l.bits).collect(),
        };
        let source_blocks: Vec<&[(usize, usize)]> = match &layouts {
            WeightLayouts::Standard(ls) => ls.iter().map(|l| l.blocks.as_slice()).collect(),
            WeightLayouts::Recursive(ls) => ls.iter().map(|l| l.blocks.as_slice()).collect(),
        };
        let mut stacked: Vec<Vec<M31>> = source_bits
            .iter()
            .map(|&bits| alloc::vec![M31::from_i64(0); 1 << bits])
            .collect();
        let mut roles: Vec<RoleLayout> = matched
            .iter()
            .map(|rec| RoleLayout {
                source: 0,
                offset: 0,
                rows: rec.rows,
                lanes: rec.lanes,
            })
            .collect();
        for (source_idx, blocks) in source_blocks.iter().enumerate() {
            for &(w, offset) in *blocks {
                let rec = matched[w];
                roles[w].source = source_idx;
                roles[w].offset = offset;
                let stride = rec.lanes.next_power_of_two();
                let target = &mut stacked[source_idx];
                for i in 0..rec.elements {
                    let v: i64 = match rec.bits {
                        16 => i64::from(i16::from_le_bytes([rec.raw[2 * i], rec.raw[2 * i + 1]])),
                        8 => i64::from(rec.raw[i] as i8),
                        _ => {
                            let n = (rec.raw[i / 2] >> (4 * (i % 2))) & 15;
                            i64::from(n) - if n >= 8 { 16 } else { 0 }
                        }
                    };
                    let row = i / rec.lanes;
                    let col = i % rec.lanes;
                    target[offset + row * stride + col] = M31::from_i64(v);
                }
            }
        }
        Ok(Self {
            vectors,
            layouts,
            stacked,
            roles,
            sources,
        })
    }
}

enum CommittedKind<'a> {
    Standard {
        prepared: Vec<PreparedSource<'a, K>>,
        certificates: Vec<VerifiedCertificate<K>>,
    },
    Recursive(Vec<relation::RecursiveModelSource<'a>>),
}

/// The prepared model commitment, built once per model (RFC-0026 §2.2, A29).
pub struct Committed<'a> {
    kind: CommittedKind<'a>,
    /// `(root, certificate)` per source, for [`Public::commitment`].
    pub commitment: Vec<([u8; 32], Vec<u8>)>,
}

impl<'a> Committed<'a> {
    pub fn new(weights: &'a Weights) -> Result<Self, Error> {
        match &weights.layouts {
            WeightLayouts::Standard(layouts) => {
                let mut prepared = Vec::new();
                let mut certificates = Vec::new();
                let mut commitment = Vec::new();
                for (layout, message) in layouts.iter().zip(&weights.stacked) {
                    let p = layout
                        .sources
                        .prepare(layout.id, layout.ell, &layout.code, message)
                        .map_err(|e| match e {
                            relation::Error::Pcs(e) => Error::Commitment(e),
                            e => Error::Engine(e),
                        })?;
                    let (bytes, _) = p.certificate().map_err(|_| {
                        Error::Commitment(stele_reductions::stele_pcs::Error::Capacity)
                    })?;
                    let (verified, _) = verify_certificate(*p.source(), &bytes)
                        .map_err(|f| Error::Commitment(f.cause))?;
                    commitment.push((p.source().root(), bytes));
                    certificates.push(verified);
                    prepared.push(p);
                }
                Ok(Self {
                    kind: CommittedKind::Standard {
                        prepared,
                        certificates,
                    },
                    commitment,
                })
            }
            WeightLayouts::Recursive(layouts) => {
                let mut sources = Vec::with_capacity(layouts.len());
                let mut commitment = Vec::with_capacity(layouts.len());
                for (layout, message) in layouts.iter().zip(&weights.stacked) {
                    let src = relation::RecursiveModelSource::register(layout, message)
                        .map_err(Error::Engine)?;
                    commitment.push((
                        src.prepared.source().root(),
                        src.prepared.certificate_proof().to_vec(),
                    ));
                    sources.push(src);
                }
                Ok(Self {
                    kind: CommittedKind::Recursive(sources),
                    commitment,
                })
            }
        }
    }
}

/// Verify every model-commitment certificate against its plan-derived model source.
fn certificates(public: &Public, bits: &[u8]) -> Result<Vec<VerifiedCertificate<K>>, Error> {
    let layouts = relation::model_layout_for(bits, public.sources).map_err(Error::Engine)?;
    if layouts.len() != public.commitment.len() {
        return Err(Error::StatementMismatch);
    }
    public
        .commitment
        .iter()
        .zip(&layouts)
        .map(|((root, bytes), l)| {
            let source = l
                .sources
                .source(l.id, l.ell, &l.code, *root)
                .map_err(|e| match e {
                    relation::Error::Pcs(e) => Error::Commitment(e),
                    e => Error::Engine(e),
                })?;
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

fn sections_v2(proof: ProofV2, cqis_id: [u8; 32], statement: [u8; 32]) -> ContainerV2 {
    ContainerV2 {
        cqis_id,
        statement,
        segments: proof
            .segments
            .into_iter()
            .map(|s| SegmentSections {
                groups: s.groups,
                multiplicities: s.multiplicities,
                identities: s.identities,
                lookups: s.lookups,
                matmuls: s.matmuls,
                reductions: s.reductions,
                openings: s.openings,
            })
            .collect(),
        model_openings: proof.model_openings,
    }
}

/// Stage timings (nanoseconds, behind `std`) and thread-count-independent counters for
/// one development proof (RFC-0018 A2, task E17-01).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// In-process model commitment (Artifact weight decode + PCS commit) nanoseconds.
    pub model_commitment_ns: u64,
    /// Witness preparation (executor init, greedy extension, capture, layout, assign) nanoseconds.
    pub witness_ns: u64,
    /// Plain-checker (`stele_ir::relation::check`) nanoseconds; runs beside the engine under `std`.
    pub plain_check_ns: u64,
    /// Relation-engine stage timings and deterministic counters.
    pub engine: relation::Metrics,
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
    prove_inner(public, executor, weights, committed, statement, None).map(|(proof, _)| proof)
}

/// [`prove`] together with in-process stage timings and deterministic counters
/// (RFC-0018 A2, task E17-01). Proof bytes are identical to [`prove`].
pub fn prove_measured(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
) -> Result<(Vec<u8>, Report), Error> {
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
    prove_inner(public, executor, weights, committed, statement, Some(hook)).map(|(proof, _)| proof)
}

fn prove_inner(
    public: &Public,
    executor: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    hook: Option<Hook<'_>>,
) -> Result<(Vec<u8>, Report), Error> {
    let witness_capture_timer = relation::Stopwatch::start();
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    let capture_ns = witness_capture_timer.elapsed_ns();
    let (proof, mut report) =
        prove_inner_captured(public, &capture, weights, committed, statement, hook)?;
    report.witness_ns = report.witness_ns.saturating_add(capture_ns);
    Ok((proof, report))
}

fn prove_inner_captured(
    public: &Public,
    capture: &Capture,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    hook: Option<Hook<'_>>,
) -> Result<(Vec<u8>, Report), Error> {
    // E16-22: stage timing, off unless STELE_STAGE_TIMES.
    let mut laps = parallel::Laps::start();
    let witness_timer = relation::Stopwatch::start();
    let d = decode(public)?;
    let mut layout = layout(&d, public, statement)?;
    let checked = hook.is_none();
    let input = public_input(public, &d.cqis_id, statement);
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;

    if public.sources == Sources::CircleRecursive {
        let CommittedKind::Recursive(rec_model) = &committed.kind else {
            return Err(Error::StatementMismatch);
        };
        if public.segment_layers > 0 {
            if hook.is_some() {
                return Err(Error::StatementMismatch);
            }
            let mut witness_ns = witness_timer.elapsed_ns();
            let mut plain_check_ns = 0u64;
            let mut carried: Option<Vec<i64>> = None;
            let mut callback_err: Option<Error> = None;
            let res = relation::prove_recursive_measured(
                &mut t,
                &layout.relation,
                |seg| {
                    let assign_timer = relation::Stopwatch::start();
                    let (values, next_carried) =
                        match layout.assign_segment(seg, capture, weights, carried.take()) {
                            Ok(pair) => pair,
                            Err(err) => {
                                callback_err = Some(err);
                                return Err(relation::Error::Unsupported);
                            }
                        };
                    witness_ns = witness_ns.saturating_add(assign_timer.elapsed_ns());
                    carried = next_carried;
                    if checked {
                        let check_timer = relation::Stopwatch::start();
                        if let Err(v) = check_segment(&layout.relation, seg, &values) {
                            callback_err = Some(Error::Check(v));
                            return Err(relation::Error::Unsupported);
                        }
                        plain_check_ns = plain_check_ns.saturating_add(check_timer.elapsed_ns());
                    }
                    Ok(values)
                },
                rec_model,
            );
            if let Some(err) = callback_err {
                return Err(err);
            }
            let (proof, engine) = res.map_err(Error::Engine)?;
            let digest = statement_digest(&input, &relation::digest(&layout.relation));
            let report = Report {
                model_commitment_ns: 0,
                witness_ns,
                plain_check_ns,
                engine,
            };
            return Ok((sections_v2(proof, d.cqis_id, digest).encode(), report));
        }

        let mut values = layout.assign(capture, weights)?;
        let witness_ns = witness_timer.elapsed_ns();
        laps.lap("witness/layout_capture_assign");
        if let Some(hook) = hook {
            hook(&mut layout.relation, &mut values);
        }
        let mut plain_check_ns = 0u64;
        if checked {
            let check_timer = relation::Stopwatch::start();
            check(&layout.relation, &values).map_err(Error::Check)?;
            plain_check_ns = check_timer.elapsed_ns();
        }
        let mut single = Some(values);
        let (proof, engine) = relation::prove_recursive_measured(
            &mut t,
            &layout.relation,
            |seg| {
                if seg == 0 {
                    single.take().ok_or(relation::Error::Unsupported)
                } else {
                    Err(relation::Error::Unsupported)
                }
            },
            rec_model,
        )
        .map_err(Error::Engine)?;
        let digest = statement_digest(&input, &relation::digest(&layout.relation));
        let report = Report {
            model_commitment_ns: 0,
            witness_ns,
            plain_check_ns,
            engine,
        };
        return Ok((sections_v2(proof, d.cqis_id, digest).encode(), report));
    }

    let CommittedKind::Standard {
        prepared,
        certificates,
    } = &committed.kind
    else {
        return Err(Error::StatementMismatch);
    };
    let model = prepared.iter().zip(certificates).collect::<Vec<_>>();

    if public.segment_layers > 0 {
        if hook.is_some() {
            return Err(Error::StatementMismatch);
        }
        let mut witness_ns = witness_timer.elapsed_ns();
        let mut plain_check_ns = 0u64;
        let mut carried: Option<Vec<i64>> = None;
        let mut callback_err: Option<Error> = None;
        let res = relation::prove_segmented_measured(
            &mut t,
            &layout.relation,
            |seg| {
                let assign_timer = relation::Stopwatch::start();
                let (values, next_carried) =
                    match layout.assign_segment(seg, capture, weights, carried.take()) {
                        Ok(pair) => pair,
                        Err(err) => {
                            callback_err = Some(err);
                            return Err(relation::Error::Unsupported);
                        }
                    };
                witness_ns = witness_ns.saturating_add(assign_timer.elapsed_ns());
                carried = next_carried;
                if checked {
                    let check_timer = relation::Stopwatch::start();
                    if let Err(v) = check_segment(&layout.relation, seg, &values) {
                        callback_err = Some(Error::Check(v));
                        return Err(relation::Error::Unsupported);
                    }
                    plain_check_ns = plain_check_ns.saturating_add(check_timer.elapsed_ns());
                }
                Ok(values)
            },
            &model,
            public.sources,
        );
        if let Some(err) = callback_err {
            return Err(err);
        }
        let (proof, engine) = res.map_err(Error::Engine)?;
        let digest = statement_digest(&input, &relation::digest(&layout.relation));
        let report = Report {
            model_commitment_ns: 0,
            witness_ns,
            plain_check_ns,
            engine,
        };
        return Ok((sections_v2(proof, d.cqis_id, digest).encode(), report));
    }

    let mut values = layout.assign(capture, weights)?;
    let witness_ns = witness_timer.elapsed_ns();
    laps.lap("witness/layout_capture_assign");
    if let Some(hook) = hook {
        hook(&mut layout.relation, &mut values);
    }
    if layout.relation.has_virtual() {
        let mut plain_check_ns = 0u64;
        if checked {
            let check_timer = relation::Stopwatch::start();
            check(&layout.relation, &values).map_err(Error::Check)?;
            plain_check_ns = check_timer.elapsed_ns();
        }
        let mut single = Some(values);
        let (proof, engine) = relation::prove_segmented_measured(
            &mut t,
            &layout.relation,
            |seg| {
                if seg == 0 {
                    single.take().ok_or(relation::Error::Unsupported)
                } else {
                    Err(relation::Error::Unsupported)
                }
            },
            &model,
            public.sources,
        )
        .map_err(Error::Engine)?;
        let digest = statement_digest(&input, &relation::digest(&layout.relation));
        let report = Report {
            model_commitment_ns: 0,
            witness_ns,
            plain_check_ns,
            engine,
        };
        return Ok((sections_v2(proof, d.cqis_id, digest).encode(), report));
    }
    // The plain checker runs beside the engine and decides: a false witness fails
    // with `Check` even if the engine errs or panics on it (E16-23).
    let mut plain_check_ns = 0u64;
    let (proof, engine) = parallel::gated(
        || {
            let mut laps = parallel::Laps::start();
            let check_timer = relation::Stopwatch::start();
            let result = if checked {
                check(&layout.relation, &values).map_err(Error::Check)
            } else {
                Ok(())
            };
            plain_check_ns = check_timer.elapsed_ns();
            laps.lap("dev/plain_check (beside the engine)");
            result
        },
        || relation::prove_measured(&mut t, &layout.relation, &values, &model, public.sources),
    )?
    .map_err(Error::Engine)?;
    laps.lap("dev/check_and_engine");
    let digest = statement_digest(&input, &relation::digest(&layout.relation));
    let report = Report {
        model_commitment_ns: 0,
        witness_ns,
        plain_check_ns,
        engine,
    };
    Ok((sections(proof, d.cqis_id, digest).encode(), report))
}

/// The statement digest the verifier derives for `(public, statement)`, the value an
/// honest container carries. Controls use it to restamp a container so that a tamper
/// must be rejected by the engine, not by this prover-written header field.
pub fn statement_digest_for(public: &Public, statement: &Statement) -> Result<[u8; 32], Error> {
    let d = decode(public)?;
    let layout = layout(&d, public, statement)?;
    let input = public_input(public, &d.cqis_id, statement);
    Ok(statement_digest(
        &input,
        &relation::digest(&layout.relation),
    ))
}

/// What a verifier must compare with trusted values, since a self-consistent
/// [`Public`] proves only that some model ran: the `cqis_id` and the model digest,
/// BLAKE3 of `stele/v0.1/dev-e2e/model`, `cqis_id`, the weight roots in plan order and
/// the 1-D records (ordinal, length, int16 codes) in record order.
pub fn model_identity(public: &Public) -> Result<([u8; 32], [u8; 32]), Error> {
    let d = decode(public)?;
    let mut h = blake3::Hasher::new();
    h.update(MODEL_TAG);
    h.update(&d.cqis_id);
    h.update(&(public.commitment.len() as u32).to_le_bytes());
    for (root, _) in &public.commitment {
        h.update(root);
    }
    h.update(&(public.vectors.len() as u32).to_le_bytes());
    for (ordinal, codes) in &public.vectors {
        h.update(&ordinal.to_le_bytes());
        h.update(&(codes.len() as u32).to_le_bytes());
        for c in codes {
            h.update(&c.to_le_bytes());
        }
    }
    Ok((d.cqis_id, *h.finalize().as_bytes()))
}

const MODEL_TAG: &[u8] = b"stele/v0.1/dev-e2e/model";

/// Verify one window (RFC-0026 §8, A26, A27) and return its ledger.
pub fn verify(public: &Public, statement: &Statement, proof: &[u8]) -> Result<Ledger, Error> {
    let decoded = container::decode_any(proof).map_err(Error::Container)?;
    let d = decode(public)?;
    if decoded.cqis_id() != d.cqis_id {
        return Err(Error::StatementMismatch);
    }
    let layout = layout(&d, public, statement)?;
    let expected_v2 = public.segment_layers > 0
        || layout.relation.has_virtual()
        || public.sources == Sources::CircleRecursive;
    if expected_v2 != matches!(decoded, container::Decoded::V2(_)) {
        return Err(Error::StatementMismatch);
    }
    layout
        .relation
        .validate()
        .map_err(|_| Error::StatementMismatch)?;
    let input = public_input(public, &d.cqis_id, statement);
    // Fail fast only: the prover writes both header fields. The binding is the
    // transcript, which absorbs `input` and the relation digest (RFC-0026 §4 step 1).
    if decoded.statement() != statement_digest(&input, &relation::digest(&layout.relation)) {
        return Err(Error::StatementMismatch);
    }
    let bits: Vec<u8> = layout
        .weights
        .iter()
        .map(|(id, _, _)| layout.relation.columns[id.0 as usize].log_len)
        .collect();
    let mut t = Transcript::<K>::new(&input).map_err(|e| Error::Engine(e.into()))?;
    if public.sources == Sources::CircleRecursive {
        let container::Decoded::V2(c) = decoded else {
            return Err(Error::StatementMismatch);
        };
        let layouts = relation::recursive_model_layout_for(&bits).map_err(Error::Engine)?;
        if layouts.len() != public.commitment.len() {
            return Err(Error::StatementMismatch);
        }
        let verified_models: Vec<_> = public
            .commitment
            .iter()
            .zip(&layouts)
            .map(|((root, bytes), l)| relation::verify_recursive_model(l, *root, bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::Engine)?;
        let sections = ProofV2 {
            segments: c
                .segments
                .into_iter()
                .map(|s| SegmentProof {
                    groups: s.groups,
                    multiplicities: s.multiplicities,
                    identities: s.identities,
                    lookups: s.lookups,
                    matmuls: s.matmuls,
                    reductions: s.reductions,
                    openings: s.openings,
                })
                .collect(),
            model_openings: c.model_openings,
        };
        return relation::verify_recursive(&mut t, &layout.relation, &verified_models, &sections)
            .map_err(Error::Engine);
    }
    let certs = certificates(public, &bits)?;
    // The engine derives every section count and length (RFC-0026 §4.1, A27).
    match decoded {
        container::Decoded::V1(c) => {
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
                public.sources,
            )
            .map_err(Error::Engine)
        }
        container::Decoded::V2(c) => {
            let sections = ProofV2 {
                segments: c
                    .segments
                    .into_iter()
                    .map(|s| SegmentProof {
                        groups: s.groups,
                        multiplicities: s.multiplicities,
                        identities: s.identities,
                        lookups: s.lookups,
                        matmuls: s.matmuls,
                        reductions: s.reductions,
                        openings: s.openings,
                    })
                    .collect(),
                model_openings: c.model_openings,
            };
            relation::verify_segmented(
                &mut t,
                &layout.relation,
                &certs.iter().collect::<Vec<_>>(),
                &sections,
                public.sources,
            )
            .map_err(Error::Engine)
        }
    }
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
    statement: Statement,
    length: usize,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    prove_window_profile(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        None,
    )
}

/// [`prove_window`] under dev-zk when `zk` holds the proof's seed (RFC-0013 A5
/// item 8: the caller draws it from the OS RNG); the model is then committed by
/// the proof's hiding weight source, for this proof only.
pub fn prove_window_profile(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    zk: Option<zk::Window<'_>>,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    prove_window_sources(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        zk,
        Sources::CircleAll,
        None,
    )
}

/// Prove a balanced development-ZK window with RFC-0014 A2 ordinary batch execution.
#[allow(clippy::too_many_arguments)]
pub fn prove_window_with_backend(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    window: zk::Window<'_>,
    backend: zk::BatchExecution<'_, K>,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    if !matches!(&window, zk::Window::Prove { commitment, .. } if commitment.profile == zk::PROFILE_BALANCED)
    {
        return Err(Error::StatementMismatch);
    }
    prove_window_sources(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        Some(window),
        Sources::CircleAll,
        Some(backend),
    )
}

/// [`prove_window_profile`] for a development proof under `profile`:
/// [`CIRCLE_ALL_PROFILE`] (A12) or [`GRIND_PROFILE`] (A14). Any other byte is
/// `StatementMismatch`.
pub fn prove_window_development(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    profile: u8,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    prove_window_development_measured(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        profile,
    )
    .map(|(public, statement, proof, _)| (public, statement, proof))
}

/// [`prove_window_development`] together with in-process stage timings (including
/// separate `model_commitment_ns`) and deterministic counters (RFC-0018 A2, task E17-01).
pub fn prove_window_development_measured(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    profile: u8,
) -> Result<(Public, Statement, Vec<u8>, Report), Error> {
    prove_window_development_segmented_measured(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        profile,
        0,
    )
}

/// [`prove_window_development_measured`] with an explicit segment size in layers (`0` = v1
/// unsegmented; `> 0` = RFC-0026 A27 segmented `stele-dev-e2e-v2` proof).
#[allow(clippy::too_many_arguments)]
pub fn prove_window_development_segmented_measured(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    profile: u8,
    segment_layers: u16,
) -> Result<(Public, Statement, Vec<u8>, Report), Error> {
    let sources = match profile {
        CIRCLE_ALL_PROFILE => Sources::CircleAll,
        GRIND_PROFILE => Sources::CircleAllGrind,
        RECURSIVE_PROFILE => Sources::CircleRecursive,
        _ => return Err(Error::StatementMismatch),
    };
    prove_window_sources_measured(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        None,
        sources,
        None,
        segment_layers,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_window_sources(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    statement: Statement,
    length: usize,
    zk: Option<zk::Window<'_>>,
    sources: Sources,
    execution: Option<zk::BatchExecution<'_, K>>,
) -> Result<(Public, Statement, Vec<u8>), Error> {
    prove_window_sources_measured(
        model,
        preparation,
        scales,
        artifact,
        statement,
        length,
        zk,
        sources,
        execution,
        0,
    )
    .map(|(public, statement, proof, _)| (public, statement, proof))
}

#[allow(clippy::too_many_arguments)]
fn prove_window_sources_measured(
    model: &[u8],
    preparation: &[u8],
    scales: &[u8],
    artifact: &[u8],
    mut statement: Statement,
    length: usize,
    zk: Option<zk::Window<'_>>,
    sources: Sources,
    execution: Option<zk::BatchExecution<'_, K>>,
    segment_layers: u16,
) -> Result<(Public, Statement, Vec<u8>, Report), Error> {
    let m = Model::decode(model).map_err(|_| Error::StatementMismatch)?;
    let p = stele_reductions::stele_cqis::model::Preparation::decode(&m, preparation)
        .map_err(|_| Error::StatementMismatch)?;
    let s = Scales::decode(&m, scales).map_err(|_| Error::StatementMismatch)?;
    let id = artifact_id(artifact);
    // E16-22: stage timing, off unless STELE_STAGE_TIMES.
    let mut laps = parallel::Laps::start();
    let witness_pre_timer = relation::Stopwatch::start();
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
    if let Some(window) = zk {
        if segment_layers > 0 {
            return Err(Error::StatementMismatch);
        }
        let weights = Weights::from_artifact_sources(&m, artifact, sources)?;
        laps.lap("witness/decode_extend_weights");
        // E12-27: the 1-D records are committed weights; the public input names
        // only their shapes.
        let mut public = Public {
            model: model.to_vec(),
            scales: scales.to_vec(),
            preparation: preparation.to_vec(),
            vectors: zk::published(model, &weights.vectors)?,
            commitment: Vec::new(),
            sources: Sources::Expander,
            segment_layers: 0,
        };
        let proof = match window {
            zk::Window::Commit {
                proofs,
                seed,
                profile,
                out,
            } => {
                let (c, state) = zk::commit(
                    &public,
                    &mut executor,
                    &weights,
                    length,
                    proofs,
                    seed,
                    profile,
                )?;
                public.commitment = alloc::vec![(c.root, Vec::new())];
                *out = Some((c, state));
                Vec::new()
            }
            zk::Window::Prove {
                seed,
                commitment,
                state,
                persist,
                index,
            } => {
                public.commitment = alloc::vec![(commitment.root, Vec::new())];
                let (proof, i) = zk::prove_next_execution(
                    &public,
                    &mut executor,
                    &weights,
                    &statement,
                    seed,
                    commitment,
                    state,
                    persist,
                    execution,
                )?;
                *index = i;
                proof
            }
        };
        return Ok((public, statement, proof, Report::default()));
    }
    // Capture before dropping the executor so its weight buffers never overlap
    // with `Weights::stacked` and `Committed::prepared` (task E18-06).
    let capture = executor
        .capture(&statement.tokens)
        .map_err(|_| Error::Witness)?;
    drop(executor);
    let witness_pre_ns = witness_pre_timer.elapsed_ns();
    // E17-01: model commitment (Artifact weight decode + PCS commit) timed in process.
    let model_commit_timer = relation::Stopwatch::start();
    let weights = Weights::from_artifact_sources(&m, artifact, sources)?;
    laps.lap("witness/decode_extend_weights");
    let committed = Committed::new(&weights)?;
    let model_commitment_ns = model_commit_timer.elapsed_ns();
    laps.lap("dev/model_sources");
    let public = Public {
        model: model.to_vec(),
        scales: scales.to_vec(),
        preparation: preparation.to_vec(),
        vectors: weights.vectors.clone(),
        commitment: committed.commitment.clone(),
        sources: weights.sources,
        segment_layers,
    };
    let (proof, mut report) =
        prove_inner_captured(&public, &capture, &weights, &committed, &statement, None)?;
    report.model_commitment_ns = model_commitment_ns;
    report.witness_ns = report.witness_ns.saturating_add(witness_pre_ns);
    Ok((public, statement, proof, report))
}

/// The Artifact identity the executor expects: BLAKE3 of its canonical bytes.
pub fn artifact_id(artifact: &[u8]) -> [u8; 32] {
    *blake3::hash(artifact).as_bytes()
}
