//! Development-profile relation engine, RFC-0026 §§2-4, §6, §8.
//!
//! [`prove`] and [`verify`] run the RFC-0026 §4 transcript order on any validated
//! [`Relation`]: group roots, multiplicity roots, one zerocheck per identity domain
//! size, one A5 lookup per table or range width (A3), one sumcheck per matmul, then one claim
//! batch and one point opening per group and weight source. The verifier derives
//! every size, source, identity and lookup statement from the relation alone; proof
//! bytes carry only messages. QM31 challenges throughout (RFC-0026 §1.2).
//!
//! Variable order: a column or domain point is MSB-first (RFC-0005 §2), so column
//! bit `j` of a `Ref` sits at coordinate `n-1-j` and reads domain coordinate
//! `m-1-vars[j]`. A group source puts the column index in the high (leading) bits.
use crate::lookup::{mu_source, Layout};
#[cfg(feature = "std")]
extern crate std;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use stele_field::{Field, Serialize, M31, QM31};
use stele_hash::{AbsorbLabel, ChallengeLabel, HashUsage, Transcript};
use stele_ir::relation::{
    ColumnId, Identity, Invalid, Kind, Ref, Relation, Term as IdentityTerm, Values,
};
use stele_pcs::{
    verify_certificate, verify_point, PreparedSource, ProofKind, Source, VerifiedCertificate,
};
use stele_sumcheck::{claim_batch, parallel, zerocheck, Dense, Instance, Term};

#[path = "relation_codec.rs"]
mod codec;
#[path = "relation_lookup.rs"]
mod lookup;
pub use codec::{digest, encode};

/// The development profile's challenge field (RFC-0026 §1.2).
pub type K = QM31;

/// A rejected relation, witness or proof; the whole attempt is discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The relation fails `Relation::validate` (RFC-0026 §8 step 2).
    StatementMismatch(Invalid),
    /// Valid relation outside what the engine proves (lookup arity/rows, source size).
    Unsupported,
    /// The prover has no values for a witness or weight column.
    Missing(ColumnId),
    /// The model commitment is missing, unexpected, or not the derived layout (A5).
    Weights,
    /// Wrong proof length or trailing bytes.
    ProofShape,
    /// A field element in the proof is not canonical.
    NoncanonicalField,
    /// A zerocheck, matmul sumcheck or claim batch rejected.
    Sumcheck(stele_sumcheck::Error),
    /// An A3 tree, root equation or selected product rejected.
    Fraction(stele_lookup::fraction::Error),
    /// An A5 table-denominator or multiplicity-piece check rejected.
    Lookup(crate::lookup::Error),
    /// A certificate or opening rejected.
    Pcs(stele_pcs::Error),
    /// A batched lookup's member evaluations do not sum to its tuple claim (A3).
    MemberSumMismatch,
    /// A matmul's shared-bit equality factor disagrees with eq(ρ, r).
    EqMismatch,
    /// A public column claim disagrees with the public values.
    PublicMismatch(ColumnId),
    /// Allocation or size overflow.
    Capacity,
    /// Transcript failure.
    Transcript(stele_hash::Error),
}
impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Self::Transcript(e)
    }
}
impl From<stele_sumcheck::Error> for Error {
    fn from(e: stele_sumcheck::Error) -> Self {
        Self::Sumcheck(e)
    }
}

/// RFC-0012 line of one ledger entry (RFC-0026 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    Rlc,
    Sc,
    Sz,
    Lu,
    /// dev-zk only: a lookup leaf's zero denominator (RFC-0008 A7, E12-19 notes).
    Zd,
    /// dev-zk only: a masked sumcheck's `α` (RFC-0013 A2/A4).
    Mask,
}
/// One interactive error term `numerator / |K|`, `|K| = p^4`. `round` is the
/// numerator of its largest single Fiat–Shamir round (RFC-0012 A17 item 3: a maximal
/// run of challenges with no absorb between them): a sumcheck record's degree, a
/// zerocheck's `τ` run, and the whole draw for the other lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub line: Line,
    pub name: String,
    pub numerator: u64,
    pub round: u64,
    /// Grinding bits of each of its rounds: an A14 LU round's `k_LU`, else 0.
    pub grind: u8,
}
/// One PCS round of a source (E8-05c): a certificate's tensor round
/// `2·ell·(e + 1)/|K|` before `2^k_t`, or a certificate or opening column round at
/// its policy's query target (Policy 1: `2^-130`, RFC-0010 A3 item 4; Policy 2:
/// `2^-92`, A14 item 2) before `2^k_q`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsRound {
    pub name: String,
    /// `Some(2·ell·(e + 1))` for a tensor round; `None` for a column round.
    pub tensor: Option<u64>,
    /// `−log2` of a column round's target (130 or 92); unused for a tensor round.
    pub target: u32,
    pub grind: u8,
}
/// Accepted-proof ledger. Interactive terms only: FS unproven (Q12), PCS conjectural.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub entries: Vec<Entry>,
    /// Sources opened (groups and weights) plus multiplicity sources; PCS lines per
    /// RFC-0012 A15 are conjectural and not summed.
    pub pcs_sources: usize,
    /// Every PCS round of the proof's certificates and openings, model sources
    /// included (E8-05c).
    pub pcs: Vec<PcsRound>,
    /// RFC-0012 A7's setup term applies: a v2 J ≥ 4 source is present.
    pub setup: bool,
}
/// The error of one enumerated round (E8-05c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundError {
    /// `numerator / |K|`.
    Field(u64),
    /// `2^-bits`.
    Pow2(u32),
}
/// One Fiat–Shamir round of a development proof (RFC-0012 A17 item 3, E8-05c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    /// `SC`, `RLC`, `SZ`, `LU`, `PCS tensor` or `PCS column`.
    pub line: &'static str,
    pub name: String,
    pub error: RoundError,
    pub grind: u8,
}
impl Ledger {
    fn add(&mut self, line: Line, name: &str, numerator: u64, round: u64) {
        self.entries.push(Entry {
            line,
            name: name.into(),
            numerator,
            round,
            grind: 0,
        });
    }
    /// A certificate's tensor and column rounds under `source`'s parameters.
    fn certificate(&mut self, name: &str, source: &Source<K>) {
        let p = source.parameters();
        self.setup |= p.setup_term;
        let ell = source.rows().trailing_zeros() as u64;
        self.pcs.push(PcsRound {
            name: name.into(),
            tensor: Some(2 * ell * (p.radius + 1)),
            target: 0,
            grind: p.tensor_grind_bits,
        });
        self.opening(name, source);
    }
    /// One column round under `source`'s parameters.
    fn opening(&mut self, name: &str, source: &Source<K>) {
        let p = source.parameters();
        self.pcs.push(PcsRound {
            name: name.into(),
            tensor: None,
            target: match p.policy {
                stele_pcs::Policy::One => 130,
                _ => 92,
            },
            grind: p.column_grind_bits,
        });
    }
    /// `ε_interactive · |K|`: the sum of every non-FS, non-PCS numerator.
    pub fn interactive(&self) -> u64 {
        self.entries.iter().map(|e| e.numerator).sum()
    }
    /// Every round of the proof, in ledger order (E8-05c). An entry of numerator `n`
    /// whose largest round is `r` becomes `⌊n/r⌋` rounds of `r` and one of the
    /// remainder: its largest round and its sum are exact, which is all (C1) and (C2)
    /// read. Only an A14 LU round grinds.
    pub fn rounds(&self) -> Vec<Round> {
        let mut out = Vec::new();
        for e in &self.entries {
            let line = match e.line {
                Line::Sc => "SC",
                Line::Rlc => "RLC",
                Line::Sz => "SZ",
                Line::Lu | Line::Zd => "LU",
                Line::Mask => "MASK",
            };
            let r = e.round.clamp(1, e.numerator.max(1));
            let (full, rest) = (e.numerator / r, e.numerator % r);
            for numerator in
                core::iter::repeat_n(r, full as usize).chain((rest > 0).then_some(rest))
            {
                out.push(Round {
                    line,
                    name: e.name.clone(),
                    error: RoundError::Field(numerator),
                    grind: e.grind,
                });
            }
        }
        for p in &self.pcs {
            out.push(Round {
                line: if p.tensor.is_some() {
                    "PCS tensor"
                } else {
                    "PCS column"
                },
                name: p.name.clone(),
                error: match p.tensor {
                    Some(n) => RoundError::Field(n),
                    None => RoundError::Pow2(p.target),
                },
                grind: p.grind,
            });
        }
        out
    }
    /// The round with the largest error after grinding (the first on ties), and
    /// its security in 1/1024 bits, rounded down.
    pub fn worst(&self) -> Option<(Round, u64)> {
        self.rounds()
            .into_iter()
            .map(|r| {
                let b = round_bits(&r);
                (r, b)
            })
            .fold(None, |w, (r, b)| match w {
                Some((w, wb)) if wb <= b => Some((w, wb)),
                _ => Some((r, b)),
            })
    }
    /// `−log2` of the floor `Σ ε_i·2^-k_i` over every round, in 1/1024 bits, rounded
    /// down. `|K| = p^4` is replaced by `2^124`, which understates each error by a
    /// factor below `1 + 2^-28`. That is far below the 1/1024-bit resolution, and the
    /// rounding absorbs it except at an exact tie; (C1)–(C4) are decided exactly by
    /// `stele_verifier::accounting::admit`, not by these printed values.
    pub fn floor_bits(&self) -> u64 {
        // Common denominator 2^(124 + 32): k ≤ 32 and column targets ≤ 156.
        let sum: u128 = self
            .rounds()
            .iter()
            .map(|r| match r.error {
                RoundError::Field(n) => u128::from(n) << (32 - u32::from(r.grind)),
                RoundError::Pow2(c) => 1u128 << (156 - c - u32::from(r.grind)),
            })
            .sum();
        (1024 * 156u64).saturating_sub(log2_1024(sum) + 1)
    }
}
/// `−log2` of one round's error after grinding, in 1/1024 bits, rounded down, with
/// `2^124` for `p^4` as in [`Ledger::floor_bits`] (display only).
fn round_bits(r: &Round) -> u64 {
    let k = u64::from(r.grind);
    match r.error {
        RoundError::Field(n) => (1024 * (124 + k)).saturating_sub(log2_1024(u128::from(n)) + 1),
        RoundError::Pow2(c) => 1024 * (u64::from(c) + k),
    }
}
/// `⌊1024·log2 n⌋` for `n ≥ 1` (`n = 0` reads as 1), by repeated squaring of a
/// Q62 mantissa.
fn log2_1024(n: u128) -> u64 {
    let n = n.max(1);
    let i = u64::from(127 - n.leading_zeros());
    let mut y = if i >= 62 {
        n >> (i - 62)
    } else {
        n << (62 - i)
    };
    let mut fraction = 0;
    for _ in 0..10 {
        y = (y * y) >> 62;
        fraction <<= 1;
        if y >= 2u128 << 62 {
            y >>= 1;
            fraction |= 1;
        }
    }
    1024 * i + fraction
}
impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in &self.entries {
            writeln!(f, "{:?}\t{}\t{}/|K|", e.line, e.name, e.numerator)?;
        }
        writeln!(
            f,
            "PCS\t{} sources\tconjectural (RFC-0012 A15)",
            self.pcs_sources
        )?;
        write!(
            f,
            "eps_interactive <= {}/p^4; FS unproven, PCS conjectural",
            self.interactive()
        )
    }
}

/// Proof sections in RFC-0026 §4.1 order. Each inner `Vec<u8>` is one section's
/// canonical bytes; the `stele-dev-e2e-v1` container frames each with its length.
/// [`verify`] derives every section count and length and rejects any other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    /// Per group: root then certificate.
    pub groups: Vec<Vec<u8>>,
    /// Per lookup/range: multiplicity root then certificate.
    pub multiplicities: Vec<Vec<u8>>,
    /// Per identity domain size: zerocheck rounds then finals.
    pub identities: Vec<Vec<u8>>,
    /// Per lookup/range: A5 trees, selected product, pieces and piece openings.
    pub lookups: Vec<Vec<u8>>,
    /// Per matmul: `out~(ρ)`, rounds, finals.
    pub matmuls: Vec<Vec<u8>>,
    /// Per opened source: claim-batch rounds, final value, opening.
    pub openings: Vec<Vec<u8>>,
}

/// Per-segment sections of a segmented development proof (`stele-dev-e2e-v2`, RFC-0026 A26, A27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SegmentProof {
    pub groups: Vec<Vec<u8>>,
    pub multiplicities: Vec<Vec<u8>>,
    pub identities: Vec<Vec<u8>>,
    pub lookups: Vec<Vec<u8>>,
    pub matmuls: Vec<Vec<u8>>,
    pub reductions: Vec<Vec<u8>>,
    pub openings: Vec<Vec<u8>>,
}

/// Segmented proof sections (`stele-dev-e2e-v2`, RFC-0026 A26, A27).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProofV2 {
    pub segments: Vec<SegmentProof>,
    pub model_openings: Vec<Vec<u8>>,
}

/// Nanosecond stage stopwatch behind `std` (RFC-0018 A2, task E17-01).
/// Under `no_std` every measurement returns zero. Never touches transcripts or bytes.
pub struct Stopwatch {
    #[cfg(feature = "std")]
    start: std::time::Instant,
}

impl Stopwatch {
    /// Start timing a prover stage.
    pub fn start() -> Self {
        Self {
            #[cfg(feature = "std")]
            start: std::time::Instant::now(),
        }
    }

    /// Elapsed nanoseconds since [`Self::start`], saturating at `u64::MAX` (0 without `std`).
    pub fn elapsed_ns(&self) -> u64 {
        #[cfg(feature = "std")]
        {
            u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }
        #[cfg(not(feature = "std"))]
        {
            0
        }
    }
}

/// Prover stage timings (behind `std`; zero under `no_std`) and thread-count-independent
/// counters for one relation-engine proof (RFC-0018 A2, task E17-01).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Relation planning nanoseconds.
    pub plan_ns: u64,
    /// Stacked witness source commitment (prepare + certificate) nanoseconds.
    pub commitment_ns: u64,
    /// Multiplicity counting, encoding and certificate nanoseconds.
    pub multiplicities_ns: u64,
    /// Zerocheck (step 4) nanoseconds.
    pub zerochecks_ns: u64,
    /// LogUp lookup proof (step 5) nanoseconds.
    pub lookups_ns: u64,
    /// Matmul / reduction sumchecks (step 6) nanoseconds.
    pub reductions_ns: u64,
    /// Claim batching and source openings (step 7) nanoseconds.
    pub openings_ns: u64,
    /// Exact committed witness cells (`sum 2^log_len` over `Kind::Witness` columns).
    pub committed_cells: u64,
    /// Padded stacked-source cell count (`2^bits`), or 0 when there is no stack.
    pub stacked_source_cells_padded: u64,
    /// Total unpadded lookup positions across all checks (`sum_{check, member} 2^m`).
    pub lookup_positions: u64,
    /// Per-check `(check.name, unpadded_positions)` in plan order.
    pub lookup_checks: Vec<(String, u64)>,
    /// Proof section byte counts by RFC-0026 §4.1 section.
    pub groups_bytes: u64,
    pub multiplicities_bytes: u64,
    pub identities_bytes: u64,
    pub lookups_bytes: u64,
    pub matmuls_bytes: u64,
    pub openings_bytes: u64,
    /// Maximum physical passes over any weight column during proving, computed as
    /// `max_w ceil(col_reads[w] / 2^(w.n))` across Steps 3–7 (RFC-0027 §7, INV-7).
    pub weight_reads: u64,
    /// Total unpadded `Kind::Weight` column element reads across Steps 3 (`lookup::counts`,
    /// selected positions), 4 (`zerochecks`), 5 (`lookup::prove` `originals`), 6 (`matmuls`,
    /// counting `2^(w.n) >> fixed_bits` for RFC-0026 A6 row-blocked `lhs`/`rhs` operands and
    /// `2^(w.n)` for `out`), and 7 (one logical opening pass per weight column in each opened
    /// model source; the unoptimised development `Opening::prove` reads both `values` and
    /// `prepared.message()` to support controls before opening).
    pub weight_elements_read: u64,
}
impl Proof {
    /// All sections concatenated, for size accounting; not a verifier input.
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.groups,
            &self.multiplicities,
            &self.identities,
            &self.lookups,
            &self.matmuls,
            &self.openings,
        ]
        .into_iter()
        .flatten()
        .flatten()
        .copied()
        .collect()
    }
}

// Instance-id namespaces; tree ids (4·id) and leaf ids (8·id) stay below 2^40.
const ZEROCHECK: u64 = 1 << 62;
const MATMUL: u64 = (1 << 62) | (1 << 48);
const BATCH: u64 = (1 << 62) | (2 << 48);
const TUPLE: u64 = (1 << 62) | (3 << 48);
/// Source id of model source `k` is `MODEL + k` (RFC-0026 A5).
const MODEL: u64 = 1 << 32;
/// Largest model source: 2^30 entries, the per-source cap of RFC-0010 v2.
const MODEL_CAP: usize = 1 << 30;
/// Smallest v2 expander exponent (RFC-0010 A3 item 2): 2^(2J) message columns.
const MIN_J: u8 = 3;
const MAX_J: u8 = 14;
/// Fixed public v2 seed; RFC-0012 A7 bounds hold for every seed.
const SEED: [u8; 32] = [0; 32];
/// RFC-0026 A11: Circle blow-up exponent of the stacked and model sources (rate 1/4).
const CIRCLE_BLOWUP: u8 = 2;

/// The source parameter set of a development proof (RFC-0026 A11). The caller binds
/// it in the public input; the plan derives every source from it and the relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sources {
    /// A4/A5 v2 expander stacked and model sources and A5 Circle rate-1/2
    /// multiplicity sources, all under RFC-0010 A3 Policy 1 (no grinding).
    Expander,
    /// A11: Circle rate-1/4 stacked and model sources and the same multiplicity
    /// sources, all under RFC-0010 A14 Policy 2 counts and grinding, resolved for
    /// the development tier (`proven: false`).
    Circle,
    /// A12: `Circle`, with every multiplicity source at Circle rate 1/4 too.
    CircleAll,
    /// A14 (Draft): `CircleAll`, with each check's `(β, α)` round ground at the
    /// least bits meeting RFC-0012 A17 (C1) (profile byte 5).
    CircleAllGrind,
}
impl Sources {
    /// Stacked and model sources are A11's Circle rate-1/4 sources (A11, A12).
    fn circle(self) -> bool {
        self != Sources::Expander
    }
    /// Every multiplicity source is Circle rate 1/4 (A12, A14).
    fn quarter_mu(self) -> bool {
        matches!(self, Sources::CircleAll | Sources::CircleAllGrind)
    }
    /// The verifier's source of `(id, ell, code)` under this set's policy.
    pub fn source(self, id: u64, ell: u8, code: &[u8], root: [u8; 32]) -> Result<Source<K>, Error> {
        match self {
            Sources::Expander => Source::from_code_id(id, ell, code, root),
            _ => Source::from_code_id_development(id, ell, code, root),
        }
        .map_err(Error::Pcs)
    }
    /// The prover's prepared source of `(id, ell, code)` under this set's policy.
    pub fn prepare<'a>(
        self,
        id: u64,
        ell: u8,
        code: &[u8],
        message: &'a [M31],
    ) -> Result<PreparedSource<'a, K>, Error> {
        let usage = &mut HashUsage::default();
        match self {
            Sources::Expander => PreparedSource::from_code_id(id, ell, code, message, usage),
            _ => PreparedSource::from_code_id_development(id, ell, code, message, usage),
        }
        .map_err(Error::Pcs)
    }
    /// Owned preparation for segmented witness stacks (RFC-0026 A27, task E18-06).
    pub fn prepare_owned(
        self,
        id: u64,
        ell: u8,
        code: &[u8],
        message: Vec<M31>,
    ) -> Result<PreparedSource<'static, K>, Error> {
        let usage = &mut HashUsage::default();
        match self {
            Sources::Expander => PreparedSource::from_code_id_policy_owned(
                id,
                ell,
                code,
                message,
                usage,
                stele_pcs::Policy::One,
            ),
            _ => PreparedSource::from_code_id_development_owned(id, ell, code, message, usage),
        }
        .map_err(Error::Pcs)
    }
}

/// A commitment group: its columns occupy one aligned block of the stacked source
/// source, column `j` at `offset + j·2^n` (RFC-0026 §2.3 as amended by A4).
struct Group {
    columns: Vec<ColumnId>,
    n: u8,
    c: u8,
    offset: usize,
}

/// One weight column as an aligned block of model source `source` (RFC-0026 A5).
struct Weight {
    column: ColumnId,
    n: u8,
    source: usize,
    offset: usize,
}

/// The stacked source: every group of the proof in one v2 source (RFC-0026 A4).
struct Stack {
    id: u64,
    bits: u8,
    ell: u8,
    code: Vec<u8>,
    sources: Sources,
}
impl Stack {
    fn source(&self, root: [u8; 32]) -> Result<Source<K>, Error> {
        self.sources.source(self.id, self.ell, &self.code, root)
    }
}

/// One lookup or range inside its table's batched A5 statement (RFC-0026 A3).
pub(crate) struct Member {
    m: u8,
    tuple: Vec<(Ref, i64)>,
    selector: Option<Ref>,
    /// Start of this member's block in the concatenated domain; a multiple of 2^m.
    offset: usize,
}

/// Every lookup into one table, or every range of one width, as one A5 statement
/// with concatenated Ref-mapped, shifted originals (RFC-0026 A3, RFC-0008 A6).
pub(crate) struct Check {
    id: u64,
    name: String,
    /// Concatenated domain bits: 2^m >= Σ 2^m_i.
    m: u8,
    members: Vec<Member>,
    entries: Vec<i64>,
    c: usize,
    t: usize,
    k: u8,
    layout: Layout,
    /// A14: the `(β, α)` round's grinding bits, from the expected context only;
    /// 0 (no nonce) outside `Sources::CircleAllGrind`.
    grind: u8,
    /// Test-only malicious-prover seam: added to the committed count of row 0.
    #[cfg(test)]
    skew: i64,
    /// Test-only malicious-prover seam: member evaluations taken from these values.
    #[cfg(test)]
    split: Option<Values>,
    /// Malicious-prover seam (tests and the `controls` feature): added to the
    /// denominator of the first table row with a zero count. The fraction sum is
    /// unchanged, so only the table-claim check sees it.
    #[cfg(any(test, feature = "controls"))]
    shift: i64,
}
impl Check {
    fn tuple_id(&self, i: usize) -> u64 {
        TUPLE | (self.id << 2) | i as u64
    }
}

/// Everything the verifier derives from the relation (RFC-0026 §8 steps 1-2).
struct Plan {
    digest: [u8; 32],
    groups: Vec<Group>,
    /// `None` when the relation has no commitment group.
    stack: Option<Stack>,
    checks: Vec<Check>,
    /// Weight blocks of the model sources, in `ColumnId` order (A5).
    weights: Vec<Weight>,
    /// The model sources, in split order; empty without weight columns.
    model: Vec<Stack>,
    sizes: Vec<u8>,
    sources: Sources,
    /// Controls-only step-7 routing; never consulted by the verifier (A18).
    #[cfg(feature = "controls")]
    column_claim: Option<ColumnId>,
}

fn ceil_log2(n: usize) -> u8 {
    n.next_power_of_two().trailing_zeros() as u8
}
fn v2_code(j: u8) -> Vec<u8> {
    let mut code = b"stele/expander-seed/v2".to_vec();
    code.push(j);
    code.extend_from_slice(&SEED);
    code
}

/// Stack geometry: at least 2·MIN_J variables (both sets, so the plan's bits do not
/// depend on the set), and the code that minimises certificate plus opening bytes
/// under the set's policy. Expander: the v2 exponent J (ties: smallest J). Circle
/// (A11): the rate-1/4 row split `ell + m = bits` (ties: smallest `ell`).
fn stack(id: u64, bits: u8, sources: Sources) -> Result<Stack, Error> {
    let bits = bits.max(2 * MIN_J);
    let candidates: Vec<(u8, Vec<u8>)> = match sources.circle() {
        false => (MIN_J..=MAX_J.min(bits / 2))
            .map(|j| (bits - 2 * j, v2_code(j)))
            .collect(),
        // Circle (m, b) exists for m <= 30 - b; a source has ell <= 30.
        true => (bits.saturating_sub(30 - CIRCLE_BLOWUP)..=bits.min(30))
            .filter_map(|ell| {
                Source::<K>::new(id, ell, bits - ell, CIRCLE_BLOWUP, [0; 32])
                    .ok()
                    .map(|s| (ell, s.code_id().to_vec()))
            })
            .collect(),
    };
    let (ell, code) = smallest(id, candidates, sources)?;
    Ok(Stack {
        id,
        bits,
        ell,
        code,
        sources,
    })
}

/// The candidate `(ell, code)` whose source under `sources` has the fewest certificate
/// plus opening bytes (ties: the first, i.e. the smallest `ell` or `J`).
fn smallest(
    id: u64,
    candidates: Vec<(u8, Vec<u8>)>,
    sources: Sources,
) -> Result<(u8, Vec<u8>), Error> {
    let mut best: Option<(usize, u8, Vec<u8>)> = None;
    for (ell, code) in candidates {
        let Ok(source) = sources.source(id, ell, &code, [0; 32]) else {
            continue;
        };
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?
            + source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
        if best.as_ref().is_none_or(|(b, _, _)| size < *b) {
            best = Some((size, ell, code));
        }
    }
    best.map(|(_, ell, code)| (ell, code))
        .ok_or(Error::Unsupported)
}

/// RFC-0008 A5 multiplicity layout of a check with `2^k` table rows: Circle rate 1/2
/// at `ell = k/2` (A5, A11), or under A12 Circle rate 1/4 at the `ell` that
/// [`smallest`] picks.
fn mu_layout(id: u64, k: u8, sources: Sources) -> Result<Layout, Error> {
    if !sources.quarter_mu() {
        return Ok(Layout {
            id,
            ell: k / 2,
            blowup: 1,
        });
    }
    let layout = |ell| Layout {
        id,
        ell,
        blowup: CIRCLE_BLOWUP,
    };
    let candidates = (0..=k)
        .filter_map(|ell| {
            mu_source::<K>(layout(ell), k, [0; 32], stele_pcs::Policy::One)
                .ok()
                .map(|s| (ell, s.code_id().to_vec()))
        })
        .collect();
    Ok(layout(smallest(id, candidates, sources)?.0))
}

/// The table a lookup or range targets: ranges are keyed by width bits, because
/// `v − width.min()` reads the same table `[0, 2^bits)` for either signedness.
#[derive(PartialEq)]
enum Target {
    Table(u32),
    Range(u8),
}

fn check(
    id: u64,
    source_id: u64,
    name: String,
    mut members: Vec<Member>,
    t: usize,
    mut entries: Vec<i64>,
    sources: Sources,
) -> Result<Check, Error> {
    let c = members[0].tuple.len();
    // RFC-0008 A2 item 5: arity 1..=2 and at most 2^16 table rows.
    if !(1..=2).contains(&c) || !(1..=1 << 16).contains(&t) || entries.len() != c * t {
        return Err(Error::Unsupported);
    }
    // Largest first keeps every block aligned to its own size.
    members.sort_by(|a, b| b.m.cmp(&a.m));
    let mut total = 0usize;
    for member in &mut members {
        member.offset = total;
        total += 1 << member.m;
    }
    let m = ceil_log2(total);
    // b = min(m, 30) = m keeps h = 0, so multiplicities precede every challenge and
    // each count stays at most 2^30 < p (RFC-0008 A2 item 2).
    if m > 30 {
        return Err(Error::Unsupported);
    }
    let k = ceil_log2(t);
    entries.resize(c << k, 0);
    let layout = mu_layout(source_id, k, sources)?;
    // A14: the least k_LU with (c(2^m + t) − 1)·2^108 ≤ p^4·2^k_LU (RFC-0008 A8 item 2's
    // rule, with the recorded A13 numerator); above 32 bits the check is unsupported.
    let grind = if sources == Sources::CircleAllGrind {
        crate::lookup::lu_grind_bits(c, 1u64 << m, t, 4).ok_or(Error::Unsupported)?
    } else {
        0
    };
    Ok(Check {
        id,
        name,
        m,
        members,
        entries,
        c,
        t,
        k,
        layout,
        grind,
        #[cfg(test)]
        skew: 0,
        #[cfg(test)]
        split: None,
        #[cfg(any(test, feature = "controls"))]
        shift: 0,
    })
}

fn plan(relation: &Relation, sources: Sources) -> Result<Plan, Error> {
    relation.validate().map_err(Error::StatementMismatch)?;
    let mut groups = Vec::new();
    for (g, group_meta) in relation.groups.iter().enumerate() {
        let columns: Vec<ColumnId> = (0..relation.columns.len() as u32)
            .map(ColumnId)
            .filter(|id| {
                relation.columns[id.0 as usize].kind
                    == Kind::Witness(stele_ir::relation::GroupId(g as u32))
            })
            .collect();
        let c = ceil_log2(columns.len().max(1));
        groups.push(Group {
            columns,
            n: group_meta.log_len,
            c,
            offset: 0,
        });
    }
    // RFC-0026 A4: blocks of 2^(n+c), largest first so each is aligned to its size;
    // ties keep GroupId order.
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_by(|a, b| (groups[*b].n + groups[*b].c).cmp(&(groups[*a].n + groups[*a].c)));
    let mut total = 0usize;
    for g in order {
        // Reject before shifting: n + c > 30 cannot fit a source (RFC-0026 A4).
        let bits = u32::from(groups[g].n) + u32::from(groups[g].c);
        if bits > 30 {
            return Err(Error::Unsupported);
        }
        groups[g].offset = total;
        total = total.checked_add(1 << bits).ok_or(Error::Unsupported)?;
    }
    let stack = match groups.is_empty() {
        true => None,
        false => {
            let bits = ceil_log2(total);
            if bits > 30 {
                return Err(Error::Unsupported);
            }
            Some(self::stack(2, bits, sources)?)
        }
    };
    let base = 3;
    // RFC-0026 A3: one check per table, in order of first use (lookups, then ranges);
    // members keep relation order before the size sort.
    let mut targets: Vec<(Target, Vec<Member>)> = Vec::new();
    let mut add =
        |target: Target, member: Member| match targets.iter_mut().find(|(t, _)| *t == target) {
            Some((_, members)) => members.push(member),
            None => targets.push((target, vec![member])),
        };
    for lookup in &relation.lookups {
        add(
            Target::Table(lookup.table.0),
            Member {
                m: lookup.vars,
                tuple: lookup.tuple.iter().map(|r| (r.clone(), 0)).collect(),
                selector: lookup.selector.clone(),
                offset: 0,
            },
        );
    }
    for range in &relation.ranges {
        let log_len = relation.columns[range.column.0 as usize].log_len;
        // RFC-0026 §3.4: v - min into 2^bits consecutive integers.
        add(
            Target::Range(range.width.bits),
            Member {
                m: log_len,
                tuple: vec![(Ref::identity(range.column, log_len), -range.width.min())],
                selector: None,
                offset: 0,
            },
        );
    }
    let mut checks = Vec::new();
    for (id, (target, members)) in targets.into_iter().enumerate() {
        let id = id as u64;
        let (name, t, entries) = match target {
            Target::Table(table) => {
                let table = &relation.tables[table as usize];
                let entries = table.rows.iter().flatten().copied().collect();
                (table.name.clone(), table.rows.len(), entries)
            }
            Target::Range(bits) => {
                let t = 1usize << bits;
                (alloc::format!("range_{bits}"), t, (0..t as i64).collect())
            }
        };
        checks.push(check(id, base + id, name, members, t, entries, sources)?);
    }
    let lengths: Vec<u8> = (0..relation.columns.len())
        .filter(|i| relation.columns[*i].kind == Kind::Weight)
        .map(|i| relation.columns[i].log_len)
        .collect();
    let (placement, model) = model_plan(&lengths, sources)?;
    let weights: Vec<Weight> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .zip(placement)
        .map(|(column, (source, offset))| Weight {
            column,
            n: relation.columns[column.0 as usize].log_len,
            source,
            offset,
        })
        .collect();
    let composes = relation.composes.iter();
    let mut sizes: Vec<u8> = relation.identities.iter().map(|i| i.vars).collect();
    sizes.extend(composes.map(|c| relation.columns[c.column.0 as usize].log_len));
    sizes.sort_unstable();
    sizes.dedup();
    Ok(Plan {
        digest: codec::digest(relation),
        groups,
        stack,
        checks,
        weights,
        model,
        sizes,
        sources,
        #[cfg(feature = "controls")]
        column_claim: None,
    })
}

/// Values of a witness or weight column, or the public values.
fn column<'a>(
    relation: &'a Relation,
    values: &'a Values,
    id: ColumnId,
) -> Result<&'a [i64], Error> {
    values.get(relation, id).ok_or(Error::Missing(id))
}

/// Column point of a `Ref` read at an MSB-first domain point.
fn restrict(r: &Ref, domain: &[K]) -> Vec<K> {
    let (n, m) = (r.vars.len(), domain.len());
    let mut point = vec![K::from_i64(0); n];
    for (j, var) in r.vars.iter().enumerate() {
        // A fixed bit (RFC-0026 A6) is a Boolean coordinate: no Schwartz–Zippel term.
        point[n - 1 - j] = match Ref::fixed(*var) {
            Some(bit) => K::from_i64(i64::from(bit)),
            None => domain[m - 1 - *var as usize],
        };
    }
    point
}

fn mle(values: &[i64], point: &[K]) -> Result<K, Error> {
    let eq = stele_poly::eq_table(point).map_err(|_| Error::Capacity)?;
    Ok(values
        .iter()
        .zip(eq)
        .fold(K::from_i64(0), |s, (v, w)| s + K::from_i64(*v) * w))
}

/// Column claims `(column point, value)`, routed to sources in step 7.
pub(crate) struct Claims(Vec<Vec<(Vec<K>, K)>>);
impl Claims {
    fn push(&mut self, r: &Ref, domain: &[K], value: K) {
        self.0[r.column.0 as usize].push((restrict(r, domain), value));
    }
}

/// Exact-length reader over untrusted proof bytes.
pub(crate) struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::ProofShape);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn k(&mut self) -> Result<K, Error> {
        let bytes: [u8; 16] = self.take(16)?.try_into().map_err(|_| Error::ProofShape)?;
        K::from_le_bytes(bytes).ok_or(Error::NoncanonicalField)
    }
    fn ks(&mut self, n: usize) -> Result<Vec<K>, Error> {
        (0..n).map(|_| self.k()).collect()
    }
    fn root(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::ProofShape)
    }
}
impl Reader<'_> {
    /// A section is canonical only if it is consumed exactly.
    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::ProofShape)
        }
    }
}
/// The sections of one §4.1 kind, in order; the count is derived by the verifier.
struct Sections<'a>(core::slice::Iter<'a, Vec<u8>>);
impl<'a> Sections<'a> {
    fn next(&mut self) -> Result<Reader<'a>, Error> {
        self.0.next().map(|s| Reader(s)).ok_or(Error::ProofShape)
    }
    fn end(mut self) -> Result<(), Error> {
        match self.0.next() {
            None => Ok(()),
            Some(_) => Err(Error::ProofShape),
        }
    }
}
fn put(out: &mut Vec<u8>, values: &[K]) {
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// The combined identity polynomial of one domain size (RFC-0026 §4 step 4).
/// Identities of domain size `m` in relation order, then each `Compose` over its
/// column's domain as the identity `column - Σ 2^shift·limb = 0` (RFC-0026 §3.5a).
fn identities_for(relation: &Relation, segment: Option<u32>, m: u8) -> Vec<Identity> {
    let mut out: Vec<Identity> = relation
        .identities
        .iter()
        .filter(|i| i.vars == m && segment.is_none_or(|s| relation.identity_segment(i) == s))
        .cloned()
        .collect();
    for compose in &relation.composes {
        let log_len = relation.columns[compose.column.0 as usize].log_len;
        if log_len != m || segment.is_some_and(|s| relation.compose_segment(compose) != s) {
            continue;
        }
        let read = |id| vec![Ref::identity(id, log_len)];
        let mut terms = vec![IdentityTerm {
            coeff: 1,
            factors: read(compose.column),
        }];
        for &(limb, shift) in &compose.limbs {
            terms.push(IdentityTerm {
                coeff: -(1i64 << shift),
                factors: read(limb),
            });
        }
        out.push(Identity {
            name: compose.name.clone(),
            vars: m,
            terms,
        });
    }
    out
}

fn combine(relation: &Relation, m: u8, lambdas: &[K]) -> (Vec<Ref>, Instance<K>) {
    combine_for(relation, None, m, ZEROCHECK | u64::from(m), lambdas)
}

fn combine_for(
    relation: &Relation,
    segment: Option<u32>,
    m: u8,
    id: u64,
    lambdas: &[K],
) -> (Vec<Ref>, Instance<K>) {
    let mut inputs: Vec<Ref> = Vec::new();
    let mut terms = Vec::new();
    for (identity, lambda) in identities_for(relation, segment, m).iter().zip(lambdas) {
        for term in &identity.terms {
            let factors = term
                .factors
                .iter()
                .map(|f| {
                    let index = inputs.iter().position(|r| r == f).unwrap_or_else(|| {
                        inputs.push(f.clone());
                        inputs.len() - 1
                    });
                    index as u32
                })
                .collect();
            terms.push(Term {
                coefficient: *lambda * K::from_i64(term.coeff),
                factors,
            });
        }
    }
    let instance = Instance {
        id,
        num_vars: u32::from(m),
        inputs: (0..inputs.len() as u64).collect(),
        terms,
        claimed_sum: K::from_i64(0),
    };
    (inputs, instance)
}

fn identity_lambdas(t: &mut Transcript<K>, relation: &Relation, m: u8) -> Result<Vec<K>, Error> {
    identity_lambdas_for(t, relation, None, m)
}

fn identity_lambdas_for(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment: Option<u32>,
    m: u8,
) -> Result<Vec<K>, Error> {
    (0..identities_for(relation, segment, m).len())
        .map(|_| Ok(t.challenge(ChallengeLabel::RelationIdentity)?))
        .collect()
}

/// Matmul sumcheck variables: shared free bits and summed bits, MSB-first.
struct MatmulShape {
    rho: Vec<K>,
    vars: Vec<u8>,
    shared: Vec<u8>,
}
impl MatmulShape {
    fn new(t: &mut Transcript<K>, mm: &stele_ir::relation::Matmul) -> Result<Self, Error> {
        let rho = (0..mm.free)
            .map(|_| Ok(t.challenge(ChallengeLabel::RelationPoint)?))
            .collect::<Result<Vec<K>, Error>>()?;
        let shared: Vec<u8> = (0..mm.free)
            .filter(|d| mm.lhs.vars.contains(d) && mm.rhs.vars.contains(d))
            .collect();
        let mut vars: Vec<u8> = shared
            .iter()
            .copied()
            .chain(mm.free..mm.free + mm.summed)
            .collect();
        vars.sort_unstable_by(|a, b| b.cmp(a));
        Ok(Self { rho, vars, shared })
    }
    fn rho_at(&self, d: u8) -> K {
        self.rho[self.rho.len() - 1 - d as usize]
    }
    /// Coordinate of a bit outside the sumcheck: its Boolean value when fixed
    /// (RFC-0026 A6), else the free bit's ρ coordinate.
    fn fixed_at(&self, d: u8) -> K {
        Ref::fixed(d).map_or_else(|| self.rho_at(d), |bit| K::from_i64(i64::from(bit)))
    }
    fn position(&self, d: u8) -> Option<usize> {
        self.vars.iter().position(|v| *v == d)
    }
    fn instance(&self, id: u64, claimed: K) -> Instance<K> {
        let k = self.shared.len();
        Instance {
            id,
            num_vars: self.vars.len() as u32,
            inputs: (0..2 + u64::from(k > 0)).collect(),
            terms: vec![Term {
                coefficient: K::from_i64(1),
                factors: if k > 0 { vec![0, 1, 2] } else { vec![0, 1] },
            }],
            claimed_sum: claimed,
        }
    }
    /// Column point: non-shared free bits at ρ, sumcheck variables at `r`.
    fn point(&self, r: &Ref, free: u8, sc: &[K]) -> Vec<K> {
        let n = r.vars.len();
        let mut point = vec![K::from_i64(0); n];
        for (j, d) in r.vars.iter().enumerate() {
            point[n - 1 - j] = match self.position(*d) {
                Some(p) => sc[p],
                None if *d < free || Ref::fixed(*d).is_some() => self.fixed_at(*d),
                None => K::from_i64(0),
            };
        }
        point
    }
    /// Operand table over the sumcheck variables, non-shared free bits fixed at ρ.
    fn table(&self, r: &Ref, col: &[i64]) -> Result<Vec<K>, Error> {
        let nv = self.vars.len();
        let mut mask = 0usize;
        // Per entry-index bit: its sumcheck variable (`inner`, as `(j, z bit)`), or a bit
        // outside the sumcheck (`outer`) whose weights `eq` folds in, in `r.vars` order.
        let (mut inner, mut outer) = (Vec::new(), Vec::new());
        let mut eq = vec![K::from_i64(1)];
        for (j, d) in r.vars.iter().enumerate() {
            match self.position(*d) {
                Some(p) => {
                    mask |= 1 << (nv - 1 - p);
                    inner.push((j, nv - 1 - p));
                }
                None => {
                    let x = self.fixed_at(*d);
                    let low: Vec<K> = eq.iter().map(|w| *w * (K::from_i64(1) - x)).collect();
                    let high: Vec<K> = eq.iter().map(|w| *w * x).collect();
                    eq = [low, high].concat();
                    outer.push(j);
                }
            }
        }
        // Entries outside a row block (RFC-0026 A6) have eq weight 0: skip them, so
        // the blocks of a split read each operand entry once in total.
        let (mut fixed, mut selected) = (0usize, 0usize);
        for (j, d) in r.vars.iter().enumerate() {
            if let Some(bit) = Ref::fixed(*d) {
                fixed |= 1 << j;
                selected |= usize::from(bit) << j;
            }
        }
        // Exact field sums: the split leaves every entry equal to the sequential loop's.
        let mut reduced = vec![K::from_i64(0); 1 << nv];
        stele_sumcheck::parallel::sum_ranges(col.len(), &mut reduced, |range, reduced| {
            for index in range {
                if index & fixed != selected {
                    continue;
                }
                let z = inner
                    .iter()
                    .fold(0, |z, (j, to)| z | ((index >> j) & 1) << to);
                let o = outer
                    .iter()
                    .enumerate()
                    .fold(0, |o, (k, j)| o | ((index >> j) & 1) << k);
                reduced[z] = reduced[z] + eq[o] * K::from_i64(col[index]);
            }
            Ok(())
        })?;
        Ok((0..1 << nv).map(|z| reduced[z & mask]).collect())
    }
    fn eq_table(&self) -> Vec<K> {
        let nv = self.vars.len();
        (0..1usize << nv)
            .map(|z| {
                self.shared.iter().fold(K::from_i64(1), |acc, d| {
                    let p = self.position(*d).unwrap_or(0);
                    let x = self.rho_at(*d);
                    acc * if (z >> (nv - 1 - p)) & 1 == 1 {
                        x
                    } else {
                        K::from_i64(1) - x
                    }
                })
            })
            .collect()
    }
    /// Out claim at ρ and operand claims at (ρ, r); `finals` lead with eq when k > 0.
    fn route(
        &self,
        mm: &stele_ir::relation::Matmul,
        sc: &[K],
        finals: &[K],
        out: K,
        claims: &mut Claims,
    ) {
        let finals = &finals[usize::from(!self.shared.is_empty())..];
        claims.push(&mm.out, &self.rho, out);
        for (r, value) in [(&mm.lhs, finals[0]), (&mm.rhs, finals[1])] {
            claims.0[r.column.0 as usize].push((self.point(r, mm.free, sc), value));
        }
    }
    fn eq_at(&self, sc: &[K]) -> K {
        self.shared.iter().fold(K::from_i64(1), |acc, d| {
            let (x, y) = (self.rho_at(*d), sc[self.position(*d).unwrap_or(0)]);
            acc * (x * y + (K::from_i64(1) - x) * (K::from_i64(1) - y))
        })
    }
}

fn bits_point(index: usize, c: u8, tail: &[K]) -> Vec<K> {
    (0..c)
        .map(|b| K::from_i64(((index >> (c - 1 - b)) & 1) as i64))
        .chain(tail.iter().copied())
        .collect()
}

/// Stack claims: column `j` of a group at block offset `o` is the stack claim at
/// `(bits(o/2^n + j) ‖ ρ)`, with the block and column index in the leading
/// coordinates (RFC-0026 §2.3, A4). Exact: Boolean coordinates only.
fn group_claims(plan: &Plan, stack: &Stack, claims: &Claims) -> Vec<(Vec<K>, K)> {
    group_claims_for(&plan.groups, stack, claims)
}

fn group_claims_for(groups: &[Group], stack: &Stack, claims: &Claims) -> Vec<(Vec<K>, K)> {
    let mut out = Vec::new();
    for group in groups {
        for (j, column) in group.columns.iter().enumerate() {
            let index = (group.offset >> group.n) + j;
            for (point, value) in &claims.0[column.0 as usize] {
                out.push((bits_point(index, stack.bits - group.n, point), *value));
            }
        }
    }
    out
}

/// Change exactly the first selected claim's Boolean prefix (RFC-0026 A18).
#[cfg(feature = "controls")]
fn route_column_claim(
    plan: &Plan,
    stack: &Stack,
    claims: &Claims,
    column: ColumnId,
    batch: &mut [(Vec<K>, K)],
) -> Result<(), Error> {
    let mut index = 0;
    for group in &plan.groups {
        for (j, &c) in group.columns.iter().enumerate() {
            if c != column {
                index += claims.0[c.0 as usize].len();
                continue;
            }
            let (tail, _) = claims.0[c.0 as usize].first().ok_or(Error::Unsupported)?;
            let honest = batch.to_vec();
            let prefix = usize::from(stack.bits - group.n);
            batch[index].0 = bits_point((group.offset >> group.n) + j + 1, prefix as u8, tail);
            assert_eq!(batch[index].1, honest[index].1);
            assert_eq!(batch[index].0[prefix..], honest[index].0[prefix..]);
            assert_eq!(batch.iter().zip(&honest).filter(|(a, b)| a != b).count(), 1);
            let routed = core::mem::replace(&mut batch[index].0, honest[index].0.clone());
            assert_eq!(batch, honest, "restoring the prefix restores every claim");
            batch[index].0 = routed;
            return Ok(());
        }
    }
    Err(Error::Unsupported)
}

/// One model source's derived layout (RFC-0026 A5); the model owner commits the
/// matching [`model_messages`] entry with `sources.prepare(id, ell, &code, ..)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelLayout {
    pub id: u64,
    pub ell: u8,
    pub code: Vec<u8>,
    /// The source parameter set this layout was derived under (A11).
    pub sources: Sources,
    /// The stacked message has `2^bits` entries.
    pub bits: u8,
    /// `(weight index in ColumnId order, block offset)` of each weight in this source.
    pub blocks: Vec<(usize, usize)>,
}

/// RFC-0026 A5 layout from the weights' lengths (`2^n` entries each, `ColumnId`
/// order): weights are split greedily into model sources of at most 2^30 entries;
/// inside a source, blocks go largest first, ties in order. Returns each weight's
/// `(source, offset)` and the sources.
type ModelPlan = (Vec<(usize, usize)>, Vec<Stack>);

fn model_plan(lengths: &[u8], sources: Sources) -> Result<ModelPlan, Error> {
    let mut placement = vec![(0usize, 0usize); lengths.len()];
    let mut totals: Vec<usize> = Vec::new();
    for (w, &n) in lengths.iter().enumerate() {
        if n > 30 {
            return Err(Error::Unsupported);
        }
        let size = 1usize << n;
        match totals.last_mut() {
            Some(total) if *total + size <= MODEL_CAP => *total += size,
            _ => totals.push(size),
        }
        placement[w].0 = totals.len() - 1;
    }
    let mut model = Vec::new();
    for (k, total) in totals.iter().enumerate() {
        let mut order: Vec<usize> = (0..lengths.len())
            .filter(|w| placement[*w].0 == k)
            .collect();
        order.sort_by(|a, b| lengths[*b].cmp(&lengths[*a]));
        let mut offset = 0usize;
        for w in order {
            placement[w].1 = offset;
            offset += 1 << lengths[w];
        }
        // Aligned blocks summing to at most 2^30 fit 2^ceil(log2 total) <= 2^30.
        model.push(self::stack(MODEL + k as u64, ceil_log2(*total), sources)?);
    }
    Ok((placement, model))
}

/// The model sources for weights of `2^lengths[i]` entries in `ColumnId` order (A5),
/// for a model owner that commits before any relation is built.
pub fn model_layout_for(lengths: &[u8], sources: Sources) -> Result<Vec<ModelLayout>, Error> {
    let (placement, model) = model_plan(lengths, sources)?;
    Ok(model
        .into_iter()
        .enumerate()
        .map(|(k, m)| ModelLayout {
            id: m.id,
            ell: m.ell,
            code: m.code,
            sources: m.sources,
            bits: m.bits,
            blocks: placement
                .iter()
                .enumerate()
                .filter(|(_, (source, _))| *source == k)
                .map(|(w, (_, offset))| (w, *offset))
                .collect(),
        })
        .collect())
}

/// The model sources of a relation, in split order; empty without weight columns.
pub fn model_layout(relation: &Relation, sources: Sources) -> Result<Vec<ModelLayout>, Error> {
    let lengths: Vec<u8> = relation
        .columns
        .iter()
        .filter(|c| c.kind == Kind::Weight)
        .map(|c| c.log_len)
        .collect();
    model_layout_for(&lengths, sources)
}

/// The plan-derived stacked source of a relation under `root`, `None` without
/// commitment groups (A4, A11). The verifier derives it the same way; controls use it
/// to locate one certificate or opening field.
pub fn stack_source(
    relation: &Relation,
    sources: Sources,
    root: [u8; 32],
) -> Result<Option<Source<K>>, Error> {
    plan(relation, sources)?
        .stack
        .map(|stack| stack.source(root))
        .transpose()
}

/// The plan-derived multiplicity source of check `index` under `root` (RFC-0008 A5,
/// RFC-0026 A12); controls use it to locate one certificate field.
pub fn multiplicity_source(
    relation: &Relation,
    sources: Sources,
    index: usize,
    root: [u8; 32],
) -> Result<Source<K>, Error> {
    let plan = plan(relation, sources)?;
    let check = plan.checks.get(index).ok_or(Error::Unsupported)?;
    let l = check.layout;
    sources.source(l.id, l.ell, mu_code(check)?.code_id(), root)
}

/// Place per-weight messages (`ColumnId` order, `2^n` entries each, signed
/// embedding) into the stacked messages of `layouts`.
pub fn stack_model(layouts: &[ModelLayout], weights: &[&[M31]]) -> Result<Vec<Vec<M31>>, Error> {
    let mut out = Vec::new();
    for layout in layouts {
        let mut message = vec![M31::from_i64(0); 1 << layout.bits];
        for &(w, offset) in &layout.blocks {
            let weight = weights.get(w).ok_or(Error::Weights)?;
            let block = message
                .get_mut(offset..offset + weight.len())
                .ok_or(Error::Weights)?;
            block.copy_from_slice(weight);
        }
        out.push(message);
    }
    Ok(out)
}

/// The model messages (signed embedding; each weight at its block offset).
pub fn model_messages(relation: &Relation, values: &Values) -> Result<Vec<Vec<M31>>, Error> {
    // Messages depend on the bits only, which no source set changes.
    let plan = plan(relation, Sources::Expander)?;
    (0..plan.model.len())
        .map(|k| weights_message(relation, &plan, k, values))
        .collect()
}

fn weights_message(
    relation: &Relation,
    plan: &Plan,
    k: usize,
    values: &Values,
) -> Result<Vec<M31>, Error> {
    let mut message = vec![M31::from_i64(0); 1 << plan.model[k].bits];
    for weight in plan.weights.iter().filter(|w| w.source == k) {
        let col = column(relation, values, weight.column)?;
        for (out, v) in message[weight.offset..].iter_mut().zip(col) {
            *out = M31::from_i64(*v);
        }
    }
    Ok(message)
}

/// The supplied model certificates must be the derived layouts under their roots.
fn model_check(plan: &Plan, certificates: &[&VerifiedCertificate<K>]) -> Result<(), Error> {
    model_check_stacks(&plan.model, certificates)
}

fn model_check_stacks(
    model_stacks: &[Stack],
    certificates: &[&VerifiedCertificate<K>],
) -> Result<(), Error> {
    if certificates.len() != model_stacks.len() {
        return Err(Error::Weights);
    }
    for (model, certificate) in model_stacks.iter().zip(certificates) {
        let source = certificate.record().source();
        if model.source(source.root())?.bytes() != source.bytes() {
            return Err(Error::Weights);
        }
    }
    Ok(())
}

/// Model claims of source `k`: weight `w` at block offset `o` maps a claim at `ρ` to
/// the model claim at `(bits(o/2^n) ‖ ρ)`, Boolean leading coordinates (A5).
fn weight_claims(plan: &Plan, k: usize, claims: &Claims) -> Vec<(Vec<K>, K)> {
    weight_claims_for(&plan.weights, &plan.model, k, claims)
}

fn weight_claims_for(
    weights: &[Weight],
    model_stacks: &[Stack],
    k: usize,
    claims: &Claims,
) -> Vec<(Vec<K>, K)> {
    let model = &model_stacks[k];
    let mut out = Vec::new();
    for weight in weights.iter().filter(|w| w.source == k) {
        for (point, value) in &claims.0[weight.column.0 as usize] {
            out.push((
                bits_point(weight.offset >> weight.n, model.bits - weight.n, point),
                *value,
            ));
        }
    }
    out
}

fn to_k(message: &[M31]) -> Vec<K> {
    message
        .iter()
        .map(|v| K::from_i64(i64::from(v.as_u32())))
        .collect()
}

/// Bind every model root to the transcript right after the statement (A5), so the
/// proof binds the model even when the caller's public input omits it.
fn absorb_model(
    t: &mut Transcript<K>,
    certificates: &[&VerifiedCertificate<K>],
) -> Result<(), Error> {
    for certificate in certificates {
        t.absorb(
            AbsorbLabel::RelationRoots,
            &certificate.record().source().root(),
        )?;
    }
    Ok(())
}

/// Produce a development-profile proof. `t` must be `Transcript::new(public)` with
/// the RFC-0026 §1.1 public inputs; `model` holds each prepared model source of
/// [`model_layout`] with its verified certificate (empty without weights), under the
/// source set `sources` the caller bound in the public input (A11). The
/// prover checks none of the verifier's equations; a false witness yields a
/// rejected proof or an error from a primitive prover.
pub fn prove(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
) -> Result<Proof, Error> {
    prove_measured(t, relation, values, model, sources).map(|(proof, _)| proof)
}

/// [`prove`] together with stage timings (behind `std`) and deterministic counters
/// (RFC-0018 A2, task E17-01). Proof bytes are identical to [`prove`].
pub fn prove_measured(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
) -> Result<(Proof, Metrics), Error> {
    // E16-22: stage timing, off unless STELE_STAGE_TIMES.
    let mut laps = parallel::Laps::start();
    let plan_timer = Stopwatch::start();
    let plan = plan(relation, sources)?;
    let plan_ns = plan_timer.elapsed_ns();
    laps.lap("dev/plan");
    let (proof, mut metrics) =
        prove_plan_measured(t, relation, &plan, values, values, model, None)?;
    metrics.plan_ns = plan_ns;
    Ok((proof, metrics))
}

/// A malicious prover for controls (feature `controls`; never a verifier input).
#[cfg(feature = "controls")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Forge {
    /// Shift the denominator of check `i`'s first zero-count table row by one.
    pub table: Option<usize>,
    /// Read public column `c`'s entry `j` plus one while proving.
    pub public: Option<(ColumnId, usize)>,
    /// Increment one in-range witness entry used by an identity. Commit and open
    /// the changed values, but use reference values for the zerocheck rounds
    /// (RFC-0026 §9 NC-1302); final evaluations come from the changed values.
    pub witness: Option<(ColumnId, usize)>,
    /// Route this witness column's first claim to the next real, equal-valued
    /// column in its group (RFC-0026 A18). Cannot combine with other mutations.
    pub column_claim: Option<ColumnId>,
}

/// [`prove`] as a malicious prover: the plan and the absorbed relation digest are
/// `relation`'s, but the proof is made with `forge` applied (controls only).
#[cfg(feature = "controls")]
pub fn prove_forged(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    forge: &Forge,
) -> Result<Proof, Error> {
    let mut plan = plan(relation, sources)?;
    if let Some(c) = forge.column_claim {
        if forge.table.is_some() || forge.public.is_some() || forge.witness.is_some() {
            return Err(Error::Unsupported);
        }
        let group = plan
            .groups
            .iter()
            .find(|g| g.columns.contains(&c))
            .ok_or(Error::Unsupported)?;
        let j = group
            .columns
            .iter()
            .position(|&id| id == c)
            .ok_or(Error::Unsupported)?;
        let next = *group.columns.get(j + 1).ok_or(Error::Unsupported)?;
        let selected = values.get(relation, c).ok_or(Error::Unsupported)?;
        let adjacent = values.get(relation, next).ok_or(Error::Unsupported)?;
        if selected != adjacent {
            return Err(Error::Unsupported);
        }
        plan.column_claim = Some(c);
    }
    if let Some(i) = forge.table {
        plan.checks.get_mut(i).ok_or(Error::Unsupported)?.shift = 1;
    }
    let mut read = relation.clone();
    if let Some((c, j)) = forge.public {
        match read.columns.get_mut(c.0 as usize).map(|c| &mut c.kind) {
            Some(Kind::Public(v)) if j < v.len() => v[j] += 1,
            _ => return Err(Error::Unsupported),
        }
    }
    let changed = forge
        .witness
        .map(|(c, j)| {
            let column = read.columns.get(c.0 as usize).ok_or(Error::Unsupported)?;
            if !matches!(column.kind, Kind::Witness(_))
                || !plan.sizes.iter().any(|&m| {
                    identities_for(&read, None, m).iter().any(|identity| {
                        identity
                            .terms
                            .iter()
                            .any(|term| term.factors.iter().any(|r| r.column == c))
                    })
                })
            {
                return Err(Error::Unsupported);
            }
            let mut entries = values.get(&read, c).ok_or(Error::Unsupported)?.to_vec();
            let entry = entries.get_mut(j).ok_or(Error::Unsupported)?;
            *entry = entry
                .checked_add(1)
                .filter(|v| column.width.contains(*v))
                .ok_or(Error::Unsupported)?;
            let mut changed = values.clone();
            changed
                .set(&read, c, entries)
                .map_err(|_| Error::Unsupported)?;
            Ok::<_, Error>(changed)
        })
        .transpose()?;
    let actual = changed.as_ref().unwrap_or(values);
    prove_plan(
        t,
        &read,
        &plan,
        actual,
        actual,
        model,
        changed.as_ref().map(|_| values),
    )
}

/// The prover. `committed` fills the group messages (step 2); `values` drives every
/// later message and claim. Controls alone may supply `round_values` for zerocheck
/// rounds while retaining genuine `values` finals (RFC-0026 §9 NC-1302).
#[cfg(any(test, feature = "controls"))]
fn prove_plan(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: &Plan,
    committed: &Values,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    round_values: Option<&Values>,
) -> Result<Proof, Error> {
    prove_plan_measured(t, relation, plan, committed, values, model, round_values)
        .map(|(proof, _)| proof)
}

fn prove_plan_measured(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: &Plan,
    committed: &Values,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    round_values: Option<&Values>,
) -> Result<(Proof, Metrics), Error> {
    let certificates: Vec<&VerifiedCertificate<K>> = model.iter().map(|(_, c)| *c).collect();
    model_check(plan, &certificates)?;
    if model
        .iter()
        .any(|(p, c)| p.source().bytes() != c.record().source().bytes())
    {
        return Err(Error::Weights);
    }
    let mut proof = Proof::default();
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);
    let mut metrics = Metrics {
        committed_cells: relation
            .columns
            .iter()
            .filter(|c| matches!(c.kind, Kind::Witness(_)))
            .map(|c| 1u64 << c.log_len)
            .sum(),
        stacked_source_cells_padded: plan.stack.as_ref().map_or(0, |s| 1u64 << s.bits),
        lookup_checks: plan
            .checks
            .iter()
            .map(|c| {
                let positions: u64 = c.members.iter().map(|m| 1u64 << m.m).sum();
                (c.name.clone(), positions)
            })
            .collect(),
        ..Metrics::default()
    };
    metrics.lookup_positions = metrics.lookup_checks.iter().map(|(_, n)| *n).sum();
    // Track exact unpadded element reads per weight column across Steps 3-7 (INV-7).
    let mut weight_index: Vec<Option<usize>> = vec![None; relation.columns.len()];
    for (w_idx, w) in plan.weights.iter().enumerate() {
        weight_index[w.column.0 as usize] = Some(w_idx);
    }
    let mut col_reads = vec![0u64; plan.weights.len()];
    let member_selected = |member: &Member| -> u64 {
        match &member.selector {
            None => 1u64 << member.m,
            Some(sel) => match &relation.columns[sel.column.0 as usize].kind {
                Kind::Public(v) => (0..(1u64 << member.m))
                    .filter(|&x| v[sel.index(x)] != 0)
                    .count() as u64,
                _ => 0,
            },
        }
    };
    // E16-22: stage timing, off unless STELE_STAGE_TIMES.
    let mut laps = parallel::Laps::start();
    // Step 1.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    absorb_model(t, &certificates)?;
    // Step 2: the stacked source (A4), signed embedding; group blocks largest first,
    // column `j` of a group at `offset + j·2^n`.
    let message = |stack: &Stack, values: &Values| -> Result<Vec<M31>, Error> {
        let mut message = vec![M31::from_i64(0); 1 << stack.bits];
        for group in &plan.groups {
            for (j, id) in group.columns.iter().enumerate() {
                let col = column(relation, values, *id)?;
                let start = group.offset + (j << group.n);
                for (out, v) in message[start..].iter_mut().zip(col) {
                    *out = M31::from_i64(*v);
                }
            }
        }
        Ok(message)
    };
    let commit_msg_timer = Stopwatch::start();
    let committed_message = match &plan.stack {
        Some(stack) => message(stack, committed)?,
        None => Vec::new(),
    };
    let commit_msg_ns = commit_msg_timer.elapsed_ns();
    // Steps 2 and 3 are independent of every challenge: the stacked source and each
    // check's counts, multiplicity source and certificate are pool tasks, and the
    // roots are absorbed in step order below (task E16-23). Errors keep that order.
    let stack_source = || {
        let timer = Stopwatch::start();
        let res = plan
            .stack
            .as_ref()
            .map(|stack| {
                let p =
                    stack
                        .sources
                        .prepare(stack.id, stack.ell, &stack.code, &committed_message)?;
                let (section, handle) = register(&p)?;
                Ok::<_, Error>((p, handle, section))
            })
            .transpose();
        (res, timer.elapsed_ns())
    };
    let mu_messages = |i: usize| {
        let counts = lookup::counts(&plan.checks[i], relation, values)?;
        let message = lookup::multiplicities(&plan.checks[i], &counts)?;
        Ok::<_, Error>((counts, message))
    };
    let ((stacked, commit_prep_ns), (mu_messages, mu_count_ns)) =
        parallel::join(stack_source, || {
            let timer = Stopwatch::start();
            let res = parallel::map(plan.checks.len(), mu_messages)
                .into_iter()
                .collect::<Result<Vec<_>, Error>>();
            (res, timer.elapsed_ns())
        });
    metrics.commitment_ns = commit_msg_ns.saturating_add(commit_prep_ns);
    let stacked = stacked?.map(|(p, handle, section)| {
        proof.groups.push(section);
        (p, handle)
    });
    if let Some((p, _)) = &stacked {
        t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
    }
    let (counts, mu_messages): (Vec<_>, Vec<_>) = mu_messages?.into_iter().unzip();
    let mu_commit_timer = Stopwatch::start();
    let mu = parallel::map(plan.checks.len(), |i| {
        let layout = plan.checks[i].layout;
        let code = mu_code(&plan.checks[i])?;
        let p = plan
            .sources
            .prepare(layout.id, layout.ell, code.code_id(), &mu_messages[i])?;
        let (section, handle) = register(&p)?;
        Ok::<_, Error>((p, handle, section))
    })
    .into_iter()
    .map(|r| {
        let (p, handle, section) = r?;
        t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
        proof.multiplicities.push(section);
        Ok((p, handle))
    })
    .collect::<Result<Vec<_>, Error>>()?;
    metrics.multiplicities_ns = mu_count_ns.saturating_add(mu_commit_timer.elapsed_ns());
    // Step 3 (`lookup::counts`) reads each weight tuple column at every selected position.
    for check in &plan.checks {
        for member in &check.members {
            let mut selected: Option<u64> = None;
            for (r, _) in &member.tuple {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    let count = *selected.get_or_insert_with(|| member_selected(member));
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(count);
                }
            }
        }
    }
    laps.lap("dev/sources_and_counts");
    // Step 4: one zerocheck per identity domain size.
    let zerocheck_timer = Stopwatch::start();
    for &m in &plan.sizes {
        let lambdas = identity_lambdas(t, relation, m)?;
        let (inputs, instance) = combine(relation, m, &lambdas);
        let zc_reads = if round_values.is_some() {
            2u64 << m
        } else {
            1u64 << m
        };
        for r in &inputs {
            if let Some(w_idx) = weight_index[r.column.0 as usize] {
                col_reads[w_idx] = col_reads[w_idx].saturating_add(zc_reads);
            }
        }
        let tables_for = |values: &Values| -> Result<Vec<Vec<K>>, Error> {
            let mut tables = Vec::new();
            for r in &inputs {
                let col = column(relation, values, r.column)?;
                let mut table = vec![K::from_i64(0); 1 << m];
                stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                    for (j, out) in chunk.iter_mut().enumerate() {
                        *out = K::from_i64(col[r.index((start + j) as u64)]);
                    }
                });
                tables.push(table);
            }
            Ok(tables)
        };
        let tables = tables_for(values)?;
        let reference = round_values.map(tables_for).transpose()?;
        let z = zerocheck::Zerocheck {
            instance: &instance,
            skip: 0,
        };
        let (zp, point) = match reference.as_deref() {
            #[cfg(feature = "controls")]
            Some(original) => z.prove_forged_finals(original, &tables, t),
            _ => z.prove_with_point(&tables, t),
        }?;
        let mut out = Vec::new();
        for row in &zp.rounds {
            put(&mut out, row);
        }
        put(&mut out, &zp.final_values);
        for (r, value) in inputs.iter().zip(&zp.final_values) {
            claims.push(r, &point, *value);
        }
        proof.identities.push(out);
    }
    metrics.zerochecks_ns = zerocheck_timer.elapsed_ns();
    laps.lap("dev/zerocheck");
    // Step 5.
    let lookup_timer = Stopwatch::start();
    for ((check, (p, handle)), counts) in plan.checks.iter().zip(&mu).zip(&counts) {
        // `lookup::prove` (`originals`) reads every member position unconditionally.
        for member in &check.members {
            for (r, _) in &member.tuple {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << member.m);
                }
            }
        }
        let mut out = Vec::new();
        lookup::prove(
            t,
            check,
            relation,
            values,
            counts,
            (p, handle),
            &mut out,
            &mut claims,
        )?;
        proof.lookups.push(out);
    }
    metrics.lookups_ns = lookup_timer.elapsed_ns();
    laps.lap("dev/logup");
    // Step 6.
    let matmul_timer = Stopwatch::start();
    for (i, mm) in relation.matmuls.iter().enumerate() {
        // `mle` reads all `2^n` entries of `mm.out`; `MatmulShape::table` skips entries
        // outside `Ref::fixed` bits (RFC-0026 A6), reading `2^n >> fixed_bits` entries.
        if let Some(w_idx) = weight_index[mm.out.column.0 as usize] {
            col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << plan.weights[w_idx].n);
        }
        for r in [&mm.lhs, &mm.rhs] {
            if let Some(w_idx) = weight_index[r.column.0 as usize] {
                let fixed_bits = r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
            }
        }
        let shape = MatmulShape::new(t, mm)?;
        let out = column(relation, values, mm.out.column)?;
        let out_value = mle(out, &restrict(&mm.out, &shape.rho))?;
        let instance = shape.instance(MATMUL | i as u64, out_value);
        let mut tables = Vec::new();
        if !shape.shared.is_empty() {
            tables.push(shape.eq_table());
        }
        tables.push(shape.table(&mm.lhs, column(relation, values, mm.lhs.column)?)?);
        tables.push(shape.table(&mm.rhs, column(relation, values, mm.rhs.column)?)?);
        let mut sc = Vec::new();
        let capture = Capture {
            dense: Dense::new(&instance, tables)?,
            point: &mut sc,
        };
        let sp = stele_sumcheck::prove(&instance, capture, t)?;
        let mut out = Vec::new();
        put(&mut out, &[out_value]);
        for row in &sp.rounds {
            put(&mut out, row);
        }
        put(&mut out, &sp.final_values);
        shape.route(mm, &sc, &sp.final_values, out_value, &mut claims);
        proof.matmuls.push(out);
    }
    metrics.reductions_ns = matmul_timer.elapsed_ns();
    laps.lap("dev/matmul");
    // Step 7: one claim batch and one opening of the stack, then per weight source.
    let openings_timer = Stopwatch::start();
    if let (Some(stack), Some((prepared, handle))) = (&plan.stack, &stacked) {
        let batch = group_claims(plan, stack, &claims);
        #[cfg(feature = "controls")]
        let batch = {
            let mut batch = batch;
            if let Some(column) = plan.column_claim {
                route_column_claim(plan, stack, &claims, column, &mut batch)?;
            }
            batch
        };
        if !batch.is_empty() {
            let opening = Opening {
                id: BATCH,
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            let table = to_k(&message(stack, values)?);
            proof
                .openings
                .push(opening.prove(t, table, prepared, handle)?);
        }
    }
    // One claim batch and one opening per model source (A5).
    for (k, (prepared, certificate)) in model.iter().enumerate() {
        let batch = weight_claims(plan, k, &claims);
        if !batch.is_empty() {
            // One logical opening pass over every weight column in source `k` (unpadded).
            for (w_idx, w) in plan.weights.iter().enumerate() {
                if w.source == k {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << w.n);
                }
            }
            let stack = &plan.model[k];
            let opening = Opening {
                id: BATCH | (1 + k as u64),
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            let table = to_k(&weights_message(relation, plan, k, values)?);
            proof
                .openings
                .push(opening.prove(t, table, prepared, certificate)?);
        }
    }
    metrics.openings_ns = openings_timer.elapsed_ns();
    laps.lap("dev/batch_and_openings");
    let section_bytes =
        |sections: &[Vec<u8>]| -> u64 { sections.iter().map(|s| s.len() as u64).sum() };
    metrics.groups_bytes = section_bytes(&proof.groups);
    metrics.multiplicities_bytes = section_bytes(&proof.multiplicities);
    metrics.identities_bytes = section_bytes(&proof.identities);
    metrics.lookups_bytes = section_bytes(&proof.lookups);
    metrics.matmuls_bytes = section_bytes(&proof.matmuls);
    metrics.openings_bytes = section_bytes(&proof.openings);
    metrics.weight_elements_read = col_reads.iter().copied().fold(0u64, u64::saturating_add);
    metrics.weight_reads = plan
        .weights
        .iter()
        .enumerate()
        .map(|(w_idx, w)| col_reads[w_idx].div_ceil(1u64 << w.n))
        .max()
        .unwrap_or(0);
    Ok((proof, metrics))
}

/// Dense strategy that records the engine's challenges (as in stele-lookup's tree).
struct Capture<'a> {
    dense: Dense<K>,
    point: &'a mut Vec<K>,
}
impl stele_sumcheck::Summand<K> for Capture<'_> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.round(i)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        self.dense.fold(r)?;
        self.point.push(r);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.final_values()
    }
}

/// A5's Circle multiplicity source of a check (its geometry is the plan's, A12);
/// only its code identity is used, under the plan's policy.
fn mu_code(check: &Check) -> Result<Source<K>, Error> {
    mu_source::<K>(check.layout, check.k, [0; 32], stele_pcs::Policy::One).map_err(Error::Lookup)
}

fn register(p: &PreparedSource<'_, K>) -> Result<(Vec<u8>, VerifiedCertificate<K>), Error> {
    let (certificate, _) = p.certificate().map_err(|f| Error::Pcs(f.cause))?;
    let (handle, _) =
        verify_certificate(*p.source(), &certificate).map_err(|f| Error::Pcs(f.cause))?;
    let mut section = p.source().root().to_vec();
    section.extend_from_slice(&certificate);
    Ok((section, handle))
}

/// One step-7 source: A2 mode-1 claim batch, then one A9 point opening.
struct Opening<'a> {
    id: u64,
    tensor: u64,
    bits: u8,
    batch: &'a [(Vec<K>, K)],
}
impl Opening<'_> {
    fn batch(&self) -> claim_batch::Batch<'_, K> {
        claim_batch::Batch {
            id: self.id,
            tensor: self.tensor,
            num_vars: u32::from(self.bits),
            claims: self.batch,
        }
    }
    fn prove(
        &self,
        t: &mut Transcript<K>,
        table: Vec<K>,
        prepared: &PreparedSource<'_, K>,
        handle: &VerifiedCertificate<K>,
    ) -> Result<Vec<u8>, Error> {
        // Batch over the committed table whenever the claims hold on it (always, for an
        // honest prover); otherwise over the proving table, so that a lying prover's
        // only failure is the opening of the committed source below.
        let committed = to_k(prepared.message());
        let same = table == committed;
        let consistent = same
            || self.batch.iter().all(|(point, value)| {
                stele_poly::eq_table(point).is_ok_and(|eq| {
                    committed
                        .iter()
                        .zip(eq)
                        .fold(K::from_i64(0), |s, (v, w)| s + *v * w)
                        == *value
                })
            });
        let batched = if consistent { committed } else { table };
        let (bp, point) = self.batch().prove_with_point(batched, t)?;
        let mut out = Vec::new();
        for row in &bp.rounds {
            put(&mut out, row);
        }
        put(&mut out, &bp.final_values);
        // Open what is committed. When the batch ran over the committed table (always,
        // for an honest prover) that is the batch final value; otherwise evaluate it.
        let committed = if consistent {
            bp.final_values[0]
        } else {
            let eq = stele_poly::eq_table(&point).map_err(|_| Error::Capacity)?;
            to_k(prepared.message())
                .into_iter()
                .zip(eq)
                .fold(K::from_i64(0), |s, (v, w)| s + v * w)
        };
        let (bytes, _) = prepared
            .opening_point(t, handle, self.tensor, &point, committed)
            .map_err(|f| Error::Pcs(f.cause))?;
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    /// Honest opening directly from `prepared.message()` without cloning a second `Vec<K>`
    /// (used by segmented proving where earlier segment `Values` have already been dropped,
    /// RFC-0026 A27).
    fn prove_committed(
        &self,
        t: &mut Transcript<K>,
        prepared: &PreparedSource<'_, K>,
        handle: &VerifiedCertificate<K>,
    ) -> Result<Vec<u8>, Error> {
        let committed = to_k(prepared.message());
        let (bp, point) = self.batch().prove_with_point(committed, t)?;
        let mut out = Vec::new();
        for row in &bp.rounds {
            put(&mut out, row);
        }
        put(&mut out, &bp.final_values);
        let (bytes, _) = prepared
            .opening_point(t, handle, self.tensor, &point, bp.final_values[0])
            .map_err(|f| Error::Pcs(f.cause))?;
        out.extend_from_slice(&bytes);
        Ok(out)
    }
    fn verify(
        &self,
        t: &mut Transcript<K>,
        certificate: &VerifiedCertificate<K>,
        reader: &mut Reader<'_>,
        ledger: &mut Ledger,
        name: &str,
    ) -> Result<(), Error> {
        let mut rounds = Vec::new();
        for _ in 0..self.bits {
            rounds.push(reader.ks(3)?);
        }
        let proof = stele_sumcheck::Proof {
            rounds,
            final_values: reader.ks(1)?,
        };
        let reduction = self.batch().verify(&proof, t)?;
        let size = certificate
            .record()
            .source()
            .proof_size(ProofKind::Opening)
            .map_err(Error::Pcs)?;
        let claim = &reduction.claims[0];
        verify_point(
            t,
            certificate,
            self.tensor,
            &claim.point,
            claim.value,
            reader.take(size)?,
        )
        .map_err(|f| Error::Pcs(f.cause))?;
        ledger.add(
            Line::Rlc,
            name,
            reduction.rlc.numerator,
            reduction.rlc.numerator,
        );
        ledger.add(
            Line::Sc,
            name,
            reduction.sc.numerator,
            u64::from(reduction.sc.degree),
        );
        ledger.pcs_sources += 1;
        ledger.opening(name, certificate.record().source());
        Ok(())
    }
}

/// Verify a development-profile proof against the plan-derived relation. The caller
/// creates `t` with the RFC-0026 §1.1 public inputs; `model` holds the verified
/// certificate of each model source (A5), whose roots the engine also absorbs.
/// Every section count and length is derived here: a missing, extra, short or long
/// section rejects with `ProofShape` (RFC-0026 §4.1).
pub fn verify(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[&VerifiedCertificate<K>],
    proof: &Proof,
    sources: Sources,
) -> Result<Ledger, Error> {
    let plan = plan(relation, sources)?;
    model_check(&plan, model)?;
    let mut ledger = Ledger::default();
    for (k, certificate) in model.iter().enumerate() {
        // A5: the caller verified each model certificate; its rounds are charged here.
        ledger.certificate(&alloc::format!("model {k}"), certificate.record().source());
    }
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);
    // Step 1.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    absorb_model(t, model)?;
    // Step 2: each certificate on its own transcript, then its root here.
    let mut sections = Sections(proof.groups.iter());
    let mut stacked = None;
    if let Some(stack) = &plan.stack {
        let mut reader = sections.next()?;
        let root = reader.root()?;
        let source = stack.source(root)?;
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        let (handle, _) =
            verify_certificate(source, reader.take(size)?).map_err(|f| Error::Pcs(f.cause))?;
        reader.end()?;
        t.absorb(AbsorbLabel::RelationRoots, &root)?;
        ledger.certificate("stack", &source);
        stacked = Some(handle);
    }
    sections.end()?;
    // Step 3: multiplicity layouts are A5's, derived from each check.
    let mut mu = Vec::new();
    let mut sections = Sections(proof.multiplicities.iter());
    for check in &plan.checks {
        let mut reader = sections.next()?;
        let root = reader.root()?;
        let l = check.layout;
        let source = sources.source(l.id, l.ell, mu_code(check)?.code_id(), root)?;
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        // A12: the section length is the derived geometry's, checked before the bytes.
        let bytes = reader.take(size)?;
        reader.end()?;
        let (handle, _) = verify_certificate(source, bytes).map_err(|f| Error::Pcs(f.cause))?;
        t.absorb(AbsorbLabel::RelationRoots, &root)?;
        mu.push(handle);
        ledger.pcs_sources += 1;
        ledger.certificate(&check.name, &source);
    }
    sections.end()?;
    // Step 4.
    let mut sections = Sections(proof.identities.iter());
    for &m in &plan.sizes {
        let mut reader = sections.next()?;
        let lambdas = identity_lambdas(t, relation, m)?;
        let (inputs, instance) = combine(relation, m, &lambdas);
        let degree = instance
            .terms
            .iter()
            .map(|t| t.factors.len())
            .max()
            .unwrap_or(0);
        let mut rounds = Vec::new();
        for _ in 0..m {
            rounds.push(reader.ks(degree + 1)?);
        }
        let zp = zerocheck::Proof {
            skip_values: Vec::new(),
            rounds,
            final_values: reader.ks(inputs.len())?,
        };
        let z = zerocheck::Zerocheck {
            instance: &instance,
            skip: 0,
        };
        reader.end()?;
        let reduction = z.verify(&zp, t)?;
        for (r, claim) in inputs.iter().zip(&reduction.claims) {
            claims.push(r, &claim.point, claim.value);
        }
        let name = alloc::format!("identities/{m}");
        let lambdas = lambdas.len() as u64;
        ledger.add(Line::Rlc, &name, lambdas, lambdas);
        // One entry per phase, so each is an exact enumeration: the `τ` run is one
        // round of its `j` draws, the skip one round of `D`, and the tail `j` rounds of
        // `δ` each (#367 review).
        let [weights, skip, tail] = reduction.sc;
        for (numerator, round) in [
            (weights.numerator, weights.numerator),
            (skip.numerator, skip.numerator),
            (tail.numerator, u64::from(tail.degree)),
        ] {
            if numerator > 0 {
                ledger.add(Line::Sc, &name, numerator, round);
            }
        }
    }
    sections.end()?;
    // Step 5.
    let mut sections = Sections(proof.lookups.iter());
    for (check, handle) in plan.checks.iter().zip(&mu) {
        let mut reader = sections.next()?;
        lookup::verify(
            t,
            check,
            relation,
            handle,
            &mut reader,
            &mut claims,
            &mut ledger,
        )?;
        reader.end()?;
    }
    sections.end()?;
    // Step 6.
    let mut sections = Sections(proof.matmuls.iter());
    for (i, mm) in relation.matmuls.iter().enumerate() {
        let mut reader = sections.next()?;
        let shape = MatmulShape::new(t, mm)?;
        let out_value = reader.k()?;
        let instance = shape.instance(MATMUL | i as u64, out_value);
        let width = if shape.shared.is_empty() { 3 } else { 4 };
        let mut rounds = Vec::new();
        for _ in 0..shape.vars.len() {
            rounds.push(reader.ks(width)?);
        }
        let sp = stele_sumcheck::Proof {
            rounds,
            final_values: reader.ks(instance.inputs.len())?,
        };
        reader.end()?;
        let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
        if !shape.shared.is_empty() && sp.final_values[0] != shape.eq_at(&reduction.point) {
            return Err(Error::EqMismatch);
        }
        shape.route(
            mm,
            &reduction.point,
            &sp.final_values,
            out_value,
            &mut claims,
        );
        ledger.add(Line::Sz, &mm.name, u64::from(mm.free), u64::from(mm.free));
        ledger.add(
            Line::Sc,
            &mm.name,
            reduction.sc.numerator,
            u64::from(reduction.sc.degree),
        );
    }
    sections.end()?;
    // Step 7.
    let mut sections = Sections(proof.openings.iter());
    if let (Some(stack), Some(handle)) = (&plan.stack, &stacked) {
        let batch = group_claims(&plan, stack, &claims);
        if !batch.is_empty() {
            let opening = Opening {
                id: BATCH,
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            let mut reader = sections.next()?;
            opening.verify(t, handle, &mut reader, &mut ledger, "stack")?;
            reader.end()?;
        }
    }
    for (k, certificate) in model.iter().enumerate() {
        let batch = weight_claims(&plan, k, &claims);
        if !batch.is_empty() {
            let stack = &plan.model[k];
            let opening = Opening {
                id: BATCH | (1 + k as u64),
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            let mut reader = sections.next()?;
            opening.verify(t, certificate, &mut reader, &mut ledger, "model")?;
            reader.end()?;
        }
    }
    sections.end()?;
    // §8 step 4: public-column claims, evaluated by the verifier.
    for (i, column) in relation.columns.iter().enumerate() {
        if let Kind::Public(values) = &column.kind {
            for (point, value) in &claims.0[i] {
                if mle(values, point)? != *value {
                    return Err(Error::PublicMismatch(ColumnId(i as u32)));
                }
            }
        }
    }
    Ok(ledger)
}

/// Per-segment plan derived from a validated [`Relation`] (RFC-0026 A27).
struct SegmentPlan {
    segment: u32,
    groups: Vec<Group>,
    stack: Option<Stack>,
    checks: Vec<Check>,
    sizes: Vec<u8>,
    matmuls: Vec<usize>,
}

/// Complete segmented plan (RFC-0026 A27).
struct SegmentedPlan {
    digest: [u8; 32],
    segments: Vec<SegmentPlan>,
    weights: Vec<Weight>,
    model: Vec<Stack>,
    sources: Sources,
}

fn plan_segmented(relation: &Relation, sources: Sources) -> Result<SegmentedPlan, Error> {
    relation.validate().map_err(Error::StatementMismatch)?;
    let seg_count = relation.segments();
    if seg_count > u32::from(u16::MAX) {
        return Err(Error::Unsupported);
    }
    let weight_segs = relation.weight_segments();
    let mut segments = Vec::with_capacity(seg_count as usize);
    for seg in 0..seg_count {
        let seg_u64 = u64::from(seg);
        let source_base = seg_u64 << 16;
        let mut groups = Vec::new();
        for (g, group_meta) in relation.groups.iter().enumerate() {
            if group_meta.segment != seg {
                continue;
            }
            let columns: Vec<ColumnId> = (0..relation.columns.len() as u32)
                .map(ColumnId)
                .filter(|id| {
                    relation.columns[id.0 as usize].kind
                        == Kind::Witness(stele_ir::relation::GroupId(g as u32))
                })
                .collect();
            let c = ceil_log2(columns.len().max(1));
            groups.push(Group {
                columns,
                n: group_meta.log_len,
                c,
                offset: 0,
            });
        }
        let mut order: Vec<usize> = (0..groups.len()).collect();
        order.sort_by(|a, b| (groups[*b].n + groups[*b].c).cmp(&(groups[*a].n + groups[*a].c)));
        let mut total = 0usize;
        for g in order {
            let bits = u32::from(groups[g].n) + u32::from(groups[g].c);
            if bits > 30 {
                return Err(Error::Unsupported);
            }
            groups[g].offset = total;
            total = total.checked_add(1 << bits).ok_or(Error::Unsupported)?;
        }
        let stack = match groups.is_empty() {
            true => None,
            false => {
                let bits = ceil_log2(total);
                if bits > 30 {
                    return Err(Error::Unsupported);
                }
                Some(self::stack(source_base + 2, bits, sources)?)
            }
        };
        let mut targets: Vec<(Target, Vec<Member>)> = Vec::new();
        let mut add =
            |target: Target, member: Member| match targets.iter_mut().find(|(t, _)| *t == target) {
                Some((_, members)) => members.push(member),
                None => targets.push((target, vec![member])),
            };
        for lookup in &relation.lookups {
            if relation.lookup_segment(lookup) != seg {
                continue;
            }
            add(
                Target::Table(lookup.table.0),
                Member {
                    m: lookup.vars,
                    tuple: lookup.tuple.iter().map(|r| (r.clone(), 0)).collect(),
                    selector: lookup.selector.clone(),
                    offset: 0,
                },
            );
        }
        for range in &relation.ranges {
            if relation.range_segment_with(range, &weight_segs) != seg {
                continue;
            }
            let log_len = relation.columns[range.column.0 as usize].log_len;
            add(
                Target::Range(range.width.bits),
                Member {
                    m: log_len,
                    tuple: vec![(Ref::identity(range.column, log_len), -range.width.min())],
                    selector: None,
                    offset: 0,
                },
            );
        }
        if targets.len() >= (1 << 16) - 3 {
            return Err(Error::Unsupported);
        }
        let mut checks = Vec::with_capacity(targets.len());
        for (j, (target, members)) in targets.into_iter().enumerate() {
            let id = source_base | (j as u64);
            let source_id = source_base + 3 + (j as u64);
            let (name, t, entries) = match target {
                Target::Table(table) => {
                    let table = &relation.tables[table as usize];
                    let entries = table.rows.iter().flatten().copied().collect();
                    (table.name.clone(), table.rows.len(), entries)
                }
                Target::Range(bits) => {
                    let t = 1usize << bits;
                    (alloc::format!("range_{bits}"), t, (0..t as i64).collect())
                }
            };
            checks.push(check(id, source_id, name, members, t, entries, sources)?);
        }
        let mut sizes: Vec<u8> = relation
            .identities
            .iter()
            .filter(|i| relation.identity_segment(i) == seg)
            .map(|i| i.vars)
            .collect();
        sizes.extend(
            relation
                .composes
                .iter()
                .filter(|c| relation.compose_segment(c) == seg)
                .map(|c| relation.columns[c.column.0 as usize].log_len),
        );
        sizes.sort_unstable();
        sizes.dedup();
        let matmuls: Vec<usize> = relation
            .matmuls
            .iter()
            .enumerate()
            .filter(|(_, mm)| relation.matmul_segment(mm) == seg)
            .map(|(idx, _)| idx)
            .collect();
        segments.push(SegmentPlan {
            segment: seg,
            groups,
            stack,
            checks,
            sizes,
            matmuls,
        });
    }
    let lengths: Vec<u8> = (0..relation.columns.len())
        .filter(|i| relation.columns[*i].kind == Kind::Weight)
        .map(|i| relation.columns[i].log_len)
        .collect();
    let (placement, model) = model_plan(&lengths, sources)?;
    let weights: Vec<Weight> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .zip(placement)
        .map(|(column, (source, offset))| Weight {
            column,
            n: relation.columns[column.0 as usize].log_len,
            source,
            offset,
        })
        .collect();
    Ok(SegmentedPlan {
        digest: codec::digest(relation),
        segments,
        weights,
        model,
        sources,
    })
}

fn segment_stack_message(
    groups: &[Group],
    stack: &Stack,
    relation: &Relation,
    values: &Values,
) -> Result<Vec<M31>, Error> {
    let mut message = vec![M31::from_i64(0); 1 << stack.bits];
    for group in groups {
        for (j, id) in group.columns.iter().enumerate() {
            let col = column(relation, values, *id)?;
            let start = group.offset + (j << group.n);
            for (out, v) in message[start..].iter_mut().zip(col) {
                *out = M31::from_i64(*v);
            }
        }
    }
    Ok(message)
}

/// Produce a segmented development proof (`stele-dev-e2e-v2`, RFC-0026 A27), streaming
/// one segment's [`Values`] at a time via `segment_values(s)` and retaining at most two
/// consecutive segments' witness commitment data in memory.
pub fn prove_segmented<F>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
) -> Result<ProofV2, Error>
where
    F: FnMut(u32) -> Result<Values, Error>,
{
    prove_segmented_measured(t, relation, segment_values, model, sources).map(|(p, _)| p)
}

/// [`prove_segmented`] together with stage timings and deterministic counters (RFC-0018 A2, RFC-0026 A27).
pub fn prove_segmented_measured<F>(
    t: &mut Transcript<K>,
    relation: &Relation,
    mut segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<Values, Error>,
{
    let plan_timer = Stopwatch::start();
    let plan = plan_segmented(relation, sources)?;
    let plan_ns = plan_timer.elapsed_ns();
    let certificates: Vec<&VerifiedCertificate<K>> = model.iter().map(|(_, c)| *c).collect();
    model_check_stacks(&plan.model, &certificates)?;
    if model
        .iter()
        .any(|(p, c)| p.source().bytes() != c.record().source().bytes())
    {
        return Err(Error::Weights);
    }

    let mut lookup_checks: Vec<(String, u64)> = Vec::new();
    for seg in &plan.segments {
        for c in &seg.checks {
            let positions: u64 = c.members.iter().map(|m| 1u64 << m.m).sum();
            if let Some((_, total)) = lookup_checks.iter_mut().find(|(n, _)| *n == c.name) {
                *total = total.saturating_add(positions);
            } else {
                lookup_checks.push((c.name.clone(), positions));
            }
        }
    }
    let mut metrics = Metrics {
        plan_ns,
        committed_cells: relation
            .columns
            .iter()
            .filter(|c| matches!(c.kind, Kind::Witness(_)))
            .map(|c| 1u64 << c.log_len)
            .sum(),
        stacked_source_cells_padded: plan
            .segments
            .iter()
            .filter_map(|seg| seg.stack.as_ref().map(|s| 1u64 << s.bits))
            .sum(),
        lookup_positions: lookup_checks.iter().map(|(_, n)| *n).sum(),
        lookup_checks,
        ..Metrics::default()
    };

    let mut weight_index: Vec<Option<usize>> = vec![None; relation.columns.len()];
    for (w_idx, w) in plan.weights.iter().enumerate() {
        weight_index[w.column.0 as usize] = Some(w_idx);
    }
    let mut col_reads = vec![0u64; plan.weights.len()];
    let member_selected = |member: &Member| -> u64 {
        match &member.selector {
            None => 1u64 << member.m,
            Some(sel) => match &relation.columns[sel.column.0 as usize].kind {
                Kind::Public(v) => (0..(1u64 << member.m))
                    .filter(|&x| v[sel.index(x)] != 0)
                    .count() as u64,
                _ => 0,
            },
        }
    };

    let mut proof = ProofV2 {
        segments: vec![SegmentProof::default(); plan.segments.len()],
        model_openings: Vec::new(),
    };
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);

    // Step 1: statement digest and model roots.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    absorb_model(t, &certificates)?;

    // At most two segments' prepared witness stacks live at any time: `prev` and `curr`.
    let mut prev: Option<(usize, PreparedSource<'static, K>, VerifiedCertificate<K>)> = None;

    for (s, seg) in plan.segments.iter().enumerate() {
        let values = segment_values(seg.segment)?;

        // Step 2.1 + 2.2: commit segment `s`'s witness stack (owned) alongside multiplicity counts.
        let commit_msg_timer = Stopwatch::start();
        let committed_message = match &seg.stack {
            Some(stack) => Some(segment_stack_message(
                &seg.groups,
                stack,
                relation,
                &values,
            )?),
            None => None,
        };
        let commit_msg_ns = commit_msg_timer.elapsed_ns();

        let stack_source = || {
            let timer = Stopwatch::start();
            let res = match (&seg.stack, committed_message) {
                (Some(stack), Some(msg)) => {
                    let p = stack
                        .sources
                        .prepare_owned(stack.id, stack.ell, &stack.code, msg);
                    p.and_then(|p| {
                        let (section, handle) = register(&p)?;
                        Ok((p, handle, section))
                    })
                    .map(Some)
                }
                _ => Ok(None),
            };
            (res, timer.elapsed_ns())
        };
        let mu_messages_fn = |i: usize| {
            let counts = lookup::counts(&seg.checks[i], relation, &values)?;
            let message = lookup::multiplicities(&seg.checks[i], &counts)?;
            Ok::<_, Error>((counts, message))
        };
        let ((stacked, commit_prep_ns), (mu_messages, mu_count_ns)) =
            parallel::join(stack_source, || {
                let timer = Stopwatch::start();
                let res = parallel::map(seg.checks.len(), mu_messages_fn)
                    .into_iter()
                    .collect::<Result<Vec<_>, Error>>();
                (res, timer.elapsed_ns())
            });
        metrics.commitment_ns = metrics
            .commitment_ns
            .saturating_add(commit_msg_ns.saturating_add(commit_prep_ns));

        let curr = stacked?.map(|(p, handle, section)| {
            proof.segments[s].groups.push(section);
            (s, p, handle)
        });
        if let Some((_, p, _)) = &curr {
            t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
        }

        let (counts, mu_messages): (Vec<_>, Vec<_>) = mu_messages?.into_iter().unzip();
        let mu_commit_timer = Stopwatch::start();
        let mu = parallel::map(seg.checks.len(), |i| {
            let layout = seg.checks[i].layout;
            let code = mu_code(&seg.checks[i])?;
            let p = plan
                .sources
                .prepare(layout.id, layout.ell, code.code_id(), &mu_messages[i])?;
            let (section, handle) = register(&p)?;
            Ok::<_, Error>((p, handle, section))
        })
        .into_iter()
        .map(|r| {
            let (p, handle, section) = r?;
            t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
            proof.segments[s].multiplicities.push(section);
            Ok((p, handle))
        })
        .collect::<Result<Vec<_>, Error>>()?;
        metrics.multiplicities_ns = metrics
            .multiplicities_ns
            .saturating_add(mu_count_ns.saturating_add(mu_commit_timer.elapsed_ns()));

        for check in &seg.checks {
            for member in &check.members {
                let mut selected: Option<u64> = None;
                for (r, _) in &member.tuple {
                    if let Some(w_idx) = weight_index[r.column.0 as usize] {
                        let count = *selected.get_or_insert_with(|| member_selected(member));
                        col_reads[w_idx] = col_reads[w_idx].saturating_add(count);
                    }
                }
            }
        }

        // Step 2.3 (a): zerochecks for segment `s`.
        let zerocheck_timer = Stopwatch::start();
        let seg_zc_base = ZEROCHECK | (u64::from(seg.segment) << 16);
        for &m in &seg.sizes {
            let lambdas = identity_lambdas_for(t, relation, Some(seg.segment), m)?;
            let (inputs, instance) = combine_for(
                relation,
                Some(seg.segment),
                m,
                seg_zc_base | u64::from(m),
                &lambdas,
            );
            let zc_reads = 1u64 << m;
            for r in &inputs {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(zc_reads);
                }
            }
            let mut tables = Vec::with_capacity(inputs.len());
            for r in &inputs {
                let col = column(relation, &values, r.column)?;
                let mut table = vec![K::from_i64(0); 1 << m];
                stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                    for (j, out) in chunk.iter_mut().enumerate() {
                        *out = K::from_i64(col[r.index((start + j) as u64)]);
                    }
                });
                tables.push(table);
            }
            let z = zerocheck::Zerocheck {
                instance: &instance,
                skip: 0,
            };
            let (zp, point) = z.prove_with_point(&tables, t)?;
            let mut out = Vec::new();
            for row in &zp.rounds {
                put(&mut out, row);
            }
            put(&mut out, &zp.final_values);
            for (r, value) in inputs.iter().zip(&zp.final_values) {
                claims.push(r, &point, *value);
            }
            proof.segments[s].identities.push(out);
        }
        metrics.zerochecks_ns = metrics
            .zerochecks_ns
            .saturating_add(zerocheck_timer.elapsed_ns());

        // Step 2.3 (b): lookups for segment `s`.
        let lookup_timer = Stopwatch::start();
        for ((check, (p, handle)), counts) in seg.checks.iter().zip(&mu).zip(&counts) {
            for member in &check.members {
                for (r, _) in &member.tuple {
                    if let Some(w_idx) = weight_index[r.column.0 as usize] {
                        col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << member.m);
                    }
                }
            }
            let mut out = Vec::new();
            lookup::prove(
                t,
                check,
                relation,
                &values,
                counts,
                (p, handle),
                &mut out,
                &mut claims,
            )?;
            proof.segments[s].lookups.push(out);
        }
        drop(mu);
        drop(mu_messages);
        drop(counts);
        metrics.lookups_ns = metrics.lookups_ns.saturating_add(lookup_timer.elapsed_ns());

        // Step 2.3 (c): matmuls for segment `s`.
        let matmul_timer = Stopwatch::start();
        for &mm_idx in &seg.matmuls {
            let mm = &relation.matmuls[mm_idx];
            if let Some(w_idx) = weight_index[mm.out.column.0 as usize] {
                col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << plan.weights[w_idx].n);
            }
            for r in [&mm.lhs, &mm.rhs] {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    let fixed_bits =
                        r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                    let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
                }
            }
            let shape = MatmulShape::new(t, mm)?;
            let out = column(relation, &values, mm.out.column)?;
            let out_value = mle(out, &restrict(&mm.out, &shape.rho))?;
            let instance = shape.instance(MATMUL | mm_idx as u64, out_value);
            let mut tables = Vec::new();
            if !shape.shared.is_empty() {
                tables.push(shape.eq_table());
            }
            tables.push(shape.table(&mm.lhs, column(relation, &values, mm.lhs.column)?)?);
            tables.push(shape.table(&mm.rhs, column(relation, &values, mm.rhs.column)?)?);
            let mut sc = Vec::new();
            let capture = Capture {
                dense: Dense::new(&instance, tables)?,
                point: &mut sc,
            };
            let sp = stele_sumcheck::prove(&instance, capture, t)?;
            let mut out = Vec::new();
            put(&mut out, &[out_value]);
            for row in &sp.rounds {
                put(&mut out, row);
            }
            put(&mut out, &sp.final_values);
            shape.route(mm, &sc, &sp.final_values, out_value, &mut claims);
            proof.segments[s].matmuls.push(out);
        }
        metrics.reductions_ns = metrics
            .reductions_ns
            .saturating_add(matmul_timer.elapsed_ns());

        // Step 2.4: drop segment `s` witness/weight `Values` before opening `prev`.
        drop(values);

        // Step 2.5: all claims on segment `s - 1` are now complete; batch, open, and drop it.
        let openings_timer = Stopwatch::start();
        if let Some((prev_s, prev_prepared, prev_handle)) = prev.take() {
            let prev_seg = &plan.segments[prev_s];
            if let Some(prev_stack) = &prev_seg.stack {
                let batch = group_claims_for(&prev_seg.groups, prev_stack, &claims);
                if !batch.is_empty() {
                    let opening = Opening {
                        id: BATCH | ((prev_s as u64) << 32),
                        tensor: prev_stack.id,
                        bits: prev_stack.bits,
                        batch: &batch,
                    };
                    proof.segments[prev_s]
                        .openings
                        .push(opening.prove_committed(t, &prev_prepared, &prev_handle)?);
                }
            }
        }
        metrics.openings_ns = metrics
            .openings_ns
            .saturating_add(openings_timer.elapsed_ns());
        prev = curr;
    }

    // Step 3: open the last segment's witness stack, drop it, then open each model source once.
    let openings_timer = Stopwatch::start();
    if let Some((last_s, last_prepared, last_handle)) = prev.take() {
        let last_seg = &plan.segments[last_s];
        if let Some(last_stack) = &last_seg.stack {
            let batch = group_claims_for(&last_seg.groups, last_stack, &claims);
            if !batch.is_empty() {
                let opening = Opening {
                    id: BATCH | ((last_s as u64) << 32),
                    tensor: last_stack.id,
                    bits: last_stack.bits,
                    batch: &batch,
                };
                proof.segments[last_s]
                    .openings
                    .push(opening.prove_committed(t, &last_prepared, &last_handle)?);
            }
        }
    }
    for (k, (prepared, certificate)) in model.iter().enumerate() {
        let batch = weight_claims_for(&plan.weights, &plan.model, k, &claims);
        if !batch.is_empty() {
            for (w_idx, w) in plan.weights.iter().enumerate() {
                if w.source == k {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << w.n);
                }
            }
            let stack = &plan.model[k];
            let opening = Opening {
                id: BATCH | (1 + k as u64),
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            proof
                .model_openings
                .push(opening.prove_committed(t, prepared, certificate)?);
        }
    }
    metrics.openings_ns = metrics
        .openings_ns
        .saturating_add(openings_timer.elapsed_ns());

    let section_bytes =
        |sections: &[Vec<u8>]| -> u64 { sections.iter().map(|s| s.len() as u64).sum() };
    for seg in &proof.segments {
        metrics.groups_bytes += section_bytes(&seg.groups);
        metrics.multiplicities_bytes += section_bytes(&seg.multiplicities);
        metrics.identities_bytes += section_bytes(&seg.identities);
        metrics.lookups_bytes += section_bytes(&seg.lookups);
        metrics.matmuls_bytes += section_bytes(&seg.matmuls) + section_bytes(&seg.reductions);
        metrics.openings_bytes += section_bytes(&seg.openings);
    }
    metrics.openings_bytes += section_bytes(&proof.model_openings);
    metrics.weight_elements_read = col_reads.iter().copied().fold(0u64, u64::saturating_add);
    metrics.weight_reads = plan
        .weights
        .iter()
        .enumerate()
        .map(|(w_idx, w)| col_reads[w_idx].div_ceil(1u64 << w.n))
        .max()
        .unwrap_or(0);
    Ok((proof, metrics))
}

/// Verify a segmented development proof (`stele-dev-e2e-v2`, RFC-0026 A27) and return its ledger.
pub fn verify_segmented(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[&VerifiedCertificate<K>],
    proof: &ProofV2,
    sources: Sources,
) -> Result<Ledger, Error> {
    let plan = plan_segmented(relation, sources)?;
    model_check_stacks(&plan.model, model)?;
    if proof.segments.len() != plan.segments.len() {
        return Err(Error::ProofShape);
    }
    let mut ledger = Ledger::default();
    for (k, certificate) in model.iter().enumerate() {
        ledger.certificate(&alloc::format!("model {k}"), certificate.record().source());
    }
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);

    // Step 1.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    absorb_model(t, model)?;

    let mut prev: Option<(usize, VerifiedCertificate<K>)> = None;

    for (s, (seg, seg_proof)) in plan.segments.iter().zip(&proof.segments).enumerate() {
        // Step 2.1: witness stack certificate.
        let mut sections = Sections(seg_proof.groups.iter());
        let mut curr = None;
        if let Some(stack) = &seg.stack {
            let mut reader = sections.next()?;
            let root = reader.root()?;
            let source = stack.source(root)?;
            let size = source
                .proof_size(ProofKind::Certificate)
                .map_err(Error::Pcs)?;
            let (handle, _) =
                verify_certificate(source, reader.take(size)?).map_err(|f| Error::Pcs(f.cause))?;
            reader.end()?;
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            ledger.certificate(&alloc::format!("s{s}/stack"), &source);
            curr = Some((s, handle));
        }
        sections.end()?;

        // Step 2.2: multiplicity certificates.
        let mut mu = Vec::with_capacity(seg.checks.len());
        let mut sections = Sections(seg_proof.multiplicities.iter());
        for check in &seg.checks {
            let mut reader = sections.next()?;
            let root = reader.root()?;
            let l = check.layout;
            let source = sources.source(l.id, l.ell, mu_code(check)?.code_id(), root)?;
            let size = source
                .proof_size(ProofKind::Certificate)
                .map_err(Error::Pcs)?;
            let bytes = reader.take(size)?;
            reader.end()?;
            let (handle, _) = verify_certificate(source, bytes).map_err(|f| Error::Pcs(f.cause))?;
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            mu.push(handle);
            ledger.pcs_sources += 1;
            ledger.certificate(&alloc::format!("s{s}/{}", check.name), &source);
        }
        sections.end()?;

        // Step 2.3 (a): zerochecks.
        let mut sections = Sections(seg_proof.identities.iter());
        let seg_zc_base = ZEROCHECK | (u64::from(seg.segment) << 16);
        for &m in &seg.sizes {
            let mut reader = sections.next()?;
            let lambdas = identity_lambdas_for(t, relation, Some(seg.segment), m)?;
            let (inputs, instance) = combine_for(
                relation,
                Some(seg.segment),
                m,
                seg_zc_base | u64::from(m),
                &lambdas,
            );
            let degree = instance
                .terms
                .iter()
                .map(|t| t.factors.len())
                .max()
                .unwrap_or(0);
            let mut rounds = Vec::new();
            for _ in 0..m {
                rounds.push(reader.ks(degree + 1)?);
            }
            let zp = zerocheck::Proof {
                skip_values: Vec::new(),
                rounds,
                final_values: reader.ks(inputs.len())?,
            };
            let z = zerocheck::Zerocheck {
                instance: &instance,
                skip: 0,
            };
            reader.end()?;
            let reduction = z.verify(&zp, t)?;
            for (r, claim) in inputs.iter().zip(&reduction.claims) {
                claims.push(r, &claim.point, claim.value);
            }
            let name = alloc::format!("s{s}/identities/{m}");
            let lambdas = lambdas.len() as u64;
            ledger.add(Line::Rlc, &name, lambdas, lambdas);
            let [weights, skip, tail] = reduction.sc;
            for (numerator, round) in [
                (weights.numerator, weights.numerator),
                (skip.numerator, skip.numerator),
                (tail.numerator, u64::from(tail.degree)),
            ] {
                if numerator > 0 {
                    ledger.add(Line::Sc, &name, numerator, round);
                }
            }
        }
        sections.end()?;

        // Step 2.3 (b): lookups.
        let mut sections = Sections(seg_proof.lookups.iter());
        for (check, handle) in seg.checks.iter().zip(&mu) {
            let mut reader = sections.next()?;
            lookup::verify(
                t,
                check,
                relation,
                handle,
                &mut reader,
                &mut claims,
                &mut ledger,
            )?;
            reader.end()?;
        }
        sections.end()?;

        // Step 2.3 (c): matmuls.
        let mut sections = Sections(seg_proof.matmuls.iter());
        for &mm_idx in &seg.matmuls {
            let mm = &relation.matmuls[mm_idx];
            let mut reader = sections.next()?;
            let shape = MatmulShape::new(t, mm)?;
            let out_value = reader.k()?;
            let instance = shape.instance(MATMUL | mm_idx as u64, out_value);
            let width = if shape.shared.is_empty() { 3 } else { 4 };
            let mut rounds = Vec::new();
            for _ in 0..shape.vars.len() {
                rounds.push(reader.ks(width)?);
            }
            let sp = stele_sumcheck::Proof {
                rounds,
                final_values: reader.ks(instance.inputs.len())?,
            };
            reader.end()?;
            let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
            if !shape.shared.is_empty() && sp.final_values[0] != shape.eq_at(&reduction.point) {
                return Err(Error::EqMismatch);
            }
            shape.route(
                mm,
                &reduction.point,
                &sp.final_values,
                out_value,
                &mut claims,
            );
            ledger.add(Line::Sz, &mm.name, u64::from(mm.free), u64::from(mm.free));
            ledger.add(
                Line::Sc,
                &mm.name,
                reduction.sc.numerator,
                u64::from(reduction.sc.degree),
            );
        }
        sections.end()?;

        // RFC-0026 A27 has no virtual columns, so `reductions` must be empty.
        if !seg_proof.reductions.is_empty() {
            return Err(Error::ProofShape);
        }

        // Step 2.5: open segment `s - 1`'s witness stack (all claims on it are complete).
        if let Some((prev_s, prev_handle)) = prev.take() {
            let prev_seg = &plan.segments[prev_s];
            let mut open_sections = Sections(proof.segments[prev_s].openings.iter());
            if let Some(prev_stack) = &prev_seg.stack {
                let batch = group_claims_for(&prev_seg.groups, prev_stack, &claims);
                if !batch.is_empty() {
                    let opening = Opening {
                        id: BATCH | ((prev_s as u64) << 32),
                        tensor: prev_stack.id,
                        bits: prev_stack.bits,
                        batch: &batch,
                    };
                    let mut reader = open_sections.next()?;
                    opening.verify(
                        t,
                        &prev_handle,
                        &mut reader,
                        &mut ledger,
                        &alloc::format!("s{prev_s}/stack"),
                    )?;
                    reader.end()?;
                }
            }
            open_sections.end()?;
        } else if s > 0 && !proof.segments[s - 1].openings.is_empty() {
            return Err(Error::ProofShape);
        }

        prev = curr;
    }

    // Step 3: verify the last segment's witness opening, then model openings.
    if let Some((last_s, last_handle)) = prev.take() {
        let last_seg = &plan.segments[last_s];
        let mut open_sections = Sections(proof.segments[last_s].openings.iter());
        if let Some(last_stack) = &last_seg.stack {
            let batch = group_claims_for(&last_seg.groups, last_stack, &claims);
            if !batch.is_empty() {
                let opening = Opening {
                    id: BATCH | ((last_s as u64) << 32),
                    tensor: last_stack.id,
                    bits: last_stack.bits,
                    batch: &batch,
                };
                let mut reader = open_sections.next()?;
                opening.verify(
                    t,
                    &last_handle,
                    &mut reader,
                    &mut ledger,
                    &alloc::format!("s{last_s}/stack"),
                )?;
                reader.end()?;
            }
        }
        open_sections.end()?;
    } else if let Some(last) = proof.segments.last() {
        if !last.openings.is_empty() {
            return Err(Error::ProofShape);
        }
    }

    let mut sections = Sections(proof.model_openings.iter());
    for (k, certificate) in model.iter().enumerate() {
        let batch = weight_claims_for(&plan.weights, &plan.model, k, &claims);
        if !batch.is_empty() {
            let stack = &plan.model[k];
            let opening = Opening {
                id: BATCH | (1 + k as u64),
                tensor: stack.id,
                bits: stack.bits,
                batch: &batch,
            };
            let mut reader = sections.next()?;
            opening.verify(t, certificate, &mut reader, &mut ledger, "model")?;
            reader.end()?;
        }
    }
    sections.end()?;

    // Public-column claims, evaluated by the verifier.
    for (i, column) in relation.columns.iter().enumerate() {
        if let Kind::Public(values) = &column.kind {
            for (point, value) in &claims.0[i] {
                if mle(values, point)? != *value {
                    return Err(Error::PublicMismatch(ColumnId(i as u32)));
                }
            }
        }
    }
    Ok(ledger)
}

#[cfg(test)]
#[path = "relation_tests.rs"]
mod tests;
