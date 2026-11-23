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
use core::borrow::Borrow;
use core::fmt;
use stele_field::{Field, Serialize, M31, QM31};
use stele_hash::{AbsorbLabel, ChallengeLabel, HashUsage, Transcript};
use stele_ir::relation::{
    ColumnId, ColumnSlice, Def, Identity, Indexer, Invalid, Kind, Ref, Relation,
    Term as IdentityTerm, Values,
};
use stele_pcs::{
    verify_certificate, verify_point, PreparedSource, ProofKind, Source, VerifiedCertificate,
};
use stele_sumcheck::{claim_batch, parallel, zerocheck, Dense, DenseTable, Instance, Term};

#[path = "relation_codec.rs"]
mod codec;
#[path = "relation_lookup.rs"]
mod lookup;
#[path = "relation_recursive.rs"]
mod recursive;
pub use codec::{digest, encode};
pub use recursive::{
    prove_recursive_measured, recursive_model_layout, recursive_model_layout_for,
    recursive_model_sources, verify_recursive, verify_recursive_model, RecursiveModelLayout,
    RecursiveModelSource,
};

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
    /// An RFC-0029 recursive commitment or joined tail rejected.
    Recursive(stele_pcs::recursive::RecursiveError),
    /// A batched lookup's member evaluations do not sum to its tuple claim (A3).
    MemberSumMismatch,
    /// A matmul's shared-bit equality factor disagrees with eq(ρ, r).
    EqMismatch,
    /// A public column claim disagrees with the public values.
    PublicMismatch(ColumnId),
    /// A Linear virtual column reduction's operand evaluations disagree with its claimed value (RFC-0028 §2.4).
    LinearMismatch(ColumnId),
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
impl From<stele_pcs::recursive::RecursiveError> for Error {
    fn from(e: stele_pcs::recursive::RecursiveError) -> Self {
        Self::Recursive(e)
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
    /// Certified registration rounds of an RFC-0029 version-4 model source (RFC-0026 A29).
    fn certified_registration(
        &mut self,
        name: &str,
        cert: &stele_pcs::recursive::CertificateLedger,
    ) {
        self.pcs.push(PcsRound {
            name: name.into(),
            tensor: Some(cert.proximity_numerator),
            target: 0,
            grind: 0,
        });
        self.pcs.push(PcsRound {
            name: name.into(),
            tensor: None,
            target: u32::from(cert.target_bits),
            grind: 0,
        });
    }
    /// Soundness ledger lines for one RFC-0029 recursion level (RFC-0029 §5, RFC-0012 A20).
    fn recursive_level(
        &mut self,
        name: &str,
        lvl: &stele_pcs::recursive::LevelLedger,
        count_proximity: bool,
    ) {
        if count_proximity && lvl.proximity_numerator > 0 {
            self.pcs.push(PcsRound {
                name: name.into(),
                tensor: Some(lvl.proximity_numerator),
                target: 0,
                grind: 0,
            });
        }
        self.pcs.push(PcsRound {
            name: name.into(),
            tensor: None,
            target: u32::from(lvl.target_bits),
            grind: 0,
        });
        if lvl.sumcheck_numerator > 0 {
            self.add(Line::Sc, name, lvl.sumcheck_numerator, 2);
        }
        if lvl.beta_numerator > 0 {
            self.add(Line::Rlc, name, lvl.beta_numerator, lvl.beta_numerator);
        }
        if lvl.gamma_numerator > 0 {
            self.add(Line::Rlc, name, lvl.gamma_numerator, lvl.gamma_numerator);
        }
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
    /// Number of claimed `Def::Contraction` virtual columns reduced in Step 2.4 (RFC-0028 §2.4).
    pub contractions_reduced: u64,
    /// Number of operand partial evaluations (`MatmulShape::table`) executed across all
    /// `Def::Contraction` reductions; equals `2 * contractions_reduced` (one per operand per
    /// contraction regardless of claim count, task E18-03).
    pub contraction_partial_evals: u64,
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
const VIRTUAL_BATCH: u64 = (1 << 62) | (4 << 48);
const VIRTUAL_CONTRACTION: u64 = (1 << 62) | (5 << 48);
const VIRTUAL_POINTWISE: u64 = (1 << 62) | (6 << 48);
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
    /// A14: `CircleAll`, with each check's `(β, α)` round ground at the
    /// least bits meeting RFC-0012 A17 (C1) (profile byte 5).
    CircleAllGrind,
    /// A29 / RFC-0029: coefficient-form Circle sources (version 4, Policy 3) for segments,
    /// stacked multiplicity sources, and certified model sources joining one recursion
    /// per proof (profile byte 6, task E19-04).
    CircleRecursive,
    /// A31: `CircleRecursive`, with the width of every weight column carried by the model's
    /// passport and no weight range check in the proof (profile byte 7).
    CirclePassport,
}
impl Sources {
    /// Stacked and model sources are A11's Circle rate-1/4 sources (A11, A12).
    fn circle(self) -> bool {
        self != Sources::Expander
    }
    /// Every multiplicity source is Circle rate 1/4 (A12, A14, A29).
    fn quarter_mu(self) -> bool {
        matches!(
            self,
            Sources::CircleAll
                | Sources::CircleAllGrind
                | Sources::CircleRecursive
                | Sources::CirclePassport
        )
    }
    /// A29's source set, proved and verified by the joined recursion (`relation::recursive`).
    pub fn recursive(self) -> bool {
        matches!(self, Sources::CircleRecursive | Sources::CirclePassport)
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

/// Default lookup instance domain bound `B` (RFC-0026 A8): 2^30 positions per instance.
pub const DEFAULT_INSTANCE_BOUND: u8 = 30;

/// RFC-0026 A30, the split floor `F` of profile byte 6: a check above `2^F` positions is
/// split even when it fits `2^B`.
pub const SPLIT_FLOOR: u8 = 25;

/// The instance bound of one check under profile byte 6 (RFC-0026 A8 as amended by A30):
/// `min(B, max(F, m − 2))` for a check whose members hold `positions` in all and
/// `m = ceil(log2 positions)`. So a check of at most `2^F` positions is one instance, and a
/// larger one has at most four instances up to `m = B + 2`.
fn check_bound(instance_bound: u8, positions: u64) -> u8 {
    let m = (u64::BITS - positions.max(1).wrapping_sub(1).leading_zeros()) as u8;
    instance_bound.min(SPLIT_FLOOR.max(m.saturating_sub(2)))
}

/// One lookup or range inside its table's batched A5 statement (RFC-0026 A3, A8).
pub(crate) struct Member {
    m: u8,
    /// Leading domain bits cut by RFC-0026 A8 when the original member exceeded `2^B`; 0 if unsplit.
    block_bits: u8,
    /// Aligned block index in `0..2^block_bits`; 0 if unsplit.
    block_index: usize,
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
    /// `Some(j)` for instance `j` of a split check (A8), whose name ends in `/inst<j>`.
    instance: Option<usize>,
    /// Test-only malicious-prover seam: added to the committed count of row 0.
    #[cfg(test)]
    skew: i64,
    /// Malicious-prover seam (tests and the `controls` feature; RFC-0026 A8 control
    /// NC-1341): override this instance's committed multiplicities, so a member value can
    /// move across an instance boundary without its multiplicity.
    #[cfg(any(test, feature = "controls"))]
    count_override: Option<Vec<i64>>,
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
        instance: None,
        #[cfg(test)]
        skew: 0,
        #[cfg(any(test, feature = "controls"))]
        count_override: None,
        #[cfg(test)]
        split: None,
        #[cfg(any(test, feature = "controls"))]
        shift: 0,
    })
}

/// Build RFC-0026 A3 & A8 check instances for `targets` under domain bound `B = instance_bound`;
/// under profile byte 6 each check has its own bound ([`check_bound`], A30).
/// Unsplit targets (`total <= 2^B`, and `<= 2^25` under byte 6) keep identical ids, source
/// ids and names.
fn build_a8_checks(
    targets: Vec<(Target, Vec<Member>)>,
    relation: &Relation,
    sources: Sources,
    instance_bound: u8,
    id_base: u64,
    source_base: u64,
    max_checks: Option<usize>,
) -> Result<Vec<Check>, Error> {
    if instance_bound == 0 || instance_bound > 30 {
        return Err(Error::Unsupported);
    }
    let mut checks = Vec::new();
    for (target, raw_members) in targets {
        // RFC-0026 A30: under profile byte 6 a check has its own bound, at most the plan's.
        // The other profiles keep A8's: A15 §6.3 and the independent replay plan one
        // instance per check.
        let instance_bound = if sources.recursive() {
            let positions = raw_members.iter().fold(0u64, |n, member| {
                n.saturating_add(1u64.checked_shl(u32::from(member.m)).unwrap_or(u64::MAX))
            });
            check_bound(instance_bound, positions)
        } else {
            instance_bound
        };
        let cap = 1usize << instance_bound;
        let (base_name, t, entries) = match target {
            Target::Table(table) => {
                let table = &relation.tables[table as usize];
                let entries: Vec<i64> = table.rows.iter().flatten().copied().collect();
                (table.name.clone(), table.rows.len(), entries)
            }
            Target::Range(bits) => {
                let t = 1usize << bits;
                (alloc::format!("range_{bits}"), t, (0..t as i64).collect())
            }
        };
        // RFC-0026 A8: cut members larger than 2^B along their leading domain bits first,
        // then sort in A3 descending-size order and split into <= 2^B instances.
        let mut expanded = Vec::new();
        for member in raw_members {
            if member.m > instance_bound {
                let block_bits = member.m - instance_bound;
                let blocks = 1usize << block_bits;
                for block_index in 0..blocks {
                    expanded.push(Member {
                        m: instance_bound,
                        block_bits,
                        block_index,
                        tuple: member.tuple.clone(),
                        selector: member.selector.clone(),
                        offset: 0,
                    });
                }
            } else {
                expanded.push(member);
            }
        }
        expanded.sort_by(|a, b| b.m.cmp(&a.m));
        let mut buckets: Vec<Vec<Member>> = Vec::new();
        let mut cur = Vec::new();
        let mut cur_total = 0usize;
        for member in expanded {
            let size = 1usize << member.m;
            if !cur.is_empty() && cur_total + size > cap {
                buckets.push(cur);
                cur = Vec::new();
                cur_total = 0;
            }
            cur_total += size;
            cur.push(member);
        }
        if !cur.is_empty() {
            buckets.push(cur);
        }
        let multi = buckets.len() > 1;
        for (inst_idx, members) in buckets.into_iter().enumerate() {
            if let Some(limit) = max_checks {
                if checks.len() >= limit {
                    return Err(Error::Unsupported);
                }
            }
            let idx = checks.len() as u64;
            let name = if multi {
                alloc::format!("{base_name}/inst{inst_idx}")
            } else {
                base_name.clone()
            };
            let mut instance = check(
                id_base | idx,
                source_base + idx,
                name,
                members,
                t,
                entries.clone(),
                sources,
            )?;
            instance.instance = multi.then_some(inst_idx);
            checks.push(instance);
        }
    }
    Ok(checks)
}

fn plan(relation: &Relation, sources: Sources) -> Result<Plan, Error> {
    plan_with_bound(relation, sources, DEFAULT_INSTANCE_BOUND)
}

/// Derive the plan with RFC-0026 A8 lookup instance bound `B` (`1 <= B <= 30`; default 30).
/// Unsplit plans (every target total `<= 2^B`) produce identical checks, ids and proof bytes.
fn plan_with_bound(
    relation: &Relation,
    sources: Sources,
    instance_bound: u8,
) -> Result<Plan, Error> {
    // A29's source set has its own planner and verifier (`relation::recursive`).
    if instance_bound == 0 || instance_bound > 30 || sources.recursive() {
        return Err(Error::Unsupported);
    }
    relation.validate().map_err(Error::StatementMismatch)?;
    if relation.has_virtual() {
        return Err(Error::Unsupported);
    }
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
    // RFC-0026 A3 & A8: one check (an ordered list of instances of <= 2^B positions) per table,
    // in order of first use (lookups, then ranges); members keep relation order before size sort.
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
                block_bits: 0,
                block_index: 0,
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
                block_bits: 0,
                block_index: 0,
                tuple: vec![(Ref::identity(range.column, log_len), -range.width.min())],
                selector: None,
                offset: 0,
            },
        );
    }
    let checks = build_a8_checks(targets, relation, sources, instance_bound, 0, base, None)?;
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
) -> Result<ColumnSlice<'a>, Error> {
    values.get(relation, id).ok_or(Error::Missing(id))
}

/// Packed integer storage for one materialized virtual column within a segment (E20-01).
enum VirtualBuf {
    I16(Vec<i16>),
    I32(Vec<i32>),
    I64(Vec<i64>),
}

impl VirtualBuf {
    /// Storage only: the narrowest type that holds every value exactly. No strategy is
    /// chosen from this scan (RFC-0006 A5 eligibility comes from the declared widths).
    fn from_i64(values: Vec<i64>) -> Self {
        let max_abs = values.iter().fold(0u64, |m, &v| m.max(v.unsigned_abs()));
        if max_abs <= i16::MAX as u64 {
            Self::I16(values.into_iter().map(|v| v as i16).collect())
        } else if max_abs <= i32::MAX as u64 {
            Self::I32(values.into_iter().map(|v| v as i32).collect())
        } else {
            Self::I64(values)
        }
    }

    fn as_slice(&self) -> ColumnSlice<'_> {
        match self {
            Self::I16(v) => ColumnSlice::I16(v),
            Self::I32(v) => ColumnSlice::I32(v),
            Self::I64(v) => ColumnSlice::I64(v),
        }
    }

    fn bump_one(&mut self, idx: usize) -> Result<(), Error> {
        let v = self
            .as_slice()
            .at(idx)
            .checked_add(1)
            .ok_or(Error::Unsupported)?;
        match self {
            Self::I16(buf) => {
                if let Ok(narrow) = i16::try_from(v) {
                    *buf.get_mut(idx).ok_or(Error::Unsupported)? = narrow;
                } else {
                    let mut wide: Vec<i64> = buf.iter().map(|&x| i64::from(x)).collect();
                    *wide.get_mut(idx).ok_or(Error::Unsupported)? = v;
                    *self = Self::I64(wide);
                }
            }
            Self::I32(buf) => {
                if let Ok(narrow) = i32::try_from(v) {
                    *buf.get_mut(idx).ok_or(Error::Unsupported)? = narrow;
                } else {
                    let mut wide: Vec<i64> = buf.iter().map(|&x| i64::from(x)).collect();
                    *wide.get_mut(idx).ok_or(Error::Unsupported)? = v;
                    *self = Self::I64(wide);
                }
            }
            Self::I64(buf) => {
                *buf.get_mut(idx).ok_or(Error::Unsupported)? = v;
            }
        }
        Ok(())
    }
}

/// Column values available within one segment: committed/weight/public columns borrowed from
/// `Values`/`Relation`, plus materialized integer values of the segment's virtual columns
/// computed from their definitions (RFC-0028 §2.1).
pub(crate) struct ResolvedColumns<'a> {
    relation: &'a Relation,
    values: &'a Values,
    computed: Vec<Option<VirtualBuf>>,
}

impl<'a> ResolvedColumns<'a> {
    pub(crate) fn borrowed(relation: &'a Relation, values: &'a Values) -> Self {
        Self {
            relation,
            values,
            computed: Vec::new(),
        }
    }

    /// Materialize every supported virtual column owned by `segment` in strictly
    /// increasing `ColumnId` order (ignoring any untrusted entries in `Values`).
    /// When `forge_entry` targets a column in this segment, +1 is applied immediately after
    /// materialization so downstream virtual columns in the same segment see the forged table
    /// (RFC-0028 §6 NC-1338).
    fn for_segment(
        relation: &'a Relation,
        values: &'a Values,
        virtuals_desc: &[ColumnId],
        forge_entry: Option<(ColumnId, usize)>,
    ) -> Result<Self, Error> {
        if virtuals_desc.is_empty() {
            return Ok(Self::borrowed(relation, values));
        }
        let mut this = Self {
            relation,
            values,
            computed: (0..relation.columns.len()).map(|_| None).collect(),
        };
        for &id in virtuals_desc.iter().rev() {
            let col = &relation.columns[id.0 as usize];
            match &col.kind {
                Kind::Virtual(Def::Linear { constant, terms }) => {
                    let n = 1usize << col.log_len;
                    let ops: Vec<(i128, ColumnSlice<'_>, Indexer<'_>)> = terms
                        .iter()
                        .map(|(c, r)| {
                            Ok::<_, Error>((
                                i128::from(*c),
                                this.get(r.column)?,
                                Indexer::new(r, n),
                            ))
                        })
                        .collect::<Result<_, _>>()?;
                    let c0 = i128::from(*constant);
                    let mut out = vec![0i64; n];
                    stele_sumcheck::parallel::for_each_chunk(&mut out, |start, chunk| {
                        let mut local_overflow = false;
                        for (j, slot) in chunk.iter_mut().enumerate() {
                            let x = (start + j) as u64;
                            let mut acc = Some(c0);
                            for (coeff, data, r) in &ops {
                                acc = acc.and_then(|a| {
                                    coeff
                                        .checked_mul(i128::from(data.at(r.index(x))))
                                        .and_then(|p| a.checked_add(p))
                                });
                            }
                            match acc.and_then(|a| i64::try_from(a).ok()) {
                                Some(v) => *slot = v,
                                None => local_overflow = true,
                            }
                        }
                        if local_overflow {
                            // Use deterministic sequential fallback below when any chunk overflows.
                            chunk[0] = i64::MIN;
                        }
                    });
                    // Re-check deterministically only if the sentinel appeared (never on honest inputs
                    // where |acc| <= HALF_MODULUS < 2^30).
                    if out.contains(&i64::MIN) {
                        for (x, slot) in out.iter_mut().enumerate() {
                            let mut acc = c0;
                            for (coeff, data, r) in &ops {
                                let prod = coeff
                                    .checked_mul(i128::from(data.at(r.index(x as u64))))
                                    .ok_or(Error::Capacity)?;
                                acc = acc.checked_add(prod).ok_or(Error::Capacity)?;
                            }
                            *slot = i64::try_from(acc).map_err(|_| Error::Capacity)?;
                        }
                    }
                    this.computed[id.0 as usize] = Some(VirtualBuf::from_i64(out));
                }
                Kind::Virtual(Def::Contraction {
                    free,
                    summed,
                    lhs,
                    rhs,
                }) => {
                    let lhs_data = this.get(lhs.column)?;
                    let rhs_data = this.get(rhs.column)?;
                    let out = match stele_ir::relation::contract(
                        *free,
                        *summed,
                        (lhs, lhs_data),
                        (rhs, rhs_data),
                    ) {
                        Some(out) => out,
                        // Past the typed paths: the checked wide loop decides.
                        None => {
                            let n_out = 1usize
                                .checked_shl(u32::from(*free))
                                .ok_or(Error::Capacity)?;
                            let n_sum = 1u64
                                .checked_shl(u32::from(*summed))
                                .ok_or(Error::Capacity)?;
                            let free_u32 = u32::from(*free);
                            let mut out = vec![0i64; n_out];
                            for (x, slot) in out.iter_mut().enumerate() {
                                let mut acc = 0i128;
                                for y in 0..n_sum {
                                    let xy = (x as u64) | (y << free_u32);
                                    let prod = i128::from(lhs_data.at(lhs.index(xy)))
                                        .checked_mul(i128::from(rhs_data.at(rhs.index(xy))))
                                        .ok_or(Error::Capacity)?;
                                    acc = acc.checked_add(prod).ok_or(Error::Capacity)?;
                                }
                                *slot = i64::try_from(acc).map_err(|_| Error::Capacity)?;
                            }
                            out
                        }
                    };
                    this.computed[id.0 as usize] = Some(VirtualBuf::from_i64(out));
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    type PointwiseTerm<'b> = (i128, Vec<(ColumnSlice<'b>, Indexer<'b>)>);
                    let n = 1usize << col.log_len;
                    let ops: Vec<PointwiseTerm<'_>> = terms
                        .iter()
                        .map(|t| {
                            let factors = t
                                .factors
                                .iter()
                                .map(|r| Ok::<_, Error>((this.get(r.column)?, Indexer::new(r, n))))
                                .collect::<Result<Vec<_>, _>>()?;
                            Ok::<_, Error>((i128::from(t.coeff), factors))
                        })
                        .collect::<Result<_, _>>()?;
                    let mut out = vec![0i64; n];
                    stele_sumcheck::parallel::for_each_chunk(&mut out, |start, chunk| {
                        let mut local_overflow = false;
                        for (j, slot) in chunk.iter_mut().enumerate() {
                            let x = (start + j) as u64;
                            let mut acc = Some(0i128);
                            for (coeff, factors) in &ops {
                                let mut prod = Some(*coeff);
                                for (data, r) in factors {
                                    prod = prod.and_then(|p| {
                                        p.checked_mul(i128::from(data.at(r.index(x))))
                                    });
                                }
                                acc = acc.and_then(|a| prod.and_then(|p| a.checked_add(p)));
                            }
                            match acc.and_then(|a| i64::try_from(a).ok()) {
                                Some(v) => *slot = v,
                                None => local_overflow = true,
                            }
                        }
                        if local_overflow {
                            chunk[0] = i64::MIN;
                        }
                    });
                    if out.contains(&i64::MIN) {
                        for (x, slot) in out.iter_mut().enumerate() {
                            let mut acc = 0i128;
                            for (coeff, factors) in &ops {
                                let mut prod = *coeff;
                                for (data, r) in factors {
                                    prod = prod
                                        .checked_mul(i128::from(data.at(r.index(x as u64))))
                                        .ok_or(Error::Capacity)?;
                                }
                                acc = acc.checked_add(prod).ok_or(Error::Capacity)?;
                            }
                            *slot = i64::try_from(acc).map_err(|_| Error::Capacity)?;
                        }
                    }
                    this.computed[id.0 as usize] = Some(VirtualBuf::from_i64(out));
                }
                _ => return Err(Error::Unsupported),
            }
            if let Some((forged_col, idx)) = forge_entry {
                if forged_col == id {
                    let col_vals = this.computed[id.0 as usize]
                        .as_mut()
                        .ok_or(Error::Unsupported)?;
                    col_vals.bump_one(idx)?;
                }
            }
        }
        Ok(this)
    }

    pub(crate) fn get(&self, id: ColumnId) -> Result<ColumnSlice<'_>, Error> {
        if matches!(
            self.relation.columns.get(id.0 as usize).map(|c| &c.kind),
            Some(Kind::Virtual(_))
        ) {
            return self
                .computed
                .get(id.0 as usize)
                .and_then(|v| v.as_ref().map(VirtualBuf::as_slice))
                .ok_or(Error::Missing(id));
        }
        column(self.relation, self.values, id)
    }
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

fn mle(values: ColumnSlice<'_>, point: &[K]) -> Result<K, Error> {
    let eq = parallel::eq_table(point).map_err(|_| Error::Capacity)?;
    let mut dot = [K::from_i64(0)];
    parallel::sum_ranges(eq.len(), &mut dot, |range, out| {
        for i in range {
            out[0] = out[0] + eq[i].mul_m31(M31::from_i64(values.at(i)));
        }
        Ok(())
    })?;
    Ok(dot[0])
}

fn mle_dot(values: ColumnSlice<'_>, eq: &[K]) -> Result<K, Error> {
    let mut acc = [K::from_i64(0)];
    stele_sumcheck::parallel::sum_ranges(values.len(), &mut acc, |range, out| {
        for i in range {
            out[0] = out[0] + eq[i].mul_m31(M31::from_i64(values.at(i)));
        }
        Ok(())
    })?;
    Ok(acc[0])
}

fn mle_parallel(values: ColumnSlice<'_>, point: &[K]) -> Result<K, Error> {
    let eq = stele_sumcheck::parallel::eq_table(point)?;
    mle_dot(values, &eq)
}

/// Absorb the operand evaluations of one `Linear` virtual-column claim (RFC-0028 §2.4, §1.4:
/// reuses `AbsorbLabel::Final` with no new transcript label and no challenge drawn).
fn absorb_linear_evals(
    t: &mut Transcript<K>,
    col_id: ColumnId,
    claim_idx: usize,
    evals: &[K],
) -> Result<(), Error> {
    let mut payload = Vec::with_capacity(8 + 16 * evals.len());
    payload.extend_from_slice(&col_id.0.to_le_bytes());
    payload.extend_from_slice(&(claim_idx as u32).to_le_bytes());
    put(&mut payload, evals);
    t.absorb(AbsorbLabel::Final, &payload)?;
    Ok(())
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
    let col_segs = segment.map(|_| relation.column_segments());
    let mut out: Vec<Identity> = relation
        .identities
        .iter()
        .filter(|i| {
            i.vars == m
                && match (segment, &col_segs) {
                    (Some(s), Some(segs)) => relation.identity_segment_with(i, segs) == s,
                    _ => true,
                }
        })
        .cloned()
        .collect();
    for compose in &relation.composes {
        let log_len = relation.columns[compose.column.0 as usize].log_len;
        let same_seg = match (segment, &col_segs) {
            (Some(s), Some(segs)) => relation.compose_segment_with(compose, segs) == s,
            _ => true,
        };
        if log_len != m || !same_seg {
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
    fn from_point(rho: Vec<K>, free: u8, summed: u8, lhs: &Ref, rhs: &Ref) -> Self {
        let shared: Vec<u8> = (0..free)
            .filter(|d| lhs.vars.contains(d) && rhs.vars.contains(d))
            .collect();
        let mut vars: Vec<u8> = shared.iter().copied().chain(free..free + summed).collect();
        vars.sort_unstable_by(|a, b| b.cmp(a));
        Self { rho, vars, shared }
    }
    fn new(t: &mut Transcript<K>, mm: &stele_ir::relation::Matmul) -> Result<Self, Error> {
        let rho = (0..mm.free)
            .map(|_| Ok(t.challenge(ChallengeLabel::RelationPoint)?))
            .collect::<Result<Vec<K>, Error>>()?;
        Ok(Self::from_point(rho, mm.free, mm.summed, &mm.lhs, &mm.rhs))
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
    /// Returns a base-field [`DenseTable::Base`] when no non-fixed outer bits exist,
    /// avoiding a dense extension-field table before the first sumcheck fold (E20-01).
    fn table_mixed(&self, r: &Ref, col: ColumnSlice<'_>) -> Result<DenseTable<K>, Error> {
        let nv = self.vars.len();
        let mut mask = 0usize;
        // Per entry-index bit: a fixed bit (RFC-0026 A6), its sumcheck variable (`inner`,
        // as `(j, z bit)`), or a non-fixed outer free bit (`outer`) folded via `eq`.
        let (mut inner, mut outer) = (Vec::new(), Vec::new());
        let (mut fixed, mut selected) = (0usize, 0usize);
        let mut eq = vec![K::from_i64(1)];
        for (j, d) in r.vars.iter().enumerate() {
            if let Some(bit) = Ref::fixed(*d) {
                fixed |= 1 << j;
                selected |= usize::from(bit) << j;
            } else if let Some(p) = self.position(*d) {
                mask |= 1 << (nv - 1 - p);
                inner.push((j, nv - 1 - p));
            } else {
                let x = self.rho_at(*d);
                let low: Vec<K> = eq.iter().map(|w| *w * (K::from_i64(1) - x)).collect();
                let high: Vec<K> = eq.iter().map(|w| *w * x).collect();
                eq = [low, high].concat();
                outer.push(j);
            }
        }
        if outer.is_empty() {
            let mut out = vec![M31::from_i64(0); 1 << nv];
            parallel::for_each_chunk(&mut out, |start, chunk| {
                for (k, slot) in chunk.iter_mut().enumerate() {
                    let z = start + k;
                    let mut index = selected;
                    for &(j, bit) in &inner {
                        index |= ((z >> bit) & 1) << j;
                    }
                    *slot = M31::from_i64(col.at(index));
                }
            });
            return Ok(DenseTable::Base(out));
        }
        // Exact field sums: the split leaves every entry equal to the sequential loop's.
        let mut reduced = vec![K::from_i64(0); 1 << nv];
        parallel::sum_ranges(col.len(), &mut reduced, |range, reduced| {
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
                reduced[z] = reduced[z] + eq[o].mul_m31(M31::from_i64(col.at(index)));
            }
            Ok(())
        })?;
        if mask == (1usize << nv) - 1 {
            Ok(DenseTable::Ext(reduced))
        } else {
            Ok(DenseTable::Ext(
                (0..1 << nv).map(|z| reduced[z & mask]).collect(),
            ))
        }
    }
    /// Shared-variable `eq(ρ_shared, ·)` table of length `2^|shared|`, never expanded across
    /// the leading `summed` variables (E20-01).
    fn eq_shared(&self) -> Result<Option<Vec<K>>, Error> {
        if self.shared.is_empty() {
            return Ok(None);
        }
        // `self.vars` is sorted descending, so `self.shared` occupies the trailing
        // `self.shared.len()` coordinates in descending bit order.
        let point: Vec<K> = self.shared.iter().rev().map(|&d| self.rho_at(d)).collect();
        Ok(Some(parallel::eq_table(&point)?))
    }
    /// Operand claims at (ρ, r); `finals` lead with eq when k > 0.
    fn route_operands(
        &self,
        lhs: &Ref,
        rhs: &Ref,
        free: u8,
        sc: &[K],
        finals: &[K],
        claims: &mut Claims,
    ) {
        let finals = &finals[usize::from(!self.shared.is_empty())..];
        for (r, value) in [(lhs, finals[0]), (rhs, finals[1])] {
            claims.0[r.column.0 as usize].push((self.point(r, free, sc), value));
        }
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
        claims.push(&mm.out, &self.rho, out);
        self.route_operands(&mm.lhs, &mm.rhs, mm.free, sc, finals, claims);
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
    route_column_claim_for(&plan.groups, stack, claims, column, batch)
}

#[cfg(feature = "controls")]
fn route_column_claim_for(
    groups: &[Group],
    stack: &Stack,
    claims: &Claims,
    column: ColumnId,
    batch: &mut [(Vec<K>, K)],
) -> Result<(), Error> {
    let mut index = 0;
    for group in groups {
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
    let stack = if relation.has_virtual() || relation.is_segmented() {
        plan_segmented(relation, sources)?
            .segments
            .into_iter()
            .next()
            .and_then(|seg| seg.stack)
    } else {
        plan(relation, sources)?.stack
    };
    stack.map(|s| s.source(root)).transpose()
}

/// The plan-derived multiplicity source of check `index` under `root` (RFC-0008 A5,
/// RFC-0026 A12); controls use it to locate one certificate field.
pub fn multiplicity_source(
    relation: &Relation,
    sources: Sources,
    index: usize,
    root: [u8; 32],
) -> Result<Source<K>, Error> {
    let check = if relation.has_virtual() || relation.is_segmented() {
        let seg = plan_segmented(relation, sources)?
            .segments
            .into_iter()
            .next()
            .ok_or(Error::Unsupported)?;
        seg.checks
            .into_iter()
            .nth(index)
            .ok_or(Error::Unsupported)?
    } else {
        plan(relation, sources)?
            .checks
            .into_iter()
            .nth(index)
            .ok_or(Error::Unsupported)?
    };
    let l = check.layout;
    sources.source(l.id, l.ell, mu_code(&check)?.code_id(), root)
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
    relation.validate().map_err(Error::StatementMismatch)?;
    // Messages depend on the bits only, which no source set changes.
    let layouts = model_layout(relation, Sources::Expander)?;
    let weight_cols: Vec<ColumnId> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .collect();
    layouts
        .iter()
        .map(|layout| {
            let mut message = vec![M31::from_i64(0); 1 << layout.bits];
            for &(w, offset) in &layout.blocks {
                let col = column(relation, values, weight_cols[w])?;
                for (out, v) in message[offset..].iter_mut().zip(col.iter()) {
                    *out = M31::from_i64(v);
                }
            }
            Ok(message)
        })
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
            *out = M31::from_i64(v);
        }
    }
    Ok(message)
}

/// True iff `committed` equals `weights_message(relation, plan, k, values)` entry-for-entry,
/// checked with zero allocation (E20-01).
fn weights_match_message(
    relation: &Relation,
    plan: &Plan,
    k: usize,
    values: &Values,
    committed: &[M31],
) -> Result<bool, Error> {
    let total = 1usize << plan.model[k].bits;
    if committed.len() != total {
        return Ok(false);
    }
    let mut covered = 0usize;
    let mut sum_len = 0usize;
    for weight in plan.weights.iter().filter(|w| w.source == k) {
        let col = column(relation, values, weight.column)?;
        let len = 1usize << weight.n;
        let end = weight.offset + len;
        if end > total || col.len() != len {
            return Ok(false);
        }
        if !committed[weight.offset..end]
            .iter()
            .zip(col)
            .all(|(&c, v)| c == M31::from_i64(v))
        {
            return Ok(false);
        }
        covered = covered.max(end);
        sum_len += len;
    }
    if sum_len != covered {
        return Ok(false);
    }
    Ok(committed[covered..].iter().all(|&c| c == M31::from_i64(0)))
}

fn eval_m31(message: &[M31], point: &[K]) -> Result<K, Error> {
    let eq = parallel::eq_table(point).map_err(|_| Error::Capacity)?;
    let mut dot = [K::from_i64(0)];
    parallel::sum_ranges(eq.len(), &mut dot, |range, out| {
        for i in range {
            out[0] = out[0] + eq[i].mul_m31(message[i]);
        }
        Ok(())
    })?;
    Ok(dot[0])
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
    prove_measured_with_instance_bound(t, relation, values, model, sources, DEFAULT_INSTANCE_BOUND)
}

/// [`prove`] with an explicit plan-fixed RFC-0026 A8 lookup instance bound `B` (`1 <= B <= 30`).
#[cfg(test)]
pub(crate) fn prove_with_instance_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    instance_bound: u8,
) -> Result<Proof, Error> {
    prove_measured_with_instance_bound(t, relation, values, model, sources, instance_bound)
        .map(|(proof, _)| proof)
}

/// [`prove_measured`] with an explicit plan-fixed RFC-0026 A8 lookup instance bound `B`.
pub(crate) fn prove_measured_with_instance_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    instance_bound: u8,
) -> Result<(Proof, Metrics), Error> {
    // E16-22: stage timing, off unless STELE_STAGE_TIMES.
    let mut laps = parallel::Laps::start();
    let plan_timer = Stopwatch::start();
    let plan = plan_with_bound(relation, sources, instance_bound)?;
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
        let block_base = (member.block_index as u64) << member.m;
        match &member.selector {
            None => 1u64 << member.m,
            Some(sel) => match &relation.columns[sel.column.0 as usize].kind {
                Kind::Public(v) => (0..(1u64 << member.m))
                    .filter(|&local| v[sel.index(block_base | local)] != 0)
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
                    *out = M31::from_i64(v);
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
    let resolved = ResolvedColumns::borrowed(relation, values);
    let mu_messages = |i: usize| {
        #[cfg(any(test, feature = "controls"))]
        let counts = match &plan.checks[i].count_override {
            Some(overridden) => overridden.clone(),
            None => lookup::counts(&plan.checks[i], relation, &resolved)?,
        };
        #[cfg(not(any(test, feature = "controls")))]
        let counts = lookup::counts(&plan.checks[i], relation, &resolved)?;
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
        let z = zerocheck::Zerocheck {
            instance: &instance,
            skip: 0,
        };
        let (zp, point) = match round_values {
            #[cfg(feature = "controls")]
            Some(original_values) => {
                let tables_k = |vals: &Values| -> Result<Vec<Vec<K>>, Error> {
                    let mut tables = Vec::new();
                    for r in &inputs {
                        let col = column(relation, vals, r.column)?;
                        let mut table = vec![K::from_i64(0); 1 << m];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, out) in chunk.iter_mut().enumerate() {
                                *out = K::from_i64(col.at(r.index((start + j) as u64)));
                            }
                        });
                        tables.push(table);
                    }
                    Ok(tables)
                };
                let original = tables_k(original_values)?;
                let tables = tables_k(values)?;
                z.prove_forged_finals(&original, &tables, t)
            }
            _ => {
                // Base-field tables before the first sumcheck fold (RFC-0006 A5, E20-01).
                let mut tables = Vec::with_capacity(inputs.len());
                for r in &inputs {
                    let col = column(relation, values, r.column)?;
                    let mut table = vec![M31::from_i64(0); 1 << m];
                    parallel::for_each_chunk(&mut table, |start, chunk| {
                        for (j, out) in chunk.iter_mut().enumerate() {
                            *out = M31::from_i64(col.at(r.index((start + j) as u64)));
                        }
                    });
                    tables.push(table);
                }
                z.prove_base_with_point(&tables, t)
            }
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
            &resolved,
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
        let out_col = column(relation, values, mm.out.column)?;
        let lhs_col = column(relation, values, mm.lhs.column)?;
        let rhs_col = column(relation, values, mm.rhs.column)?;
        // Evaluate `out~(ρ)` and build both operand tables concurrently on the work pool (E20-02).
        let ((out_value, eq), (lhs, rhs)) = parallel::join(
            || {
                let out_pt = restrict(&mm.out, &shape.rho);
                (mle(out_col, &out_pt), shape.eq_shared())
            },
            || {
                parallel::join(
                    || shape.table_mixed(&mm.lhs, lhs_col),
                    || shape.table_mixed(&mm.rhs, rhs_col),
                )
            },
        );
        let out_value = out_value?;
        let eq = eq?;
        let lhs = lhs?;
        let rhs = rhs?;
        let instance = shape.instance(MATMUL | i as u64, out_value);
        let mut sc = Vec::new();
        let summand = MatmulSummand {
            rem: 1usize << shape.vars.len(),
            eq,
            lhs,
            rhs,
            point: &mut sc,
        };
        let sp = stele_sumcheck::prove(&instance, summand, t)?;
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
            let proving = if core::ptr::eq(committed, values) {
                None
            } else {
                Some(message(stack, values)?)
            };
            proof
                .openings
                .push(opening.prove(t, proving.as_deref(), prepared, handle)?);
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
            let proving = if weights_match_message(relation, plan, k, values, prepared.message())? {
                None
            } else {
                Some(weights_message(relation, plan, k, values)?)
            };
            proof
                .openings
                .push(opening.prove(t, proving.as_deref(), prepared, certificate)?);
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

/// Contraction sumcheck strategy with base-field operands and unexpanded shared-bit
/// `eq(ρ_shared, ·)` table (RFC-0006 A5, E20-01). Proof bytes match `Dense` identically.
struct MatmulSummand<'a> {
    rem: usize,
    eq: Option<Vec<K>>,
    lhs: DenseTable<K>,
    rhs: DenseTable<K>,
    point: &'a mut Vec<K>,
}

fn fold_dense_table(table: &mut DenseTable<K>, r: K) -> Result<(), stele_sumcheck::Error> {
    match table {
        DenseTable::Base(v) => {
            *table = DenseTable::Ext(parallel::fold_base(v, r)?);
        }
        DenseTable::Ext(v) => {
            parallel::fold(v, r);
        }
    }
    Ok(())
}

fn final_dense_value(table: &DenseTable<K>) -> Result<K, stele_sumcheck::Error> {
    match table {
        DenseTable::Base(v) if v.len() == 1 => Ok(K::from_i64(i64::from(v[0].as_u32()))),
        DenseTable::Ext(v) if v.len() == 1 => Ok(v[0]),
        _ => Err(stele_sumcheck::Error::PublicShape),
    }
}

impl stele_sumcheck::Summand<K> for MatmulSummand<'_> {
    fn shape(&self) -> (u32, usize) {
        (
            self.rem.trailing_zeros(),
            2 + usize::from(self.eq.is_some()),
        )
    }
    /// The rounds hard-code one product of every input with coefficient one.
    fn validate_instance(&self, instance: &Instance<K>) -> Result<(), stele_sumcheck::Error> {
        let (num_vars, inputs) = self.shape();
        let product = matches!(instance.terms.as_slice(), [term]
            if term.coefficient == K::from_i64(1)
                && term.factors.iter().copied().eq(0..inputs as u32));
        if num_vars != instance.num_vars || inputs != instance.inputs.len() || !product {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        Ok(())
    }
    fn round(&self, _instance: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        if self.rem < 2 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let half = self.rem / 2;
        let zero = K::from_i64(0);
        let one = K::from_i64(1);
        match &self.eq {
            None => {
                let mut evals = vec![zero; 3];
                parallel::sum_ranges(half, &mut evals, |range, out| {
                    match (&self.lhs, &self.rhs) {
                        (DenseTable::Base(l), DenseTable::Base(r)) => {
                            let mut local = [M31::from_i64(0); 3];
                            for i in range {
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                local[0] = local[0] + l0 * r0;
                                local[1] = local[1] + l1 * r1;
                                local[2] = local[2] + (l1 + dl) * (r1 + dr);
                            }
                            for t in 0..3 {
                                out[t] = out[t] + one.mul_m31(local[t]);
                            }
                        }
                        (DenseTable::Base(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                out[0] = out[0] + r0.mul_m31(l0);
                                out[1] = out[1] + r1.mul_m31(l1);
                                out[2] = out[2] + (r1 + dr).mul_m31(l1 + dl);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Base(r)) => {
                            for i in range {
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                out[0] = out[0] + l0.mul_m31(r0);
                                out[1] = out[1] + l1.mul_m31(r1);
                                out[2] = out[2] + (l1 + dl).mul_m31(r1 + dr);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                out[0] = out[0] + l0 * r0;
                                out[1] = out[1] + l1 * r1;
                                out[2] = out[2] + (l1 + dl) * (r1 + dr);
                            }
                        }
                    }
                    Ok(())
                })?;
                Ok(evals)
            }
            Some(eq) if eq.len() < self.rem => {
                // Summed round: `eq` depends only on the trailing `shared` bits, so
                // `eq[i]` and `eq[i + half]` are identical (`e(t) = eq[i & mask]`).
                let mask = eq.len() - 1;
                let mut evals = vec![zero; 4];
                parallel::sum_ranges(half, &mut evals, |range, out| {
                    match (&self.lhs, &self.rhs) {
                        (DenseTable::Base(l), DenseTable::Base(r)) => {
                            for i in range {
                                let e = eq[i & mask];
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e.mul_m31(l0 * r0);
                                out[1] = out[1] + e.mul_m31(l1 * r1);
                                out[2] = out[2] + e.mul_m31(l2 * r2);
                                out[3] = out[3] + e.mul_m31((l2 + dl) * (r2 + dr));
                            }
                        }
                        (DenseTable::Base(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let e = eq[i & mask];
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e * r0.mul_m31(l0);
                                out[1] = out[1] + e * r1.mul_m31(l1);
                                out[2] = out[2] + e * r2.mul_m31(l2);
                                out[3] = out[3] + e * (r2 + dr).mul_m31(l2 + dl);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Base(r)) => {
                            for i in range {
                                let e = eq[i & mask];
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e * l0.mul_m31(r0);
                                out[1] = out[1] + e * l1.mul_m31(r1);
                                out[2] = out[2] + e * l2.mul_m31(r2);
                                out[3] = out[3] + e * (l2 + dl).mul_m31(r2 + dr);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let e = eq[i & mask];
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e * l0 * r0;
                                out[1] = out[1] + e * l1 * r1;
                                out[2] = out[2] + e * l2 * r2;
                                out[3] = out[3] + e * (l2 + dl) * (r2 + dr);
                            }
                        }
                    }
                    Ok(())
                })?;
                Ok(evals)
            }
            Some(eq) => {
                // Shared round: `eq` has length `self.rem` and folds with `lhs` and `rhs`.
                let mut evals = vec![zero; 4];
                parallel::sum_ranges(half, &mut evals, |range, out| {
                    match (&self.lhs, &self.rhs) {
                        (DenseTable::Base(l), DenseTable::Base(r)) => {
                            for i in range {
                                let (e0, e1) = (eq[i], eq[i + half]);
                                let de = e1 - e0;
                                let e2 = e1 + de;
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e0.mul_m31(l0 * r0);
                                out[1] = out[1] + e1.mul_m31(l1 * r1);
                                out[2] = out[2] + e2.mul_m31(l2 * r2);
                                out[3] = out[3] + (e2 + de).mul_m31((l2 + dl) * (r2 + dr));
                            }
                        }
                        (DenseTable::Base(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let (e0, e1) = (eq[i], eq[i + half]);
                                let de = e1 - e0;
                                let e2 = e1 + de;
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e0 * r0.mul_m31(l0);
                                out[1] = out[1] + e1 * r1.mul_m31(l1);
                                out[2] = out[2] + e2 * r2.mul_m31(l2);
                                out[3] = out[3] + (e2 + de) * (r2 + dr).mul_m31(l2 + dl);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Base(r)) => {
                            for i in range {
                                let (e0, e1) = (eq[i], eq[i + half]);
                                let de = e1 - e0;
                                let e2 = e1 + de;
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e0 * l0.mul_m31(r0);
                                out[1] = out[1] + e1 * l1.mul_m31(r1);
                                out[2] = out[2] + e2 * l2.mul_m31(r2);
                                out[3] = out[3] + (e2 + de) * (l2 + dl).mul_m31(r2 + dr);
                            }
                        }
                        (DenseTable::Ext(l), DenseTable::Ext(r)) => {
                            for i in range {
                                let (e0, e1) = (eq[i], eq[i + half]);
                                let de = e1 - e0;
                                let e2 = e1 + de;
                                let (l0, l1) = (l[i], l[i + half]);
                                let (r0, r1) = (r[i], r[i + half]);
                                let (dl, dr) = (l1 - l0, r1 - r0);
                                let (l2, r2) = (l1 + dl, r1 + dr);
                                out[0] = out[0] + e0 * l0 * r0;
                                out[1] = out[1] + e1 * l1 * r1;
                                out[2] = out[2] + e2 * l2 * r2;
                                out[3] = out[3] + (e2 + de) * (l2 + dl) * (r2 + dr);
                            }
                        }
                    }
                    Ok(())
                })?;
                Ok(evals)
            }
        }
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        if self.rem < 2 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        if let Some(eq) = &mut self.eq {
            if eq.len() == self.rem {
                parallel::fold(eq, r);
            }
        }
        fold_dense_table(&mut self.lhs, r)?;
        fold_dense_table(&mut self.rhs, r)?;
        self.rem /= 2;
        self.point.push(r);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if self.rem != 1 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let mut out = Vec::with_capacity(2 + usize::from(self.eq.is_some()));
        if let Some(eq) = &self.eq {
            if eq.len() != 1 {
                return Err(stele_sumcheck::Error::PublicShape);
            }
            out.push(eq[0]);
        }
        out.push(final_dense_value(&self.lhs)?);
        out.push(final_dense_value(&self.rhs)?);
        Ok(out)
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
        proving: Option<&[M31]>,
        prepared: &PreparedSource<'_, K>,
        handle: &VerifiedCertificate<K>,
    ) -> Result<Vec<u8>, Error> {
        // Batch over the committed base-field message whenever the claims hold on it
        // (always, for an honest prover); otherwise over the proving message, so that a
        // lying prover's only failure is the opening of the committed source below.
        // No dense extension-field table is allocated before the first sumcheck fold (E20-01).
        let committed_msg = prepared.message();
        let same = proving.is_none_or(|msg| msg == committed_msg);
        let consistent = same
            || self.batch.iter().all(|(point, value)| {
                eval_m31(committed_msg, point).is_ok_and(|eval| eval == *value)
            });
        let batched = if consistent {
            committed_msg
        } else {
            proving.unwrap_or(committed_msg)
        };
        let (bp, point) = self.batch().prove_base_with_point(batched, t)?;
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
            eval_m31(committed_msg, &point)?
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
        let (bp, point) = self.batch().prove_base_with_point(prepared.message(), t)?;
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
    verify_with_instance_bound(t, relation, model, proof, sources, DEFAULT_INSTANCE_BOUND)
}

/// [`verify`] with an explicit plan-fixed RFC-0026 A8 lookup instance bound `B` (`1 <= B <= 30`).
pub(crate) fn verify_with_instance_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[&VerifiedCertificate<K>],
    proof: &Proof,
    sources: Sources,
    instance_bound: u8,
) -> Result<Ledger, Error> {
    let plan = plan_with_bound(relation, sources, instance_bound)?;
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
                if mle(ColumnSlice::I64(values), point)? != *value {
                    return Err(Error::PublicMismatch(ColumnId(i as u32)));
                }
            }
        }
    }
    Ok(ledger)
}

/// Per-segment plan derived from a validated [`Relation`] (RFC-0026 A27, RFC-0028 §2.3).
struct SegmentPlan {
    segment: u32,
    groups: Vec<Group>,
    stack: Option<Stack>,
    checks: Vec<Check>,
    sizes: Vec<u8>,
    matmuls: Vec<usize>,
    /// Virtual columns owned by this segment in strictly decreasing `ColumnId` order (RFC-0028 §2.4).
    virtuals: Vec<ColumnId>,
}

/// Complete segmented plan (RFC-0026 A27, RFC-0028 §2.3).
struct SegmentedPlan {
    digest: [u8; 32],
    segments: Vec<SegmentPlan>,
    weights: Vec<Weight>,
    model: Vec<Stack>,
    sources: Sources,
    #[cfg(feature = "controls")]
    column_claim: Option<ColumnId>,
}

/// Shared RFC-0006 A1 sumcheck instance for a `Def::Pointwise` virtual column:
/// `Σ_x eq(z, x) · Σ_t c_t Π_f f(x) = claimed_sum` (RFC-0028 §2.4).
/// Input `0` is `eq(z, ·)`; inputs `1..=inputs.len()` are the deduplicated factor `Ref`s.
fn pointwise_instance(
    col_id: ColumnId,
    log_len: u8,
    terms: &[IdentityTerm],
    claimed_sum: K,
) -> (Vec<Ref>, Instance<K>, usize) {
    let mut inputs: Vec<Ref> = Vec::new();
    let mut sc_terms = Vec::with_capacity(terms.len());
    let mut degree = 1usize;
    for term in terms {
        let mut factors = Vec::with_capacity(1 + term.factors.len());
        factors.push(0u32);
        for f in &term.factors {
            let index = inputs.iter().position(|r| r == f).unwrap_or_else(|| {
                inputs.push(f.clone());
                inputs.len() - 1
            });
            factors.push((1 + index) as u32);
        }
        degree = degree.max(factors.len());
        sc_terms.push(Term {
            coefficient: K::from_i64(term.coeff),
            factors,
        });
    }
    let instance = Instance {
        id: VIRTUAL_POINTWISE | u64::from(col_id.0),
        num_vars: u32::from(log_len),
        inputs: (0..(1 + inputs.len()) as u64).collect(),
        terms: sc_terms,
        claimed_sum,
    };
    (inputs, instance, degree)
}

fn plan_segmented(relation: &Relation, sources: Sources) -> Result<SegmentedPlan, Error> {
    plan_segmented_with_bound(relation, sources, DEFAULT_INSTANCE_BOUND)
}

fn plan_segmented_with_bound(
    relation: &Relation,
    sources: Sources,
    instance_bound: u8,
) -> Result<SegmentedPlan, Error> {
    // A29's source set has its own planner and verifier (`relation::recursive`).
    if sources.recursive() {
        return Err(Error::Unsupported);
    }
    relation.validate().map_err(Error::StatementMismatch)?;
    // RFC-0028 §2.1: all three virtual kinds (`Linear`, `Pointwise`, `Contraction`) are admitted;
    // contractions must fit their sumcheck variables (`shared + summed`) within `MAX_VARS`.
    for col in &relation.columns {
        if let Kind::Virtual(Def::Contraction {
            free,
            summed,
            lhs,
            rhs,
        }) = &col.kind
        {
            let shared = (0..*free)
                .filter(|d| lhs.vars.contains(d) && rhs.vars.contains(d))
                .count();
            if shared + usize::from(*summed) > usize::from(stele_ir::relation::MAX_VARS) {
                return Err(Error::Unsupported);
            }
        }
    }
    let seg_count = relation.segments();
    if seg_count > u32::from(u16::MAX) {
        return Err(Error::Unsupported);
    }
    let col_segs = relation.column_segments();
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
            if relation.lookup_segment_with(lookup, &col_segs) != seg {
                continue;
            }
            add(
                Target::Table(lookup.table.0),
                Member {
                    m: lookup.vars,
                    block_bits: 0,
                    block_index: 0,
                    tuple: lookup.tuple.iter().map(|r| (r.clone(), 0)).collect(),
                    selector: lookup.selector.clone(),
                    offset: 0,
                },
            );
        }
        for range in &relation.ranges {
            if relation.range_segment_with_segs(range, &col_segs, &weight_segs) != seg {
                continue;
            }
            let log_len = relation.columns[range.column.0 as usize].log_len;
            add(
                Target::Range(range.width.bits),
                Member {
                    m: log_len,
                    block_bits: 0,
                    block_index: 0,
                    tuple: vec![(Ref::identity(range.column, log_len), -range.width.min())],
                    selector: None,
                    offset: 0,
                },
            );
        }
        let checks = build_a8_checks(
            targets,
            relation,
            sources,
            instance_bound,
            source_base,
            source_base + 3,
            Some((1 << 16) - 3),
        )?;
        let mut sizes: Vec<u8> = relation
            .identities
            .iter()
            .filter(|i| relation.identity_segment_with(i, &col_segs) == seg)
            .map(|i| i.vars)
            .collect();
        sizes.extend(
            relation
                .composes
                .iter()
                .filter(|c| relation.compose_segment_with(c, &col_segs) == seg)
                .map(|c| relation.columns[c.column.0 as usize].log_len),
        );
        sizes.sort_unstable();
        sizes.dedup();
        let matmuls: Vec<usize> = relation
            .matmuls
            .iter()
            .enumerate()
            .filter(|(_, mm)| relation.matmul_segment_with(mm, &col_segs) == seg)
            .map(|(idx, _)| idx)
            .collect();
        let virtuals: Vec<ColumnId> = (0..relation.columns.len())
            .rev()
            .filter(|&idx| {
                matches!(relation.columns[idx].kind, Kind::Virtual(_)) && col_segs[idx] == Some(seg)
            })
            .map(|idx| ColumnId(idx as u32))
            .collect();
        segments.push(SegmentPlan {
            segment: seg,
            groups,
            stack,
            checks,
            sizes,
            matmuls,
            virtuals,
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
        #[cfg(feature = "controls")]
        column_claim: None,
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
            for (out, v) in message[start..].iter_mut().zip(col.iter()) {
                *out = M31::from_i64(v);
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

/// [`prove_segmented_measured`] with an explicit RFC-0026 A8 lookup instance bound `B`.
#[cfg(test)]
pub(crate) fn prove_segmented_measured_with_instance_bound<F>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    instance_bound: u8,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<Values, Error>,
{
    let plan_timer = Stopwatch::start();
    let plan = plan_segmented_with_bound(relation, sources, instance_bound)?;
    let plan_ns = plan_timer.elapsed_ns();
    prove_segmented_with_plan(
        t,
        relation,
        &plan,
        plan_ns,
        segment_values,
        model,
        None,
        None,
    )
}

/// [`prove_segmented`] together with stage timings and deterministic counters (RFC-0018 A2, RFC-0026 A27, RFC-0028 §2.4).
/// A caller that keeps its `Values`, to run the plain check beside this, lends them.
pub fn prove_segmented_measured<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    prove_segmented_impl(t, relation, segment_values, model, sources, None)
}

/// Malicious-prover seam for RFC-0028 §6 NC-1338: prove with one virtual column's
/// materialized value perturbed by +1 at `index` so downstream checks see the forged
/// virtual table and the verifier rejects at the virtual column's Step 2.4 reduction.
/// When `compensate_operand` is `Some(term_idx)`, the prover also shifts `evals[term_idx]`
/// in Step 2.4 so the `Linear` equation passes and tests downstream operand-claim discharge.
#[cfg(any(test, feature = "controls"))]
#[allow(clippy::too_many_arguments)]
pub fn prove_segmented_forged_virtual<F>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    column: ColumnId,
    index: usize,
    compensate_operand: Option<usize>,
) -> Result<ProofV2, Error>
where
    F: FnMut(u32) -> Result<Values, Error>,
{
    prove_segmented_impl(
        t,
        relation,
        segment_values,
        model,
        sources,
        Some((column, index, compensate_operand)),
    )
    .map(|(p, _)| p)
}

/// Wrapper capturing sumcheck verifier challenges for a `Summand` (e.g. `Dense<K>`).
struct Capture<'a, S> {
    inner: S,
    point: &'a mut Vec<K>,
}

impl<S: stele_sumcheck::Summand<K>> stele_sumcheck::Summand<K> for Capture<'_, S> {
    fn shape(&self) -> (u32, usize) {
        self.inner.shape()
    }
    fn round(&self, instance: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.inner.round(instance)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        self.point.push(challenge);
        self.inner.fold(challenge)
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.inner.final_values()
    }
}

/// Malicious-prover helper for RFC-0028 §6 NC-1338 on sumcheck-backed virtual reductions:
/// emits a sumcheck proof matching the RFC-0006 A1 transcript order against a forged
/// `instance.claimed_sum` without honest-prover self-abort. When `force_rounds` is `false`,
/// round 0's honest polynomial disagrees with `claimed_sum` (`RoundSumMismatch`); when
/// `force_rounds` is `true`, each round's `values[0]` is shifted to satisfy the round-sum
/// equation so the verifier rejects at `FinalEvaluationMismatch`.
#[cfg(any(test, feature = "controls"))]
fn prove_sumcheck_forged<S: stele_sumcheck::Summand<K>>(
    instance: &Instance<K>,
    mut dense: S,
    t: &mut Transcript<K>,
    force_rounds: bool,
) -> Result<(stele_sumcheck::Proof<K>, Vec<K>), Error> {
    use stele_field::Inverse;

    let degree = instance
        .terms
        .iter()
        .map(|t| t.factors.len())
        .max()
        .unwrap_or(0);
    let payload = instance.encode()?;
    t.absorb(AbsorbLabel::Instance, &payload)?;
    let mut running = instance.claimed_sum;
    let mut rounds = Vec::with_capacity(instance.num_vars as usize);
    let mut point = Vec::with_capacity(instance.num_vars as usize);
    for index in 0..instance.num_vars {
        let mut values = dense.round(instance)?;
        if values.len() != degree + 1 {
            return Err(Error::ProofShape);
        }
        if force_rounds {
            let cur = values[0] + values[if values.len() == 1 { 0 } else { 1 }];
            values[0] = values[0] + (running - cur);
        }
        let msg = stele_sumcheck::message_bytes(instance.id, index, &values)?;
        t.absorb(AbsorbLabel::Round, &msg)?;
        let challenge = t.challenge(ChallengeLabel::Sumcheck)?;
        let mut next = K::from_i64(0);
        for (i, &v) in values.iter().enumerate() {
            let mut num = K::from_i64(1);
            let mut den = K::from_i64(1);
            for j in 0..values.len() {
                if i != j {
                    num = num * (challenge - K::from_i64(j as i64));
                    den = den * K::from_i64(i as i64 - j as i64);
                }
            }
            let inv = den.inverse().ok_or(Error::Unsupported)?;
            next = next + v * num * inv;
        }
        dense.fold(challenge)?;
        point.push(challenge);
        running = next;
        rounds.push(values);
    }
    let final_values = dense.final_values()?;
    let msg =
        stele_sumcheck::message_bytes(instance.id, instance.inputs.len() as u32, &final_values)?;
    t.absorb(AbsorbLabel::Final, &msg)?;
    Ok((
        stele_sumcheck::Proof {
            rounds,
            final_values,
        },
        point,
    ))
}

/// Forge a segmented or virtual-column proof (`ProofV2`, RFC-0028) by applying a
/// `Forge` tamper (`table` shift or `public` entry bump) while keeping `relation`'s
/// original statement digest in the transcript (controls only).
#[cfg(feature = "controls")]
pub fn prove_segmented_forged(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    forge: &Forge,
) -> Result<ProofV2, Error> {
    let plan_timer = Stopwatch::start();
    let mut plan = plan_segmented(relation, sources)?;
    let plan_ns = plan_timer.elapsed_ns();
    if let Some(c) = forge.column_claim {
        if forge.table.is_some() || forge.public.is_some() || forge.witness.is_some() {
            return Err(Error::Unsupported);
        }
        let group = plan
            .segments
            .iter()
            .flat_map(|seg| seg.groups.iter())
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
        plan.segments
            .first_mut()
            .and_then(|seg| seg.checks.get_mut(i))
            .ok_or(Error::Unsupported)?
            .shift = 1;
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
                || !plan.segments.iter().any(|seg| {
                    seg.sizes.iter().any(|&m| {
                        identities_for(&read, Some(seg.segment), m)
                            .iter()
                            .any(|identity| {
                                identity
                                    .terms
                                    .iter()
                                    .any(|term| term.factors.iter().any(|r| r.column == c))
                            })
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
    prove_segmented_with_plan(
        t,
        &read,
        &plan,
        plan_ns,
        |_| Ok(actual.clone()),
        model,
        None,
        changed.as_ref().map(|_| values),
    )
    .map(|(p, _)| p)
}

fn prove_segmented_impl<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    sources: Sources,
    forge_virtual: Option<(ColumnId, usize, Option<usize>)>,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    let plan_timer = Stopwatch::start();
    let plan = plan_segmented(relation, sources)?;
    let plan_ns = plan_timer.elapsed_ns();
    prove_segmented_with_plan(
        t,
        relation,
        &plan,
        plan_ns,
        segment_values,
        model,
        forge_virtual,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_segmented_with_plan<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: &SegmentedPlan,
    plan_ns: u64,
    mut segment_values: F,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
    forge_virtual: Option<(ColumnId, usize, Option<usize>)>,
    round_values: Option<&Values>,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    if let Some((col_id, idx, comp)) = forge_virtual {
        let col = relation
            .columns
            .get(col_id.0 as usize)
            .ok_or(Error::Unsupported)?;
        if idx >= (1usize << col.log_len) {
            return Err(Error::Unsupported);
        }
        match &col.kind {
            Kind::Virtual(Def::Linear { terms, .. }) => {
                if comp.is_some_and(|i| i >= terms.len()) {
                    return Err(Error::Unsupported);
                }
            }
            Kind::Virtual(Def::Contraction { .. } | Def::Pointwise { .. }) => {
                if comp.is_some_and(|m| m > 0) {
                    return Err(Error::Unsupported);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
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
        // A8: a block reads its selector at `(block index ‖ local)`.
        let block_base = (member.block_index as u64) << member.m;
        match &member.selector {
            None => 1u64 << member.m,
            Some(sel) => match &relation.columns[sel.column.0 as usize].kind {
                Kind::Public(v) => (0..(1u64 << member.m))
                    .filter(|&local| v[sel.index(block_base | local)] != 0)
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
        let owner = segment_values(seg.segment)?;
        let values: &Values = owner.borrow();
        let resolved = ResolvedColumns::for_segment(
            relation,
            values,
            &seg.virtuals,
            forge_virtual.map(|(col_id, idx, _)| (col_id, idx)),
        )?;
        // Account for `ResolvedColumns::for_segment` reading every `Kind::Weight` operand of
        // this segment's virtual columns (INV-7).
        for &vid in &seg.virtuals {
            match &relation.columns[vid.0 as usize].kind {
                Kind::Virtual(Def::Linear { terms, .. }) => {
                    let v_len = 1u64 << relation.columns[vid.0 as usize].log_len;
                    for (_, r) in terms {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(v_len);
                        }
                    }
                }
                Kind::Virtual(Def::Contraction { lhs, rhs, .. }) => {
                    for r in [lhs, rhs] {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            let fixed_bits =
                                r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                            let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
                        }
                    }
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    let v_len = 1u64 << relation.columns[vid.0 as usize].log_len;
                    for term in terms {
                        for f in &term.factors {
                            if let Some(w_idx) = weight_index[f.column.0 as usize] {
                                col_reads[w_idx] = col_reads[w_idx].saturating_add(v_len);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Step 2.1 + 2.2: commit segment `s`'s witness stack (owned) alongside multiplicity counts.
        let commit_msg_timer = Stopwatch::start();
        let committed_message = match &seg.stack {
            Some(stack) => Some(segment_stack_message(&seg.groups, stack, relation, values)?),
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
            #[cfg(any(test, feature = "controls"))]
            let counts = match &seg.checks[i].count_override {
                Some(overridden) => overridden.clone(),
                None => lookup::counts(&seg.checks[i], relation, &resolved)?,
            };
            #[cfg(not(any(test, feature = "controls")))]
            let counts = lookup::counts(&seg.checks[i], relation, &resolved)?;
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
        #[cfg(feature = "controls")]
        let round_resolved = round_values
            .map(|rv| ResolvedColumns::for_segment(relation, rv, &seg.virtuals, None))
            .transpose()?;
        #[cfg(not(feature = "controls"))]
        let _ = round_values;
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
            let z = zerocheck::Zerocheck {
                instance: &instance,
                skip: 0,
            };
            #[cfg(feature = "controls")]
            let (zp, point) = match round_resolved.as_ref() {
                Some(orig) => {
                    let tables_k = |res: &ResolvedColumns<'_>| -> Result<Vec<Vec<K>>, Error> {
                        let mut tables = Vec::with_capacity(inputs.len());
                        for r in &inputs {
                            let col = res.get(r.column)?;
                            let mut table = vec![K::from_i64(0); 1 << m];
                            stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                                for (j, out) in chunk.iter_mut().enumerate() {
                                    *out = K::from_i64(col.at(r.index((start + j) as u64)));
                                }
                            });
                            tables.push(table);
                        }
                        Ok(tables)
                    };
                    let reference = tables_k(orig)?;
                    let tables = tables_k(&resolved)?;
                    z.prove_forged_finals(&reference, &tables, t)
                }
                None => {
                    let mut tables = Vec::with_capacity(inputs.len());
                    for r in &inputs {
                        let col = resolved.get(r.column)?;
                        let mut table = vec![M31::from_i64(0); 1 << m];
                        stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, out) in chunk.iter_mut().enumerate() {
                                *out = M31::from_i64(col.at(r.index((start + j) as u64)));
                            }
                        });
                        tables.push(table);
                    }
                    z.prove_base_with_point(&tables, t)
                }
            }?;
            #[cfg(not(feature = "controls"))]
            let (zp, point) = {
                let mut tables = Vec::with_capacity(inputs.len());
                for r in &inputs {
                    let col = resolved.get(r.column)?;
                    let mut table = vec![M31::from_i64(0); 1 << m];
                    stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                        for (j, out) in chunk.iter_mut().enumerate() {
                            *out = M31::from_i64(col.at(r.index((start + j) as u64)));
                        }
                    });
                    tables.push(table);
                }
                z.prove_base_with_point(&tables, t)?
            };
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
                &resolved,
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
            let out = resolved.get(mm.out.column)?;
            let out_value = mle(out, &restrict(&mm.out, &shape.rho))?;
            let instance = shape.instance(MATMUL | mm_idx as u64, out_value);
            let eq = shape.eq_shared()?;
            let lhs = shape.table_mixed(&mm.lhs, resolved.get(mm.lhs.column)?)?;
            let rhs = shape.table_mixed(&mm.rhs, resolved.get(mm.rhs.column)?)?;
            let mut sc = Vec::new();
            let summand = MatmulSummand {
                rem: 1usize << shape.vars.len(),
                eq,
                lhs,
                rhs,
                point: &mut sc,
            };
            let sp = stele_sumcheck::prove(&instance, summand, t)?;
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

        // Step 2.4: reduce virtual columns of segment `s` in strictly decreasing `ColumnId`
        // order (RFC-0028 §2.4), then drop segment `s` witness/virtual storage before Step 2.5.
        let v_timer = Stopwatch::start();
        for &col_id in &seg.virtuals {
            let col_claims = core::mem::take(&mut claims.0[col_id.0 as usize]);
            if col_claims.is_empty() {
                continue;
            }
            let col = &relation.columns[col_id.0 as usize];
            match &col.kind {
                Kind::Virtual(Def::Linear { constant, terms }) => {
                    let mut out = Vec::with_capacity(col_claims.len() * terms.len() * 16);
                    for (claim_idx, (z, claimed_val)) in col_claims.iter().enumerate() {
                        let mut eq_z: Option<Vec<K>> = None;
                        let mut evals = Vec::with_capacity(terms.len());
                        let mut op_points = Vec::with_capacity(terms.len());
                        for (_, r) in terms {
                            if let Some(w_idx) = weight_index[r.column.0 as usize] {
                                col_reads[w_idx] =
                                    col_reads[w_idx].saturating_add(1u64 << plan.weights[w_idx].n);
                            }
                            let op_data = resolved.get(r.column)?;
                            let op_point = restrict(r, z);
                            let eval = if op_point == *z {
                                let eq = match &eq_z {
                                    Some(table) => table,
                                    None => eq_z.insert(stele_sumcheck::parallel::eq_table(z)?),
                                };
                                mle_dot(op_data, eq)?
                            } else {
                                mle_parallel(op_data, &op_point)?
                            };
                            evals.push(eval);
                            op_points.push(op_point);
                        }
                        if let Some((forged_col, _, Some(term_idx))) = forge_virtual {
                            if forged_col == col_id {
                                use stele_field::Inverse;
                                let honest_sum = terms
                                    .iter()
                                    .zip(&evals)
                                    .fold(K::from_i64(*constant), |acc, ((c, _), v)| {
                                        acc + K::from_i64(*c) * *v
                                    });
                                let delta = *claimed_val - honest_sum;
                                let inv_c = K::from_i64(terms[term_idx].0)
                                    .inverse()
                                    .ok_or(Error::Unsupported)?;
                                evals[term_idx] = evals[term_idx] + delta * inv_c;
                            }
                        }
                        put(&mut out, &evals);
                        absorb_linear_evals(t, col_id, claim_idx, &evals)?;
                        for (((_, r), op_point), eval) in terms.iter().zip(op_points).zip(evals) {
                            claims.0[r.column.0 as usize].push((op_point, eval));
                        }
                    }
                    proof.segments[s].reductions.push(out);
                }
                Kind::Virtual(Def::Contraction {
                    free,
                    summed,
                    lhs,
                    rhs,
                }) => {
                    let mut out = Vec::new();
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let col_slice = resolved.get(col_id)?;
                        let mut table = vec![M31::from_i64(0); col_slice.len()];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(col_slice.at(start + j));
                            }
                        });
                        let (bp, point) = batch.prove_base_with_point(&table, t)?;
                        for row in &bp.rounds {
                            put(&mut out, row);
                        }
                        put(&mut out, &bp.final_values);
                        (point, bp.final_values[0])
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    for r in [lhs, rhs] {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            let fixed_bits =
                                r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                            let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
                        }
                    }
                    let shape = MatmulShape::from_point(z, *free, *summed, lhs, rhs);
                    let instance =
                        shape.instance(VIRTUAL_CONTRACTION | u64::from(col_id.0), claimed_val);
                    let eq = shape.eq_shared()?;
                    let lhs_tbl = shape.table_mixed(lhs, resolved.get(lhs.column)?)?;
                    let rhs_tbl = shape.table_mixed(rhs, resolved.get(rhs.column)?)?;
                    metrics.contractions_reduced = metrics.contractions_reduced.saturating_add(1);
                    metrics.contraction_partial_evals =
                        metrics.contraction_partial_evals.saturating_add(2);
                    let mut sc = Vec::new();
                    let summand = MatmulSummand {
                        rem: 1usize << shape.vars.len(),
                        eq,
                        lhs: lhs_tbl,
                        rhs: rhs_tbl,
                        point: &mut sc,
                    };
                    #[cfg(any(test, feature = "controls"))]
                    let (sp, sc) = if let Some((forged_col, _, comp)) = forge_virtual {
                        if forged_col == col_id {
                            prove_sumcheck_forged(&instance, summand, t, comp.is_some())?
                        } else {
                            let sp = stele_sumcheck::prove(&instance, summand, t)?;
                            (sp, sc)
                        }
                    } else {
                        let sp = stele_sumcheck::prove(&instance, summand, t)?;
                        (sp, sc)
                    };
                    #[cfg(not(any(test, feature = "controls")))]
                    let (sp, sc) = {
                        let sp = stele_sumcheck::prove(&instance, summand, t)?;
                        (sp, sc)
                    };
                    for row in &sp.rounds {
                        put(&mut out, row);
                    }
                    put(&mut out, &sp.final_values);
                    shape.route_operands(lhs, rhs, *free, &sc, &sp.final_values, &mut claims);
                    proof.segments[s].reductions.push(out);
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    let mut out = Vec::new();
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let col_slice = resolved.get(col_id)?;
                        let mut table = vec![M31::from_i64(0); col_slice.len()];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(col_slice.at(start + j));
                            }
                        });
                        let (bp, point) = batch.prove_base_with_point(&table, t)?;
                        for row in &bp.rounds {
                            put(&mut out, row);
                        }
                        put(&mut out, &bp.final_values);
                        (point, bp.final_values[0])
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let (inputs, instance, _degree) =
                        pointwise_instance(col_id, col.log_len, terms, claimed_val);
                    let pw_reads = 1u64 << col.log_len;
                    for r in &inputs {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(pw_reads);
                        }
                    }
                    let mut tables = Vec::with_capacity(1 + inputs.len());
                    tables.push(DenseTable::Ext(stele_sumcheck::parallel::eq_table(&z)?));
                    for r in &inputs {
                        let data = resolved.get(r.column)?;
                        let mut table = vec![M31::from_i64(0); 1usize << col.log_len];
                        stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(data.at(r.index((start + j) as u64)));
                            }
                        });
                        tables.push(DenseTable::Base(table));
                    }
                    let dense = Dense::new_mixed(&instance, tables)?;
                    #[cfg(any(test, feature = "controls"))]
                    let (sp, sc) = if let Some((forged_col, _, comp)) = forge_virtual {
                        if forged_col == col_id {
                            prove_sumcheck_forged(&instance, dense, t, comp.is_some())?
                        } else {
                            let mut sc = Vec::new();
                            let capture = Capture {
                                inner: dense,
                                point: &mut sc,
                            };
                            let sp = stele_sumcheck::prove(&instance, capture, t)?;
                            (sp, sc)
                        }
                    } else {
                        let mut sc = Vec::new();
                        let capture = Capture {
                            inner: dense,
                            point: &mut sc,
                        };
                        let sp = stele_sumcheck::prove(&instance, capture, t)?;
                        (sp, sc)
                    };
                    #[cfg(not(any(test, feature = "controls")))]
                    let (sp, sc) = {
                        let mut sc = Vec::new();
                        let capture = Capture {
                            inner: dense,
                            point: &mut sc,
                        };
                        let sp = stele_sumcheck::prove(&instance, capture, t)?;
                        (sp, sc)
                    };
                    for row in &sp.rounds {
                        put(&mut out, row);
                    }
                    put(&mut out, &sp.final_values);
                    for (r, &val) in inputs.iter().zip(&sp.final_values[1..]) {
                        claims.push(r, &sc, val);
                    }
                    proof.segments[s].reductions.push(out);
                }
                _ => return Err(Error::Unsupported),
            }
        }
        metrics.reductions_ns = metrics.reductions_ns.saturating_add(v_timer.elapsed_ns());
        drop(resolved);
        drop(owner);

        // Step 2.5: all claims on segment `s - 1` are now complete; batch, open, and drop it.
        let openings_timer = Stopwatch::start();
        if let Some((prev_s, prev_prepared, prev_handle)) = prev.take() {
            let prev_seg = &plan.segments[prev_s];
            if let Some(prev_stack) = &prev_seg.stack {
                #[allow(unused_mut)]
                let mut batch = group_claims_for(&prev_seg.groups, prev_stack, &claims);
                if !batch.is_empty() {
                    #[cfg(feature = "controls")]
                    if let Some(c) = plan.column_claim {
                        if prev_seg.groups.iter().any(|g| g.columns.contains(&c)) {
                            route_column_claim_for(
                                &prev_seg.groups,
                                prev_stack,
                                &claims,
                                c,
                                &mut batch,
                            )?;
                        }
                    }
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
            #[allow(unused_mut)]
            let mut batch = group_claims_for(&last_seg.groups, last_stack, &claims);
            if !batch.is_empty() {
                #[cfg(feature = "controls")]
                if let Some(c) = plan.column_claim {
                    if last_seg.groups.iter().any(|g| g.columns.contains(&c)) {
                        route_column_claim_for(
                            &last_seg.groups,
                            last_stack,
                            &claims,
                            c,
                            &mut batch,
                        )?;
                    }
                }
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

/// RFC-0026 A8 control (NC-1341): [`prove_segmented`] under the instance bound `bound`,
/// with the committed multiplicities of lookup instance `forge.0` of the first segment
/// replaced by `forge.1`. A development plan fixes `B = 30`, where no test-sized check
/// splits, so the control and its verifier take the bound (controls only).
#[cfg(feature = "controls")]
pub fn prove_segmented_forged_multiplicities<F>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    sources: Sources,
    bound: u8,
    forge: Option<(usize, Vec<i64>)>,
) -> Result<ProofV2, Error>
where
    F: FnMut(u32) -> Result<Values, Error>,
{
    let mut plan = plan_segmented_with_bound(relation, sources, bound)?;
    if let Some((instance, counts)) = forge {
        plan.segments
            .first_mut()
            .and_then(|s| s.checks.get_mut(instance))
            .ok_or(Error::Unsupported)?
            .count_override = Some(counts);
    }
    prove_segmented_with_plan(t, relation, &plan, 0, segment_values, &[], None, None)
        .map(|(proof, _)| proof)
}

/// [`verify_segmented`] under the instance bound of
/// [`prove_segmented_forged_multiplicities`] (controls only).
#[cfg(feature = "controls")]
pub fn verify_segmented_under_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    proof: &ProofV2,
    sources: Sources,
    bound: u8,
) -> Result<Ledger, Error> {
    verify_segmented_with_instance_bound(t, relation, &[], proof, sources, bound)
}

/// Verify a segmented development proof (`stele-dev-e2e-v2`, RFC-0026 A27) and return its ledger.
pub fn verify_segmented(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[&VerifiedCertificate<K>],
    proof: &ProofV2,
    sources: Sources,
) -> Result<Ledger, Error> {
    verify_segmented_with_instance_bound(t, relation, model, proof, sources, DEFAULT_INSTANCE_BOUND)
}

/// [`verify_segmented`] with an explicit RFC-0026 A8 lookup instance bound `B`.
pub(crate) fn verify_segmented_with_instance_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[&VerifiedCertificate<K>],
    proof: &ProofV2,
    sources: Sources,
    instance_bound: u8,
) -> Result<Ledger, Error> {
    let plan = plan_segmented_with_bound(relation, sources, instance_bound)?;
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

        // Step 2.4: verify virtual-column reductions of segment `s` in strictly decreasing
        // `ColumnId` order (RFC-0028 §2.4).
        let mut red_sections = Sections(seg_proof.reductions.iter());
        for &col_id in &seg.virtuals {
            let col_claims = core::mem::take(&mut claims.0[col_id.0 as usize]);
            if col_claims.is_empty() {
                continue;
            }
            let mut reader = red_sections.next()?;
            let col = &relation.columns[col_id.0 as usize];
            match &col.kind {
                Kind::Virtual(Def::Linear { constant, terms }) => {
                    for (claim_idx, (z, claimed_val)) in col_claims.iter().enumerate() {
                        let evals = reader.ks(terms.len())?;
                        absorb_linear_evals(t, col_id, claim_idx, &evals)?;
                        let sum = terms
                            .iter()
                            .zip(&evals)
                            .fold(K::from_i64(*constant), |acc, ((c, _), v)| {
                                acc + K::from_i64(*c) * *v
                            });
                        if sum != *claimed_val {
                            return Err(Error::LinearMismatch(col_id));
                        }
                        for ((_, r), &eval) in terms.iter().zip(&evals) {
                            claims.push(r, z, eval);
                        }
                    }
                    reader.end()?;
                }
                Kind::Virtual(Def::Contraction {
                    free,
                    summed,
                    lhs,
                    rhs,
                }) => {
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                        for _ in 0..col.log_len {
                            rounds.push(reader.ks(3)?);
                        }
                        let bp = stele_sumcheck::Proof {
                            rounds,
                            final_values: reader.ks(1)?,
                        };
                        let reduction = batch.verify(&bp, t)?;
                        ledger.add(
                            Line::Rlc,
                            &col.name,
                            reduction.rlc.numerator,
                            reduction.rlc.numerator,
                        );
                        ledger.add(
                            Line::Sc,
                            &col.name,
                            reduction.sc.numerator,
                            u64::from(reduction.sc.degree),
                        );
                        let claim = &reduction.claims[0];
                        (claim.point.clone(), claim.value)
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let shape = MatmulShape::from_point(z, *free, *summed, lhs, rhs);
                    let instance =
                        shape.instance(VIRTUAL_CONTRACTION | u64::from(col_id.0), claimed_val);
                    let width = if shape.shared.is_empty() { 3 } else { 4 };
                    let mut rounds = Vec::with_capacity(shape.vars.len());
                    for _ in 0..shape.vars.len() {
                        rounds.push(reader.ks(width)?);
                    }
                    let sp = stele_sumcheck::Proof {
                        rounds,
                        final_values: reader.ks(instance.inputs.len())?,
                    };
                    reader.end()?;
                    let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
                    if !shape.shared.is_empty()
                        && sp.final_values[0] != shape.eq_at(&reduction.point)
                    {
                        return Err(Error::EqMismatch);
                    }
                    shape.route_operands(
                        lhs,
                        rhs,
                        *free,
                        &reduction.point,
                        &sp.final_values,
                        &mut claims,
                    );
                    ledger.add(
                        Line::Sc,
                        &col.name,
                        reduction.sc.numerator,
                        u64::from(reduction.sc.degree),
                    );
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                        for _ in 0..col.log_len {
                            rounds.push(reader.ks(3)?);
                        }
                        let bp = stele_sumcheck::Proof {
                            rounds,
                            final_values: reader.ks(1)?,
                        };
                        let reduction = batch.verify(&bp, t)?;
                        ledger.add(
                            Line::Rlc,
                            &col.name,
                            reduction.rlc.numerator,
                            reduction.rlc.numerator,
                        );
                        ledger.add(
                            Line::Sc,
                            &col.name,
                            reduction.sc.numerator,
                            u64::from(reduction.sc.degree),
                        );
                        let claim = &reduction.claims[0];
                        (claim.point.clone(), claim.value)
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let (inputs, instance, degree) =
                        pointwise_instance(col_id, col.log_len, terms, claimed_val);
                    let width = degree + 1;
                    let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                    for _ in 0..col.log_len {
                        rounds.push(reader.ks(width)?);
                    }
                    let sp = stele_sumcheck::Proof {
                        rounds,
                        final_values: reader.ks(instance.inputs.len())?,
                    };
                    reader.end()?;
                    let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
                    let expected_eq = stele_poly::eq_evaluate(&z, &reduction.point)
                        .map_err(|_| Error::Capacity)?;
                    if sp.final_values[0] != expected_eq {
                        return Err(Error::EqMismatch);
                    }
                    for (r, &val) in inputs.iter().zip(&sp.final_values[1..]) {
                        claims.push(r, &reduction.point, val);
                    }
                    ledger.add(
                        Line::Sc,
                        &col.name,
                        reduction.sc.numerator,
                        u64::from(reduction.sc.degree),
                    );
                }
                _ => return Err(Error::Unsupported),
            }
        }
        red_sections.end()?;

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

    // Every virtual-column claim must have been discharged during its owning segment's Step 2.4.
    for (i, column) in relation.columns.iter().enumerate() {
        if matches!(column.kind, Kind::Virtual(_)) && !claims.0[i].is_empty() {
            return Err(Error::ProofShape);
        }
    }
    // Public-column claims, evaluated by the verifier.
    for (i, column) in relation.columns.iter().enumerate() {
        if let Kind::Public(values) = &column.kind {
            for (point, value) in &claims.0[i] {
                if mle(ColumnSlice::I64(values), point)? != *value {
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
