//! RFC-0013 A5 items 1–6 with RFC-0026 A9: masked claims, identity and matmul
//! zero-sums, the shared mask source and per-source batching (dev-zk components).
//!
//! Defined for no profile (A5 item 8); task E12-14 wires it into the development
//! prover and verifier. Order on the caller's transcript:
//!
//! 1. Every claim source (a hiding source of committed columns with their claim
//!    masks, multiplicities included): bytes absorbed (`FieldSources`),
//!    certificates on their own A9 transcripts.
//! 2. Each lookup's `β, α` (`LookupBeta`, `LookupAlpha`), then the top source
//!    (every lookup's committed top layer, RFC-0008 A7 item 3) and the shared mask
//!    source: bytes absorbed together (`FieldSources`).
//! 3. Each relation in plan order (the statement's, then each lookup's
//!    `h·q − p = 0` and `Σ h = 0`): its public draws (`ZeroWeight` for an identity's
//!    `τ`, `RelationPoint` for a matmul's free point), then one masked A1 sumcheck
//!    on the `V̇` of A5 item 2, its mask bound by the shared source.
//! 4. Each lookup's masked GKR steps ([`lookup`], RFC-0008 A7 item 4).
//! 5. Each claim source with claims: `γ_a` (`BatchCoefficient`), the zero-weight
//!    batch of item 5 (mask in the shared source), one point opening.
//! 6. The shared source: `γ_j` over every `μ_j` and layer-block claim, the item-5
//!    batch with its own RFC-0013 A4 two-block mask source (item 5a), one opening.
//!
//! Plan rules fixed here (not protocol choices of the RFC; E12-14 may replace them
//! with the development plan's): a claim source holds its columns in index order,
//! each followed by its `t_x` blocks of `D` entries, packed from data position 0,
//! with `R = 2D` rows and `C = 2^m ≥ 2^9` columns; a `K`-valued top column is `D`
//! limb columns, limb-major. The shared source holds each masked instance's plain
//! mask `g_j` (relations, GKR steps, then batches) as `n_j(δ_j + 1)` consecutive
//! columns, limb `d` in data row `d`, and the layer blocks from data row `D` on.
//! Ids: claim sources `0..S` (the top source last), the shared source next, then
//! relations, GKR steps, batches and the shared batch; every mask stream is
//! therefore used once per proof.
use super::{basis, prove_at, verify_with, Error, Seed, BLOWUP, MIN_M};
use crate::relation::Line;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use stele_field::{Inverse, Serialize, M31};
use stele_hash::mask::{MaskStream, SOURCE_MASK};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_point, CodeField, Parameters, Policy, PreparedSource, Source,
    VerifiedCertificate,
};
use stele_sumcheck::masked::{self, Mask, MaskRecord};
use stele_sumcheck::{Dense, Instance, Reduction, Summand, Term};

#[path = "zk_lookup.rs"]
mod lookup;

/// The source set of a dev-zk proof: its sources' geometry and PCS policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Geometry {
    /// Profile byte 1 (A5, A6, A7): `R = 2D` rows on every claim source, policy 1,
    /// the shared source's limb `d` in data row `d`.
    Narrow,
    /// Profile byte 4 (RFC-0013 A8): each source's `ell` by A8 item 2's byte rule,
    /// policy 2 (development resolution), the shared source's limbs as `L`-wide runs.
    Balanced,
}

impl Geometry {
    /// The PCS policy of every source of this geometry.
    pub fn policy(self) -> Policy {
        match self {
            Geometry::Narrow => Policy::One,
            Geometry::Balanced => Policy::Two,
        }
    }
}

/// A committed column of `2^log_len` M31 entries in claim source `source`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    /// Index of its claim source.
    pub source: usize,
    /// Log2 of its length.
    pub log_len: u32,
}

/// One masked occurrence of a column in an identity: column coordinate `j`
/// (MSB-first) reads domain variable `vars[j]`; other domain variables broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Read {
    /// Index into [`Statement::columns`].
    pub column: usize,
    /// Distinct domain variables, one per column coordinate.
    pub vars: Vec<u32>,
}

impl Read {
    /// A `vars` entry fixing the coordinate to 0 (RFC-0026 A6, contractions only).
    pub const FIXED_0: u32 = u32::MAX - 1;
    /// A `vars` entry fixing the coordinate to 1 (RFC-0026 A6, contractions only).
    pub const FIXED_1: u32 = u32::MAX;
}

/// A public column read like a [`Read`]: never masked; the verifier evaluates it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Public {
    /// `2^{vars.len()}` values, MSB-first.
    pub values: Vec<i64>,
    /// Domain variable (or `Read::FIXED_*`) per column coordinate.
    pub vars: Vec<u32>,
}

/// A factor of a [`Relation::Combined`] or [`Relation::Contraction`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operand {
    /// A committed column, one masked occurrence (A5 item 2).
    Column(Read),
    /// A public column (RFC-0026 §3.2: coefficient vectors, masks, selectors).
    Public(Public),
}

/// A relation instance in A1 form (RFC-0026 A9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Relation<K> {
    /// `Σ_x eq(τ, x)·Σ_k c_k·Π_{f ∈ k} V̇_f(x) = 0` over `num_vars` variables,
    /// padded to `c_D + 1`. Term factors index `reads` (at most three per term).
    Identity {
        /// Domain variables before padding.
        num_vars: u32,
        /// One masked occurrence each.
        reads: Vec<Read>,
        /// Terms over `reads`; `eq(τ, ·)` is prepended to each.
        terms: Vec<Term<K>>,
    },
    /// `out(i, j) = Σ_k lhs(i, k)·rhs(k, j)` as the zero-sum
    /// `Σ_y [V̇_lhs(ρ_i, y)·V̇_rhs(y, ρ_j) − 2^{−inner}·Ȯ(ρ, y)] = 0`, `y` padded to
    /// `c_D + 1` variables; `out~(ρ)` is never sent.
    Matmul {
        /// Column `(i ‖ k)`.
        lhs: usize,
        /// Column `(k ‖ j)`.
        rhs: usize,
        /// Column `(i ‖ j)`.
        out: usize,
        /// Bits of `i`, `k` and `j`.
        rows: u32,
        /// Bits of `k`.
        inner: u32,
        /// Bits of `j`.
        cols: u32,
    },
    /// RFC-0026 §4 step 4 under A9: the identities of one domain size as one
    /// zero-sum `Σ_x eq(τ, x)·Σ_k γ_{parts[k]}·c_k·Π_f F_f(x) = 0`, with `count`
    /// `relation/identity` coefficients `γ` drawn before `τ`. Factors index
    /// `operands`; a term has at most three; each distinct committed read is one
    /// masked occurrence.
    Combined {
        /// Domain variables before padding.
        num_vars: u32,
        /// Distinct reads.
        operands: Vec<Operand>,
        /// Terms over `operands`, at most three factors each.
        terms: Vec<Term<K>>,
        /// The identity of each term, `< count`.
        parts: Vec<u32>,
        /// Identities combined.
        count: u32,
    },
    /// RFC-0026 §3.5 with A9: `out(x) = Σ_y lhs(x, y)·rhs(x, y)` over a domain of
    /// `free + summed` variables, MSB-first, the summed ones first. `ρ ∈ K^free`
    /// (`relation/point`, variable `summed + i` at `ρ_i`); the zero-sum runs over
    /// `y`, the shared free variables (read by both `lhs` and `rhs`, under
    /// `eq(ρ_shared, ·)`) and A9 padding. `out` reads free variables only.
    Contraction {
        /// Free variables.
        free: u32,
        /// Summed variables.
        summed: u32,
        /// The result, read on free variables.
        out: Operand,
        /// The left factor.
        lhs: Operand,
        /// The right factor.
        rhs: Operand,
    },
}

/// The public statement: claim sources, committed columns and relations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement<K> {
    /// Number of claim sources.
    pub sources: usize,
    /// Committed columns.
    pub columns: Vec<Column>,
    /// Relations in plan order.
    pub relations: Vec<Relation<K>>,
    /// Lookups proven by ZK-GKR (RFC-0008 A7), after the relations.
    pub lookups: Vec<Lookup>,
}

/// One RFC-0026 A3 check of `c`-tuples into a public table (RFC-0008 A7): every
/// selected tuple of every member must be a valid table row, and
/// `multiplicity(j)` counts the lookups of row `j` (each entry of a padded member
/// `2^pad` times, RFC-0026 A9). Members are concatenated largest first into a
/// lookup half of `2^n` positions, `n = max(c_D + 1, k, ⌈log Σ 2^{m'}⌉)` with
/// `m' = max(vars, c_D + 1)`; the table half is the table padded to `2^n` rows.
/// One tree: leaf `(x, 0)` is `S(x)/(α − Σ β^i S(x)·X_i(x))` with `S` the
/// concatenated selector (0 off the members) and `X_i` the concatenated shifted
/// tuple; leaf `(x, 1)` is `−mult(x)/(α − Σ β^i T_i(x))`, padded rows `0/1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    /// Members, in relation order.
    pub members: Vec<Member>,
    /// The committed multiplicity column, `2^k` entries.
    pub multiplicity: usize,
    /// Public table: `2^k` rows of `c` values; rows from `valid` on are padding.
    pub table: Vec<Vec<i64>>,
    /// Number of valid table rows.
    pub valid: usize,
}

/// One lookup or range of a check (RFC-0026 §3.3–3.4): over `vars` member
/// variables (MSB-first), each tuple entry is `tuple[i] + shifts[i]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    /// Member domain variables before A9 padding.
    pub vars: u32,
    /// `c` committed reads over the member domain.
    pub tuple: Vec<Read>,
    /// Added to each tuple entry (a range's `−width.min()`).
    pub shifts: Vec<i64>,
    /// Public 0/1 selector over the member domain; `None` selects all.
    pub selector: Option<Public>,
}

impl Lookup {
    /// One unselected, unshifted member reading `columns` on all of `n` variables.
    pub fn single(
        columns: &[usize],
        n: u32,
        multiplicity: usize,
        table: Vec<Vec<i64>>,
        valid: usize,
    ) -> Self {
        Self {
            members: vec![Member {
                vars: n,
                tuple: columns
                    .iter()
                    .map(|c| Read {
                        column: *c,
                        vars: (0..n).collect(),
                    })
                    .collect(),
                shifts: vec![0; columns.len()],
                selector: None,
            }],
            multiplicity,
            table,
            valid,
        }
    }
}

/// One linear claim `value = Σ weight·X[position]` on a source's data message
/// (row-major, `R × C`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim<K> {
    /// Sparse data weights.
    pub weights: Vec<(usize, K)>,
    /// The claimed value.
    pub value: K,
}

/// RFC-0013 A6: claim source `source` is a lifetime weight source,
/// committed once and opened by at most `proofs` proofs. Its column `i` (in
/// column order) reserves `proofs·blocks[i]` claim-mask blocks; proof `index`
/// uses blocks `index·blocks[i]..`, so every proof's masks are fresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lifetime {
    /// The source geometry and policy of the proof (RFC-0013 A8).
    pub geometry: Geometry,
    /// The lifetime source.
    pub source: usize,
    /// Its proof budget `P`.
    pub proofs: usize,
    /// This proof's index, `< proofs`.
    pub index: usize,
    /// Per-proof claim-mask blocks of each of its columns, in column order.
    pub blocks: Vec<usize>,
}

/// The prover's half of a lifetime source: the model seed and the
/// row-coefficient vectors its earlier openings revealed, in order.
pub struct ModelSecret<'a, K> {
    /// The seed the source was committed from.
    pub seed: &'a [u8; 32],
    /// Earlier openings' row-coefficient vectors.
    pub revealed: Vec<Vec<K>>,
    /// The published root. The rebuilt source must match it before any transcript
    /// work: other weights under the same masks would leak their difference.
    pub root: [u8; 32],
}

/// A batch of A5 item 5 on a plain-masked instance, with its point opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch<K> {
    /// The masked A1 rounds of `Σ (1 − w)·W·M̃'`, finals `[W', M']` and `μ`.
    pub sumcheck: masked::Proof<K>,
    /// The A9 point opening of the source at the final point.
    pub opening: Vec<u8>,
}

/// A dev-zk claims proof (A5 items 1–6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// Claim sources' exact version-3 bytes, then the shared mask source's.
    pub sources: Vec<Vec<u8>>,
    /// Their A9 certificates, in the same order.
    pub certificates: Vec<Vec<u8>>,
    /// One masked sumcheck per relation, in plan order.
    pub relations: Vec<masked::Proof<K>>,
    /// One masked sumcheck per GKR step, lookups in order, top layer first.
    pub gkr: Vec<masked::Proof<K>>,
    /// One batch per claim source with claims, in source order.
    pub batches: Vec<Batch<K>>,
    /// The shared source's batch, with its A4 mask source.
    pub shared: super::Proof<K>,
    /// The shared source's point opening.
    pub shared_opening: Vec<u8>,
}

/// What an accepted proof leaves: every A1 reduction (relations, GKR steps,
/// batches, shared batch, in order) with its SC record, and one MASK record per
/// masked instance. Every claim is already discharged by its source's opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified<K> {
    /// Reductions in transcript order; relation `j` is entry `j`.
    pub reductions: Vec<Reduction<K>>,
    /// MASK records in the same order.
    pub masks: Vec<MaskRecord>,
    /// Each lookup's public `(β, α)`.
    pub lookups: Vec<[K; 2]>,
    /// Each relation's public draws (`τ` or `ρ`), in plan order.
    pub draws: Vec<Vec<K>>,
    /// The dev-zk soundness ledger (E12-26), derived by the verifier.
    pub ledger: Ledger,
}

/// One interactive dev-zk term `numerator/|K|` (RFC-0026 §6 with RFC-0013 A5 and
/// RFC-0008 A7). `round` is the numerator of its largest single round, a maximal
/// run of challenges (RFC-0012 A17): an SC record's degree, and for draws that share
/// a run (`γ` with `τ`, `β` with `α`, `t*` with the next `λ`) the whole run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub line: Line,
    pub name: String,
    pub numerator: u64,
    pub round: u64,
}

/// One hiding source's PCS rounds under its verifier-derived parameters: the
/// certificate's tensor and column rounds and `openings` opening column rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsSource {
    pub name: String,
    /// Row exponent of the source, mask rows included (RFC-0010 A15's `ell + 1`).
    pub ell: u8,
    pub parameters: Parameters,
    pub openings: usize,
}

impl PcsSource {
    /// The tensor round's numerator `2·ell·(e + 1)` over `|K|` (RFC-0010 A14
    /// item 4), before its `2^k_t`.
    pub fn tensor(&self) -> u64 {
        2 * u64::from(self.ell) * (self.parameters.radius + 1)
    }
    /// `−log2` of a column round's bound: the policy's query target (Policy 1:
    /// 2^-130, A3 item 4; Policy 2: 2^-92, A14 item 2) plus `k_q`.
    pub fn column_bits(&self) -> u64 {
        let target = match self.parameters.policy {
            Policy::One => 130,
            _ => 92,
        };
        target + u64::from(self.parameters.column_grind_bits)
    }
}

/// The dev-zk soundness ledger of one accepted proof (E12-26). Interactive terms
/// only, as RFC-0026 §6: FS unproven (Q12), PCS conjectural (RFC-0012 A15), and
/// nothing summed into a claimed level. Producer aborts (RFC-0013 A5 item 4) are
/// completeness terms over `p`, printed and not summed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub entries: Vec<Entry>,
    pub pcs: Vec<PcsSource>,
    /// Masked claims across every claim source (each a claim-block rank abort).
    pub claims: usize,
    /// Extension degree `D` of `K`.
    pub degree: usize,
}

/// One round of the ledger with its security in 1/1024 bits: `−log2` of its error,
/// rounded down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    pub line: &'static str,
    pub name: String,
    pub bits: u64,
    pub grind: u8,
}

/// `⌊1024·log2 n⌋` for `n ≥ 1`, by repeated squaring of the Q62 mantissa.
fn log2_1024(n: u64) -> u64 {
    let n = n.max(1);
    let i = u64::from(63 - n.leading_zeros());
    let mut y = (u128::from(n) << 62) >> i;
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

/// `−log2(numerator/(2^grind·|K|))` in 1/1024 bits, rounded down (`|K| = p^4 <
/// 2^124`, and the log is rounded up).
fn bits(numerator: u64, grind: u8) -> u64 {
    (1024 * (124 + u64::from(grind))).saturating_sub(log2_1024(numerator) + 1)
}

impl Ledger {
    fn add(&mut self, line: Line, name: &str, numerator: u64, round: u64) {
        if numerator > 0 {
            self.entries.push(Entry {
                line,
                name: name.to_string(),
                numerator,
                round,
            });
        }
    }
    /// A masked instance's SC record (rounds of its degree) and MASK `1/|K|`.
    fn masked<K>(&mut self, name: &str, result: &masked::Reduction<K>) {
        let sc = &result.reduction.sc;
        self.add(Line::Sc, name, sc.numerator, u64::from(sc.degree));
        self.add(Line::Mask, name, 1, 1);
    }
    /// `ε_interactive·|K|`: the sum of every non-FS, non-PCS numerator.
    pub fn interactive(&self) -> u64 {
        self.entries.iter().map(|e| e.numerator).sum()
    }
    /// Every round: the algebraic ones (none grinded under dev-zk) and each
    /// source's PCS tensor and column rounds.
    pub fn rounds(&self) -> Vec<Round> {
        let mut rounds: Vec<Round> = self
            .entries
            .iter()
            .map(|e| Round {
                line: match e.line {
                    Line::Rlc => "RLC",
                    Line::Sc => "SC",
                    Line::Sz => "SZ",
                    Line::Lu => "LU",
                    Line::Zd => "ZD",
                    Line::Mask => "MASK",
                },
                name: e.name.clone(),
                bits: bits(e.round, 0),
                grind: 0,
            })
            .collect();
        for s in &self.pcs {
            let p = &s.parameters;
            rounds.push(Round {
                line: "PCS tensor",
                name: s.name.clone(),
                bits: bits(s.tensor(), p.tensor_grind_bits),
                grind: p.tensor_grind_bits,
            });
            rounds.push(Round {
                line: "PCS column",
                name: s.name.clone(),
                bits: 1024 * s.column_bits(),
                grind: p.column_grind_bits,
            });
        }
        rounds
    }
    /// The round with the largest error (least `bits`); the first in ledger order
    /// on ties.
    pub fn worst(&self) -> Option<Round> {
        self.rounds().into_iter().fold(None, |w, r| match w {
            Some(w) if w.bits <= r.bits => Some(w),
            _ => Some(r),
        })
    }
}

/// `2^-x.y` for a security of `bits/1024`, rounded down to a tenth.
pub fn tenths(bits: u64) -> String {
    let t = bits * 10 / 1024;
    alloc::format!("2^-{}.{}", t / 10, t % 10)
}

impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for e in &self.entries {
            writeln!(f, "{:?}\t{}\t{}/|K|", e.line, e.name, e.numerator)?;
        }
        let d = self.degree as u64;
        for s in &self.pcs {
            let p = &s.parameters;
            writeln!(
                f,
                "PCS\t{}\tell {}, policy {:?}, q_c/q_o {}/{}, k_t {}, k_q {}, {} opening(s); \
                 tensor {}/|K| before 2^{}, column {}\tconjectural (RFC-0012 A15)",
                s.name,
                s.ell,
                p.policy,
                p.certificate_queries,
                p.opening_queries,
                p.tensor_grind_bits,
                p.column_grind_bits,
                s.openings,
                s.tensor(),
                p.tensor_grind_bits,
                tenths(1024 * s.column_bits()),
            )?;
        }
        for s in &self.pcs {
            writeln!(
                f,
                "abort\tMaskRank {}\t{}/p\tcompleteness only",
                s.name,
                2 * d * u64::from(s.ell)
            )?;
        }
        writeln!(
            f,
            "abort\tclaim-block rank, {} claims\t{}/p\tcompleteness only",
            self.claims,
            self.claims as u64 * d * u64::from(d.trailing_zeros())
        )?;
        if let Some(w) = self.worst() {
            writeln!(
                f,
                "worst round\t{} {}\t{}\tgrinding {} bits",
                w.line,
                w.name,
                tenths(w.bits),
                w.grind
            )?;
        }
        write!(
            f,
            "eps_interactive <= {}/p^4; FS unproven, PCS conjectural",
            self.interactive()
        )
    }
}

fn dim<K: CodeField>() -> usize {
    <K as CodeField>::DEGREE as usize
}

fn zero<K: ChallengeField>() -> K {
    K::from_i64(0)
}

fn kappa<K: ChallengeField>(t: K) -> K {
    t * (K::from_i64(1) - t)
}

fn ceil_log2(n: usize) -> u8 {
    n.max(1).next_power_of_two().trailing_zeros() as u8
}

fn element<K: ChallengeField>(x: M31) -> K {
    K::from_i64(i64::from(x.as_u32()))
}

fn limbs<K: ChallengeField + CodeField>(value: K) -> Result<Vec<M31>, Error> {
    let bytes = value.to_le_bytes();
    (0..dim::<K>())
        .map(|d| {
            let limb = bytes.as_ref()[4 * d..4 * d + 4]
                .try_into()
                .map_err(|_| Error::MaskSource)?;
            M31::from_le_bytes(limb).ok_or(Error::MaskSource)
        })
        .collect()
}

/// A column coordinate: a domain variable or a coordinate of the drawn point.
#[derive(Clone, Copy, Debug)]
enum Coord {
    Var(usize),
    Free(usize),
    /// A fixed Boolean coordinate (RFC-0026 A6): no Schwartz–Zippel term.
    Fixed(u8),
}

/// A public input of a step: its values and coordinates.
#[derive(Clone, Debug)]
struct PublicInput<K> {
    values: Vec<K>,
    coords: Vec<Coord>,
}

/// One masked occurrence: column, coordinates, vanishing variable `v`, mask
/// coordinates `u` and its block index in the column's claim mask.
#[derive(Clone, Debug)]
struct Occurrence {
    column: usize,
    coords: Vec<Coord>,
    v: usize,
    u: Vec<usize>,
    block: usize,
}

/// A relation's plan: its instance shape, draws and occurrences.
struct Step<K> {
    id: u64,
    num_vars: u32,
    /// `eq(τ, ·)` over the leading `len` step variables is input 0, with `τ` the
    /// draws at these indices (an identity: all `num_vars`; a contraction: its
    /// shared free variables).
    eq: Option<Vec<usize>>,
    label: ChallengeLabel,
    draws: usize,
    occurrences: Vec<Occurrence>,
    /// Public inputs, after the occurrences.
    publics: Vec<PublicInput<K>>,
    terms: Vec<Term<K>>,
    degree: usize,
    /// `Combined`: each term's identity and the coefficient count, drawn first.
    parts: Option<(Vec<u32>, usize)>,
}

impl<K: ChallengeField> Step<K> {
    fn first(&self) -> usize {
        usize::from(self.eq.is_some())
    }
    /// The terms with each identity's coefficient applied.
    fn scaled(&self, gammas: &[K]) -> Vec<Term<K>> {
        match &self.parts {
            None => self.terms.clone(),
            Some((parts, _)) => self
                .terms
                .iter()
                .zip(parts)
                .map(|(t, p)| Term {
                    coefficient: t.coefficient * gammas[*p as usize],
                    factors: t.factors.clone(),
                })
                .collect(),
        }
    }
    /// `τ`: the draws under `eq`.
    fn tau(&self, free: &[K]) -> Vec<K> {
        self.eq.iter().flatten().map(|i| free[*i]).collect()
    }
}

/// A committed column of the plan: the statement's, then each lookup's top `p, q,
/// h` (`K`-valued, `limbs = D`).
#[derive(Clone, Copy, Debug)]
struct PlanColumn {
    source: usize,
    log_len: u32,
    limbs: usize,
}

/// A claim source's layout: `R = 2^ell`, `C = 2^m`, each column's offset and its
/// first block's offset.
struct Layout {
    ell: u8,
    m: u8,
    offsets: Vec<(usize, usize)>,
}

struct Plan<K> {
    columns: Vec<PlanColumn>,
    steps: Vec<Step<K>>,
    lookups: Vec<lookup::LookupPlan>,
    gkr: Vec<lookup::GkrStep>,
    /// Per column: (offset, first block offset) in its source; per source: (ell, m).
    layouts: Vec<Layout>,
    /// Sources with at least one claim, in order.
    batched: Vec<usize>,
    /// Every masked instance's (id, num_vars, degree): relations, GKR steps, batches.
    masks: Vec<(u64, u32, usize)>,
    /// Column offset of each mask in the shared source, and its `(ell, m)`.
    shared_offsets: Vec<usize>,
    shared: (u8, u8),
    /// Data positions per limb run of the shared source's plain masks: `L = C` under
    /// [`Geometry::Narrow`] (limb `d` in row `d`), the total mask width under
    /// [`Geometry::Balanced`]. Layer blocks start at `D·L`.
    stride: usize,
    /// The proof's source set.
    geometry: Geometry,
    /// Layer blocks of `4D` entries in the shared source, from data row `D`.
    blocks: usize,
    /// Masked occurrences (claim-mask blocks) per column.
    counts: Vec<usize>,
    /// Claim-mask blocks committed per column (`counts`, or `P·t` for a lifetime
    /// source's columns).
    reserved: Vec<usize>,
    /// The lifetime source, if any.
    lifetime: Option<Lifetime>,
}

impl<K: ChallengeField + CodeField> Plan<K> {
    fn source_id(&self, s: usize) -> u64 {
        s as u64
    }
    fn policy(&self) -> Policy {
        self.geometry.policy()
    }
    fn shared_id(&self) -> u64 {
        self.layouts.len() as u64
    }
    fn shared_batch_id(&self) -> u64 {
        self.shared_id() + 1 + self.masks.len() as u64
    }
    /// Sources committed before the lookup draws: all but the top source.
    fn early(&self) -> usize {
        self.layouts.len() - usize::from(!self.lookups.is_empty())
    }
}

/// A5 item 2's default over one instance's inputs: each `free` input takes as `v`
/// the lowest-index variable not used as `v` by an earlier masked input sharing a
/// term, and as `u` the `c_D` lowest-index others. A statement that leaves an
/// occurrence no fresh variable is outside item 2 and refused.
fn vanish<K>(
    num_vars: usize,
    c: usize,
    terms: &[Term<K>],
    masked: &mut [Option<(usize, Vec<usize>)>],
    free: &[bool],
) -> Result<(), Error> {
    // The terms each input appears in, so `a`'s term-sharing partners are found
    // without scanning every earlier input against every term (E16-24).
    let mut terms_of = vec![Vec::new(); masked.len()];
    for (k, t) in terms.iter().enumerate() {
        for f in &t.factors {
            if let Some(list) = terms_of.get_mut(*f as usize) {
                if list.last() != Some(&k) {
                    list.push(k);
                }
            }
        }
    }
    let mut used = vec![false; num_vars];
    for a in 0..masked.len() {
        if !free[a] {
            continue;
        }
        // `v` of every earlier masked input sharing a term with `a`.
        used.iter_mut().for_each(|u| *u = false);
        for &k in &terms_of[a] {
            for &b in &terms[k].factors {
                let b = b as usize;
                if b < a {
                    if let Some((v, _)) = &masked[b] {
                        if let Some(u) = used.get_mut(*v) {
                            *u = true;
                        }
                    }
                }
            }
        }
        let v = (0..num_vars).find(|q| !used[*q]).ok_or(Error::Statement)?;
        masked[a] = Some((v, (0..num_vars).filter(|&q| q != v).take(c).collect()));
    }
    Ok(())
}

/// A5 item 3: the per-variable maximum over terms, where a masked input has degree
/// `2 + [v ∈ u]` in its vanishing variable `v` and every input degree 1 elsewhere.
fn degree<K>(num_vars: usize, terms: &[Term<K>], masked: &[Option<(usize, Vec<usize>)>]) -> usize {
    terms
        .iter()
        .flat_map(|t| {
            (0..num_vars).map(move |q| {
                t.factors
                    .iter()
                    .map(|f| match &masked[*f as usize] {
                        Some((v, u)) if *v == q => 2 + usize::from(u.contains(&q)),
                        _ => 1,
                    })
                    .sum::<usize>()
            })
        })
        .max()
        .unwrap_or(1)
        .max(1)
}

/// [`vanish`] and [`degree`] for a relation whose inputs `first..` are its
/// occurrences.
fn assign<K>(
    num_vars: usize,
    occurrences: &mut [Occurrence],
    first: usize,
    terms: &[Term<K>],
    c: usize,
) -> Result<usize, Error> {
    let inputs = terms
        .iter()
        .flat_map(|t| t.factors.iter())
        .map(|f| *f as usize + 1)
        .max()
        .unwrap_or(0);
    let mut masked = vec![None; inputs.max(first + occurrences.len())];
    let free: Vec<bool> = (0..masked.len())
        .map(|i| i >= first && i < first + occurrences.len())
        .collect();
    vanish(num_vars, c, terms, &mut masked, &free)?;
    for (o, m) in occurrences.iter_mut().zip(&masked[first..]) {
        if let Some((v, u)) = m {
            o.v = *v;
            o.u = u.clone();
        }
    }
    Ok(degree(num_vars, terms, &masked))
}

/// An identity step `Σ_x eq(τ, x)·Σ_k c_k·Π V̇ = 0` over `reads` (A5, RFC-0026 A9).
fn identity_step<K: ChallengeField>(
    id: u64,
    num_vars: usize,
    reads: Vec<(usize, Vec<usize>)>,
    terms: &[Term<K>],
    c: usize,
    eq: bool,
) -> Result<Step<K>, Error> {
    let mut occurrences: Vec<Occurrence> = reads
        .into_iter()
        .map(|(column, vars)| Occurrence {
            column,
            coords: vars.into_iter().map(Coord::Var).collect(),
            v: 0,
            u: Vec::new(),
            block: 0,
        })
        .collect();
    let first = usize::from(eq);
    // eq(τ, ·) is input 0 of every term.
    let terms: Vec<Term<K>> = terms
        .iter()
        .map(|t| Term {
            coefficient: t.coefficient,
            factors: eq
                .then_some(0)
                .into_iter()
                .chain(t.factors.iter().map(|f| f + first as u32))
                .collect(),
        })
        .collect();
    let degree = assign(num_vars, &mut occurrences, first, &terms, c)?;
    Ok(Step {
        id,
        num_vars: num_vars as u32,
        eq: eq.then(|| (0..num_vars).collect()),
        label: ChallengeLabel::ZeroWeight,
        draws: if eq { num_vars } else { 0 },
        occurrences,
        publics: Vec::new(),
        terms,
        degree,
        parts: None,
    })
}

/// Maps a read's variables to step coordinates.
type CoordMap<'a> = dyn Fn(&[u32]) -> Result<Vec<Coord>, Error> + 'a;

fn distinct(vars: &[u32]) -> Result<(), Error> {
    let fixed = |q: &u32| *q >= Read::FIXED_0;
    match vars
        .iter()
        .enumerate()
        .any(|(k, q)| !fixed(q) && vars[..k].contains(q))
    {
        true => Err(Error::Statement),
        false => Ok(()),
    }
}

/// A step over `operands` (input 0 reserved for `eq`): committed reads become
/// occurrences, public reads public inputs after them; term factors are remapped.
fn operand_step<K: ChallengeField>(
    id: u64,
    n: usize,
    operands: &[Operand],
    terms: &[Term<K>],
    map: &CoordMap<'_>,
    column: &dyn Fn(usize, u32) -> Result<usize, Error>,
) -> Result<Step<K>, Error> {
    let mut occurrences = Vec::new();
    let mut publics = Vec::new();
    for operand in operands {
        match operand {
            Operand::Column(read) => occurrences.push(Occurrence {
                column: column(read.column, read.vars.len() as u32)?,
                coords: map(&read.vars)?,
                v: 0,
                u: Vec::new(),
                block: 0,
            }),
            Operand::Public(p) => {
                if p.values.len() != 1usize << p.vars.len() {
                    return Err(Error::Statement);
                }
                publics.push(PublicInput {
                    values: p.values.iter().map(|v| K::from_i64(*v)).collect(),
                    coords: map(&p.vars)?,
                });
            }
        }
    }
    // Input of operand `o`: 1 + its rank among occurrences, or after them.
    let (mut seen_c, mut seen_p) = (0u32, 0u32);
    let index: Vec<u32> = operands
        .iter()
        .map(|o| match o {
            Operand::Column(_) => {
                seen_c += 1;
                seen_c
            }
            Operand::Public(_) => {
                seen_p += 1;
                occurrences.len() as u32 + seen_p
            }
        })
        .collect();
    let terms = terms
        .iter()
        .map(|t| Term {
            coefficient: t.coefficient,
            factors: core::iter::once(0)
                .chain(t.factors.iter().map(|f| index[*f as usize]))
                .collect(),
        })
        .collect();
    Ok(Step {
        id,
        num_vars: n as u32,
        eq: None,
        label: ChallengeLabel::RelationPoint,
        draws: 0,
        occurrences,
        publics,
        terms,
        degree: 0,
        parts: None,
    })
}

/// A [`Relation::Contraction`]'s step: variables are the shared free ones (under
/// `eq(ρ_shared, ·)`, input 0), then the summed ones, then A9 padding.
fn contraction<K: ChallengeField>(
    id: u64,
    free: u32,
    summed: u32,
    [out, lhs, rhs]: [&Operand; 3],
    c: usize,
    column: &dyn Fn(usize, u32) -> Result<usize, Error>,
) -> Result<Step<K>, Error> {
    let (a, s) = (free as usize, summed as usize);
    let vars = |o: &Operand| match o {
        Operand::Column(r) => r.vars.clone(),
        Operand::Public(p) => p.vars.clone(),
    };
    let reads = |o: &Operand, q: usize| vars(o).contains(&(q as u32));
    let shared: Vec<usize> = (s..s + a)
        .filter(|q| reads(lhs, *q) && reads(rhs, *q))
        .collect();
    let n = (shared.len() + s).max(c + 1);
    // `out` reads free variables only (RFC-0026 §3.5); any ref may fix a bit (A6).
    if n > 24
        || [out, lhs, rhs].iter().any(|o| {
            vars(o)
                .iter()
                .any(|q| *q < Read::FIXED_0 && *q as usize >= a + s)
        })
        || vars(out).iter().any(|q| (*q as usize) < s)
    {
        return Err(Error::Statement);
    }
    let map = |vars: &[u32]| -> Result<Vec<Coord>, Error> {
        distinct(vars)?;
        Ok(vars
            .iter()
            .map(|q| match *q {
                Read::FIXED_0 => Coord::Fixed(0),
                Read::FIXED_1 => Coord::Fixed(1),
                q if (q as usize) < s => Coord::Var(shared.len() + q as usize),
                q => match shared.iter().position(|x| *x == q as usize) {
                    Some(p) => Coord::Var(p),
                    None => Coord::Free(q as usize - s),
                },
            })
            .collect())
    };
    // Σ eq·lhs·rhs counts out 2^pad times and Σ eq·Ȯ counts it 2^{s+pad} times,
    // so −2^{−s} balances them (RFC-0026 A9).
    let half = K::from_i64(2).inverse().ok_or(Error::Statement)?;
    let scale = (0..s).fold(K::from_i64(1), |p, _| p * half);
    let terms = [
        Term {
            coefficient: K::from_i64(1),
            factors: vec![1, 2],
        },
        Term {
            coefficient: zero::<K>() - scale,
            factors: vec![0],
        },
    ];
    let operands = [out.clone(), lhs.clone(), rhs.clone()];
    let mut step = operand_step(id, n, &operands, &terms, &map, column)?;
    if shared.is_empty() {
        // No eq input: every factor moves down by one.
        for t in &mut step.terms {
            t.factors.remove(0);
            for f in &mut t.factors {
                *f -= 1;
            }
        }
    } else {
        step.eq = Some(shared.iter().map(|q| q - s).collect());
    }
    step.draws = a;
    step.label = ChallengeLabel::RelationPoint;
    let first = step.first();
    step.degree = assign(n, &mut step.occurrences, first, &step.terms, c)?;
    Ok(step)
}

fn plan<K: ChallengeField + CodeField>(statement: &Statement<K>) -> Result<Plan<K>, Error> {
    plan_with(statement, None)
}

/// RFC-0013 A8 item 2: the `(ell, m)` of a balanced policy-2 hiding source of at
/// least `entries` data positions minimising its proof bytes
/// `2·4D·2C + (q_c + q_o)·(4·2R + 32·log2 N + 32)`, ties to the smallest `ell`. For
/// each `ell` the least admissible `m` is taken; a lifetime source (`proofs`) must
/// also admit A6's lifetime. No admissible shape is `Statement`.
fn balanced_shape<K: ChallengeField + CodeField>(
    entries: usize,
    proofs: Option<usize>,
) -> Result<(u8, u8), Error> {
    let mut best: Option<(usize, u8, u8)> = None;
    for ell in 1u8..30 {
        let least = MIN_M.max(ceil_log2(entries.max(1).div_ceil(1usize << ell)));
        let shape = (least..30).find_map(|m| {
            let source = Source::<K>::hiding_with(0, ell, m, BLOWUP, [0; 32], Policy::Two).ok()?;
            proofs
                .is_none_or(|p| source.admits_lifetime(p))
                .then_some((m, source))
        });
        let Some((m, source)) = shape else {
            continue;
        };
        let p = source.parameters();
        let response =
            4 * source.rows() + 32 * source.codeword_len().trailing_zeros() as usize + 32;
        let bytes = 2 * 4 * dim::<K>() * source.columns()
            + (usize::from(p.certificate_queries) + usize::from(p.opening_queries)) * response;
        if best.is_none_or(|(b, _, _)| bytes < b) {
            best = Some((bytes, ell, m));
        }
    }
    best.map(|(_, ell, m)| (ell, m)).ok_or(Error::Statement)
}

/// A6's admission of a lifetime source: the smallest `(ell, m)` with `R ≥ 2D`,
/// `R ≥ (P + 1)·D` and `q_c + P·q_o ≤ C − 1`, holding at least `entries`.
fn lifetime_shape<K: ChallengeField + CodeField>(
    id: u64,
    proofs: usize,
    entries: usize,
) -> Result<(u8, u8), Error> {
    let ell = ceil_log2((2 * dim::<K>()).max((proofs + 1) * dim::<K>()));
    let mut m = MIN_M.max(ceil_log2(entries.div_ceil(1 << ell)));
    while m < 30 {
        let source = Source::<K>::hiding(id, ell, m, BLOWUP, [0; 32]).map_err(Error::Pcs)?;
        if source.admits_lifetime(proofs) {
            return Ok((ell, m));
        }
        m += 1;
    }
    Err(Error::Statement)
}

fn plan_with<K: ChallengeField + CodeField>(
    statement: &Statement<K>,
    lifetime: Option<&Lifetime>,
) -> Result<Plan<K>, Error> {
    let geometry = lifetime.map_or(Geometry::Narrow, |l| l.geometry);
    let c = dim::<K>().trailing_zeros() as usize;
    let s = statement.sources;
    if s == 0
        || statement
            .columns
            .iter()
            .any(|x| x.source >= s || x.log_len > 24)
    {
        return Err(Error::Statement);
    }
    let lookups = !statement.lookups.is_empty();
    let sources = s + usize::from(lookups);
    let mut columns: Vec<PlanColumn> = statement
        .columns
        .iter()
        .map(|x| PlanColumn {
            source: x.source,
            log_len: x.log_len,
            limbs: 1,
        })
        .collect();
    let column = |index: usize, len: u32| -> Result<usize, Error> {
        match statement.columns.get(index) {
            Some(x) if x.log_len == len => Ok(index),
            _ => Err(Error::Statement),
        }
    };
    let mut steps = Vec::new();
    let id = |j: usize| (sources + 1 + j) as u64;
    for (j, relation) in statement.relations.iter().enumerate() {
        let step = match relation {
            Relation::Identity {
                num_vars,
                reads,
                terms,
            } => {
                let mut checked = Vec::new();
                for read in reads {
                    if read
                        .vars
                        .iter()
                        .enumerate()
                        .any(|(k, q)| *q >= *num_vars || read.vars[..k].contains(q))
                    {
                        return Err(Error::Statement);
                    }
                    let vars = read.vars.iter().map(|q| *q as usize).collect();
                    checked.push((column(read.column, read.vars.len() as u32)?, vars));
                }
                if terms.iter().any(|t| {
                    t.factors.len() > 3 || t.factors.iter().any(|f| *f as usize >= reads.len())
                }) {
                    return Err(Error::Statement);
                }
                let n = (*num_vars as usize).max(c + 1);
                if n > 24 {
                    return Err(Error::Statement);
                }
                identity_step(id(j), n, checked, terms, c, true)?
            }
            Relation::Matmul {
                lhs,
                rhs,
                out,
                rows,
                inner,
                cols,
            } => {
                let (a, k, b) = (*rows as usize, *inner as usize, *cols as usize);
                let n = k.max(c + 1);
                if n > 24 {
                    return Err(Error::Statement);
                }
                let free = |range: core::ops::Range<usize>| range.map(Coord::Free);
                let vars = || (0..k).map(Coord::Var);
                let occurrence = |column, coords| Occurrence {
                    column,
                    coords,
                    v: 0,
                    u: Vec::new(),
                    block: 0,
                };
                let mut occurrences = vec![
                    occurrence(
                        column(*lhs, rows + inner)?,
                        free(0..a).chain(vars()).collect(),
                    ),
                    occurrence(
                        column(*rhs, inner + cols)?,
                        vars().chain(free(a..a + b)).collect(),
                    ),
                    occurrence(column(*out, rows + cols)?, free(0..a + b).collect()),
                ];
                // Σ_y lhs·rhs counts out 2^pad times and Σ_y Ȯ counts it 2^n
                // times, so −2^{−inner} balances them (RFC-0026 A9).
                let half = K::from_i64(2).inverse().ok_or(Error::Statement)?;
                let scale = (0..k).fold(K::from_i64(1), |p, _| p * half);
                let terms = vec![
                    Term {
                        coefficient: K::from_i64(1),
                        factors: vec![0, 1],
                    },
                    Term {
                        coefficient: zero::<K>() - scale,
                        factors: vec![2],
                    },
                ];
                let degree = assign(n, &mut occurrences, 0, &terms, c)?;
                Step {
                    id: id(j),
                    num_vars: n as u32,
                    eq: None,
                    label: ChallengeLabel::RelationPoint,
                    draws: a + b,
                    occurrences,
                    publics: Vec::new(),
                    terms,
                    degree,
                    parts: None,
                }
            }
            Relation::Combined {
                num_vars,
                operands,
                terms,
                parts,
                count,
            } => {
                let n = (*num_vars as usize).max(c + 1);
                if n > 24
                    || parts.len() != terms.len()
                    || parts.iter().any(|p| p >= count)
                    || terms.iter().any(|t| {
                        t.factors.len() > 3
                            || t.factors.iter().any(|f| *f as usize >= operands.len())
                    })
                {
                    return Err(Error::Statement);
                }
                let map = |vars: &[u32]| -> Result<Vec<Coord>, Error> {
                    distinct(vars)?;
                    vars.iter()
                        .map(|q| match *q {
                            q if q < *num_vars => Ok(Coord::Var(q as usize)),
                            _ => Err(Error::Statement),
                        })
                        .collect()
                };
                let mut step = operand_step(id(j), n, operands, terms, &map, &column)?;
                step.eq = Some((0..n).collect());
                step.label = ChallengeLabel::ZeroWeight;
                step.draws = n;
                step.parts = Some((parts.clone(), *count as usize));
                step.degree = assign(n, &mut step.occurrences, 1, &step.terms, c)?;
                step
            }
            Relation::Contraction {
                free,
                summed,
                out,
                lhs,
                rhs,
            } => contraction(id(j), *free, *summed, [out, lhs, rhs], c, &column)?,
        };
        steps.push(step);
    }
    // RFC-0008 A7 item 3: each lookup's top p, q, h in the top source, proven by
    // `h·q − p = 0` and `Σ h = 0`; then its masked GKR steps (item 4).
    let mut lookup_plans = Vec::new();
    let mut gkr = Vec::new();
    let mut blocks = 0;
    for (l, spec) in statement.lookups.iter().enumerate() {
        let top = columns.len();
        let k0 = c + 1;
        for _ in 0..3 {
            columns.push(PlanColumn {
                source: s,
                log_len: k0 as u32,
                limbs: dim::<K>(),
            });
        }
        let vars: Vec<usize> = (0..k0).collect();
        let reads = vec![
            (top + 2, vars.clone()),
            (top + 1, vars.clone()),
            (top, vars.clone()),
        ];
        let one = |factors: Vec<u32>, coefficient: i64| Term {
            coefficient: K::from_i64(coefficient),
            factors,
        };
        let terms = [one(vec![0, 1], 1), one(vec![2], -1)];
        let identity = Some(steps.len());
        steps.push(identity_step(id(steps.len()), k0, reads, &terms, c, true)?);
        let sum = [one(vec![0], 1)];
        steps.push(identity_step(
            id(steps.len()),
            k0,
            vec![(top + 2, vars)],
            &sum,
            c,
            false,
        )?);
        let (mut lp, steps_l) =
            lookup::plan_lookup::<K>(statement, l, spec, [top, top + 1, top + 2], blocks, c)?;
        lp.identity = identity;
        blocks += lp.block_count();
        lookup_plans.push(lp);
        gkr.extend(steps_l);
    }
    for (g, step) in gkr.iter_mut().enumerate() {
        step.id = id(steps.len() + g);
    }
    // Block indices in plan order: relations, then GKR steps.
    let mut counts = vec![0usize; columns.len()];
    for occurrence in steps
        .iter_mut()
        .flat_map(|st| st.occurrences.iter_mut())
        .chain(gkr.iter_mut().flat_map(|g| g.occurrences_mut()))
    {
        occurrence.block = counts[occurrence.column];
        counts[occurrence.column] += 1;
    }
    // RFC-0013 A6: a lifetime source's columns reserve P·t blocks; this proof
    // takes its own set, after `index·t`.
    let mut reserved = counts.clone();
    if let Some(life) = lifetime {
        let members: Vec<usize> = (0..columns.len())
            .filter(|c| columns[*c].source == life.source)
            .collect();
        if life.source >= s
            || life.proofs == 0
            || life.index >= life.proofs
            || members.len() != life.blocks.len()
            || members
                .iter()
                .zip(&life.blocks)
                .any(|(c, t)| counts[*c] > *t)
        {
            return Err(Error::Statement);
        }
        for (c, t) in members.iter().zip(&life.blocks) {
            reserved[*c] = life.proofs.checked_mul(*t).ok_or(Error::Statement)?;
        }
        for occurrence in steps
            .iter_mut()
            .flat_map(|st| st.occurrences.iter_mut())
            .chain(gkr.iter_mut().flat_map(|g| g.occurrences_mut()))
        {
            if let Some(i) = members.iter().position(|c| *c == occurrence.column) {
                occurrence.block += life.index * life.blocks[i];
            }
        }
    }
    // Claim sources: columns in index order, each followed by its blocks.
    let rows = 2 * dim::<K>();
    let ell = ceil_log2(rows);
    let mut cursors = vec![0usize; sources];
    let mut offsets = Vec::new();
    for (index, x) in columns.iter().enumerate() {
        let at = cursors[x.source];
        let blocks = at + (x.limbs << x.log_len);
        // A hostile commitment file can name huge block counts.
        cursors[x.source] = reserved[index]
            .checked_mul(dim::<K>())
            .and_then(|b| b.checked_add(blocks))
            .ok_or(Error::Statement)?;
        offsets.push((at, blocks));
    }
    let mut layouts = Vec::new();
    for (source, cursor) in cursors.iter().enumerate() {
        let (ell, m) = match (lifetime, geometry) {
            (Some(life), Geometry::Narrow) if life.source == source => {
                lifetime_shape::<K>(source as u64, life.proofs, *cursor)?
            }
            (Some(life), Geometry::Balanced) if life.source == source => {
                balanced_shape::<K>(*cursor, Some(life.proofs))?
            }
            (_, Geometry::Narrow) => (ell, MIN_M.max(ceil_log2(cursor.div_ceil(rows)))),
            (_, Geometry::Balanced) => balanced_shape::<K>(*cursor, None)?,
        };
        if m >= 30 {
            return Err(Error::Statement);
        }
        layouts.push(Layout {
            ell,
            m,
            offsets: Vec::new(),
        });
    }
    for (x, offset) in columns.iter().zip(offsets) {
        layouts[x.source].offsets.push(offset);
    }
    let batched: Vec<usize> = (0..sources)
        .filter(|&source| {
            columns
                .iter()
                .zip(&counts)
                .any(|(x, n)| x.source == source && *n > 0)
        })
        .collect();
    let mut masks: Vec<(u64, u32, usize)> = steps
        .iter()
        .map(|st| (st.id, st.num_vars, st.degree))
        .chain(gkr.iter().map(|g| (g.id, g.num_vars, g.degree)))
        .collect();
    for source in &batched {
        let layout = &layouts[*source];
        masks.push((id(masks.len()), u32::from(layout.ell + 1 + layout.m), 2));
    }
    let mut shared_offsets = Vec::new();
    let mut width = 0usize;
    for (_, n, degree) in &masks {
        shared_offsets.push(width);
        width += *n as usize * (degree + 1);
    }
    // Narrow: limb d in data row d, blocks in data rows D..2D, so C ≥ width and
    // C ≥ 4·blocks. Balanced (RFC-0013 A8 item 2): limb d at [d·L, (d + 1)·L) with
    // L = width, then the blocks from D·L, on the shape A8's byte rule picks.
    let (shared, stride) = match geometry {
        Geometry::Narrow => {
            let m = MIN_M.max(ceil_log2(width)).max(ceil_log2(4 * blocks));
            if m >= 30 {
                return Err(Error::Statement);
            }
            ((ell, m), 1usize << m)
        }
        Geometry::Balanced => {
            let entries = dim::<K>() * (width + 4 * blocks);
            (balanced_shape::<K>(entries, None)?, width.max(1))
        }
    };
    Ok(Plan {
        columns,
        steps,
        lookups: lookup_plans,
        gkr,
        layouts,
        batched,
        masks,
        shared_offsets,
        shared,
        stride,
        geometry,
        blocks,
        counts,
        reserved,
        lifetime: lifetime.cloned(),
    })
}

/// The column's position within its source's `offsets`.
fn slot<K>(plan: &Plan<K>, column: usize) -> usize {
    let source = plan.columns[column].source;
    plan.columns[..column]
        .iter()
        .filter(|x| x.source == source)
        .count()
}

/// A column point: its `Var` coordinates at `ρ`, its `Free` ones at `free`.
fn column_point<K: ChallengeField>(coords: &[Coord], point: &[K], free: &[K]) -> Vec<K> {
    coords
        .iter()
        .map(|c| match c {
            Coord::Var(q) => point[*q],
            Coord::Free(i) => free[*i],
            Coord::Fixed(b) => K::from_i64(i64::from(*b)),
        })
        .collect()
}

/// The linear claim of one occurrence on its source:
/// `c_a = x̃(ρ|coords) + κ(ρ_v)·r̃_x(a, ρ_u)` (A5 item 2). A `K`-valued column
/// weighs limb `d` by `e_d`.
fn occurrence_claim<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    occurrence: &Occurrence,
    point: &[K],
    free: &[K],
    value: K,
) -> Result<(usize, Claim<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let column = plan.columns[occurrence.column];
    let (at, blocks) = plan.layouts[column.source].offsets[slot(plan, occurrence.column)];
    let x = stele_poly::eq_table(&column_point(&occurrence.coords, point, free))
        .map_err(|_| Error::Statement)?;
    let u: Vec<K> = occurrence.u.iter().map(|q| point[*q]).collect();
    let r = stele_poly::eq_table(&u).map_err(|_| Error::Statement)?;
    let k = kappa(point[occurrence.v]);
    let first = blocks + occurrence.block * dim::<K>();
    let len = 1usize << column.log_len;
    let mut weights = Vec::new();
    for d in 0..column.limbs {
        let e = if column.limbs == 1 {
            K::from_i64(1)
        } else {
            basis::<K>(d)?
        };
        weights.extend(
            x.iter()
                .enumerate()
                .map(|(p, w)| (at + d * len + p, e * *w)),
        );
    }
    weights.extend(r.into_iter().enumerate().map(|(p, w)| (first + p, k * w)));
    Ok((column.source, Claim { weights, value }))
}
/// `μ_j` as a linear claim on the shared source: `Σ_{d,c} e_d·b_c·X[d][o_j + c]`
/// with `b` the plain mask's column weights at `ρ_j`.
fn mask_claim<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    index: usize,
    point: &[K],
    value: K,
) -> Result<Claim<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (_, n, degree) = plan.masks[index];
    let b = masked::column_weights(n, degree, point, true).map_err(Error::Sumcheck)?;
    let stride = plan.stride;
    let offset = plan.shared_offsets[index];
    let mut weights = Vec::new();
    for d in 0..dim::<K>() {
        let e = basis::<K>(d)?;
        weights.extend(
            b.iter()
                .enumerate()
                .map(|(c, w)| (d * stride + offset + c, e * *w)),
        );
    }
    Ok(Claim { weights, value })
}

/// A5 item 4's claim-block rank: the `D` M31 coordinates of `eq(ρ_u, ·)` must have
/// rank `D`. Public; the producer aborts otherwise.
fn block_rank<K: ChallengeField + CodeField>(u: &[K]) -> Result<bool, Error> {
    let eq = stele_poly::eq_table(u).map_err(|_| Error::Statement)?;
    full_rank(&[eq])
}

/// Whether the M31 coordinates of the `K`-valued functionals (each over the same
/// block entries) are independent: `D` per functional. Public data only.
fn full_rank<K: ChallengeField + CodeField>(functionals: &[Vec<K>]) -> Result<bool, Error> {
    let mut rows: Vec<Vec<M31>> = Vec::new();
    for f in functionals {
        let columns: Vec<Vec<M31>> = f.iter().map(|v| limbs(*v)).collect::<Result<_, _>>()?;
        rows.extend((0..dim::<K>()).map(|limb| columns.iter().map(|c| c[limb]).collect()));
    }
    let (height, width) = (rows.len(), rows.first().map_or(0, Vec::len));
    let mut rank = 0;
    for column in 0..width {
        let Some(pivot) = (rank..height).find(|&i| rows[i][column] != M31::ZERO) else {
            continue;
        };
        rows.swap(rank, pivot);
        let inverse = rows[rank][column].inverse().unwrap_or(M31::ZERO);
        let head = rows[rank].clone();
        for row in rows.iter_mut().skip(rank + 1) {
            let factor = row[column] * inverse;
            for (value, p) in row.iter_mut().zip(&head) {
                *value = *value - factor * *p;
            }
        }
        rank += 1;
    }
    Ok(rank == height)
}

/// `γ_a` for a batch, one per claim (`BatchCoefficient`).
pub fn coefficients<K: ChallengeField>(
    t: &mut Transcript<K>,
    count: usize,
) -> Result<Vec<K>, Error> {
    (0..count)
        .map(|_| {
            t.challenge(ChallengeLabel::BatchCoefficient)
                .map_err(|e| Error::Sumcheck(e.into()))
        })
        .collect()
}

/// A5 item 5's weight `(1 − w)·W` over `(w, row, col)` of a hiding source's data
/// face `Y = 0`: `W = Σ_a γ_a·w_a` on the data rows (`w = 0`), zero on `w = 1`.
pub fn weight_table<K: ChallengeField>(
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Result<Vec<K>, Error> {
    let half = (source.rows() / 2) * (source.columns() / 2);
    if claims.len() != gammas.len() {
        return Err(Error::Statement);
    }
    let mut table = vec![zero::<K>(); 2 * half];
    for (claim, gamma) in claims.iter().zip(gammas) {
        for (position, weight) in &claim.weights {
            let entry = table[..half].get_mut(*position).ok_or(Error::Statement)?;
            *entry = *entry + *gamma * *weight;
        }
    }
    Ok(table)
}

/// The batch instance: `Σ_{w,row,col} W'·M̃'` over `ell + 1 + m` variables, with
/// the public claimed sum `Σ_a γ_a·c_a`.
fn batch_instance<K: ChallengeField>(
    id: u64,
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Instance<K> {
    let num_vars = source.rows().trailing_zeros() + source.columns().trailing_zeros() - 1;
    Instance {
        id,
        num_vars,
        inputs: vec![0, 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: claims
            .iter()
            .zip(gammas)
            .fold(zero::<K>(), |s, (c, g)| s + *g * c.value),
    }
}

/// `M̃'` on the face `Y = 0`, over `(w, row, col)`.
fn face<K: ChallengeField>(prepared: &PreparedSource<'_, K>) -> Vec<K> {
    let columns = prepared.source().columns();
    prepared
        .message()
        .chunks_exact(columns)
        .flat_map(|row| row[..columns / 2].iter().map(|x| element::<K>(*x)))
        .collect()
}

/// The opening point `(w*, row*, 0, col*)` of the batch point `(w*, row*, col*)`.
fn opening_point<K: ChallengeField>(point: &[K], ell: usize) -> Vec<K> {
    let mut full = point.to_vec();
    full.insert(ell + 1, zero::<K>());
    full
}

/// The verifier's `W'(ρ) = (1 − w*)·W̃(row*, col*)`, zero weight on `w = 1`.
// shortcut: O(R·C) dense evaluation; a succinct eq-sum per claim when sources grow.
fn expected_weight<K: ChallengeField>(
    source: &Source<K>,
    claims: &[Claim<K>],
    gammas: &[K],
    point: &[K],
) -> Result<K, Error> {
    let table = weight_table(source, claims, gammas)?;
    let eq = stele_poly::eq_table(&point[1..]).map_err(|_| Error::Statement)?;
    let data = eq
        .iter()
        .zip(&table)
        .fold(zero::<K>(), |s, (e, w)| s + *e * *w);
    Ok((K::from_i64(1) - point[0]) * data)
}

/// Prove one A5 item-5 batch of `claims` on a hiding source, with its plain mask
/// bound by `binding`; returns the batch and its point.
pub fn prove_batch<K: ChallengeField + CodeField + Eq>(
    id: u64,
    prepared: &PreparedSource<'_, K>,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(Batch<K>, Vec<K>), Error> {
    let gammas = coefficients(t, claims.len())?;
    let weights = weight_table(prepared.source(), claims, &gammas)?;
    prove_weighted(
        id, prepared, verified, claims, &gammas, weights, mask, binding, t,
    )
}

/// [`prove_batch`] after the `γ_a` draws, on a caller-supplied weight table over
/// `(w, row, col)`. An honest caller passes [`weight_table`]'s, which is zero on
/// `w = 1`; NC-0915 passes one that is not.
#[allow(clippy::too_many_arguments)]
pub fn prove_weighted<K: ChallengeField + CodeField + Eq>(
    id: u64,
    prepared: &PreparedSource<'_, K>,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    gammas: &[K],
    weights: Vec<K>,
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(Batch<K>, Vec<K>), Error> {
    let i = batch_instance(id, prepared.source(), claims, gammas);
    let dense = Dense::new(&i, vec![weights, face(prepared)]).map_err(Error::Sumcheck)?;
    let (sumcheck, point) = masked::prove(&i, dense, mask, binding, t).map_err(Error::Sumcheck)?;
    // A5 item 4: w* = 0 leaves the opening without mask-row weight.
    if point[0] == zero::<K>() {
        return Err(Error::BatchPoint);
    }
    let ell = prepared.source().rows().trailing_zeros() as usize - 1;
    let opening = prepared
        .opening_point(
            t,
            verified,
            id,
            &opening_point(&point, ell),
            sumcheck.final_values[1],
        )
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((Batch { sumcheck, opening }, point))
}

/// Verify one batch: the masked rounds at degree 2, the weight final against the
/// verifier's own `(1 − w*)·W̃` (NC-0915), and the point opening. Returns the
/// reduction and `μ`, a claim on the shared mask source.
pub fn verify_batch<K: ChallengeField + CodeField + Eq>(
    id: u64,
    verified: &VerifiedCertificate<K>,
    claims: &[Claim<K>],
    batch: &Batch<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<masked::Reduction<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let source = verified.record().source();
    let gammas = coefficients(t, claims.len())?;
    let i = batch_instance(id, source, claims, &gammas);
    let result =
        masked::verify_degree(&i, 2, &batch.sumcheck, binding, t).map_err(Error::Sumcheck)?;
    let point = &result.reduction.point;
    if result.reduction.claims[0].1 != expected_weight(source, claims, &gammas, point)? {
        return Err(Error::Sumcheck(
            stele_sumcheck::Error::FinalEvaluationMismatch,
        ));
    }
    let ell = source.rows().trailing_zeros() as usize - 1;
    verify_point(
        t,
        verified,
        id,
        &opening_point(point, ell),
        result.reduction.claims[1].1,
        &batch.opening,
    )
    .map_err(|f| Error::Pcs(f.cause))?;
    Ok(result)
}

/// One masked factor `V̇ = x + κ(X_v)·r` over the remaining variables, or a public
/// factor (`r` empty, no `v`). After `v` is bound, `x` holds `x + κ(ρ_v)·r`.
struct Factor<K> {
    x: Vec<K>,
    r: Vec<K>,
    v: Option<usize>,
}

/// The A5 item 2 prover strategy: before its vanishing variable is bound a mask
/// term is zero on the cube; in that round it contributes `κ(t)·r`, after it
/// `κ(ρ_v)·r`.
struct Occurrences<K> {
    factors: Vec<Factor<K>>,
    terms: Vec<Term<K>>,
    degree: usize,
    num_vars: u32,
    bound: usize,
    /// A leaf with several members: `factors` and `terms` are compact (one
    /// combined factor per tuple entry); the instance's inputs are these.
    expand: Option<lookup::Expand<K>>,
}

/// A term's coefficient, with `±1` kept apart so its product is not multiplied by it.
#[derive(Clone, Copy)]
enum Coefficient<K> {
    One,
    MinusOne,
    Other(K),
}

/// `Σ_k c_k·Π_{f ∈ F_k} v_f` in a cheaper but equal form (E16-24): coefficients `±1`
/// are not multiplied, and the factor in most terms (at least two) is multiplied once,
/// outside their sum. Field arithmetic is exact, so the value is the same element.
struct TermPlan<K> {
    outer: Terms<K>,
    common: Option<(u32, Terms<K>)>,
}

/// Coefficient and factor list per term.
type Terms<K> = Vec<(Coefficient<K>, Vec<u32>)>;

impl<K: ChallengeField> TermPlan<K> {
    fn new(terms: &[Term<K>]) -> Self {
        let coefficient = |c: K| match c.to_i64_signed() {
            Some(1) => Coefficient::One,
            Some(-1) => Coefficient::MinusOne,
            _ => Coefficient::Other(c),
        };
        let mut counts: Vec<(u32, usize)> = Vec::new();
        for t in terms {
            for f in &t.factors {
                match counts.iter_mut().find(|(g, _)| g == f) {
                    Some((_, n)) => *n += 1,
                    None => counts.push((*f, 1)),
                }
            }
        }
        // Most terms first, then lowest factor; a factor repeated in one term counts
        // per occurrence, and only one occurrence is taken out.
        let common = counts
            .iter()
            .filter(|(_, n)| *n >= 2)
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
            .map(|(g, _)| *g);
        let mut outer = Vec::new();
        let mut inner = Vec::new();
        for t in terms {
            let c = coefficient(t.coefficient);
            match common.and_then(|g| t.factors.iter().position(|f| *f == g)) {
                Some(at) => {
                    let mut rest = t.factors.clone();
                    rest.remove(at);
                    inner.push((c, rest));
                }
                None => outer.push((c, t.factors.clone())),
            }
        }
        match common {
            Some(g) if inner.len() >= 2 => Self {
                outer,
                common: Some((g, inner)),
            },
            // One term holds `g`: nothing to share; keep it whole.
            _ => {
                let mut all = outer;
                if let Some(g) = common {
                    for (c, mut rest) in inner {
                        rest.insert(0, g);
                        all.push((c, rest));
                    }
                }
                Self {
                    outer: all,
                    common: None,
                }
            }
        }
    }
    fn sum(terms: &[(Coefficient<K>, Vec<u32>)], values: &[K]) -> K {
        terms.iter().fold(zero::<K>(), |s, (c, factors)| {
            let product = factors.split_first().map(|(f, rest)| {
                rest.iter()
                    .fold(values[*f as usize], |p, g| p * values[*g as usize])
            });
            match (c, product) {
                (Coefficient::One, Some(p)) => s + p,
                (Coefficient::MinusOne, Some(p)) => s - p,
                (Coefficient::Other(c), Some(p)) => s + *c * p,
                (Coefficient::One, None) => s + K::from_i64(1),
                (Coefficient::MinusOne, None) => s - K::from_i64(1),
                (Coefficient::Other(c), None) => s + *c,
            }
        })
    }
    fn evaluate(&self, values: &[K]) -> K {
        let outer = Self::sum(&self.outer, values);
        match &self.common {
            Some((g, inner)) => outer + values[*g as usize] * Self::sum(inner, values),
            None => outer,
        }
    }
}

impl<K: ChallengeField> Summand<K> for Occurrences<K> {
    fn shape(&self) -> (u32, usize) {
        let inputs = self
            .expand
            .as_ref()
            .map_or(self.factors.len(), lookup::Expand::inputs);
        (self.num_vars - self.bound as u32, inputs)
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        let half = self.factors[0].x.len() / 2;
        let nodes = self.degree + 1;
        // κ(t) per node, once; a factor at node t is reached by adding its slope t
        // times (exact field arithmetic, so every node value equals lo + t·(hi − lo)).
        let kappas: Vec<K> = (0..nodes).map(|t| kappa(K::from_i64(t as i64))).collect();
        let masked: Vec<bool> = self
            .factors
            .iter()
            .map(|f| f.v == Some(self.bound))
            .collect();
        let mut out = vec![zero::<K>(); nodes];
        let products: usize = self.terms.iter().map(|t| t.factors.len() + 1).sum();
        let cost = nodes * (self.factors.len() + products);
        let plan = TermPlan::new(&self.terms);
        stele_sumcheck::parallel::sum_ranges_weighted(half, cost, &mut out, |range, out| {
            let width = self.factors.len();
            let mut x = vec![zero::<K>(); width];
            let mut dx = vec![zero::<K>(); width];
            let mut r = vec![zero::<K>(); width];
            let mut dr = vec![zero::<K>(); width];
            let mut values = vec![zero::<K>(); width];
            for column in range {
                for (k, f) in self.factors.iter().enumerate() {
                    x[k] = f.x[column];
                    dx[k] = f.x[column + half] - x[k];
                    if masked[k] {
                        r[k] = f.r[column];
                        dr[k] = f.r[column + half] - r[k];
                    }
                }
                for (node, result) in out.iter_mut().enumerate() {
                    if node > 0 {
                        for k in 0..width {
                            x[k] = x[k] + dx[k];
                            if masked[k] {
                                r[k] = r[k] + dr[k];
                            }
                        }
                    }
                    for k in 0..width {
                        // κ(0) = κ(1) = 0: the mask term vanishes on the cube.
                        values[k] = if masked[k] && node > 1 {
                            x[k] + kappas[node] * r[k]
                        } else {
                            x[k]
                        };
                    }
                    *result = *result + plan.evaluate(&values);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        let bound = self.bound;
        let k = kappa(challenge);
        // Factors are independent; many small ones split over the pool, and a large
        // table's own fold splits as well (E16-24).
        let cost = self.factors.first().map_or(1, |f| f.x.len());
        stele_sumcheck::parallel::for_each_chunk_weighted(&mut self.factors, cost, |_, chunk| {
            for f in chunk {
                stele_sumcheck::parallel::fold(&mut f.x, challenge);
                if !f.r.is_empty() {
                    stele_sumcheck::parallel::fold(&mut f.r, challenge);
                }
                if f.v == Some(bound) {
                    for (x, r) in f.x.iter_mut().zip(&f.r) {
                        *x = *x + k * *r;
                    }
                    f.r.clear();
                }
            }
        });
        self.bound += 1;
        if let Some(e) = &mut self.expand {
            e.record(challenge);
        }
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        let compact: Vec<K> = self.factors.iter().map(|f| f.x[0]).collect();
        match &self.expand {
            None => Ok(compact),
            Some(e) => e
                .finals(&compact)
                .map_err(|_| stele_sumcheck::Error::InvalidInstance),
        }
    }
}

fn bit(index: usize, var: usize, n: usize) -> usize {
    (index >> (n - 1 - var)) & 1
}

/// `x̂` over the domain: the column at its `Free` coordinates, broadcast over the
/// variables it does not read.
fn domain_table<K: ChallengeField>(column: &[K], coords: &[Coord], free: &[K], n: usize) -> Vec<K> {
    let len = coords.len();
    let mut partial = vec![zero::<K>(); 1 << n];
    let mut read = 0usize;
    for c in coords {
        if let Coord::Var(q) = c {
            read |= 1 << (n - 1 - q);
        }
    }
    for (index, value) in column.iter().enumerate() {
        let mut weight = K::from_i64(1);
        let mut target = 0usize;
        for (j, c) in coords.iter().enumerate() {
            let b = bit(index, j, len);
            match c {
                Coord::Var(q) => target |= b << (n - 1 - q),
                Coord::Free(i) => {
                    weight = weight
                        * if b == 1 {
                            free[*i]
                        } else {
                            K::from_i64(1) - free[*i]
                        }
                }
                Coord::Fixed(bit) => {
                    if b != usize::from(*bit) {
                        weight = zero::<K>();
                    }
                }
            }
        }
        partial[target] = partial[target] + weight * *value;
    }
    (0..1usize << n)
        .map(|index| partial[index & read])
        .collect()
}

/// `r̂(X) = r̃_x(a, X_u)` over the domain.
fn block_table<K: ChallengeField>(block: &[M31], u: &[usize], n: usize) -> Vec<K> {
    (0..1usize << n)
        .map(|index| {
            let entry = u
                .iter()
                .enumerate()
                .fold(0, |e, (k, q)| e | bit(index, *q, n) << (u.len() - 1 - k));
            element::<K>(block[entry])
        })
        .collect()
}

/// Read data position `p` of a hiding message `M'` (`2R × 2C`).
fn data(message: &[M31], columns: usize, p: usize) -> M31 {
    message[(p / columns) * 2 * columns + p % columns]
}

impl<K: ChallengeField + CodeField> Plan<K> {
    /// An occurrence's claim-mask block, read from its source's message.
    fn block(&self, messages: &[&[M31]], o: &Occurrence) -> Vec<M31> {
        let source = self.columns[o.column].source;
        let (_, blocks) = self.layouts[source].offsets[slot(self, o.column)];
        let width = 1usize << self.layouts[source].m;
        let first = blocks + o.block * dim::<K>();
        (first..first + dim::<K>())
            .map(|p| data(messages[source], width, p))
            .collect()
    }
}

/// A `Combined` step's `relation/identity` coefficients, drawn before `τ`.
fn step_draws<K: ChallengeField>(t: &mut Transcript<K>, step: &Step<K>) -> Result<Vec<K>, Error> {
    let count = step.parts.as_ref().map_or(0, |(_, c)| *c);
    draws(t, ChallengeLabel::RelationIdentity, count)
}

/// `eq(τ, ·)` over the leading `τ.len()` of `n` variables, broadcast below.
fn eq_input<K: ChallengeField>(tau: &[K], n: usize) -> Result<Vec<K>, Error> {
    let eq = stele_sumcheck::parallel::eq_table(tau).map_err(|_| Error::Statement)?;
    let low = n - tau.len();
    Ok((0..1usize << n).map(|index| eq[index >> low]).collect())
}

/// The verifier's checks of a step's public finals: `eq(τ, ρ_lead)` and each
/// public input's MLE at its column point (`ClaimMismatch`).
fn public_finals<K: ChallengeField + Eq>(
    step: &Step<K>,
    point: &[K],
    free: &[K],
    finals: &[K],
) -> Result<(), Error> {
    let mismatch = Error::Sumcheck(stele_sumcheck::Error::ClaimMismatch);
    if step.eq.is_some() {
        let tau = step.tau(free);
        let eq =
            stele_poly::eq_evaluate(&tau, &point[..tau.len()]).map_err(|_| Error::Statement)?;
        if finals[0] != eq {
            return Err(mismatch);
        }
    }
    let first = step.first() + step.occurrences.len();
    for (p, value) in step.publics.iter().zip(&finals[first..]) {
        let w = stele_poly::eq_table(&column_point(&p.coords, point, free))
            .map_err(|_| Error::Statement)?;
        let expected = p
            .values
            .iter()
            .zip(&w)
            .fold(zero::<K>(), |s, (a, b)| s + *a * *b);
        if *value != expected {
            return Err(mismatch);
        }
    }
    Ok(())
}

fn draws<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: ChallengeLabel,
    count: usize,
) -> Result<Vec<K>, Error> {
    (0..count)
        .map(|_| t.challenge(label).map_err(|e| Error::Sumcheck(e.into())))
        .collect()
}

fn instance<K: ChallengeField>(
    id: u64,
    num_vars: u32,
    terms: Vec<Term<K>>,
    claimed: K,
) -> Instance<K> {
    let inputs = terms
        .iter()
        .flat_map(|t| t.factors.iter())
        .max()
        .map_or(0, |m| *m as u64 + 1);
    Instance {
        id,
        num_vars,
        inputs: (0..inputs).collect(),
        terms,
        claimed_sum: claimed,
    }
}

fn step_instance<K: ChallengeField>(step: &Step<K>, gammas: &[K]) -> Instance<K> {
    let mut i = instance(step.id, step.num_vars, step.scaled(gammas), zero::<K>());
    i.inputs = (0..(step.first() + step.occurrences.len() + step.publics.len()) as u64).collect();
    i
}

/// Draw `count` uniform M31 values after the source's `3RC` data masks (A5 item 1).
// shortcut: replays the 3RC data-mask draws of `hiding_message`; share its stream if this shows in a profile.
fn after_masks(seed: &[u8; 32], id: u64, rows: usize, width: usize) -> MaskStream {
    let mut stream = MaskStream::new(seed, SOURCE_MASK, id);
    for _ in 0..3 * rows * width {
        stream.m31();
    }
    stream
}

/// A claim source's message `M'` (A2 item 1): columns and claim masks as data,
/// the masks drawn from the `zk/source-mask` stream after the data masks (A5
/// item 1). `claim_masks = false` leaves the blocks zero (privacy-test control).
fn source_message<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    source: usize,
    columns: &[Vec<K>],
    seed: &[u8; 32],
    claim_masks: bool,
) -> Result<Vec<M31>, Error> {
    let layout = &plan.layouts[source];
    let (rows, width) = (1usize << layout.ell, 1usize << layout.m);
    let mut x = vec![M31::ZERO; rows * width];
    let mut stream = after_masks(seed, plan.source_id(source), rows, width);
    let members = plan
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.source == source);
    for ((index, column), (at, blocks)) in members.zip(&layout.offsets) {
        let len = 1usize << column.log_len;
        for (p, value) in columns[index].iter().enumerate() {
            for (d, limb) in limbs(*value)?.into_iter().take(column.limbs).enumerate() {
                x[at + d * len + p] = limb;
            }
        }
        for value in &mut x[*blocks..*blocks + plan.reserved[index] * dim::<K>()] {
            let drawn = stream.m31();
            if claim_masks {
                *value = drawn;
            }
        }
    }
    stele_pcs::hiding_message(plan.source_id(source), layout.ell, layout.m, &x, seed)
        .map_err(Error::Pcs)
}

/// The shared mask source's data: each plain mask's values as `D` limb rows, then
/// the layer blocks from data row `D`, drawn after the data masks.
fn shared_message<K: ChallengeField + CodeField>(
    plan: &Plan<K>,
    masks: &[Mask<K>],
    seed: &[u8; 32],
    claim_masks: bool,
) -> Result<Vec<M31>, Error> {
    let (ell, m) = plan.shared;
    let (rows, width) = (1usize << ell, 1usize << m);
    let mut x = vec![M31::ZERO; rows * width];
    for (mask, offset) in masks.iter().zip(&plan.shared_offsets) {
        for (c, value) in mask.columns(0).enumerate() {
            for (d, limb) in limbs(value)?.into_iter().enumerate() {
                x[d * plan.stride + offset + c] = limb;
            }
        }
    }
    let mut stream = after_masks(seed, plan.shared_id(), rows, width);
    let start = dim::<K>() * plan.stride;
    for value in &mut x[start..start + 4 * dim::<K>() * plan.blocks] {
        let drawn = stream.m31();
        if claim_masks {
            *value = drawn;
        }
    }
    stele_pcs::hiding_message(plan.shared_id(), ell, m, &x, seed).map_err(Error::Pcs)
}

fn certify<K: ChallengeField + CodeField>(
    prepared: &PreparedSource<'_, K>,
) -> Result<(Vec<u8>, VerifiedCertificate<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let certificate = prepared.certificate().map_err(|f| Error::Pcs(f.cause))?.0;
    let verified = verify_certificate(*prepared.source(), &certificate)
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((certificate, verified))
}

/// Prove `statement` on `columns` (one M31 table per column) from one fresh
/// secret seed (A5 items 1–6, RFC-0008 A7). Aborts (`ClaimRank`, `Vanishing`,
/// `BatchPoint`, `DenominatorZero`, A2's `MaskRank`, `MaskWeight`, A4's
/// `MaskPoint`) are public events.
///
/// # Security
///
/// As [`super::prove`]: a seed serves one proof. After an abort, retry with a
/// fresh seed only if nothing from the attempt was published.
pub fn prove<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(statement, columns, &seed.0, t, true, None, None).map(|p| p.0)
}

/// The root of claim source `source` as [`prove`] commits it from `seed`: a
/// caller binds it before the transcript starts (a dev-zk weight source, whose
/// root is a public input, RFC-0013 A5 item 7). Deterministic in the seed.
pub fn source_root<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    source: usize,
    seed: &Seed,
) -> Result<[u8; 32], Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan(statement)?;
    if source >= plan.early() || columns.len() != statement.columns.len() {
        return Err(Error::Statement);
    }
    let data: Vec<Vec<K>> = columns
        .iter()
        .map(|column| column.iter().map(|x| element::<K>(*x)).collect())
        .collect();
    let message = source_message(&plan, source, &data, &seed.0, true)?;
    let layout = &plan.layouts[source];
    let prepared = PreparedSource::<K>::hiding_with(
        plan.source_id(source),
        layout.ell,
        layout.m,
        BLOWUP,
        &message,
        &seed.0,
        &mut HashUsage::default(),
        plan.policy(),
    )
    .map_err(Error::Pcs)?;
    Ok(prepared.source().root())
}

/// The privacy tests' leak control, never a verifier input: [`prove`] with every
/// claim-mask block and layer block left zero, so each revealed claim is the bare
/// evaluation `x̃(ρ)`. The proof still verifies; no verifier sees masks.
#[cfg(feature = "controls")]
pub fn prove_unmasked<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(statement, columns, &seed.0, t, false, None, None).map(|p| p.0)
}

/// Which instance an adversary forges (controls only).
#[derive(Clone, Copy, PartialEq)]
enum Forgery {
    /// NC-0916: relation `j`, free rounds and `μ` solved last.
    Relation(usize),
    /// NC-0913: GKR step `g`, free rounds, its first layer child plus one, `μ`
    /// solved last.
    Layer(usize),
    /// GKR step `g` (not the first): honest rounds, its two block finals moved so
    /// that `P(finals)` and `μ` are unchanged.
    Block(usize),
    /// GKR step `g`, free rounds, final `input` plus one, `μ` solved last.
    Final(usize, usize),
    /// Relation `j` on a false witness: the honest rounds and the true `μ`,
    /// without the producer's own round-sum check.
    Unchecked(usize),
    /// Lookup `l`: the true top `p, q`, but `h` shifted so that `Σ h = 0`, with the
    /// top identity `h·q − p = 0` forged (free rounds, `μ` solved last).
    Ratio(usize),
}

/// NC-0917 and NC-0918's adversary, never a verifier input: the honest prover,
/// except that GKR step `step` reveals final `input` plus one, with free rounds and
/// `μ` solved last so the step's final check passes. Input 0 is the head
/// (`eq(r, x)` or `(1 − s)·eq(r, x)`); inputs 1 and 3 of a later step are the
/// selectors `S_p`, `S_q`. Only the verifier's own evaluation of that public final
/// rejects it.
#[doc(hidden)]
pub fn forge_final<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    step: usize,
    input: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let forgery = Some(Forgery::Final(step, input));
    prove_with(statement, columns, &seed.0, t, true, forgery, None).map(|p| p.0)
}

/// NC-0920..0926's adversary, never a verifier input: the honest prover on a
/// false witness, except that relation `relation` sends its honest rounds and the
/// true `μ` without the producer's own round-sum check. Only that relation's
/// first-round check rejects it; the rest of the proof is honest.
#[cfg(feature = "controls")]
pub fn forge_unchecked<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    relation: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let forgery = Some(Forgery::Unchecked(relation));
    prove_with(statement, columns, &seed.0, t, true, forgery, None).map(|p| p.0)
}

/// [`forge_unchecked`]'s instance: honest rounds and `μ`, no self-check.
#[allow(clippy::type_complexity)]
fn unchecked<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    summand: Occurrences<K>,
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>, Vec<K>, K), Error> {
    #[cfg(feature = "controls")]
    {
        let (proof, point) =
            masked::prove_unchecked(i, summand, mask, binding, t).map_err(Error::Sumcheck)?;
        let (truth, mu) = (proof.final_values.clone(), proof.mask_final);
        Ok((proof, point, truth, mu))
    }
    #[cfg(not(feature = "controls"))]
    {
        let _ = (i, summand, mask, binding, t);
        Err(Error::Statement)
    }
}

/// NC-0919's adversary, never a verifier input: for a false lookup, it commits the
/// true top `p, q` and `h = p/q` shifted at one entry so that `Σ h = 0`, then
/// forges the top identity `h·q − p = 0` (free rounds, `μ` solved last). Every
/// other step is honest. Only the top identity, through its `μ` in the shared
/// batch, rejects it.
#[doc(hidden)]
pub fn forge_ratio<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    lookup: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let forgery = Some(Forgery::Ratio(lookup));
    prove_with(statement, columns, &seed.0, t, true, forgery, None).map(|p| p.0)
}

/// The block-claim adversary's strategy: honest rounds, then `B_p + 1` and
/// `B_q − S_p/(λ·S_q)`, which leaves `S_p·B_p + λ·S_q·B_q` (and so the final
/// check) unchanged. Inputs 1..=4 of a later GKR step are `S_p, B_p, S_q, B_q`.
struct Perturb<K> {
    inner: Occurrences<K>,
    lambda: K,
}

impl<K: ChallengeField> Perturb<K> {
    fn shift(finals: &[K], lambda: K) -> Result<K, Error> {
        let inverse = (lambda * finals[3]).inverse().ok_or(Error::Statement)?;
        Ok(finals[1] * inverse)
    }
}

impl<K: ChallengeField> Summand<K> for Perturb<K> {
    fn shape(&self) -> (u32, usize) {
        self.inner.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.inner.round(i)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        self.inner.fold(challenge)
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        let mut finals = self.inner.final_values()?;
        let shift = Self::shift(&finals, self.lambda)
            .map_err(|_| stele_sumcheck::Error::InvalidInstance)?;
        finals[2] = finals[2] + K::from_i64(1);
        finals[4] = finals[4] - shift;
        Ok(finals)
    }
}

/// The block-claim adversary, never a verifier input: the honest prover, except
/// that later GKR step `step` reveals two wrong block finals with the step's final
/// check intact. Only the block claims in the shared batch reject it.
#[doc(hidden)]
pub fn forge_block<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    step: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(
        statement,
        columns,
        &seed.0,
        t,
        true,
        Some(Forgery::Block(step)),
        None,
    )
    .map(|p| p.0)
}

/// NC-0916's adversary, never a verifier input: the honest prover, except that
/// relation `relation` runs A4's NC-0908 attack. The sources are honest, the rounds
/// are free (`[running, 0, …]`), and `μ` is solved last so the relation's final
/// check passes. The finals are the true `V̇` values at the forged point, so every
/// source batch passes. Only binding each relation's `μ_j` to the committed `g_j`
/// in the shared batch rejects it.
#[doc(hidden)]
pub fn forge<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    relation: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let forgery = Some(Forgery::Relation(relation));
    prove_with(statement, columns, &seed.0, t, true, forgery, None).map(|p| p.0)
}

/// NC-0913's adversary, never a verifier input: the honest prover, except that GKR
/// step `step` reveals its first masked layer value plus one, with free rounds and
/// `μ` solved last so the step itself passes. The prover continues from the true
/// value, so only the next step's claimed sum rejects it.
#[doc(hidden)]
pub fn forge_layer<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    step: usize,
) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    prove_with(
        statement,
        columns,
        &seed.0,
        t,
        true,
        Some(Forgery::Layer(step)),
        None,
    )
    .map(|p| p.0)
}

fn evaluate<K: ChallengeField>(terms: &[Term<K>], values: &[K]) -> K {
    terms.iter().fold(zero::<K>(), |s, term| {
        s + term
            .factors
            .iter()
            .fold(term.coefficient, |p, f| p * values[*f as usize])
    })
}

/// The masked sumcheck's messages (A4 order) with free rounds and `μ` solved last.
/// `tweak` adds one to that final before `μ` is solved. Returns the proof, the
/// point and the true finals.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn forged<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    degree: usize,
    mut summand: Occurrences<K>,
    mask: &Mask<K>,
    binding: &[u8],
    tweak: Option<usize>,
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>, Vec<K>), Error> {
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    let sumcheck = Error::Sumcheck;
    let mask_sum = mask.sum();
    t.absorb(
        AbsorbLabel::Instance,
        &i.encode_degree(degree).map_err(sumcheck)?,
    )
    .map_err(fail)?;
    t.absorb(AbsorbLabel::FieldSources, binding).map_err(fail)?;
    let bytes = stele_sumcheck::message_bytes(i.id, 0, &[mask_sum]).map_err(sumcheck)?;
    t.absorb(AbsorbLabel::ZkMaskSum, &bytes).map_err(fail)?;
    let alpha = t.challenge(ChallengeLabel::ZkMaskWeight).map_err(fail)?;
    let mut running = i.claimed_sum + alpha * mask_sum;
    let (mut rounds, mut point) = (Vec::new(), Vec::new());
    for index in 0..i.num_vars {
        let mut values = vec![zero::<K>(); degree + 1];
        values[0] = running;
        let bytes = stele_sumcheck::message_bytes(i.id, index, &values).map_err(sumcheck)?;
        t.absorb(AbsorbLabel::Round, &bytes).map_err(fail)?;
        let c = t.challenge(ChallengeLabel::Sumcheck).map_err(fail)?;
        // The polynomial with value `running` at 0 and 0 at 1..δ, at `c`.
        for k in 1..=degree as i64 {
            let inverse = K::from_i64(-k).inverse().ok_or(Error::Statement)?;
            running = running * (c - K::from_i64(k)) * inverse;
        }
        summand.fold(c).map_err(sumcheck)?;
        rounds.push(values);
        point.push(c);
    }
    let truth = summand.final_values().map_err(sumcheck)?;
    let mut finals = truth.clone();
    if let Some(index) = tweak {
        finals[index] = finals[index] + K::from_i64(1);
    }
    let inverse = alpha.inverse().ok_or(Error::Statement)?;
    let mask_final = (running - evaluate(&i.terms, &finals)) * inverse;
    let mut values = finals.clone();
    values.push(mask_final);
    let bytes =
        stele_sumcheck::message_bytes(i.id, finals.len() as u32 + 1, &values).map_err(sumcheck)?;
    t.absorb(AbsorbLabel::Final, &bytes).map_err(fail)?;
    Ok((
        masked::Proof {
            mask_sum,
            rounds,
            final_values: finals,
            mask_final,
        },
        point,
        truth,
    ))
}

/// One masked instance: honest, or forged under `forgery`. Returns the proof, the
/// point, the true finals and the `μ` the shared batch receives (the true `g(ρ)`
/// when forged).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn masked_instance<K: ChallengeField + CodeField + Eq>(
    i: &Instance<K>,
    degree: usize,
    summand: Occurrences<K>,
    mask: &Mask<K>,
    binding: &[u8],
    forged_here: bool,
    tweak: Option<usize>,
    t: &mut Transcript<K>,
) -> Result<(masked::Proof<K>, Vec<K>, Vec<K>, K), Error> {
    if forged_here {
        let (proof, point, truth) = forged(i, degree, summand, mask, binding, tweak, t)?;
        let mu = mask.evaluate(&point).map_err(Error::Sumcheck)?;
        Ok((proof, point, truth, mu))
    } else {
        let (proof, point) =
            masked::prove(i, summand, mask, binding, t).map_err(Error::Sumcheck)?;
        let (truth, mu) = (proof.final_values.clone(), proof.mask_final);
        Ok((proof, point, truth, mu))
    }
}

#[allow(clippy::type_complexity)]
fn prove_with<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: &[u8; 32],
    t: &mut Transcript<K>,
    claim_masks: bool,
    forgery: Option<Forgery>,
    lifetime: Option<(&Lifetime, ModelSecret<'_, K>)>,
) -> Result<(Proof<K>, Option<Vec<K>>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan_with(statement, lifetime.as_ref().map(|(l, _)| *l))?;
    let (life_source, model) = match lifetime {
        Some((l, secret)) => (Some(l.source), Some(secret)),
        None => (None, None),
    };
    if columns.len() != statement.columns.len()
        || columns
            .iter()
            .zip(&statement.columns)
            .any(|(c, x)| c.len() != 1usize << x.log_len)
    {
        return Err(Error::Statement);
    }
    let mut data: Vec<Vec<K>> = columns
        .iter()
        .map(|column| column.iter().map(|x| element::<K>(*x)).collect())
        .collect();
    let early = plan.early();
    // A6: the lifetime source is rebuilt from the model seed, every proof alike.
    let seed_of = |s: usize| match (&model, life_source) {
        (Some(m), Some(l)) if l == s => m.seed,
        _ => seed,
    };
    // Independent per source; built concurrently, kept in source order (E16-24).
    let messages = stele_sumcheck::parallel::map(early, |s| {
        source_message(&plan, s, &data, seed_of(s), claim_masks)
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let masks = plan
        .masks
        .iter()
        .map(|(id, n, degree)| Mask::plain(seed, *id, *n, *degree).map_err(Error::Sumcheck))
        .collect::<Result<Vec<_>, _>>()?;
    let hiding = |id: u64, (ell, m): (u8, u8), message| {
        PreparedSource::<K>::hiding_with(
            id,
            ell,
            m,
            BLOWUP,
            message,
            seed,
            &mut HashUsage::default(),
            plan.policy(),
        )
        .map_err(Error::Pcs)
    };
    let mut model = model;
    let revealed = model
        .as_mut()
        .map(|m| core::mem::take(&mut m.revealed))
        .unwrap_or_default();
    let model = model;
    // Sources are independent: prepared (encoding, salts, Merkle tree) and certified
    // concurrently; results and the first error are taken in source order (E16-24).
    let prepare = |s: usize| {
        let layout = &plan.layouts[s];
        match (model.as_ref(), &plan.lifetime) {
            (Some(m), Some(l)) if l.source == s => {
                let p = PreparedSource::<K>::hiding_lifetime_with(
                    plan.source_id(s),
                    layout.ell,
                    layout.m,
                    BLOWUP,
                    &messages[s],
                    m.seed,
                    &mut HashUsage::default(),
                    l.proofs,
                    revealed.clone(),
                    plan.policy(),
                )
                .map_err(Error::Pcs)?;
                // RFC-0013 A6: the producer refuses weights other than the committed ones.
                if p.source().root() != m.root {
                    return Err(Error::Pcs(stele_pcs::Error::Merkle(
                        stele_hash::merkle::Error::RootMismatch,
                    )));
                }
                Ok(p)
            }
            _ => hiding(plan.source_id(s), (layout.ell, layout.m), &messages[s]),
        }
    };
    let mut prepared = stele_sumcheck::parallel::map(early, prepare)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut sources = Vec::new();
    let mut certificates = Vec::new();
    let mut verified = Vec::new();
    let certified = stele_sumcheck::parallel::map(prepared.len(), |i| certify(&prepared[i]));
    for (p, c) in prepared.iter().zip(certified) {
        let (certificate, v) = c?;
        sources.push(p.source().bytes().to_vec());
        certificates.push(certificate);
        verified.push(v);
    }
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    t.absorb(AbsorbLabel::FieldSources, &sources.concat())
        .map_err(fail)?;
    // RFC-0008 A7 items 1–3: β and α after the multiplicities, then the top.
    let mut runs = Vec::new();
    let mut trees = Vec::new();
    for (l, lp) in plan.lookups.iter().enumerate() {
        lookup::messages(lp, l, t)?;
        let beta = t.challenge(ChallengeLabel::LookupBeta).map_err(fail)?;
        let alpha = t.challenge(ChallengeLabel::LookupAlpha).map_err(fail)?;
        let layers = lookup::tree(lp, &data, beta, alpha);
        let [p, q, mut h] = lookup::top(lp, &layers)?;
        if forgery == Some(Forgery::Ratio(l)) {
            let total = h.iter().fold(zero::<K>(), |s, v| s + *v);
            h[0] = h[0] - total;
        }
        data.extend([p, q, h]);
        trees.push(layers);
        runs.push(lookup::Run::new(beta, alpha));
    }
    let top_message = if plan.lookups.is_empty() {
        Vec::new()
    } else {
        source_message(&plan, early, &data, seed, claim_masks)?
    };
    let shared_message = self::shared_message(&plan, &masks, seed, claim_masks)?;
    let (top, shared) = stele_sumcheck::parallel::join(
        || {
            (!plan.lookups.is_empty()).then(|| {
                let layout = &plan.layouts[early];
                hiding(plan.source_id(early), (layout.ell, layout.m), &top_message)
            })
        },
        || hiding(plan.shared_id(), plan.shared, &shared_message),
    );
    if let Some(top) = top {
        prepared.push(top?);
    }
    prepared.push(shared?);
    let certified =
        stele_sumcheck::parallel::map(prepared.len() - early, |i| certify(&prepared[early + i]));
    for (p, c) in prepared[early..].iter().zip(certified) {
        let (certificate, v) = c?;
        sources.push(p.source().bytes().to_vec());
        certificates.push(certificate);
        verified.push(v);
    }
    t.absorb(AbsorbLabel::FieldSources, &sources[early..].concat())
        .map_err(fail)?;
    let shared_index = plan.layouts.len();
    let binding = sources[shared_index].clone();
    let mut all: Vec<&[M31]> = messages.iter().map(Vec::as_slice).collect();
    all.push(&top_message);
    let block_of = |o: &Occurrence| plan.block(&all, o);
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); plan.layouts.len()];
    let mut mus = Vec::new();
    let mut relations = Vec::new();
    for (j, step) in plan.steps.iter().enumerate() {
        let gammas = step_draws(t, step)?;
        let free = draws(t, step.label, step.draws)?;
        let n = step.num_vars as usize;
        let mut factors = Vec::new();
        if step.eq.is_some() {
            factors.push(Factor {
                x: eq_input(&step.tau(&free), n)?,
                r: Vec::new(),
                v: None,
            });
        }
        for o in &step.occurrences {
            factors.push(Factor {
                x: domain_table(&data[o.column], &o.coords, &free, n),
                r: block_table(&block_of(o), &o.u, n),
                v: Some(o.v),
            });
        }
        for p in &step.publics {
            factors.push(Factor {
                x: domain_table(&p.values, &p.coords, &free, n),
                r: Vec::new(),
                v: None,
            });
        }
        let i = step_instance(step, &gammas);
        let summand = Occurrences {
            factors,
            terms: i.terms.clone(),
            degree: step.degree,
            num_vars: step.num_vars,
            bound: 0,
            expand: None,
        };
        let here = forgery == Some(Forgery::Relation(j))
            || plan
                .lookups
                .iter()
                .enumerate()
                .any(|(l, lp)| forgery == Some(Forgery::Ratio(l)) && lp.identity == Some(j));
        let (proof, point, truth, mu) = if forgery == Some(Forgery::Unchecked(j)) {
            unchecked(&i, summand, &masks[j], &binding, t)?
        } else {
            masked_instance(&i, step.degree, summand, &masks[j], &binding, here, None, t)?
        };
        let first = step.first();
        for (k, o) in step.occurrences.iter().enumerate() {
            // A5 item 4: public aborts before the claim leaves the producer.
            if kappa(point[o.v]) == zero::<K>() {
                return Err(Error::Vanishing);
            }
            let u: Vec<K> = o.u.iter().map(|q| point[*q]).collect();
            if !block_rank(&u)? {
                return Err(Error::ClaimRank);
            }
            let (source, claim) = occurrence_claim(&plan, o, &point, &free, truth[first + k])?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, &point, mu)?);
        relations.push(proof);
    }
    let mut gkr = Vec::new();
    for (g, step) in plan.gkr.iter().enumerate() {
        let index = plan.steps.len() + g;
        let run = &mut runs[step.lookup_index()];
        let (terms, claimed) = lookup::start(step, &plan.lookups[step.lookup_index()], run, t)?;
        let i = instance(step.id, step.num_vars, terms, claimed);
        let (factors, compact, expand) = lookup::factors(
            &plan,
            step,
            run,
            &trees[step.lookup_index()],
            &data,
            &shared_message,
            &block_of,
        )?;
        let summand = Occurrences {
            factors,
            terms: compact.unwrap_or_else(|| i.terms.clone()),
            degree: step.degree,
            num_vars: step.num_vars,
            bound: 0,
            expand,
        };
        let tweak = match forgery {
            Some(Forgery::Layer(x)) if x == g => lookup::first_layer(step),
            Some(Forgery::Final(x, input)) if x == g => Some(input),
            _ => None,
        };
        let here = tweak.is_some();
        let (proof, point, truth, mu) = if forgery == Some(Forgery::Block(g)) {
            let lambda = i.terms[1].coefficient;
            let summand = Perturb {
                inner: summand,
                lambda,
            };
            let (proof, point) =
                masked::prove(&i, summand, &masks[index], &binding, t).map_err(Error::Sumcheck)?;
            let mut truth = proof.final_values.clone();
            let shift = Perturb::<K>::shift(&truth, lambda)?;
            truth[2] = truth[2] - K::from_i64(1);
            truth[4] = truth[4] + shift;
            let mu = proof.mask_final;
            (proof, point, truth, mu)
        } else {
            masked_instance(
                &i,
                step.degree,
                summand,
                &masks[index],
                &binding,
                here,
                tweak,
                t,
            )?
        };
        lookup::aborts(step, run, &point)?;
        let finals = lookup::finals(&plan, step, run, &point, &truth)?;
        for (source, claim) in finals.claims.iter().cloned() {
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, index, &point, mu)?);
        mus.extend(finals.blocks.iter().cloned());
        lookup::advance(step, run, &point, &finals, t)?;
        gkr.push(proof);
    }
    let mut batches = Vec::new();
    let mut revealed = None;
    for (b, source) in plan.batched.iter().enumerate() {
        let index = plan.steps.len() + plan.gkr.len() + b;
        let (batch, point) = prove_batch(
            plan.masks[index].0,
            &prepared[*source],
            &verified[*source],
            &claims[*source],
            &masks[index],
            &binding,
            t,
        )?;
        mus.push(mask_claim(&plan, index, &point, batch.sumcheck.mask_final)?);
        if life_source == Some(*source) {
            let ell = plan.layouts[*source].ell as usize;
            revealed = Some(
                stele_sumcheck::parallel::eq_table(&opening_point(&point, ell)[..ell + 1])
                    .map_err(|_| Error::Statement)?,
            );
        }
        batches.push(batch);
    }
    let shared = &prepared[shared_index];
    let gammas = coefficients(t, mus.len())?;
    let weights = weight_table(shared.source(), &mus, &gammas)?;
    let i = batch_instance(plan.shared_batch_id(), shared.source(), &mus, &gammas);
    let dense = Dense::new(&i, vec![weights, face(shared)]).map_err(Error::Sumcheck)?;
    let (proof, point) = prove_at(&i, dense, seed, t, plan.policy())?;
    if point[0] == zero::<K>() {
        return Err(Error::BatchPoint);
    }
    let shared_opening = shared
        .opening_point(
            t,
            &verified[shared_index],
            plan.shared_batch_id(),
            &opening_point(&point, plan.shared.0 as usize),
            proof.sumcheck.final_values[1],
        )
        .map_err(|f| Error::Pcs(f.cause))?
        .0;
    Ok((
        Proof {
            sources,
            certificates,
            relations,
            gkr,
            batches,
            shared: proof,
            shared_opening,
        },
        revealed,
    ))
}

/// [`prove`] with claim source `lifetime.source` a lifetime weight source (RFC-0013
/// A6): rebuilt from the model seed, opened as proof `lifetime.index`
/// with that proof's own claim-mask blocks. Returns the proof and the
/// row-coefficient vector this opening revealed, which the caller appends to the
/// model secret before the next proof.
pub fn prove_lifetime<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    seed: Seed,
    t: &mut Transcript<K>,
    lifetime: &Lifetime,
    model: ModelSecret<'_, K>,
) -> Result<(Proof<K>, Vec<K>), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (proof, revealed) = prove_with(
        statement,
        columns,
        &seed.0,
        t,
        true,
        None,
        Some((lifetime, model)),
    )?;
    Ok((proof, revealed.ok_or(Error::Statement)?))
}

/// The root of lifetime source `lifetime.source`, committed once from `model`
/// (the published model commitment, RFC-0013 A6).
pub fn lifetime_root<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    lifetime: &Lifetime,
    model: &[u8; 32],
) -> Result<[u8; 32], Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan_with(statement, Some(lifetime))?;
    let data: Vec<Vec<K>> = columns
        .iter()
        .map(|column| column.iter().map(|x| element::<K>(*x)).collect())
        .collect();
    let s = lifetime.source;
    let message = source_message(&plan, s, &data, model, true)?;
    let layout = &plan.layouts[s];
    let prepared = PreparedSource::<K>::hiding_with(
        plan.source_id(s),
        layout.ell,
        layout.m,
        BLOWUP,
        &message,
        model,
        &mut HashUsage::default(),
        plan.policy(),
    )
    .map_err(Error::Pcs)?;
    Ok(prepared.source().root())
}

/// Masked occurrences per statement column (the per-proof block need `t_x`).
pub fn occurrence_counts<K: ChallengeField + CodeField>(
    statement: &Statement<K>,
) -> Result<Vec<usize>, Error> {
    let plan = plan(statement)?;
    Ok(plan.counts[..statement.columns.len()].to_vec())
}

/// Verify a dev-zk claims proof against the verifier-owned statement. Every claim
/// is discharged by its source's batch and opening; returns the SC and MASK
/// records of every masked instance.
pub fn verify<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<Verified<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    verify_lifetime(statement, None, proof, t)
}

/// [`verify`] with an optional lifetime source (RFC-0013 A6): its layout and
/// this proof's block set follow `lifetime`, and its source must admit the
/// lifetime budget.
pub fn verify_lifetime<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    lifetime: Option<&Lifetime>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<Verified<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan_with(statement, lifetime)?;
    let shape = Error::Sumcheck(stele_sumcheck::Error::ProofShape);
    let shared_index = plan.layouts.len();
    if proof.sources.len() != shared_index + 1
        || proof.certificates.len() != proof.sources.len()
        || proof.relations.len() != plan.steps.len()
        || proof.gkr.len() != plan.gkr.len()
        || proof.batches.len() != plan.batched.len()
    {
        return Err(shape);
    }
    let mut verified = Vec::new();
    let mut ledger = Ledger {
        degree: dim::<K>(),
        ..Ledger::default()
    };
    for (s, (bytes, certificate)) in proof.sources.iter().zip(&proof.certificates).enumerate() {
        let (id, (ell, m)) = if s < shared_index {
            (plan.source_id(s), (plan.layouts[s].ell, plan.layouts[s].m))
        } else {
            (plan.shared_id(), plan.shared)
        };
        let source = Source::<K>::from_bytes(bytes).map_err(Error::Pcs)?;
        let expected = Source::<K>::hiding_with(id, ell, m, BLOWUP, source.root(), plan.policy())
            .map_err(Error::Pcs)?;
        if expected.bytes() != source.bytes() {
            return Err(Error::MaskSource);
        }
        if let Some(l) = lifetime.filter(|l| l.source == s) {
            if !expected.admits_lifetime(l.proofs) {
                return Err(Error::MaskSource);
            }
        }
        verified.push(
            verify_certificate(expected, certificate)
                .map_err(|f| Error::Pcs(f.cause))?
                .0,
        );
        ledger.pcs.push(PcsSource {
            name: if s < shared_index {
                alloc::format!("source {s}")
            } else {
                "shared mask source".to_string()
            },
            ell: expected.rows().trailing_zeros() as u8,
            parameters: expected.parameters(),
            openings: usize::from(s == shared_index || plan.batched.contains(&s)),
        });
    }
    let fail = |e: stele_hash::Error| Error::Sumcheck(e.into());
    let early = plan.early();
    t.absorb(AbsorbLabel::FieldSources, &proof.sources[..early].concat())
        .map_err(fail)?;
    let mut runs = Vec::new();
    for (l, lp) in plan.lookups.iter().enumerate() {
        lookup::messages(lp, l, t)?;
        let beta = t.challenge(ChallengeLabel::LookupBeta).map_err(fail)?;
        let alpha = t.challenge(ChallengeLabel::LookupAlpha).map_err(fail)?;
        runs.push(lookup::Run::new(beta, alpha));
        let (lu, zd) = lp.lu();
        let name = alloc::format!("check {l}");
        ledger.add(Line::Lu, &name, lu, lu + zd);
        ledger.add(Line::Zd, &name, zd, lu + zd);
    }
    t.absorb(AbsorbLabel::FieldSources, &proof.sources[early..].concat())
        .map_err(fail)?;
    let binding = &proof.sources[shared_index];
    let mut claims: Vec<Vec<Claim<K>>> = vec![Vec::new(); plan.layouts.len()];
    let mut mus = Vec::new();
    let mut reductions = Vec::new();
    let mut records = Vec::new();
    let mut all_draws = Vec::new();
    for (j, (step, relation)) in plan.steps.iter().zip(&proof.relations).enumerate() {
        let gammas = step_draws(t, step)?;
        let free = draws(t, step.label, step.draws)?;
        all_draws.push(free.clone());
        let i = step_instance(step, &gammas);
        let result = masked::verify_degree(&i, step.degree, relation, binding, t)
            .map_err(Error::Sumcheck)?;
        let name = alloc::format!("relation {j}");
        let (g, d) = (gammas.len() as u64, free.len() as u64);
        ledger.add(Line::Rlc, &name, g, g + d);
        ledger.add(Line::Sz, &name, d, g + d);
        ledger.masked(&name, &result);
        let point = &result.reduction.point;
        let finals = &relation.final_values;
        public_finals(step, point, &free, finals)?;
        let first = step.first();
        for (k, o) in step.occurrences.iter().enumerate() {
            let (source, claim) = occurrence_claim(&plan, o, point, &free, finals[first + k])?;
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, j, point, result.mask_final)?);
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    for (g, (step, sumcheck)) in plan.gkr.iter().zip(&proof.gkr).enumerate() {
        let index = plan.steps.len() + g;
        let run = &mut runs[step.lookup_index()];
        let (terms, claimed) = lookup::start(step, &plan.lookups[step.lookup_index()], run, t)?;
        let i = instance(step.id, step.num_vars, terms, claimed);
        let result = masked::verify_degree(&i, step.degree, sumcheck, binding, t)
            .map_err(Error::Sumcheck)?;
        let name = alloc::format!("check {} step {g}", step.lookup_index());
        // `r` and `λ` share a run, as `t*` and the next step's `λ` do (counted here).
        let (r, line) = step.draws();
        ledger.add(Line::Sz, &name, r, r + 2);
        ledger.add(Line::Rlc, &name, line, r + 2);
        ledger.masked(&name, &result);
        let point = &result.reduction.point;
        let finals = lookup::finals(&plan, step, run, point, &sumcheck.final_values)?;
        for (source, claim) in finals.claims.iter().cloned() {
            claims[source].push(claim);
        }
        mus.push(mask_claim(&plan, index, point, result.mask_final)?);
        mus.extend(finals.blocks.iter().cloned());
        lookup::advance(step, run, point, &finals, t)?;
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    for (b, (source, batch)) in plan.batched.iter().zip(&proof.batches).enumerate() {
        let index = plan.steps.len() + plan.gkr.len() + b;
        let result = verify_batch(
            plan.masks[index].0,
            &verified[*source],
            &claims[*source],
            batch,
            binding,
            t,
        )?;
        let name = alloc::format!("batch source {source}");
        let count = claims[*source].len() as u64;
        ledger.claims += claims[*source].len();
        ledger.add(Line::Rlc, &name, count, count);
        ledger.masked(&name, &result);
        mus.push(mask_claim(
            &plan,
            index,
            &result.reduction.point,
            result.mask_final,
        )?);
        reductions.push(result.reduction);
        records.push(result.mask);
    }
    let shared = &verified[shared_index];
    let source = shared.record().source();
    let gammas = coefficients(t, mus.len())?;
    let i = batch_instance(plan.shared_batch_id(), source, &mus, &gammas);
    let (reduction, record, mask_source) = verify_with(&i, &proof.shared, t, plan.policy())?;
    let name = "shared batch";
    ledger.add(Line::Rlc, name, mus.len() as u64, mus.len() as u64);
    ledger.add(
        Line::Sc,
        name,
        reduction.sc.numerator,
        u64::from(reduction.sc.degree),
    );
    ledger.add(Line::Mask, name, 1, 1);
    ledger.pcs.push(PcsSource {
        name: "shared batch mask source".to_string(),
        ell: mask_source.rows().trailing_zeros() as u8,
        parameters: mask_source.parameters(),
        openings: 1,
    });
    let point = &reduction.point;
    if reduction.claims[0].1 != expected_weight(source, &mus, &gammas, point)? {
        return Err(Error::Sumcheck(
            stele_sumcheck::Error::FinalEvaluationMismatch,
        ));
    }
    verify_point(
        t,
        shared,
        plan.shared_batch_id(),
        &opening_point(point, plan.shared.0 as usize),
        reduction.claims[1].1,
        &proof.shared_opening,
    )
    .map_err(|f| Error::Pcs(f.cause))?;
    reductions.push(reduction);
    records.push(record);
    Ok(Verified {
        reductions,
        masks: records,
        lookups: runs.iter().map(|r| [r.beta, r.alpha]).collect(),
        draws: all_draws,
        ledger,
    })
}

/// The privacy tests' exact leak count (RFC-0013 A5 item 7): for every masked
/// occurrence (statement columns and the lookups' committed tops `p, q, h`) and
/// every masked GKR layer child in an accepted proof, whether its revealed final
/// equals the bare evaluation at its point. Returns
/// `(occurrences, equal)`; masks make `equal` zero except with probability
/// `≈ occurrences/|K|`. Replays [`verify`] on `t`.
#[cfg(feature = "controls")]
pub fn leaks<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    columns: &[Vec<M31>],
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<(usize, usize), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    leaks_lifetime(statement, None, columns, proof, t)
}

/// [`leaks`] of a proof with a lifetime source (RFC-0013 A6), under its geometry
/// (RFC-0013 A8): the byte-4 privacy tests count bare evaluations through it.
#[cfg(feature = "controls")]
pub fn leaks_lifetime<K: ChallengeField + CodeField + Eq>(
    statement: &Statement<K>,
    lifetime: Option<&Lifetime>,
    columns: &[Vec<M31>],
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<(usize, usize), Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = plan_with(statement, lifetime)?;
    let verified = verify_lifetime(statement, lifetime, proof, t)?;
    // Every plan column as K, the lookups' committed tops p, q, h included, and
    // each lookup's tree from its public (β, α).
    let mut data: Vec<Vec<K>> = columns
        .iter()
        .map(|c| c.iter().map(|x| element::<K>(*x)).collect())
        .collect();
    let mut trees = Vec::new();
    for (lp, [beta, alpha]) in plan.lookups.iter().zip(&verified.lookups) {
        let layers = lookup::tree(lp, &data, *beta, *alpha);
        data.extend(lookup::top(lp, &layers)?);
        trees.push(layers);
    }
    let mle = |values: &[K], point: Vec<K>| -> Result<K, Error> {
        let w = stele_poly::eq_table(&point).map_err(|_| Error::Statement)?;
        Ok(values
            .iter()
            .zip(&w)
            .fold(zero::<K>(), |s, (x, e)| s + *x * *e))
    };
    let (mut total, mut equal) = (0, 0);
    for (j, step) in plan.steps.iter().enumerate() {
        let point = &verified.reductions[j].point;
        for (k, o) in step.occurrences.iter().enumerate() {
            let x = mle(
                &data[o.column],
                column_point(&o.coords, point, &verified.draws[j]),
            )?;
            total += 1;
            equal += usize::from(proof.relations[j].final_values[step.first() + k] == x);
        }
    }
    for (g, step) in plan.gkr.iter().enumerate() {
        let point = &verified.reductions[plan.steps.len() + g].point;
        for (input, o) in lookup::occurrences(step) {
            let x = mle(&data[o.column], column_point(&o.coords, point, &[]))?;
            total += 1;
            equal += usize::from(proof.gkr[g].final_values[input] == x);
        }
        for (input, x) in lookup::layer_values(step, &trees[step.lookup_index()], point)? {
            total += 1;
            equal += usize::from(proof.gkr[g].final_values[input] == x);
        }
    }
    Ok((total, equal))
}

/// The `stele-dev-zk-proof-v1` bytes of a claims proof (E12-14b): every count is a
/// `u32`, every byte string a `u32` length then bytes, every field element its
/// canonical little-endian limbs. The verifier's statement fixes every shape, so
/// [`verify`] rejects a decoded proof of the wrong shape (`ProofShape`).
pub fn encode<K: ChallengeField>(proof: &Proof<K>) -> Vec<u8> {
    let mut out = Vec::new();
    let count = |out: &mut Vec<u8>, n: usize| out.extend_from_slice(&(n as u32).to_le_bytes());
    let bytes = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    };
    let values = |out: &mut Vec<u8>, v: &[K]| {
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        for x in v {
            out.extend_from_slice(x.to_le_bytes().as_ref());
        }
    };
    let sumcheck = |out: &mut Vec<u8>, p: &masked::Proof<K>| {
        out.extend_from_slice(p.mask_sum.to_le_bytes().as_ref());
        count(out, p.rounds.len());
        for r in &p.rounds {
            values(out, r);
        }
        values(out, &p.final_values);
        out.extend_from_slice(p.mask_final.to_le_bytes().as_ref());
    };
    for list in [&proof.sources, &proof.certificates] {
        count(&mut out, list.len());
        for b in list {
            bytes(&mut out, b);
        }
    }
    for list in [&proof.relations, &proof.gkr] {
        count(&mut out, list.len());
        for p in list {
            sumcheck(&mut out, p);
        }
    }
    count(&mut out, proof.batches.len());
    for b in &proof.batches {
        sumcheck(&mut out, &b.sumcheck);
        bytes(&mut out, &b.opening);
    }
    bytes(&mut out, &proof.shared.source);
    bytes(&mut out, &proof.shared.certificate);
    sumcheck(&mut out, &proof.shared.sumcheck);
    bytes(&mut out, &proof.shared.opening);
    bytes(&mut out, &proof.shared_opening);
    out
}

/// Decode [`encode`]'s bytes; malformed, noncanonical or trailing bytes reject
/// (`ProofShape`). Every count is bounded by the bytes that remain.
pub fn decode<K: ChallengeField>(input: &[u8]) -> Result<Proof<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    struct Cursor<'a>(&'a [u8]);
    let shape = Error::Sumcheck(stele_sumcheck::Error::ProofShape);
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
            self.0 = tail;
            Some(head)
        }
        fn count(&mut self) -> Option<usize> {
            let n = u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize;
            // Every item takes at least one byte (or four, for a count).
            (n <= self.0.len()).then_some(n)
        }
        fn bytes(&mut self) -> Option<Vec<u8>> {
            let n = self.count()?;
            self.take(n).map(<[u8]>::to_vec)
        }
        fn value<K: ChallengeField>(&mut self) -> Option<K>
        where
            for<'b> K::Bytes: TryFrom<&'b [u8]>,
        {
            let width = core::mem::size_of::<K::Bytes>();
            K::from_le_bytes(self.take(width)?.try_into().ok()?)
        }
        fn values<K: ChallengeField>(&mut self) -> Option<Vec<K>>
        where
            for<'b> K::Bytes: TryFrom<&'b [u8]>,
        {
            let n = self.count()?;
            (0..n).map(|_| self.value()).collect()
        }
        fn sumcheck<K: ChallengeField>(&mut self) -> Option<masked::Proof<K>>
        where
            for<'b> K::Bytes: TryFrom<&'b [u8]>,
        {
            let mask_sum = self.value()?;
            let n = self.count()?;
            let rounds = (0..n).map(|_| self.values()).collect::<Option<_>>()?;
            Some(masked::Proof {
                mask_sum,
                rounds,
                final_values: self.values()?,
                mask_final: self.value()?,
            })
        }
    }
    let mut c = Cursor(input);
    let run = |c: &mut Cursor<'_>| -> Option<Proof<K>> {
        let mut lists = [Vec::new(), Vec::new()];
        for list in &mut lists {
            let n = c.count()?;
            *list = (0..n).map(|_| c.bytes()).collect::<Option<_>>()?;
        }
        let [sources, certificates] = lists;
        let mut steps = [Vec::new(), Vec::new()];
        for list in &mut steps {
            let n = c.count()?;
            *list = (0..n).map(|_| c.sumcheck()).collect::<Option<_>>()?;
        }
        let [relations, gkr] = steps;
        let n = c.count()?;
        let batches = (0..n)
            .map(|_| {
                Some(Batch {
                    sumcheck: c.sumcheck()?,
                    opening: c.bytes()?,
                })
            })
            .collect::<Option<_>>()?;
        let shared = super::Proof {
            source: c.bytes()?,
            certificate: c.bytes()?,
            sumcheck: c.sumcheck()?,
            opening: c.bytes()?,
        };
        let shared_opening = c.bytes()?;
        Some(Proof {
            sources,
            certificates,
            relations,
            gkr,
            batches,
            shared,
            shared_opening,
        })
    };
    let proof = run(&mut c).ok_or(shape)?;
    match c.0.is_empty() {
        true => Ok(proof),
        false => Err(shape),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    /// E12-26: the ledger's integer log2 and its round security, rounded toward the
    /// larger error; the eight-layer byte-4 LU and witness tensor rounds.
    #[test]
    fn matches_reference_ledger_bits() {
        let logs = [1, 2, 3, 1 << 40, 12_648_447].map(log2_1024);
        assert_eq!(logs, [0, 1024, 1623, 40 * 1024, 24158]);
        assert_eq!(bits(12_648_447, 0), 102_817);
        assert_eq!(tenths(bits(12_648_447, 0)), "2^-100.4");
        assert_eq!(tenths(bits(1_310_720, 5)), "2^-108.6");
        assert_eq!(tenths(108 * 1024), "2^-108.0");
    }

    /// RFC-0013 A8 item 2: the balanced shapes of `research/zk-sources/zkgeom.py`'s
    /// model (2^12 → ell 3, 2^19 → ell 7, 2^24 → ell 9; the lifetime source at P = 8
    /// → ell 7), and `Statement` when no shape is admissible.
    #[test]
    fn matches_reference_balanced_shapes() {
        let ell = |entries: usize, proofs| balanced_shape::<QM31>(entries, proofs).map(|s| s.0);
        assert_eq!(ell(1 << 12, None), Ok(3));
        assert_eq!(ell(1 << 19, None), Ok(7));
        assert_eq!(ell(1 << 24, None), Ok(9));
        assert_eq!(ell(1 << 19, Some(8)), Ok(7));
        assert_eq!(balanced_shape::<QM31>(1 << 24, None), Ok((9, 15)));
        assert_eq!(balanced_shape::<QM31>(1 << 60, None), Err(Error::Statement));
    }

    /// E16-24: the factored term evaluation is the same element as the plain
    /// `Σ c·Π v`, over shapes with a shared factor, `±1` and other coefficients,
    /// empty products and repeated factors.
    #[test]
    fn matches_reference_term_plan() {
        let mut state = 0x5354_454c_4516_0024u64;
        let mut next = |m: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % m
        };
        for _ in 0..2000 {
            let width = 1 + next(10) as usize;
            let values: Vec<QM31> = (0..width)
                .map(|_| {
                    let (a, b, c) = (next(1 << 31), next(1 << 31), next(1 << 31));
                    QM31::from_i64(a as i64)
                        + QM31::from_i64(7) * QM31::from_i64(b as i64) * QM31::from_i64(c as i64)
                })
                .collect();
            let terms: Vec<Term<QM31>> = (0..next(8))
                .map(|_| Term {
                    coefficient: match next(4) {
                        0 => QM31::from_i64(1),
                        1 => QM31::from_i64(-1),
                        _ => values[0] * QM31::from_i64(next(1000) as i64 - 500),
                    },
                    factors: (0..next(5)).map(|_| next(width as u64) as u32).collect(),
                })
                .collect();
            let naive = terms.iter().fold(QM31::from_i64(0), |s, t| {
                s + t
                    .factors
                    .iter()
                    .fold(t.coefficient, |p, f| p * values[*f as usize])
            });
            assert_eq!(TermPlan::new(&terms).evaluate(&values), naive);
        }
    }

    /// Leak control for the privacy test of `tests/zk_claims.rs`: with the claim
    /// masks removed the proof still verifies (no verifier sees masks), but the
    /// claim on `a` is exactly `ã(ρ)` for every seed, so the uniformity test of its
    /// masked part fails. With masks the masked part is never zero.
    #[test]
    fn rejects_unmasked_claims_in_privacy_test() {
        let read = |column| Read {
            column,
            vars: vec![0, 1, 2],
        };
        let term = |coefficient, factors| Term {
            coefficient: QM31::from_i64(coefficient),
            factors,
        };
        let statement = Statement::<QM31> {
            sources: 1,
            columns: (0..3)
                .map(|_| Column {
                    source: 0,
                    log_len: 3,
                })
                .collect(),
            relations: vec![Relation::Identity {
                num_vars: 3,
                reads: (0..3).map(read).collect(),
                terms: vec![term(1, vec![0, 1]), term(-1, vec![2])],
            }],
            lookups: Vec::new(),
        };
        let a: Vec<M31> = (0..8).map(|n| M31::from_i64(n + 2)).collect();
        let b: Vec<M31> = (0..8).map(|n| M31::from_i64(5 - n)).collect();
        let c = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
        let columns = vec![a.clone(), b, c];
        for masks in [true, false] {
            for n in 0..8u8 {
                let t = || Transcript::<QM31>::new(b"leak").expect("transcript");
                let proof = prove_with(&statement, &columns, &[n; 32], &mut t(), masks, None, None)
                    .map(|p| p.0)
                    .expect("proof");
                let verified = verify(&statement, &proof, &mut t()).expect("accepted");
                let eq = stele_poly::eq_table(&verified.reductions[0].point).expect("eq");
                let exact = a
                    .iter()
                    .zip(&eq)
                    .fold(QM31::from_i64(0), |s, (x, e)| s + *e * element::<QM31>(*x));
                let residual = proof.relations[0].final_values[1] - exact;
                assert_eq!(residual == QM31::from_i64(0), !masks);
            }
        }
    }

    /// A lookup of `x` (16 entries) into the table `3j + 1`, 12 valid rows.
    fn lookup_case() -> (Statement<QM31>, Vec<Vec<M31>>) {
        let statement = Statement::<QM31> {
            sources: 1,
            columns: (0..2)
                .map(|_| Column {
                    source: 0,
                    log_len: 4,
                })
                .collect(),
            relations: Vec::new(),
            lookups: vec![Lookup::single(
                &[0],
                4,
                1,
                (0..16).map(|j| vec![3 * j + 1]).collect(),
                12,
            )],
        };
        let mut counts = vec![0i64; 16];
        let x = (0..16)
            .map(|i| {
                let j = (5 * i + 2) % 12;
                counts[j] += 1;
                M31::from_i64(3 * j as i64 + 1)
            })
            .collect();
        (
            statement,
            vec![x, counts.into_iter().map(M31::from_i64).collect()],
        )
    }

    /// Leak control for `accepts_uniform_layer_values` (check_gkr.py's no-mask
    /// variant): with the layer blocks removed, the first step's revealed `p(x*, 0)`
    /// is exactly the tree's layer value; with them it never is.
    #[test]
    fn rejects_unmasked_layers_in_privacy_test() {
        let (statement, columns) = lookup_case();
        let plan = plan(&statement).expect("plan");
        let data: Vec<Vec<QM31>> = columns
            .iter()
            .map(|c| c.iter().map(|x| element::<QM31>(*x)).collect())
            .collect();
        for masks in [true, false] {
            for n in 0..6u8 {
                let t = || Transcript::<QM31>::new(b"leak").expect("transcript");
                let proof = prove_with(&statement, &columns, &[n; 32], &mut t(), masks, None, None)
                    .map(|p| p.0)
                    .expect("proof");
                let verified = verify(&statement, &proof, &mut t()).expect("accepted");
                let [beta, alpha] = verified.lookups[0];
                let layers = lookup::tree(&plan.lookups[0], &data, beta, alpha);
                let mut at = verified.reductions[2].point.clone();
                at.push(QM31::from_i64(0));
                let eq = stele_poly::eq_table(&at).expect("eq");
                let exact = layers[4]
                    .iter()
                    .zip(&eq)
                    .fold(QM31::from_i64(0), |s, (v, e)| s + v[0] * *e);
                let residual = proof.gkr[0].final_values[3] - exact;
                assert_eq!(residual == QM31::from_i64(0), !masks);
            }
        }
    }

    /// RFC-0013 A6 item 3: proofs 0 and 1 against one lifetime source use
    /// disjoint claim-mask block positions for every weight occurrence, inside the
    /// `P·t` blocks the source reserves.
    #[test]
    fn accepts_disjoint_lifetime_blocks_per_proof() {
        let read = |column| Read {
            column,
            vars: vec![0, 1, 2],
        };
        let term = |coefficient, factors| Term {
            coefficient: QM31::from_i64(coefficient),
            factors,
        };
        let statement = Statement::<QM31> {
            sources: 2,
            columns: vec![
                Column {
                    source: 0,
                    log_len: 3,
                },
                Column {
                    source: 1,
                    log_len: 3,
                },
            ],
            relations: vec![
                Relation::Identity {
                    num_vars: 3,
                    reads: vec![read(0), read(1)],
                    terms: vec![term(1, vec![0, 1]), term(-1, vec![0])],
                },
                Relation::Identity {
                    num_vars: 3,
                    reads: vec![read(1)],
                    terms: vec![term(1, vec![0])],
                },
            ],
            lookups: Vec::new(),
        };
        let t = occurrence_counts(&statement).expect("counts")[1];
        assert_eq!(t, 2);
        let positions = |index| {
            let life = Lifetime {
                geometry: Geometry::Narrow,
                source: 1,
                proofs: 3,
                index,
                blocks: vec![t],
            };
            let plan = plan_with(&statement, Some(&life)).expect("plan");
            let (_, first) = plan.layouts[1].offsets[0];
            assert_eq!(plan.reserved[1], 3 * t);
            let mut out: Vec<usize> = plan
                .steps
                .iter()
                .flat_map(|s| s.occurrences.iter())
                .filter(|o| o.column == 1)
                .flat_map(|o| {
                    assert!(o.block < 3 * t, "block past the reservation");
                    let at = first + o.block * dim::<QM31>();
                    at..at + dim::<QM31>()
                })
                .collect();
            out.sort_unstable();
            out
        };
        let (zero, one, two) = (positions(0), positions(1), positions(2));
        assert_eq!(zero.len(), t * dim::<QM31>());
        for (a, b) in [(&zero, &one), (&zero, &two), (&one, &two)] {
            assert!(
                a.iter().all(|p| !b.contains(p)),
                "two proofs share a mask entry"
            );
        }
    }

    /// RFC-0008 A7 item 3: a zero denominator in the committed top aborts.
    #[test]
    fn rejects_zero_top_denominator() {
        let (statement, _) = lookup_case();
        let plan = plan(&statement).expect("plan");
        let mut layers = vec![Vec::new(); 6];
        layers[3] = vec![[QM31::from_i64(1), QM31::from_i64(2)]; 8];
        assert!(lookup::top(&plan.lookups[0], &layers).is_ok());
        layers[3][5][1] = QM31::from_i64(0);
        assert_eq!(
            lookup::top(&plan.lookups[0], &layers).err(),
            Some(Error::DenominatorZero)
        );
    }
}
