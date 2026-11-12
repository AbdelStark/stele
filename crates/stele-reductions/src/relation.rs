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
/// One interactive error term `numerator / |K|`, `|K| = p^4`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub line: Line,
    pub name: String,
    pub numerator: u64,
}
/// Accepted-proof ledger. Interactive terms only: FS unproven (Q12), PCS conjectural.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub entries: Vec<Entry>,
    /// Sources opened (groups and weights) plus multiplicity sources; PCS lines per
    /// RFC-0012 A15 are conjectural and not summed.
    pub pcs_sources: usize,
}
impl Ledger {
    fn add(&mut self, line: Line, name: &str, numerator: u64) {
        self.entries.push(Entry {
            line,
            name: name.into(),
            numerator,
        });
    }
    /// `ε_interactive · |K|`: the sum of every non-FS, non-PCS numerator.
    pub fn interactive(&self) -> u64 {
        self.entries.iter().map(|e| e.numerator).sum()
    }
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
}
impl Sources {
    /// Stacked and model sources are A11's Circle rate-1/4 sources (A11, A12).
    fn circle(self) -> bool {
        self != Sources::Expander
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
    /// Test-only malicious-prover seam: added to the committed count of row 0.
    #[cfg(test)]
    skew: i64,
    /// Test-only malicious-prover seam: member evaluations taken from these values.
    #[cfg(test)]
    split: Option<Values>,
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
    if sources != Sources::CircleAll {
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
        #[cfg(test)]
        skew: 0,
        #[cfg(test)]
        split: None,
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
fn identities(relation: &Relation, m: u8) -> Vec<Identity> {
    let mut out: Vec<Identity> = relation
        .identities
        .iter()
        .filter(|i| i.vars == m)
        .cloned()
        .collect();
    for compose in &relation.composes {
        let log_len = relation.columns[compose.column.0 as usize].log_len;
        if log_len != m {
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
    let mut inputs: Vec<Ref> = Vec::new();
    let mut terms = Vec::new();
    for (identity, lambda) in identities(relation, m).iter().zip(lambdas) {
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
        id: ZEROCHECK | u64::from(m),
        num_vars: u32::from(m),
        inputs: (0..inputs.len() as u64).collect(),
        terms,
        claimed_sum: K::from_i64(0),
    };
    (inputs, instance)
}

fn identity_lambdas(t: &mut Transcript<K>, relation: &Relation, m: u8) -> Result<Vec<K>, Error> {
    (0..identities(relation, m).len())
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
    let mut out = Vec::new();
    for group in &plan.groups {
        for (j, column) in group.columns.iter().enumerate() {
            let index = (group.offset >> group.n) + j;
            for (point, value) in &claims.0[column.0 as usize] {
                out.push((bits_point(index, stack.bits - group.n, point), *value));
            }
        }
    }
    out
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
    if certificates.len() != plan.model.len() {
        return Err(Error::Weights);
    }
    for (model, certificate) in plan.model.iter().zip(certificates) {
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
    let model = &plan.model[k];
    let mut out = Vec::new();
    for weight in plan.weights.iter().filter(|w| w.source == k) {
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
    let plan = plan(relation, sources)?;
    prove_plan(t, relation, &plan, values, values, model)
}

/// The prover. `committed` fills the group messages (step 2); `values` drives every
/// later message and claim. They differ only in malicious-prover controls.
fn prove_plan(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: &Plan,
    committed: &Values,
    values: &Values,
    model: &[(&PreparedSource<'_, K>, &VerifiedCertificate<K>)],
) -> Result<Proof, Error> {
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
    let committed_message = match &plan.stack {
        Some(stack) => message(stack, committed)?,
        None => Vec::new(),
    };
    // Steps 2 and 3 are independent of every challenge: the stacked source and each
    // check's counts, multiplicity source and certificate are pool tasks, and the
    // roots are absorbed in step order below (task E16-23). Errors keep that order.
    let stack_source = || {
        plan.stack
            .as_ref()
            .map(|stack| {
                let p =
                    stack
                        .sources
                        .prepare(stack.id, stack.ell, &stack.code, &committed_message)?;
                let (section, handle) = register(&p)?;
                Ok::<_, Error>((p, handle, section))
            })
            .transpose()
    };
    let mu_messages = |i: usize| {
        let counts = lookup::counts(&plan.checks[i], relation, values)?;
        let message = lookup::multiplicities(&plan.checks[i], &counts)?;
        Ok::<_, Error>((counts, message))
    };
    let (stacked, mu_messages) = parallel::join(stack_source, || {
        parallel::map(plan.checks.len(), mu_messages)
            .into_iter()
            .collect::<Result<Vec<_>, Error>>()
    });
    let stacked = stacked?.map(|(p, handle, section)| {
        proof.groups.push(section);
        (p, handle)
    });
    if let Some((p, _)) = &stacked {
        t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
    }
    let (counts, mu_messages): (Vec<_>, Vec<_>) = mu_messages?.into_iter().unzip();
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
    // Step 4: one zerocheck per identity domain size.
    for &m in &plan.sizes {
        let lambdas = identity_lambdas(t, relation, m)?;
        let (inputs, instance) = combine(relation, m, &lambdas);
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
        proof.identities.push(out);
    }
    // Step 5.
    for ((check, (p, handle)), counts) in plan.checks.iter().zip(&mu).zip(&counts) {
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
    // Step 6.
    for (i, mm) in relation.matmuls.iter().enumerate() {
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
    // Step 7: one claim batch and one opening of the stack, then per weight source.
    if let (Some(stack), Some((prepared, handle))) = (&plan.stack, &stacked) {
        let batch = group_claims(plan, stack, &claims);
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
    Ok(proof)
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
        ledger.add(Line::Rlc, name, reduction.rlc.numerator);
        ledger.add(Line::Sc, name, reduction.sc.numerator);
        ledger.pcs_sources += 1;
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
        ledger.add(Line::Rlc, &name, lambdas.len() as u64);
        ledger.add(
            Line::Sc,
            &name,
            reduction.sc.iter().map(|s| s.numerator).sum(),
        );
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
        ledger.add(Line::Sz, &mm.name, u64::from(mm.free));
        ledger.add(Line::Sc, &mm.name, reduction.sc.numerator);
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

#[cfg(test)]
#[path = "relation_tests.rs"]
mod tests;
