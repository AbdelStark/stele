//! Development-profile relation engine, RFC-0026 §§2-4, §6, §8.
//!
//! [`prove`] and [`verify`] run the RFC-0026 §4 transcript order on any validated
//! [`Relation`]: group roots, multiplicity roots, one zerocheck per identity domain
//! size, one A5 lookup per lookup/range, one sumcheck per matmul, then one claim
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
use stele_sumcheck::{claim_batch, zerocheck, Dense, Instance, Term};

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
    /// Weight certificates disagree with the relation's weight columns.
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
/// Smallest v2 expander exponent (RFC-0010 A3 item 2): 2^(2J) message columns.
const MIN_J: u8 = 3;
const MAX_J: u8 = 14;
/// Fixed public v2 seed; RFC-0012 A7 bounds hold for every seed.
const SEED: [u8; 32] = [0; 32];

/// A commitment group as one v2 source (RFC-0026 §2.3).
struct Group {
    id: u64,
    columns: Vec<ColumnId>,
    n: u8,
    c: u8,
    ell: u8,
    code: Vec<u8>,
}
impl Group {
    fn source(&self, root: [u8; 32]) -> Result<Source<K>, Error> {
        Source::from_code_id(self.id, self.ell, &self.code, root).map_err(Error::Pcs)
    }
    fn bits(&self) -> u8 {
        self.n + self.c
    }
}

/// A lookup or range as an A5 statement with Ref-mapped, shifted originals.
pub(crate) struct Check {
    id: u64,
    name: String,
    m: u8,
    tuple: Vec<(Ref, i64)>,
    selector: Option<Ref>,
    entries: Vec<i64>,
    c: usize,
    t: usize,
    k: u8,
    layout: Layout,
    /// Test-only malicious-prover seam: added to the committed count of row 0.
    #[cfg(test)]
    skew: i64,
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
    checks: Vec<Check>,
    weights: Vec<ColumnId>,
    sizes: Vec<u8>,
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

/// Group geometry: zero columns pad the count to 2^c with n+c >= 2·MIN_J, and the
/// expander exponent J minimises certificate plus opening bytes (ties: smallest J).
fn group(id: u64, n: u8, columns: Vec<ColumnId>) -> Result<Group, Error> {
    let c = ceil_log2(columns.len().max(1)).max((2 * MIN_J).saturating_sub(n));
    let bits = n + c;
    let mut best: Option<(usize, u8)> = None;
    for j in MIN_J..=MAX_J.min(bits / 2) {
        let ell = bits - 2 * j;
        let Ok(source) = Source::<K>::from_code_id(id, ell, &v2_code(j), [0; 32]) else {
            continue;
        };
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?
            + source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
        if best.is_none_or(|(b, _)| size < b) {
            best = Some((size, j));
        }
    }
    let (_, j) = best.ok_or(Error::Unsupported)?;
    Ok(Group {
        id,
        columns,
        n,
        c,
        ell: bits - 2 * j,
        code: v2_code(j),
    })
}

#[allow(clippy::too_many_arguments)]
fn check(
    id: u64,
    source_id: u64,
    name: &str,
    m: u8,
    tuple: Vec<(Ref, i64)>,
    selector: Option<Ref>,
    t: usize,
    mut entries: Vec<i64>,
) -> Result<Check, Error> {
    let c = tuple.len();
    // RFC-0008 A2 item 5: arity 1..=2 and at most 2^16 table rows.
    if !(1..=2).contains(&c) || !(1..=1 << 16).contains(&t) {
        return Err(Error::Unsupported);
    }
    let k = ceil_log2(t);
    if entries.len() != c * t {
        return Err(Error::Unsupported);
    }
    entries.resize(c << k, 0);
    let layout = Layout {
        id: source_id,
        ell: k / 2,
        blowup: 1,
    };
    Ok(Check {
        id,
        name: name.into(),
        m,
        tuple,
        selector,
        entries,
        c,
        t,
        k,
        layout,
        #[cfg(test)]
        skew: 0,
    })
}

fn plan(relation: &Relation) -> Result<Plan, Error> {
    relation.validate().map_err(Error::StatementMismatch)?;
    let mut groups = Vec::new();
    for (g, group_meta) in relation.groups.iter().enumerate() {
        let columns = (0..relation.columns.len() as u32)
            .map(ColumnId)
            .filter(|id| {
                relation.columns[id.0 as usize].kind
                    == Kind::Witness(stele_ir::relation::GroupId(g as u32))
            })
            .collect();
        groups.push(group(2 + g as u64, group_meta.log_len, columns)?);
    }
    let base = 2 + groups.len() as u64;
    let mut checks = Vec::new();
    for lookup in &relation.lookups {
        let table = &relation.tables[lookup.table.0 as usize];
        let id = checks.len() as u64;
        let tuple = lookup.tuple.iter().map(|r| (r.clone(), 0)).collect();
        let entries = table.rows.iter().flatten().copied().collect();
        let selector = lookup.selector.clone();
        let t = table.rows.len();
        checks.push(check(
            id,
            base + id,
            &lookup.name,
            lookup.vars,
            tuple,
            selector,
            t,
            entries,
        )?);
    }
    for range in &relation.ranges {
        let log_len = relation.columns[range.column.0 as usize].log_len;
        let id = checks.len() as u64;
        // RFC-0026 §3.4: v - min into 2^bits consecutive integers.
        let tuple = vec![(Ref::identity(range.column, log_len), -range.width.min())];
        let t = 1usize << range.width.bits;
        let entries = (0..t as i64).collect();
        checks.push(check(
            id,
            base + id,
            &range.name,
            log_len,
            tuple,
            None,
            t,
            entries,
        )?);
    }
    let weights = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .collect();
    let composes = relation.composes.iter();
    let mut sizes: Vec<u8> = relation.identities.iter().map(|i| i.vars).collect();
    sizes.extend(composes.map(|c| relation.columns[c.column.0 as usize].log_len));
    sizes.sort_unstable();
    sizes.dedup();
    Ok(Plan {
        digest: codec::digest(relation),
        groups,
        checks,
        weights,
        sizes,
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
        point[n - 1 - j] = domain[m - 1 - *var as usize];
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
                None if *d < free => self.rho_at(*d),
                None => K::from_i64(0),
            };
        }
        point
    }
    /// Operand table over the sumcheck variables, non-shared free bits fixed at ρ.
    fn table(&self, r: &Ref, col: &[i64]) -> Vec<K> {
        let nv = self.vars.len();
        let mut reduced = vec![K::from_i64(0); 1 << nv];
        let mut mask = 0usize;
        for d in &r.vars {
            if let Some(p) = self.position(*d) {
                mask |= 1 << (nv - 1 - p);
            }
        }
        for (index, v) in col.iter().enumerate() {
            let (mut z, mut w) = (0usize, K::from_i64(1));
            for (j, d) in r.vars.iter().enumerate() {
                let bit = (index >> j) & 1;
                match self.position(*d) {
                    Some(p) => z |= bit << (nv - 1 - p),
                    None => {
                        let x = self.rho_at(*d);
                        w = w * if bit == 1 { x } else { K::from_i64(1) - x };
                    }
                }
            }
            reduced[z] = reduced[z] + w * K::from_i64(*v);
        }
        (0..1 << nv).map(|z| reduced[z & mask]).collect()
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

/// Source claims of group `g`: column `j` at `(bits(j) ‖ ρ)` (RFC-0026 §2.3).
fn group_claims(group: &Group, claims: &Claims) -> Vec<(Vec<K>, K)> {
    let mut out = Vec::new();
    for (j, column) in group.columns.iter().enumerate() {
        for (point, value) in &claims.0[column.0 as usize] {
            out.push((bits_point(j, group.c, point), *value));
        }
    }
    out
}

fn weight_check(
    relation: &Relation,
    plan: &Plan,
    certificates: &[&VerifiedCertificate<K>],
) -> Result<(), Error> {
    if certificates.len() != plan.weights.len() {
        return Err(Error::Weights);
    }
    for (id, certificate) in plan.weights.iter().zip(certificates) {
        let source = certificate.record().source();
        if source.rows() * source.columns() != 1 << relation.columns[id.0 as usize].log_len {
            return Err(Error::Weights);
        }
    }
    Ok(())
}

fn to_k(message: &[M31]) -> Vec<K> {
    message
        .iter()
        .map(|v| K::from_i64(i64::from(v.as_u32())))
        .collect()
}

/// Produce a development-profile proof. `t` must be `Transcript::new(public)` with
/// the RFC-0026 §1.1 public inputs, including the model-commitment roots that
/// `certificates` (one per weight column, in `ColumnId` order) carry. The prover
/// checks none of the verifier's equations; a false witness yields a rejected proof
/// or an error from a primitive prover.
pub fn prove(
    t: &mut Transcript<K>,
    relation: &Relation,
    values: &Values,
    weights: &[&PreparedSource<'_, K>],
    certificates: &[&VerifiedCertificate<K>],
) -> Result<Proof, Error> {
    let plan = plan(relation)?;
    prove_plan(t, relation, &plan, values, values, weights, certificates)
}

/// The prover. `committed` fills the group messages (step 2); `values` drives every
/// later message and claim. They differ only in malicious-prover controls.
fn prove_plan(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: &Plan,
    committed: &Values,
    values: &Values,
    weights: &[&PreparedSource<'_, K>],
    certificates: &[&VerifiedCertificate<K>],
) -> Result<Proof, Error> {
    weight_check(relation, plan, certificates)?;
    if weights.len() != certificates.len()
        || weights
            .iter()
            .zip(certificates)
            .any(|(w, c)| w.source().bytes() != c.record().source().bytes())
    {
        return Err(Error::Weights);
    }
    let mut proof = Proof::default();
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);
    // Step 1.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    // Step 2: group messages, signed embedding, column index in the high bits.
    let message = |group: &Group, values: &Values| -> Result<Vec<M31>, Error> {
        let mut message = vec![M31::from_i64(0); 1 << group.bits()];
        for (j, id) in group.columns.iter().enumerate() {
            let col = column(relation, values, *id)?;
            for (out, v) in message[j << group.n..].iter_mut().zip(col) {
                *out = M31::from_i64(*v);
            }
        }
        Ok(message)
    };
    let mut messages = Vec::new();
    for group in &plan.groups {
        messages.push(message(group, committed)?);
    }
    let mut usage = HashUsage::default();
    let mut prepared = Vec::new();
    let mut handles = Vec::new();
    for (group, message) in plan.groups.iter().zip(&messages) {
        let p = PreparedSource::<K>::from_code_id(
            group.id,
            group.ell,
            &group.code,
            message,
            &mut usage,
        )
        .map_err(Error::Pcs)?;
        let (section, handle) = register(&p)?;
        t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
        proof.groups.push(section);
        prepared.push(p);
        handles.push(handle);
    }
    // Step 3: multiplicity sources, independent of every challenge.
    let mut mu_messages = Vec::new();
    for check in &plan.checks {
        mu_messages.push(lookup::multiplicities(check, relation, values)?);
    }
    let mut mu = Vec::new();
    for (check, message) in plan.checks.iter().zip(&mu_messages) {
        let layout = check.layout;
        let columns = check.k - layout.ell + 2;
        let p = PreparedSource::<K>::new(
            layout.id,
            layout.ell,
            columns,
            layout.blowup,
            message,
            &mut usage,
        )
        .map_err(Error::Pcs)?;
        let (section, handle) = register(&p)?;
        t.absorb(AbsorbLabel::RelationRoots, &p.source().root())?;
        proof.multiplicities.push(section);
        mu.push((p, handle));
    }
    // Step 4: one zerocheck per identity domain size.
    for &m in &plan.sizes {
        let lambdas = identity_lambdas(t, relation, m)?;
        let (inputs, instance) = combine(relation, m, &lambdas);
        let mut tables = Vec::new();
        for r in &inputs {
            let col = column(relation, values, r.column)?;
            tables.push(
                (0..1u64 << m)
                    .map(|x| K::from_i64(col[r.index(x)]))
                    .collect(),
            );
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
    for (check, (p, handle)) in plan.checks.iter().zip(&mu) {
        let mut out = Vec::new();
        lookup::prove(
            t,
            check,
            relation,
            values,
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
        tables.push(shape.table(&mm.lhs, column(relation, values, mm.lhs.column)?));
        tables.push(shape.table(&mm.rhs, column(relation, values, mm.rhs.column)?));
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
    // Step 7: one claim batch and one opening per group, then per weight source.
    for (s, group) in plan.groups.iter().enumerate() {
        let batch = group_claims(group, &claims);
        if batch.is_empty() {
            continue;
        }
        let opening = Opening {
            id: BATCH | s as u64,
            tensor: group.id,
            bits: group.bits(),
            batch: &batch,
        };
        let table = to_k(&message(group, values)?);
        proof
            .openings
            .push(opening.prove(t, table, &prepared[s], &handles[s])?);
    }
    for (w, id) in plan.weights.iter().enumerate() {
        let batch = &claims.0[id.0 as usize];
        if batch.is_empty() {
            continue;
        }
        let opening = Opening {
            id: BATCH | (plan.groups.len() + w) as u64,
            tensor: certificates[w].record().source().descriptor().id,
            bits: relation.columns[id.0 as usize].log_len,
            batch,
        };
        let column = column(relation, values, *id)?;
        let table = column.iter().map(|v| K::from_i64(*v)).collect();
        proof
            .openings
            .push(opening.prove(t, table, weights[w], certificates[w])?);
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
        let consistent = table == committed
            || self.batch.iter().all(|(point, value)| {
                stele_poly::eq_table(point).is_ok_and(|eq| {
                    committed
                        .iter()
                        .zip(eq)
                        .fold(K::from_i64(0), |s, (v, w)| s + *v * w)
                        == *value
                })
            });
        let table = if consistent { committed } else { table };
        let (bp, point) = self.batch().prove_with_point(table, t)?;
        let mut out = Vec::new();
        for row in &bp.rounds {
            put(&mut out, row);
        }
        put(&mut out, &bp.final_values);
        // Open what is committed; an honest batch table equals it, so this is the
        // batch final value. A lying prover's mismatch is left to the verifier.
        let eq = stele_poly::eq_table(&point).map_err(|_| Error::Capacity)?;
        let committed = to_k(prepared.message())
            .into_iter()
            .zip(eq)
            .fold(K::from_i64(0), |s, (v, w)| s + v * w);
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
/// creates `t` with the RFC-0026 §1.1 public inputs, which bind the model roots that
/// `certificates` (verified, one per weight column in `ColumnId` order) carry.
/// Every section count and length is derived here: a missing, extra, short or long
/// section rejects with `ProofShape` (RFC-0026 §4.1).
pub fn verify(
    t: &mut Transcript<K>,
    relation: &Relation,
    certificates: &[&VerifiedCertificate<K>],
    proof: &Proof,
) -> Result<Ledger, Error> {
    let plan = plan(relation)?;
    weight_check(relation, &plan, certificates)?;
    let mut ledger = Ledger::default();
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);
    // Step 1.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    // Step 2: each certificate on its own transcript, then its root here.
    let mut handles = Vec::new();
    let mut sections = Sections(proof.groups.iter());
    for group in &plan.groups {
        let mut reader = sections.next()?;
        let root = reader.root()?;
        let source = group.source(root)?;
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        let (handle, _) =
            verify_certificate(source, reader.take(size)?).map_err(|f| Error::Pcs(f.cause))?;
        reader.end()?;
        t.absorb(AbsorbLabel::RelationRoots, &root)?;
        handles.push(handle);
    }
    sections.end()?;
    // Step 3: multiplicity layouts are A5's, derived from each check.
    let mut mu = Vec::new();
    let mut sections = Sections(proof.multiplicities.iter());
    for check in &plan.checks {
        let mut reader = sections.next()?;
        let root = reader.root()?;
        let source = mu_source::<K>(check.layout, check.k, root).map_err(Error::Lookup)?;
        let size = source
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        let (handle, _) =
            verify_certificate(source, reader.take(size)?).map_err(|f| Error::Pcs(f.cause))?;
        reader.end()?;
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
    for (s, group) in plan.groups.iter().enumerate() {
        let batch = group_claims(group, &claims);
        if batch.is_empty() {
            continue;
        }
        let opening = Opening {
            id: BATCH | s as u64,
            tensor: group.id,
            bits: group.bits(),
            batch: &batch,
        };
        let name = &relation.groups[s].name;
        let mut reader = sections.next()?;
        opening.verify(t, &handles[s], &mut reader, &mut ledger, name)?;
        reader.end()?;
    }
    for (w, id) in plan.weights.iter().enumerate() {
        let batch = &claims.0[id.0 as usize];
        if batch.is_empty() {
            continue;
        }
        let column = &relation.columns[id.0 as usize];
        let opening = Opening {
            id: BATCH | (plan.groups.len() + w) as u64,
            tensor: certificates[w].record().source().descriptor().id,
            bits: column.log_len,
            batch,
        };
        let mut reader = sections.next()?;
        opening.verify(t, certificates[w], &mut reader, &mut ledger, &column.name)?;
        reader.end()?;
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
