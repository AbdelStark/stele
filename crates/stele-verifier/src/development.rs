//! The development proof verifier for profile byte 5: the public file, the transcript
//! public input, the container (RFC-0026 A15 §§2–4) and the engine replay (A15 §6.4),
//! task E8-02f1.
//!
//! Written from the RFC-0026 text (A15 and the amendments it cites),
//! `formal/native-lookup.md` and `formal/native-field-pcs.md`, with no production crate
//! open (ADR-128). It composes this crate's primitives: the A3 zerocheck, the A1
//! sumcheck, the A2 mode-1 claim batch, the PCS consumer, the RFC-0008 A3 fraction
//! trees and leaf, and the LogUp `(β, α)` round.
//!
//! Scope: the relation and `cqis_id` are inputs. Deriving them from the Model,
//! Scales and Preparation (RFC-0025, §2's record and `NumericalIdentity` checks) is
//! E8-02f2. Every check names its section; every failure is a typed [`Error`].

use crate::batch::ClaimBatch;
use crate::plan::{self, Check, Plan, MATMUL_ID, TUPLE_ID, ZEROCHECK_ID};
use crate::relation::{pow2, Kind, Ref, Relation, FIXED_0, FIXED_1};
use crate::sumcheck::{self, Instance, Proof, Term};
use crate::zerocheck::{self, Zerocheck};
use crate::{fraction, logup, pcs};
use alloc::vec::Vec;
use stele_field::{Field, Serialize, QM31};
use stele_hash::{AbsorbLabel, ChallengeLabel, Transcript};

type K = QM31;
const W: usize = 16;

/// Why a development proof was refused. Names follow RFC-0026 and A15.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A15 §4: fewer than 18 bytes, a wrong magic or a wrong version.
    Header,
    /// A15 §4/§6: a truncated, trailing, missing, extra, short or long field or section.
    ProofShape,
    /// A15 §§2–5, §6.0: the statement, the relation or a header field disagrees.
    StatementMismatch,
    /// A15 §6.2–6.3: a relation outside the supported shapes.
    Unsupported,
    /// A15 §1: a `K` limb at or above p.
    NoncanonicalField,
    /// A15 §6.4 step 5: the right tree's denominator differs from the table's.
    TableDenominatorMismatch,
    /// A3 member split.
    MemberSumMismatch,
    /// formal/native-lookup.md §2: the pieces do not sum to the table numerator.
    PieceSumMismatch,
    /// A15 §6.4 step 6: the matmul's eq final.
    EqMismatch,
    /// A15 §6.4 step 8: a public column's MLE differs from its claim.
    PublicMismatch,
    Capacity,
    Sumcheck(sumcheck::Error),
    Pcs(pcs::Error),
    Fraction(fraction::Error),
    Logup(logup::Error),
    Transcript(stele_hash::Error),
}

impl From<sumcheck::Error> for Error {
    fn from(e: sumcheck::Error) -> Self {
        match e {
            sumcheck::Error::Capacity => Error::Capacity,
            e => Error::Sumcheck(e),
        }
    }
}
impl From<pcs::Error> for Error {
    fn from(e: pcs::Error) -> Self {
        match e {
            pcs::Error::Capacity => Error::Capacity,
            e => Error::Pcs(e),
        }
    }
}
impl From<fraction::Error> for Error {
    fn from(e: fraction::Error) -> Self {
        match e {
            fraction::Error::Capacity => Error::Capacity,
            e => Error::Fraction(e),
        }
    }
}
impl From<logup::Error> for Error {
    fn from(e: logup::Error) -> Self {
        Error::Logup(e)
    }
}
impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Error::Transcript(e)
    }
}

/// A vector with `n` slots reserved fallibly.
pub(crate) fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}

/// A little-endian cursor; running past the end, or a count that cannot fit, is `err`.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    err: Error,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], err: Error) -> Self {
        Reader { bytes, at: 0, err }
    }
    pub(crate) fn fail(&self) -> Error {
        self.err
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(self.err)?;
        let out = self.bytes.get(self.at..end).ok_or(self.err)?;
        self.at = end;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| self.err)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(crate) fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_le_bytes(self.array()?))
    }
    pub(crate) fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// A `u32` count of elements of at least `min` bytes each, bounded by what remains.
    pub(crate) fn count(&mut self, min: usize) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n > (self.bytes.len() - self.at) / min.max(1) {
            return Err(self.err);
        }
        Ok(n)
    }
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(self.err)
        }
    }
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }
}

/// `count` canonical `K` values (A15 §1).
fn values(r: &mut Reader, count: usize) -> Result<Vec<K>, Error> {
    let raw = r.take(count.checked_mul(W).ok_or(Error::Capacity)?)?;
    let mut out = reserve(count)?;
    for c in raw.chunks_exact(W) {
        let bytes: [u8; W] = c.try_into().map_err(|_| Error::ProofShape)?;
        out.push(K::from_le_bytes(bytes).ok_or(Error::NoncanonicalField)?);
    }
    Ok(out)
}

fn rows(all: &[K], width: usize) -> Result<Vec<Vec<K>>, Error> {
    let mut out = reserve(all.len() / width.max(1))?;
    for row in all.chunks_exact(width.max(1)) {
        let mut v = reserve(row.len())?;
        v.extend_from_slice(row);
        out.push(v);
    }
    Ok(out)
}

const PUBLIC_MAGIC: &[u8; 19] = b"stele-dev-public-v4";
const INPUT_TAG: &[u8; 31] = b"stele/v0.1/dev-e2e/public-input";
const STATEMENT_TAG: &[u8; 28] = b"stele/v0.1/dev-e2e/statement";
const CONTAINER_MAGIC: &[u8; 16] = b"stele-dev-e2e-v1";
/// A14 item 1: the profile byte.
const PROFILE: u8 = 5;

/// The decoded `stele-dev-public-v4` file (A15 §2).
struct Public<'a> {
    /// Model, Scales, Preparation and the 1-D records, exactly as in the file.
    data: &'a [u8],
    roots: Vec<[u8; 32]>,
    certificates: Vec<&'a [u8]>,
    /// Tokens, checked range and next token, exactly as in the file.
    statement: &'a [u8],
}

impl<'a> Public<'a> {
    /// A15 §2. Every failure is `StatementMismatch`.
    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let r = &mut Reader::new(bytes, Error::StatementMismatch);
        // A15 §2: a byte-5 verifier accepts only `stele-dev-public-v4`.
        if r.take(PUBLIC_MAGIC.len())? != PUBLIC_MAGIC {
            return Err(Error::StatementMismatch);
        }
        let start = r.at;
        for _ in 0..3 {
            r.blob()?;
        }
        for _ in 0..r.count(6)? {
            r.take(2)?;
            // A15 §2: a codes blob of odd length.
            if r.blob()?.len() % 2 != 0 {
                return Err(Error::StatementMismatch);
            }
        }
        let data = &bytes[start..r.at];
        let n = r.count(36)?;
        let (mut roots, mut certificates) = (reserve(n)?, reserve(n)?);
        for _ in 0..n {
            roots.push(r.array::<32>()?);
            certificates.push(r.blob()?);
        }
        let start = r.at;
        let t = r.count(4)?;
        r.take(4 * t)?;
        let (begin, end) = (r.u32()?, r.u32()?);
        let next = match r.u8()? {
            0 => false,
            1 => {
                r.u32()?;
                true
            }
            _ => return Err(Error::StatementMismatch),
        };
        r.end()?;
        // §1.1: T a power of two, 0 ≤ r < e ≤ T, y present exactly when e = T.
        let t = t as u64;
        if !t.is_power_of_two()
            || begin >= end
            || u64::from(end) > t
            || next != (u64::from(end) == t)
        {
            return Err(Error::StatementMismatch);
        }
        Ok(Public {
            data,
            roots,
            certificates,
            statement: &bytes[start..],
        })
    }

    /// A15 §3: the argument of `Transcript::new`.
    fn input(&self, cqis_id: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let size = 31 + 32 + self.data.len() + 4 + 32 * self.roots.len() + self.statement.len() + 1;
        let mut out = reserve(size)?;
        out.extend_from_slice(INPUT_TAG);
        out.extend_from_slice(cqis_id);
        out.extend_from_slice(self.data);
        out.extend_from_slice(&(self.roots.len() as u32).to_le_bytes());
        for r in &self.roots {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(self.statement);
        out.push(PROFILE);
        Ok(out)
    }
}

/// A15 §3: BLAKE3(tag ‖ u64 len ‖ input ‖ relation digest).
fn statement_digest(input: &[u8], relation: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut bytes = reserve(28 + 8 + input.len() + 32)?;
    bytes.extend_from_slice(STATEMENT_TAG);
    bytes.extend_from_slice(&(input.len() as u64).to_le_bytes());
    bytes.extend_from_slice(input);
    bytes.extend_from_slice(relation);
    Ok(stele_hash::blake3_digest(&bytes))
}

/// The container's six section lists (A15 §4).
struct Container<'a> {
    cqis_id: [u8; 32],
    digest: [u8; 32],
    sections: [Vec<&'a [u8]>; 6],
}

impl<'a> Container<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        // A15 §4: fewer than 18 bytes, a wrong magic or version is Header.
        if bytes.len() < 18 || &bytes[..16] != CONTAINER_MAGIC || bytes[16..18] != [1, 0] {
            return Err(Error::Header);
        }
        let r = &mut Reader::new(&bytes[18..], Error::ProofShape);
        let cqis_id = r.array()?;
        let digest = r.array()?;
        let mut sections: [Vec<&[u8]>; 6] = Default::default();
        for list in &mut sections {
            // A15 §4: a count above the remaining bytes over 4 is ProofShape.
            let n = r.count(4)?;
            *list = reserve(n)?;
            for _ in 0..n {
                list.push(r.blob()?);
            }
        }
        r.end()?;
        Ok(Container {
            cqis_id,
            digest,
            sections,
        })
    }
}

/// A section that must be exactly `len` bytes (A15 §4: short or long is ProofShape).
fn exact(section: &[u8], len: usize) -> Result<Reader<'_>, Error> {
    if section.len() != len {
        return Err(Error::ProofShape);
    }
    Ok(Reader::new(section, Error::ProofShape))
}

fn bit(b: bool) -> K {
    K::from_i64(i64::from(b))
}

/// The point of `r` given the value of each domain bit (A15 §6.4 step 4 restriction,
/// A6 fixed bits): `y[n − 1 − j]` is domain bit `vars[j]`'s value.
fn read(r: &Ref, at: impl Fn(u8) -> K) -> Result<Vec<K>, Error> {
    let n = r.vars.len();
    let mut y = reserve(n)?;
    y.resize(n, K::from_i64(0));
    for (j, v) in r.vars.iter().enumerate() {
        y[n - 1 - j] = match *v {
            FIXED_0 => bit(false),
            FIXED_1 => bit(true),
            d => at(d),
        };
    }
    Ok(y)
}

/// The MSB-first domain point `x` as a domain-bit lookup: bit `d` is `x[m − 1 − d]`.
fn domain(x: &[K]) -> impl Fn(u8) -> K + '_ {
    move |d| x[x.len() - 1 - usize::from(d)]
}

/// `Π_j eq(z_j, bit j of index)`, MSB-first over `z.len()` bits.
fn eq_bits(z: &[K], index: u64) -> K {
    let n = z.len();
    let one = K::from_i64(1);
    z.iter().enumerate().fold(one, |acc, (j, x)| {
        acc * if (index >> (n - 1 - j)) & 1 == 1 {
            *x
        } else {
            one - *x
        }
    })
}

/// The MSB-first eq table of `z`, `2^len(z)` entries, in O(2^n).
fn eq_table(z: &[K]) -> Result<Vec<K>, Error> {
    let size = u8::try_from(z.len())
        .ok()
        .and_then(pow2)
        .ok_or(Error::Capacity)?;
    let mut t = reserve(size)?;
    t.push(K::from_i64(1));
    for x in z {
        let len = t.len();
        t.resize(2 * len, K::from_i64(0));
        for i in (0..len).rev() {
            let v = t[i];
            t[2 * i + 1] = v * *x;
            t[2 * i] = v - t[2 * i + 1];
        }
    }
    Ok(t)
}

/// The MLE of `entries` (`2^len(z)` of them, mapped through `f`) at `z`.
fn mle<T>(entries: &[T], z: &[K], f: impl Fn(&T) -> K) -> Result<K, Error> {
    let eq = eq_table(z)?;
    if eq.len() != entries.len() {
        return Err(Error::Capacity);
    }
    Ok(eq
        .iter()
        .zip(entries)
        .fold(K::from_i64(0), |acc, (e, x)| acc + *e * f(x)))
}

/// Every column's claims, in the order the replay emits them (A15 §6.4 step 7).
struct Claims(Vec<Vec<(Vec<K>, K)>>);

impl Claims {
    fn push(&mut self, column: u32, point: Vec<K>, value: K) -> Result<(), Error> {
        let list = &mut self.0[column as usize];
        list.try_reserve(1).map_err(|_| Error::Capacity)?;
        list.push((point, value));
        Ok(())
    }
}

/// Verify a byte-5 development proof (RFC-0026 A15): the public file, the container,
/// and the relation in its §5 encoding, with the `cqis_id` the caller derived from
/// the model. `Ok` is acceptance.
pub fn verify(
    public: &[u8],
    container: &[u8],
    relation: &[u8],
    cqis_id: &[u8; 32],
) -> Result<(), Error> {
    let file = Public::decode(public)?;
    // A15 §6.0: the relation is decoded and validated before any proof byte is read.
    let rel = Relation::decode(relation)?;
    rel.validate()?;
    let plan = Plan::derive(&rel)?;
    let relation_digest = stele_hash::blake3_digest(relation);
    let input = file.input(cqis_id)?;
    let proof = Container::decode(container)?;
    // A15 §4: cqis_id and statement digest fail fast; the transcript is the binding.
    if proof.cqis_id != *cqis_id || proof.digest != statement_digest(&input, &relation_digest)? {
        return Err(Error::StatementMismatch);
    }
    let [groups, multiplicities, identities, lookups, matmuls, openings] = &proof.sections;
    // A15 §4 / §6.4: section counts are derived; openings are checked in step 7.
    if groups.len() != usize::from(plan.stacked)
        || multiplicities.len() != plan.checks.len()
        || identities.len() != plan.sizes.len()
        || lookups.len() != plan.checks.len()
        || matmuls.len() != rel.matmuls.len()
    {
        return Err(Error::ProofShape);
    }
    // A15 §6.4 step 1: the statement, the relation digest and the model roots.
    let t = &mut Transcript::<K>::new(&input)?;
    t.absorb(AbsorbLabel::RelationStatement, &relation_digest)?;
    let models = &plan.sources[usize::from(plan.stacked)..];
    // A15 §6.4 step 1: one certificate per derived model layout.
    if file.roots.len() != models.len() {
        return Err(Error::StatementMismatch);
    }
    let mut certificates = reserve(plan.sources.len())?;
    let mut model_certificates = reserve(models.len())?;
    for ((m, root), cert) in models.iter().zip(&file.roots).zip(&file.certificates) {
        t.absorb(AbsorbLabel::RelationRoots, root)?;
        // A15 §6.4 step 1 / RFC-0010 A9: each certificate on its own transcript.
        let source = m.geometry.source(*root);
        model_certificates.push(pcs::verify_certificate::<K>(&source, cert)?);
    }
    // A15 §6.4 step 2: the stacked root and certificate.
    if let (true, Some(section)) = (plan.stacked, groups.first()) {
        let g = plan.sources[0].geometry;
        let r = &mut exact(section, 32 + g.certificate)?;
        let root = r.array::<32>()?;
        certificates.push(pcs::verify_certificate::<K>(&g.source(root), r.rest())?);
        t.absorb(AbsorbLabel::RelationRoots, &root)?;
    }
    certificates.extend(model_certificates);
    // A15 §6.4 step 3: one multiplicity root and certificate per check.
    let mut mu = reserve(plan.checks.len())?;
    for (check, section) in plan.checks.iter().zip(multiplicities) {
        // A12 item 5: the length is checked before the certificate is parsed.
        let r = &mut exact(section, 32 + check.multiplicity.certificate)?;
        let root = r.array::<32>()?;
        mu.push(pcs::verify_certificate::<K>(
            &check.multiplicity.source(root),
            r.rest(),
        )?);
        t.absorb(AbsorbLabel::RelationRoots, &root)?;
    }
    let mut claims = Claims(reserve(rel.columns.len())?);
    claims.0.resize_with(rel.columns.len(), Vec::new);
    for (m, section) in plan.sizes.iter().zip(identities) {
        identity(&rel, *m, section, t, &mut claims)?;
    }
    for (i, ((check, section), cert)) in plan.checks.iter().zip(lookups).zip(&mu).enumerate() {
        lookup(&rel, i as u64, check, cert, section, t, &mut claims)?;
    }
    for (i, (m, section)) in rel.matmuls.iter().zip(matmuls).enumerate() {
        matmul(i as u64, m, section, t, &mut claims)?;
    }
    open(&rel, &plan, &certificates, openings, t, &claims)?;
    // A15 §6.4 step 8: every public column's claims against the MLE of its values.
    for (c, list) in rel.columns.iter().zip(&claims.0) {
        if let Kind::Public(v) = &c.kind {
            for (point, value) in list {
                if mle(v, point, |x| K::from_i64(*x))? != *value {
                    return Err(Error::PublicMismatch);
                }
            }
        }
    }
    Ok(())
}

/// A15 §6.4 step 4: the zerocheck of domain size `m`.
fn identity(
    rel: &Relation,
    m: u8,
    section: &[u8],
    t: &mut Transcript<K>,
    claims: &mut Claims,
) -> Result<(), Error> {
    // Identities of size m in relation order, then composes as 1·column − Σ 2^s·limb.
    let mut polys: Vec<Vec<(i64, Vec<Ref>)>> = Vec::new();
    for i in rel.identities.iter().filter(|i| i.vars == m) {
        let mut terms = reserve(i.terms.len())?;
        for term in &i.terms {
            let mut f = reserve(term.factors.len())?;
            f.extend(term.factors.iter().cloned());
            terms.push((term.coeff, f));
        }
        polys.try_reserve(1).map_err(|_| Error::Capacity)?;
        polys.push(terms);
    }
    for c in &rel.composes {
        let n = rel.column(c.column)?.log_len;
        if n != m {
            continue;
        }
        let whole = |column: u32| -> Result<Vec<Ref>, Error> {
            let mut vars = reserve(usize::from(n))?;
            vars.extend(0..n);
            let mut v = reserve(1)?;
            v.push(Ref { column, vars });
            Ok(v)
        };
        let mut terms = reserve(1 + c.limbs.len())?;
        terms.push((1, whole(c.column)?));
        for (limb, shift) in &c.limbs {
            terms.push((-(1i64 << shift), whole(*limb)?));
        }
        polys.try_reserve(1).map_err(|_| Error::Capacity)?;
        polys.push(terms);
    }
    // One relation/identity challenge λ per identity, in that order.
    let mut inputs: Vec<&Ref> = Vec::new();
    let mut terms = Vec::new();
    for poly in &polys {
        let lambda: K = t.challenge(ChallengeLabel::RelationIdentity)?;
        for (coeff, factors) in poly {
            let mut ids = reserve(factors.len())?;
            for f in factors {
                // Inputs are the distinct refs in first-appearance order.
                let at = match inputs.iter().position(|r| *r == f) {
                    Some(at) => at,
                    None => {
                        inputs.try_reserve(1).map_err(|_| Error::Capacity)?;
                        inputs.push(f);
                        inputs.len() - 1
                    }
                };
                ids.push(at as u32);
            }
            terms.try_reserve(1).map_err(|_| Error::Capacity)?;
            terms.push(Term {
                coefficient: lambda * K::from_i64(*coeff),
                factors: ids,
            });
        }
    }
    let mut ids = reserve(inputs.len())?;
    ids.extend(0..inputs.len() as u64);
    let instance = Instance {
        id: ZEROCHECK_ID + u64::from(m),
        num_vars: u32::from(m),
        inputs: ids,
        terms,
        claimed_sum: K::from_i64(0),
    };
    let d = instance
        .terms
        .iter()
        .map(|t| t.factors.len())
        .max()
        .unwrap_or(0);
    // [m] ([D + 1] K) rounds, then one final K per input.
    let n = usize::from(m) * (d + 1) + inputs.len();
    let r = &mut exact(section, n * W)?;
    let all = values(r, n)?;
    let (round, finals) = all.split_at(usize::from(m) * (d + 1));
    let proof = zerocheck::Proof {
        skip_values: Vec::new(),
        rounds: rows(round, d + 1)?,
        final_values: finals.to_vec(),
    };
    let reduction = Zerocheck {
        instance: &instance,
        skip: 0,
    }
    .verify(&proof, t)?;
    for c in &reduction.claims {
        let r = inputs[c.tensor as usize];
        claims.push(r.column, read(r, domain(&c.point))?, c.value)?;
    }
    Ok(())
}

/// The table's columns over `2^k` rows (zero padded) and the valid-row indicator,
/// at `x` (A15 §6.4 step 5, table claim).
fn table_at(check: &Check, x: &[K]) -> Result<(Vec<K>, K), Error> {
    let eq = eq_table(x)?;
    let mut columns = reserve(check.c)?;
    columns.resize(check.c, K::from_i64(0));
    let mut valid = K::from_i64(0);
    for (row, e) in check.rows.chunks_exact(check.c).zip(&eq) {
        valid = valid + *e;
        for (c, v) in columns.iter_mut().zip(row) {
            *c = *c + *e * K::from_i64(*v);
        }
    }
    Ok((columns, valid))
}

/// A15 §6.4 step 5: check `i`'s lookup section.
fn lookup(
    rel: &Relation,
    i: u64,
    check: &Check,
    cert: &pcs::VerifiedCertificate<K>,
    section: &[u8],
    t: &mut Transcript<K>,
    claims: &mut Claims,
) -> Result<(), Error> {
    let (m, k, c) = (usize::from(check.m), usize::from(check.k), check.c);
    let geometry = check.multiplicity;
    let row_bits = usize::from(k as u8 - geometry.ell);
    let (q, s) = (check.t >> row_bits, check.t & ((1 << row_bits) - 1));
    // formal/native-lookup.md §2: piece 0 when q > 0, piece 1 when s > 0.
    let pieces: &[u8] = match (q > 0, s > 0) {
        (true, true) => &[0, 1],
        (true, false) => &[0],
        (false, true) => &[1],
        (false, false) => &[],
    };
    let members = check.members.len();
    let tree = |v: usize| 2 + 2 * v * v + 3 * v;
    let len = 8 * usize::from(check.k_lu >= 1)
        + W * (tree(m) + tree(k) + 4 * m + c + 2 + members * c + pieces.len())
        + pieces.len() * geometry.opening;
    let r = &mut exact(section, len)?;
    // Statement and units.
    let mut tuple_ids = reserve(c)?;
    tuple_ids.extend((0..c as u64).map(|j| TUPLE_ID + 4 * i + j));
    let mut st = reserve(37 + members + 8 * c)?;
    st.extend_from_slice(&[1, 4]);
    st.extend_from_slice(&i.to_le_bytes());
    st.extend_from_slice(&[check.m, check.m.min(30), 1, c as u8]);
    st.extend_from_slice(&(check.t as u32).to_le_bytes());
    st.push(check.k);
    st.extend_from_slice(&geometry.id.to_le_bytes());
    st.extend_from_slice(&[geometry.ell, plan::BLOWUP]);
    st.extend_from_slice(&(members as u32).to_le_bytes());
    st.extend(check.members.iter().map(|m| m.vars));
    for id in &tuple_ids {
        st.extend_from_slice(&id.to_le_bytes());
    }
    t.absorb(AbsorbLabel::LookupStatement, &st)?;
    let mut tag = [0u8; 9];
    tag[..8].copy_from_slice(&i.to_le_bytes());
    t.absorb(AbsorbLabel::LookupUnits, &tag)?;
    // Multiplicity bundle: u64 i ‖ u8 1 ‖ u8 0 ‖ source bytes ‖ certificate id.
    let source = cert.source().bytes()?;
    let mut bundle = reserve(10 + source.len() + 32)?;
    bundle.extend_from_slice(&i.to_le_bytes());
    bundle.extend_from_slice(&[1, 0]);
    bundle.extend_from_slice(&source);
    bundle.extend_from_slice(cert.id());
    t.absorb(AbsorbLabel::LookupMultiplicities, &bundle)?;
    let mut rep = [0u8; 10];
    rep[..8].copy_from_slice(&i.to_le_bytes());
    t.absorb(AbsorbLabel::LookupRepetition, &rep)?;
    // A14 item 4: the nonce is the section's first 8 bytes when k_LU ≥ 1.
    let nonce = if check.k_lu >= 1 {
        Some(u64::from_le_bytes(r.array()?))
    } else {
        None
    };
    let (beta, alpha) = logup::round(t, check.k_lu, nonce)?;
    rep[9] = 1;
    t.absorb(AbsorbLabel::LookupRepetition, &rep)?;
    // Trees: left (4i, m, b = m), right (4i + 1, k), then the A3 item 4 root equation.
    let left = fraction::Descriptor {
        id: 4 * i,
        m: m as u32,
        b: m as u32,
        leaves: [8 * i, 8 * i + 1],
        theta: Vec::new(),
    };
    let right = fraction::Descriptor {
        id: 4 * i + 1,
        m: k as u32,
        b: k as u32,
        leaves: [8 * i + 2, 8 * i + 3],
        theta: Vec::new(),
    };
    let left_proof = fraction::Proof::decode(&left, r.take(W * tree(m))?)?;
    let right_proof = fraction::Proof::decode(&right, r.take(W * tree(k))?)?;
    let lr = fraction::verify(t, &left, &left_proof)?;
    let rr = fraction::verify(t, &right, &right_proof)?;
    fraction::root_equation(left_proof.root, right_proof.root)?;
    // Table claim: Q = 1 + (α − 1)·V − Σ β^j·T_j at the right tree's point.
    let (columns, valid) = table_at(check, &rr.point)?;
    let (mut compress, mut power) = (K::from_i64(0), K::from_i64(1));
    for col in &columns {
        compress = compress + power * *col;
        power = power * beta;
    }
    let one = K::from_i64(1);
    if rr.values[1] != one + (alpha - one) * valid - compress {
        return Err(Error::TableDenominatorMismatch);
    }
    // Leaf: σ is each member's selector (or ones) on its block, 0 on the padding.
    let size = pow2(check.m).ok_or(Error::Capacity)?;
    let mut sigma = reserve(size)?;
    sigma.resize(size, K::from_i64(0));
    for member in &check.members {
        let base = member.offset as usize;
        for u in 0..1usize << member.vars {
            sigma[base + u] = match &member.selector {
                None => one,
                Some(s) => {
                    let Kind::Public(v) = &rel.column(s.column)?.kind else {
                        return Err(Error::StatementMismatch);
                    };
                    let index = s
                        .vars
                        .iter()
                        .enumerate()
                        .fold(0usize, |acc, (j, d)| acc | (((u >> d) & 1) << j));
                    K::from_i64(*v.get(index).ok_or(Error::StatementMismatch)?)
                }
            };
        }
    }
    let leaf_proof = fraction::decode_leaf(&left, c, r.take(W * (4 * m + c + 2))?)?;
    let leaf = fraction::verify_leaf(t, &left, &lr, &sigma, &tuple_ids, &leaf_proof, alpha, beta)?;
    // Member values and the A3 member split.
    let split = values(r, members * c)?;
    for (j, (_, total)) in leaf.claims.iter().enumerate() {
        let mut sum = K::from_i64(0);
        for (member, row) in check.members.iter().zip(split.chunks_exact(c)) {
            let high = m - usize::from(member.vars);
            sum = sum + eq_bits(&leaf.point[..high], member.offset >> member.vars) * row[j];
        }
        if sum != *total {
            return Err(Error::MemberSumMismatch);
        }
    }
    for (member, row) in check.members.iter().zip(split.chunks_exact(c)) {
        let low = &leaf.point[m - usize::from(member.vars)..];
        for (r, v) in member.tuple.iter().zip(row) {
            claims.push(
                r.column,
                read(r, domain(low))?,
                *v - K::from_i64(member.shift),
            )?;
        }
    }
    // Multiplicity pieces (formal/native-lookup.md §2).
    let piece_values = values(r, pieces.len())?;
    let total = piece_values.iter().fold(K::from_i64(0), |acc, v| acc + *v);
    if total != rr.values[0] {
        return Err(Error::PieceSumMismatch);
    }
    let mut bound = reserve(10 + W * (k + 1) + (1 + W) * pieces.len())?;
    bound.extend_from_slice(&i.to_le_bytes());
    bound.extend_from_slice(&[0, pieces.len() as u8]);
    for x in rr.point.iter().chain(core::iter::once(&rr.values[0])) {
        bound.extend_from_slice(&x.to_le_bytes());
    }
    for (id, v) in pieces.iter().zip(&piece_values) {
        bound.push(*id);
        bound.extend_from_slice(&v.to_le_bytes());
    }
    t.absorb(AbsorbLabel::LookupMultiplicityClaims, &bound)?;
    let ell = usize::from(geometry.ell);
    let rows_eq = eq_table(&rr.point[..ell])?;
    let cols_eq = eq_table(&rr.point[ell..])?;
    let mut basis = [[0u8; W]; 4];
    for (a, e) in basis.iter_mut().enumerate() {
        e[4 * a] = 1;
    }
    let basis = basis.map(|b| K::from_le_bytes(b).unwrap_or(one));
    for (id, v) in pieces.iter().zip(&piece_values) {
        let mut a = reserve(rows_eq.len())?;
        a.extend(rows_eq.iter().enumerate().map(|(u, e)| match id {
            0 if u < q => *e,
            1 if u == q => *e,
            _ => K::from_i64(0),
        }));
        let mut b = reserve(4 * cols_eq.len())?;
        for (col, e) in cols_eq.iter().enumerate() {
            let on = *id == 0 || col < s;
            for x in &basis {
                b.push(if on { *e * *x } else { K::from_i64(0) });
            }
        }
        pcs::verify_opening(
            t,
            u64::from(*id),
            cert,
            &a,
            &b,
            *v,
            r.take(geometry.opening)?,
        )?;
    }
    Ok(())
}

/// A15 §6.4 step 6: matmul `i`.
fn matmul(
    i: u64,
    mm: &crate::relation::Matmul,
    section: &[u8],
    t: &mut Transcript<K>,
    claims: &mut Claims,
) -> Result<(), Error> {
    let a = mm.free;
    let mut rho = reserve(usize::from(a))?;
    for _ in 0..a {
        rho.push(t.challenge(ChallengeLabel::RelationPoint)?);
    }
    // Bit d is ρ[free − 1 − d].
    let rho_at = |d: u8| rho[usize::from(a - 1 - d)];
    let reads = |r: &Ref, d: u8| r.vars.contains(&d);
    // Sumcheck variables: shared free bits and the summed bits, descending.
    let mut vars = reserve(usize::from(a) + usize::from(mm.summed))?;
    for d in (0..a + mm.summed).rev() {
        if d >= a || (reads(&mm.lhs, d) && reads(&mm.rhs, d)) {
            vars.push(d);
        }
    }
    let shared = vars.iter().any(|d| *d < a);
    let (width, finals) = if shared { (4, 3) } else { (3, 2) };
    let n = 1 + vars.len() * width + finals;
    let r = &mut exact(section, n * W)?;
    let all = values(r, n)?;
    let out = all[0];
    let (round, last) = all[1..].split_at(vars.len() * width);
    let mut inputs = reserve(finals)?;
    inputs.extend(0..finals as u64);
    let mut factors = reserve(finals)?;
    factors.extend(0..finals as u32);
    let instance = Instance {
        id: MATMUL_ID + i,
        num_vars: vars.len() as u32,
        inputs,
        terms: alloc::vec![Term {
            coefficient: K::from_i64(1),
            factors,
        }],
        claimed_sum: out,
    };
    let proof = Proof {
        rounds: rows(round, width)?,
        final_values: last.to_vec(),
    };
    let reduction = sumcheck::verify(&instance, &proof, t)?;
    let point = &reduction.point;
    let at = |d: u8| match vars.iter().position(|v| *v == d) {
        Some(p) => point[p],
        None => rho_at(d),
    };
    if shared {
        // The eq final is Π_d eq(ρ_d, r_d) over the shared bits.
        let one = K::from_i64(1);
        let eq = vars.iter().filter(|d| **d < a).fold(one, |acc, d| {
            let (x, y) = (rho_at(*d), at(*d));
            acc * (x * y + (one - x) * (one - y))
        });
        if last[0] != eq {
            return Err(Error::EqMismatch);
        }
    }
    claims.push(mm.out.column, read(&mm.out, rho_at)?, out)?;
    claims.push(mm.lhs.column, read(&mm.lhs, at)?, last[finals - 2])?;
    claims.push(mm.rhs.column, read(&mm.rhs, at)?, last[finals - 1])?;
    Ok(())
}

/// A15 §6.4 step 7: one claim batch and point opening per committed source with a claim.
fn open(
    rel: &Relation,
    plan: &Plan,
    certificates: &[pcs::VerifiedCertificate<K>],
    sections: &[&[u8]],
    t: &mut Transcript<K>,
    claims: &Claims,
) -> Result<(), Error> {
    let mut used = 0;
    for (s, (source, cert)) in plan.sources.iter().zip(certificates).enumerate() {
        let bits = usize::from(source.bits);
        // Columns in GroupId then group order (stacked), or ColumnId order (model).
        let mut columns: Vec<(u64, usize)> = Vec::new();
        for (id, home) in plan.homes.iter().enumerate() {
            if let Some(h) = home.filter(|h| h.source == s) {
                columns.try_reserve(1).map_err(|_| Error::Capacity)?;
                columns.push((h.index, id));
            }
        }
        if plan.stacked && s == 0 {
            columns.sort_by_key(|(_, id)| match rel.columns[*id].kind {
                Kind::Witness(g) => g,
                _ => u32::MAX,
            });
        }
        let mut batch = Vec::new();
        for (index, id) in columns {
            let lead = bits - usize::from(rel.columns[id].log_len);
            for (point, value) in &claims.0[id] {
                let mut full = reserve(bits)?;
                full.extend((0..lead).map(|j| bit((index >> (lead - 1 - j)) & 1 == 1)));
                full.extend_from_slice(point);
                batch.try_reserve(1).map_err(|_| Error::Capacity)?;
                batch.push((full, *value));
            }
        }
        if batch.is_empty() {
            continue;
        }
        let section = sections.get(used).ok_or(Error::ProofShape)?;
        used += 1;
        let r = &mut exact(section, W * (3 * bits + 1) + source.geometry.opening)?;
        let all = values(r, 3 * bits + 1)?;
        let proof = Proof {
            rounds: rows(&all[..3 * bits], 3)?,
            final_values: alloc::vec![all[3 * bits]],
        };
        let reduced = ClaimBatch {
            id: source.batch,
            tensor: source.geometry.id,
            num_vars: source.bits.into(),
            claims: &batch,
        }
        .verify(&proof, t)?;
        pcs::verify_point(
            t,
            source.geometry.id,
            cert,
            &reduced.point,
            reduced.claims[0].value,
            r.rest(),
        )?;
    }
    // A15 §4: a missing or extra opening section.
    if used != sections.len() {
        return Err(Error::ProofShape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC-0026 A15 golden vectors (`matches_a15_small_codec_vectors` and the second one).
    const RELATION_1: &str = "7374656c652f76302e312f72656c6174696f6e2f656e636f64696e672f76310100000005000000472f782f31010300000001000000770000000000010801010000006b01010401010000007002020000000100000000000000feffffffffffffff010301010000000100000074010000000002020000000100000000000000000000000100000003000000000000000100000001000000690101000000fdffffffffffffff0200000000010002000000010001000000010000006c0101020000000100010000000000000001000000000001000000010000007200000000010801000000010000006d01000000000001000100000001ff02000000010001000000010000006300000000010000000100000004";
    const PUBLIC_1: &str = "7374656c652d6465762d7075626c69632d7634030000004d444c020000005343010000005001000000030004000000ffff020001000000abababababababababababababababababababababababababababababababab0300000001020302000000050000000600000000000000020000000107000000";
    const INPUT_1: &str = "7374656c652f76302e312f6465762d6532652f7075626c69632d696e7075741111111111111111111111111111111111111111111111111111111111111111030000004d444c020000005343010000005001000000030004000000ffff020001000000abababababababababababababababababababababababababababababababab0200000005000000060000000000000002000000010700000005";
    const DIGEST_1: &str = "a8f02660942bce4421ee7b2e1af127e560a859f3cfefac9d721a8477e209ff8b";
    const CONTAINER_1: &str = "7374656c652d6465762d6532652d7631010001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010000000200000003040000000001000000010000000500000000000000000100000003000000060708";
    const RELATION_2: &str = "7374656c652f76302e312f72656c6174696f6e2f656e636f64696e672f76310100000005000000472f782f31010300000001000000770000000000010801010000006b01010401010000007002020000000100000000000000feffffffffffffff010301010000000100000074010000000002020000000100000000000000000000000100000003000000000000000100000001000000690101000000fdffffffffffffff0200000000010002000000010001000000010000006c0100010000000000000001000000000001000000010000007200000000010801000000010000006d01000000000001000100000001fe02000000010001000000010000006300000000010000000100000004";
    const PUBLIC_2: &str = "7374656c652d6465762d7075626c69632d7634030000004d444c020000005343010000005001000000030004000000ffff020001000000abababababababababababababababababababababababababababababababab03000000010203020000000500000006000000000000000100000000";
    const INPUT_2: &str = "7374656c652f76302e312f6465762d6532652f7075626c69632d696e7075741111111111111111111111111111111111111111111111111111111111111111030000004d444c020000005343010000005001000000030004000000ffff020001000000abababababababababababababababababababababababababababababababab02000000050000000600000000000000010000000005";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("test vector"))
            .collect()
    }

    #[test]
    fn matches_reference_a15_small_codec_vectors() {
        for (relation, public, input) in [
            (RELATION_1, PUBLIC_1, INPUT_1),
            (RELATION_2, PUBLIC_2, INPUT_2),
        ] {
            let rel = Relation::decode(&hex(relation)).expect("test vector");
            assert_eq!(
                (
                    rel.groups.len(),
                    rel.columns.len(),
                    rel.tables.len(),
                    rel.identities.len()
                ),
                (1, 3, 1, 1)
            );
            assert_eq!(
                (
                    rel.lookups.len(),
                    rel.ranges.len(),
                    rel.matmuls.len(),
                    rel.composes.len()
                ),
                (1, 1, 1, 1)
            );
            let bytes = hex(public);
            let file = Public::decode(&bytes).expect("test vector");
            assert_eq!(file.input(&[0x11; 32]).expect("test vector"), hex(input));
        }
        let rel = Relation::decode(&hex(RELATION_1)).expect("test vector");
        assert!(rel.lookups[0].selector.is_some());
        assert_eq!(rel.matmuls[0].lhs.vars[0], 0xff);
        let second = Relation::decode(&hex(RELATION_2)).expect("test vector");
        assert!(second.lookups[0].selector.is_none());
        assert_eq!(second.matmuls[0].lhs.vars[0], 0xfe);
        assert_eq!(
            statement_digest(&hex(INPUT_1), &[0x22; 32])
                .expect("test vector")
                .to_vec(),
            hex(DIGEST_1)
        );
        let container = hex(CONTAINER_1);
        let c = Container::decode(&container).expect("test vector");
        assert_eq!((c.cqis_id, c.digest), ([1; 32], [2; 32]));
        assert_eq!(c.sections.each_ref().map(Vec::len), [1, 0, 1, 0, 0, 1]);
        // A15 §4: a trailing byte, and truncation, are ProofShape; §5 likewise for the
        // relation (StatementMismatch).
        let mut long = container.clone();
        long.push(0);
        assert!(matches!(Container::decode(&long), Err(Error::ProofShape)));
        assert!(matches!(
            Container::decode(&container[..container.len() - 1]),
            Err(Error::ProofShape)
        ));
        let mut rel = hex(RELATION_1);
        rel.push(0);
        assert_eq!(Relation::decode(&rel), Err(Error::StatementMismatch));
    }

    #[test]
    fn eq_table_matches_eq_bits() {
        let z = [K::from_i64(3), K::from_i64(7), K::from_i64(11)];
        let table = eq_table(&z).expect("test vector");
        for (x, e) in table.iter().enumerate() {
            assert_eq!(*e, eq_bits(&z, x as u64));
        }
    }

    #[test]
    fn rejects_short_headers_and_counts_past_the_input() {
        assert!(matches!(
            Container::decode(b"stele-dev-e2e-v1\x01"),
            Err(Error::Header)
        ));
        assert!(matches!(
            Container::decode(b"stele-dev-e2e-v1\x02\x00"),
            Err(Error::Header)
        ));
        let mut c = b"stele-dev-e2e-v1\x01\x00".to_vec();
        c.extend_from_slice(&[0; 64]);
        c.extend_from_slice(&5u32.to_le_bytes());
        assert!(matches!(Container::decode(&c), Err(Error::ProofShape)));
    }
}
