//! RFC-0023 §§1,2.3-2.4,4: expected bytes, cumulative admission and untrusted wire.
//! O((4+R)N+E+J) public preparation; no transcript, source authentication or replay.
use super::{buffer, Constraints, Error, Limits, Schema};
use crate::lookup;
use alloc::vec::Vec;
use core::mem::size_of;
use stele_field::{Serialize, M31};
use stele_hash::ChallengeField;
use stele_pcs::{ProofKind, Source, VerifiedCertificate};
use stele_sumcheck::{Instance, Term};
#[path = "requant_producer.rs"]
pub(super) mod producer;
#[path = "requant_verifier.rs"]
pub(super) mod verifier;

struct Wire<'b> {
    root: [u8; 32],
    parts: [&'b [u8]; 8],
}

/// Caller-owned expected input and output claim; construction validates nothing.
#[derive(Clone, Copy)]
pub struct Statement<'a, 'cert, K: ChallengeField> {
    /// Reserved operation interval, 1<=stage<2^20.
    pub stage: u32,
    /// Real positions; m and padded N are derived, never supplied by a proof.
    pub n: u64,
    /// Immutable generated scalar parameters, record and advice layout.
    pub schema: &'a Schema,
    /// One or two actual A5 repetitions; this does not choose a profile.
    pub repetitions: u8,
    /// Expected advice code blowup; the input keeps its own genuine rate.
    pub advice_blowup: u8,
    /// Expected output position point and value.
    pub point: &'a [K],
    /// Expected output MLE value.
    pub value: K,
    /// Actual registered input source, independently expected by the caller.
    pub input: &'cert VerifiedCertificate<K>,
}

/// Checked expected metadata, retaining genuine handles but accepting no proof.
/// An advice handle cannot escape its owner:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor, Statement, Limits};
/// fn escape(s: Statement<'static,'static,QM31>, a: VerifiedCertificate<QM31>, l: Limits)
///     -> Descriptor<'static,'static,QM31> { Descriptor::new(s,&a,l).unwrap() }
/// ```
/// The original input handle remains borrowed too:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor, Statement, Limits};
/// fn escape(s: Statement<'static,'static,QM31>, i: VerifiedCertificate<QM31>,
///     a: &'static VerifiedCertificate<QM31>, l: Limits) -> Descriptor<'static,'static,QM31> {
///     Descriptor::new(Statement { input: &i, ..s },a,l).unwrap()
/// }
/// ```
pub struct Descriptor<'a, 'cert, K: ChallengeField> {
    statement: Statement<'a, 'cert, K>,
    originals: [[&'cert VerifiedCertificate<K>; 1]; 2],
    table: lookup::Table,
    selectors: [Vec<u8>; 2],
    layouts: [[lookup::Layout; 2]; 2],
    constraints: Constraints<K>,
    ids: Vec<u64>,
    output: Instance<K>,
    base: u64,
    m: u8,
    limits: Limits,
    statement_bytes: usize,
    constraints_bytes: usize,
    parts: [usize; 8],
    proof_bytes: usize,
    public_bytes: usize,
    local_hashes: u64,
}

fn sum(values: &[usize]) -> Result<usize, Error> {
    values
        .iter()
        .try_fold(0usize, |s, v| s.checked_add(*v).ok_or(Error::Capacity))
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn addressable<T>(count: usize) -> Result<(), Error> {
    if mul(count, size_of::<T>())? > isize::MAX as usize {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}
fn geometry(stage: u32, n: u64) -> Result<(u64, u8, usize), Error> {
    if !(1..1 << 20).contains(&stage) || n == 0 {
        return Err(Error::Statement);
    }
    let padded = n.checked_next_power_of_two().ok_or(Error::Capacity)?;
    Ok((
        u64::from(stage) << 40,
        padded.trailing_zeros() as u8,
        usize::try_from(padded).map_err(|_| Error::Capacity)?,
    ))
}
impl Schema {
    /// Derive an unauthenticated expected advice context for actual A9 registration.
    pub fn advice_source<K: ChallengeField>(
        &self,
        stage: u32,
        n: u64,
        blowup: u8,
        root: [u8; 32],
    ) -> Result<Source<K>, Error> {
        let (base, m, _) = geometry(stage, n)?;
        if !(1..=2).contains(&blowup) {
            return Err(Error::Statement);
        }
        Source::new(
            base + 2,
            self.rows().trailing_zeros() as u8,
            m,
            blowup,
            root,
        )
        .map_err(Error::Pcs)
    }
}
fn term<K: ChallengeField>(coefficient: K, factors: &[u32]) -> Result<Term<K>, Error> {
    let mut out = buffer(factors.len())?;
    out.extend_from_slice(factors);
    Ok(Term {
        coefficient,
        factors: out,
    })
}
fn opening_cost<K: ChallengeField>(source: &Source<K>) -> Result<(usize, u64), Error> {
    for n in [
        source.rows(),
        source.columns(),
        source.code().codeword_len(),
    ] {
        addressable::<K>(n)?;
    }
    let proof = source.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
    let public = sum(&[
        source.opening_frame_size().map_err(Error::Pcs)?,
        proof.checked_sub(1).ok_or(Error::Capacity)?,
    ])?;
    let hashes = u64::from(source.queries(ProofKind::Opening))
        .checked_mul(1 + source.path_height() as u64)
        .ok_or(Error::Capacity)?;
    Ok((public, hashes))
}

impl<'a, 'cert, K: ChallengeField> Descriptor<'a, 'cert, K> {
    /// Validate expected data and exact cumulative caps, without hashing or replay.
    /// Limits::positions counts BOTH full physical sources: (4+R)*N.
    pub fn new(
        statement: Statement<'a, 'cert, K>,
        advice: &'cert VerifiedCertificate<K>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let s = statement;
        let (base, m, n) = geometry(s.stage, s.n)?;
        if !(1..=2).contains(&s.repetitions) || s.point.len() != usize::from(m) {
            return Err(Error::Statement);
        }
        let input = s.input.record().source();
        let actual = advice.record().source();
        let expected = s
            .schema
            .advice_source::<K>(s.stage, s.n, s.advice_blowup, actual.root())?;
        let id = input.descriptor().id;
        if id < 2
            || (base..base + (1 << 40)).contains(&id)
            || input.rows() != 4
            || input.columns() != n
            || actual.bytes() != expected.bytes()
        {
            return Err(Error::SourceRoster);
        }
        let r = s.schema.rows();
        let w = 4 * K::DEGREE;
        let q = s.schema.values()[2].value().len();
        let counts = [mul(4, n)?, mul(r, n)?];
        let positions = sum(&counts)?;
        // Cheap admission precedes the two literal all-one selector allocations.
        if u64::try_from(positions).map_err(|_| Error::Capacity)? > limits.positions
            || positions > limits.public_bytes
        {
            return Err(Error::ResourceLimit);
        }
        for count in counts {
            addressable::<K>(count)?;
        }
        addressable::<Vec<K>>(usize::from(m))?;
        let certificate = actual
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        let input_opening = input.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
        let advice_opening = actual.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
        let zero_bytes = mul(w, sum(&[4 * usize::from(m), 5 + r])?)?;
        let output_bytes = mul(w, sum(&[4 * usize::from(m), 2 + q])?)?;
        if sum(&[
            34,
            certificate,
            input_opening,
            mul(2, advice_opening)?,
            zero_bytes,
            output_bytes,
        ])? > limits.proof_bytes
        {
            return Err(Error::ResourceLimit);
        }
        let (input_public, input_h) = opening_cost(input)?;
        let (advice_public, advice_h) = opening_cost(actual)?;
        let constraints = s.schema.constraints::<K>()?;
        let p = constraints.input_count();
        let j = constraints.equations().len();
        // RFC-0023 §4: concrete aggregate, decoded arithmetic and retained claim
        // buffers are admitted before replay, including A3's P separate points.
        let terms = constraints
            .equations()
            .iter()
            .try_fold(0, |n, ts| sum(&[n, ts.len()]))?;
        addressable::<Term<K>>(terms)?;
        addressable::<stele_sumcheck::batch::Claim<K>>(p)?;
        addressable::<K>(mul(p, usize::from(m))?)?;
        addressable::<K>(j)?;
        addressable::<(u32, u64, K)>(r)?;
        addressable::<K>(sum(&[4 * usize::from(m), 2 + q])?)?;
        let t = constraints
            .equations()
            .iter()
            .flatten()
            .try_fold(0, |total, term| {
                sum(&[total, w, 1, mul(4, term.factors.len())?])
            })?;
        let statement_bytes = sum(&[
            297,
            s.schema.bounds().as_bytes().len(),
            mul(usize::from(m) + 1, w)?,
        ])?;
        let constraints_bytes = sum(&[13, mul(8, p)?, mul(13, j)?, t])?;
        if sum(&[positions, statement_bytes, constraints_bytes])? > limits.public_bytes {
            return Err(Error::ResourceLimit);
        }
        // RFC-0023 §2.3: R<=2048 and J<2^20 keep all generated id ranges disjoint.
        let mut ids = buffer(p)?;
        ids.push(base + (1 << 28));
        ids.extend((0..4 + r).map(|i| base + (1 << 24) + i as u64));
        let mut output_ids = buffer(2 + q)?;
        output_ids.extend_from_slice(&[base + (1 << 28) + 1, base + (1 << 24) + 4]);
        output_ids.extend(
            s.schema.values()[2]
                .value()
                .map(|row| base + (1 << 24) + 4 + row as u64),
        );
        let mut terms = buffer(2 * q)?;
        let mut power = K::from_i64(1);
        for k in 0..q {
            terms.push(term(power, &[0, 2 + k as u32])?);
            terms.push(term(K::from_i64(-2) * power, &[0, 1, 2 + k as u32])?);
            power = power * K::from_i64(256);
        }
        let output = Instance {
            id: base + 2048,
            num_vars: u32::from(m),
            inputs: output_ids,
            terms,
            claimed_sum: s.value,
        };
        let mut selectors = [buffer(counts[0])?, buffer(counts[1])?];
        for (v, count) in selectors.iter_mut().zip(counts) {
            v.resize(count, 1);
        }
        let mut d = Self {
            statement,
            originals: [[s.input], [advice]],
            table: lookup::Table::range(8).map_err(|e| Error::Lookup(lookup::Error::Table(e)))?,
            selectors,
            layouts: core::array::from_fn(|b| {
                core::array::from_fn(|k| lookup::Layout {
                    id: base + 16 + 2 * b as u64 + k as u64,
                    ell: 0,
                    blowup: 1,
                })
            }),
            constraints,
            ids,
            output,
            base,
            m,
            limits,
            statement_bytes,
            constraints_bytes,
            parts: [0; 8],
            proof_bytes: 0,
            public_bytes: 0,
            local_hashes: 1,
        };
        let left = d.lookup(0)?;
        let right = d.lookup(1)?;
        let parts = [
            certificate,
            left.proof_size(),
            right.proof_size(),
            zero_bytes,
            input_opening,
            advice_opening,
            output_bytes,
            advice_opening,
        ];
        let mut public = sum(&[
            statement_bytes,
            constraints_bytes,
            left.public_bytes(),
            right.public_bytes(),
            24,
            mul(8, p)?,
            t,
            16,
            mul(p, w)?, // Actual Zero descriptor and ZeroFinal (skip=0).
            d.output.encoded_len().map_err(Error::Sumcheck)?,
            12,
            mul(2 + q, w)?,
            mul(2 * usize::from(m), 12 + 4 * w)?,
            input_public,
            mul(2, advice_public)?,
        ])?;
        for c in [4, r, 1 + q] {
            let frame = sum(&[147, mul(usize::from(m), w)?, mul(c, 12 + w)?])?;
            addressable::<u8>(frame)?;
            public = sum(&[public, frame])?;
        }
        let local_hashes = [
            left.max_local_hashes(),
            right.max_local_hashes(),
            input_h,
            advice_h,
            advice_h,
        ]
        .into_iter()
        .try_fold(1u64, |s, v| s.checked_add(v).ok_or(Error::Capacity))?;
        let proof_bytes = sum(&[34, sum(&parts)?])?;
        for size in [statement_bytes, constraints_bytes, proof_bytes] {
            addressable::<u8>(size)?;
        }
        addressable::<K>(sum(&[4 * usize::from(m), p])?)?;
        if public > limits.public_bytes || proof_bytes > limits.proof_bytes {
            return Err(Error::ResourceLimit);
        }
        d.parts = parts;
        d.proof_bytes = proof_bytes;
        d.public_bytes = public;
        d.local_hashes = local_hashes;
        Ok(d)
    }
    // Each descriptor borrows existing owner storage; there is no self-reference.
    fn lookup(&self, group: usize) -> Result<lookup::Descriptor<'_, 'cert, K>, Error> {
        let m = self.selectors[group].len().trailing_zeros() as u8;
        lookup::Descriptor::new(
            lookup::Statement {
                id: self.base / 16 + 8 + group as u64,
                m,
                b: m.min(30),
                table: &self.table,
                selector: &self.selectors[group],
                originals: &self.originals[group],
                multiplicities: &self.layouts[group][..usize::from(self.statement.repetitions)],
            },
            self.limits,
        )
        .map_err(Error::Lookup)
    }
    /// Exact expected RequantStatement payload length.
    pub fn statement_size(&self) -> usize {
        self.statement_bytes
    }
    /// Exact complete common-roster RequantConstraints payload length.
    pub fn constraints_size(&self) -> usize {
        self.constraints_bytes
    }
    /// Exact complete untrusted proof length, including all nested packets.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes
    }
    /// Cumulative absorb payload bound, excluding framing/challenges and imports.
    pub fn public_bytes(&self) -> usize {
        self.public_bytes
    }
    /// Ordinary local hash maximum; not observed Usage or registration work.
    pub fn max_local_hashes(&self) -> u64 {
        self.local_hashes
    }
    /// Encode complete expected parameters, generated record and genuine handle ids.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let s = self.statement;
        let mut out = buffer(self.statement_bytes)?;
        for raw in [
            &[1, K::DEGREE as u8][..],
            &s.stage.to_le_bytes(),
            &s.n.to_le_bytes(),
            &[self.m],
            &s.schema.layout.params,
            &[s.repetitions, s.advice_blowup],
            &(s.schema.bounds().as_bytes().len() as u16).to_le_bytes(),
            s.schema.bounds().as_bytes(),
        ] {
            put(&mut out, raw)?;
        }
        for original in self.originals {
            put(&mut out, &original[0].record().source().bytes())?;
            put(&mut out, &original[0].record().id())?;
        }
        for value in s.point.iter().chain(core::iter::once(&s.value)) {
            put(&mut out, value.to_le_bytes().as_ref())?;
        }
        Ok(out)
    }
    /// Encode every unsampled constraint without dropping zero terms or inputs.
    pub fn encode_constraints(&self) -> Result<Vec<u8>, Error> {
        let mut out = buffer(self.constraints_bytes)?;
        put(&mut out, &self.statement.stage.to_le_bytes())?;
        put(&mut out, &[self.m])?;
        put(&mut out, &(self.ids.len() as u32).to_le_bytes())?;
        for id in &self.ids {
            put(&mut out, &id.to_le_bytes())?;
        }
        put(
            &mut out,
            &(self.constraints.equations().len() as u32).to_le_bytes(),
        )?;
        for (i, equation) in self.constraints.equations().iter().enumerate() {
            put(&mut out, &(self.base + 4096 + i as u64).to_le_bytes())?;
            put(
                &mut out,
                &[equation.iter().map(|t| t.factors.len()).max().unwrap_or(0) as u8],
            )?;
            put(&mut out, &(equation.len() as u32).to_le_bytes())?;
            for term in equation {
                put(&mut out, term.coefficient.to_le_bytes().as_ref())?;
                put(&mut out, &[term.factors.len() as u8])?;
                for f in &term.factors {
                    put(&mut out, &f.to_le_bytes())?;
                }
            }
        }
        Ok(out)
    }
    /// Check complete shape and canonical arithmetic/row prefixes without allocation.
    /// Advice root/packet identities and A9 response authentication remain unchecked.
    pub fn preflight(&self, bytes: &[u8]) -> Result<(), Error> {
        self.wire(bytes).map(|_| ())
    }
    fn wire<'b>(&self, bytes: &'b [u8]) -> Result<Wire<'b>, Error> {
        if bytes.len() != self.proof_bytes || bytes.get(..2) != Some(&[1, K::DEGREE as u8]) {
            return Err(Error::ProofShape);
        }
        let mut rest = &bytes[34..];
        let mut parts = [&[][..]; 8];
        for (out, size) in parts.iter_mut().zip(self.parts) {
            *out = take(&mut rest, size)?;
        }
        let advice = self.originals[1][0].record().source();
        let input = self.originals[0][0].record().source();
        advice
            .parse(ProofKind::Certificate, parts[0])
            .map_err(Error::Pcs)?;
        for b in 0..2 {
            self.lookup(b)?
                .preflight(parts[1 + b])
                .map_err(Error::Lookup)?;
        }
        for at in [3, 6] {
            for word in parts[at].chunks_exact(4) {
                M31::from_le_bytes(word.try_into().map_err(|_| Error::NoncanonicalField)?)
                    .ok_or(Error::NoncanonicalField)?;
            }
        }
        for (source, at) in [(input, 4), (advice, 5), (advice, 7)] {
            source
                .parse(ProofKind::Opening, parts[at])
                .map_err(Error::Pcs)?;
        }
        if !rest.is_empty() {
            return Err(Error::ProofShape);
        }
        Ok(Wire {
            root: bytes[2..34].try_into().map_err(|_| Error::ProofShape)?,
            parts,
        })
    }
}
fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > out.capacity() - out.len() {
        return Err(Error::Capacity);
    }
    out.extend_from_slice(bytes);
    Ok(())
}
fn take<'b>(rest: &mut &'b [u8], size: usize) -> Result<&'b [u8], Error> {
    let out = rest.get(..size).ok_or(Error::ProofShape)?;
    *rest = &rest[size..];
    Ok(out)
}

#[cfg(test)]
#[path = "requant_codec_tests.rs"]
mod tests;
