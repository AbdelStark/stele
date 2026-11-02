//! RFC-0024 §§1–4: centered signed-int8 matmul joined to one embedded Requant cut.
//! Original range registration and witness capture remain separate charged events.
use crate::{byte_range::ByteRange, lookup, matmul, requant};
use alloc::vec::Vec;
pub use requant::Format;
#[path = "integer_linear_verifier.rs"]
mod verifier;
use stele_cqis::bounds;
use stele_field::{Serialize, M31};
use stele_gkr::stacked;
use stele_hash::ChallengeField;
use stele_pcs::{ProofKind, Source, VerifiedCertificate};
use stele_sumcheck::{Instance, Term};
pub use verifier::{Failure, PointEqualityRecord, Record, RegistrationFailure};
#[path = "integer_linear_producer.rs"]
mod producer;
pub use producer::{ProducerLimits, ProverFailure, ProverUsage};

/// The expected operation; proof metadata cannot select parameters or original owners.
#[derive(Clone, Copy)]
pub struct Statement<'a, 'cert, K: ChallengeField> {
    /// Reserved stage, 1<=stage<2^20.
    pub stage: u32,
    /// Exact full-power-of-two exponents h,a,b,c.
    pub bits: [u8; 4],
    /// Expected scalar mantissa in the complete CQIS domain.
    pub mantissa: u32,
    /// Expected scalar shift in the complete CQIS domain.
    pub shift: u32,
    /// Signed output width; original matrices always use centered int8.
    pub format: Format,
    /// One or two A5 repetitions, matching both original range events.
    pub repetitions: u8,
    /// Expected advice code blowup, one or two.
    pub advice_blowup: u8,
    /// Incoming output position point, ordered (layer,row,column).
    pub point: &'a [K],
    /// Incoming output MLE value.
    pub value: K,
    /// Completed original X,W whole-source range events, borrowed without deduplication.
    pub originals: [&'cert ByteRange<'cert, K>; 2],
}

/// Invalid expected data, malformed wire or the actual rejecting child cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid expected stage or axes.
    Statement,
    /// Invalid CQIS scalar parameters.
    Parameters(stele_cqis::Error),
    /// Failed static integer bound.
    Bounds(bounds::Error),
    /// Unexpected internally generated schema encoding.
    Encoding,
    /// Overflow, addressability or fallible allocation failure.
    Capacity,
    /// Outer positions, public payload or wire budget exceeded.
    ResourceLimit,
    /// Original/range/advice roster disagreement.
    SourceRoster,
    /// Wrong complete version, length or field.
    ProofShape,
    /// Noncanonical arithmetic field word.
    NoncanonicalField,
    /// Genuine advice context mismatch.
    CertificateContext,
    /// Packet differs from the genuinely registered identity.
    CertificateIdentity,
    /// Actual arithmetic ids or points differ from the expected roster.
    ArithmeticRoster,
    /// Actual public coefficient final is incorrect.
    CoefficientMismatch,
    /// Requant witness generation failure.
    Witness,
    /// Actual A7 cause.
    PublicCoefficient(stele_gkr::public_mle::Error),
    /// Actual A3/A1 cause.
    Sumcheck(stele_sumcheck::Error),
    /// Actual A5 cause.
    Lookup(lookup::Error),
    /// Actual A9 cause.
    Pcs(stele_pcs::Error),
    /// Actual signed A4/A1/A7/original A9 cause.
    Matmul(matmul::Error),
    /// Actual transcript cause.
    Transcript(stele_hash::Error),
}
impl From<requant::Error> for Error {
    fn from(e: requant::Error) -> Self {
        match e {
            requant::Error::Statement => Self::Statement,
            requant::Error::Parameters(e) => Self::Parameters(e),
            requant::Error::Bounds(e) => Self::Bounds(e),
            requant::Error::Encoding => Self::Encoding,
            requant::Error::Capacity => Self::Capacity,
            requant::Error::ResourceLimit => Self::ResourceLimit,
            requant::Error::SourceRoster => Self::SourceRoster,
            requant::Error::ProofShape => Self::ProofShape,
            requant::Error::NoncanonicalField => Self::NoncanonicalField,
            requant::Error::CertificateContext => Self::CertificateContext,
            requant::Error::CertificateIdentity => Self::CertificateIdentity,
            requant::Error::ArithmeticRoster => Self::ArithmeticRoster,
            requant::Error::CoefficientMismatch => Self::CoefficientMismatch,
            requant::Error::Witness => Self::Witness,
            requant::Error::PublicCoefficient(e) => Self::PublicCoefficient(e),
            requant::Error::Sumcheck(e) => Self::Sumcheck(e),
            requant::Error::Lookup(e) => Self::Lookup(e),
            requant::Error::Pcs(e) => Self::Pcs(e),
            requant::Error::Transcript(e) => Self::Transcript(e),
        }
    }
}

/// Derived expected geometry and owners; construction does not accept a proof.
pub struct Descriptor<'a, 'cert, K: ChallengeField> {
    statement: Statement<'a, 'cert, K>,
    advice: [&'cert VerifiedCertificate<K>; 1],
    schema: requant::EmbeddedSchema,
    table: lookup::Table,
    selector: Vec<u8>,
    layouts: [lookup::Layout; 2],
    constraints: requant::Constraints<K>,
    ids: Vec<u64>,
    output: Instance<K>,
    base: u64,
    m: u8,
    n: usize,
    limits: lookup::Limits,
    matmul_limits: stacked::Limits,
    matmul: matmul::centered::Geometry,
    statement_bytes: usize,
    constraints_bytes: usize,
    parts: [usize; 8],
    proof_bytes: usize,
    public_bytes: usize,
    local_hashes: u64,
}
struct Wire<'b> {
    root: [u8; 32],
    parts: [&'b [u8]; 8],
}
fn sum(values: &[usize]) -> Result<usize, Error> {
    values
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(*v).ok_or(Error::Capacity))
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn addressable<T>(count: usize) -> Result<(), Error> {
    if mul(count, core::mem::size_of::<T>())? > isize::MAX as usize {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}
fn buffer<T>(count: usize) -> Result<Vec<T>, Error> {
    addressable::<T>(count)?;
    let mut v = Vec::new();
    v.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    Ok(v)
}
fn put(out: &mut Vec<u8>, raw: &[u8]) -> Result<(), Error> {
    if raw.len() > out.capacity() - out.len() {
        return Err(Error::Capacity);
    }
    out.extend_from_slice(raw);
    Ok(())
}
fn term<K: ChallengeField>(coefficient: K, factors: &[u32]) -> Result<Term<K>, Error> {
    let mut out = buffer(factors.len())?;
    out.extend_from_slice(factors);
    Ok(Term {
        coefficient,
        factors: out,
    })
}
fn matmul_error(e: matmul::Error) -> Error {
    match e {
        matmul::Error::InvalidMatmul => Error::Statement,
        matmul::Error::SourceRoster => Error::SourceRoster,
        matmul::Error::Capacity => Error::Capacity,
        matmul::Error::ProofShape => Error::ProofShape,
        matmul::Error::NoncanonicalField => Error::NoncanonicalField,
        e => Error::Matmul(e),
    }
}

impl<'a, 'cert, K: ChallengeField> Descriptor<'a, 'cert, K> {
    /// Derive both static bounds, complete canonical rosters, suffix shape and all caps.
    /// Original/range registration and advice import Usage remain separate.
    pub fn new(
        s: Statement<'a, 'cert, K>,
        advice: &'cert VerifiedCertificate<K>,
        limits: lookup::Limits,
        matmul_limits: stacked::Limits,
    ) -> Result<Self, Error> {
        let [h, a, b, c] = s.bits.map(usize::from);
        let m = h + a + c;
        if !(1..1 << 20).contains(&s.stage)
            || m > 63
            || !(1..=2).contains(&s.repetitions)
            || !(1..=2).contains(&s.advice_blowup)
            || s.point.len() != m
        {
            return Err(Error::Statement);
        }
        let schema = requant::EmbeddedSchema::new(s.bits[2], s.mantissa, s.shift, s.format)?;
        let base = u64::from(s.stage) << 40;
        let n = 1usize.checked_shl(m as u32).ok_or(Error::Capacity)?;
        let originals = s.originals.map(ByteRange::original);
        let ids = originals.map(|c| c.record().source().descriptor().id);
        if ids[0] == ids[1]
            || ids
                .iter()
                .any(|id| *id < 2 || (base..base + (1 << 40)).contains(id))
        {
            return Err(Error::SourceRoster);
        }
        for range in s.originals {
            let parameters = range.lookup().parameters();
            if parameters.degree != K::DEGREE as u8
                || parameters.repetitions != s.repetitions
                || (base..base + (1 << 40)).contains(&(parameters.id << 4))
                || range.multiplicities().iter().any(|c| {
                    (base..base + (1 << 40)).contains(&c.record().source().descriptor().id)
                })
            {
                return Err(Error::SourceRoster);
            }
        }
        let actual = advice.record().source();
        let expected = Source::<K>::new(
            base + 2,
            schema.rows().trailing_zeros() as u8,
            m as u8,
            s.advice_blowup,
            actual.root(),
        )
        .map_err(Error::Pcs)?;
        if actual.bytes() != expected.bytes() {
            return Err(Error::SourceRoster);
        }
        let geometry = matmul::centered::Geometry::new(s.bits, originals, matmul_limits)
            .map_err(matmul_error)?;
        let r = schema.rows();
        let p = r + 1;
        let w = 4 * K::DEGREE;
        let q = schema.semantic().values()[2].value().len();
        let cells = mul(r, n)?;
        let positions = sum(&[
            cells,
            mul(1usize << (h + b), sum(&[1usize << a, 1usize << c])?)?,
        ])?;
        if u64::try_from(positions).map_err(|_| Error::Capacity)? > limits.positions
            || cells > limits.public_bytes
        {
            return Err(Error::ResourceLimit);
        }
        for count in [cells, mul(p, n)?, mul(q + 2, n)?, sum(&[r, n])?, m + 1] {
            addressable::<K>(count)?;
        }
        addressable::<Vec<K>>(p)?;
        addressable::<Vec<K>>(q + 2)?;
        let constraints = schema.constraints::<K>()?;
        let j = constraints.equations().len();
        let term_count = constraints
            .equations()
            .iter()
            .try_fold(0usize, |n, e| sum(&[n, e.len()]))?;
        addressable::<Term<K>>(term_count)?;
        addressable::<stele_sumcheck::batch::Claim<K>>(p)?;
        addressable::<K>(mul(p, m)?)?;
        addressable::<K>(j)?;
        addressable::<(u32, u64, K)>(r)?;
        let t = constraints
            .equations()
            .iter()
            .flatten()
            .try_fold(0usize, |n, t| sum(&[n, w, 1, mul(4, t.factors.len())?]))?;
        let statement_bytes = sum(&[
            457,
            mul(274, usize::from(s.repetitions))?,
            schema.semantic().bounds().as_bytes().len(),
            mul(m + 1, w)?,
        ])?;
        let constraints_bytes = sum(&[13, mul(8, p)?, mul(13, j)?, t])?;
        if sum(&[cells, statement_bytes, constraints_bytes])? > limits.public_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut ids = buffer(p)?;
        ids.push(base + (1 << 28));
        ids.extend((0..r).map(|i| base + (1 << 24) + i as u64));
        let mut output_ids = buffer(q + 2)?;
        output_ids.extend_from_slice(&[base + (1 << 28) + 1, base + (1 << 24) + 4]);
        output_ids.extend(
            schema.semantic().values()[2]
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
            num_vars: m as u32,
            inputs: output_ids,
            terms,
            claimed_sum: s.value,
        };
        let mut selector = buffer(cells)?;
        selector.resize(cells, 1);
        let certificate = actual
            .proof_size(ProofKind::Certificate)
            .map_err(Error::Pcs)?;
        let opening = actual.proof_size(ProofKind::Opening).map_err(Error::Pcs)?;
        let opening_public = sum(&[
            actual.opening_frame_size().map_err(Error::Pcs)?,
            opening.checked_sub(1).ok_or(Error::Capacity)?,
        ])?;
        let opening_hashes = u64::from(actual.queries(ProofKind::Opening))
            .checked_mul(1 + actual.path_height() as u64)
            .ok_or(Error::Capacity)?;
        let mut d = Self {
            statement: s,
            advice: [advice],
            schema,
            table: lookup::Table::range(8).map_err(|e| Error::Lookup(lookup::Error::Table(e)))?,
            selector,
            layouts: core::array::from_fn(|k| lookup::Layout {
                id: base + 18 + k as u64,
                ell: 0,
                blowup: 1,
            }),
            constraints,
            ids,
            output,
            base,
            m: m as u8,
            n,
            limits,
            matmul_limits,
            matmul: geometry,
            statement_bytes,
            constraints_bytes,
            parts: [0; 8],
            proof_bytes: 0,
            public_bytes: 0,
            local_hashes: 0,
        };
        let a5 = d.lookup()?;
        let parts = [
            certificate,
            a5.proof_size(),
            mul(w, sum(&[4 * m, p])?)?,
            opening,
            opening,
            mul(w, sum(&[4 * m, q + 2])?)?,
            opening,
            d.matmul.wire_bytes,
        ];
        let mut public = sum(&[
            statement_bytes,
            constraints_bytes,
            a5.public_bytes(),
            24,
            mul(8, p)?,
            t,
            16,
            mul(w, p)?,
            d.output.encoded_len().map_err(Error::Sumcheck)?,
            12,
            mul(w, q + 2)?,
            mul(2 * m, 12 + 4 * w)?,
            mul(3, opening_public)?,
            d.matmul.public_bytes,
        ])?;
        for count in [4, r - 4, q + 1] {
            public = sum(&[public, 147, mul(m, w)?, mul(count, 12 + w)?])?;
        }
        let hashes = 1u64
            .checked_add(a5.max_local_hashes())
            .and_then(|n| n.checked_add(opening_hashes.checked_mul(3)?))
            .and_then(|n| n.checked_add(d.matmul.local_hashes))
            .ok_or(Error::Capacity)?;
        let proof = sum(&[34, sum(&parts)?])?;
        for count in [statement_bytes, constraints_bytes, public, proof] {
            addressable::<u8>(count)?;
        }
        if public > limits.public_bytes || proof > limits.proof_bytes {
            return Err(Error::ResourceLimit);
        }
        d.parts = parts;
        d.proof_bytes = proof;
        d.public_bytes = public;
        d.local_hashes = hashes;
        Ok(d)
    }
    fn lookup(&self) -> Result<lookup::Descriptor<'_, 'cert, K>, Error> {
        let m = self.selector.len().trailing_zeros() as u8;
        lookup::Descriptor::new(
            lookup::Statement {
                id: self.base / 16 + 9,
                m,
                b: m.min(30),
                table: &self.table,
                selector: &self.selector,
                originals: &self.advice,
                multiplicities: &self.layouts[..usize::from(self.statement.repetitions)],
            },
            self.limits,
        )
        .map_err(Error::Lookup)
    }
    fn arithmetic(&self) -> requant::arithmetic::Arithmetic<'_, 'cert, K> {
        requant::arithmetic::Arithmetic {
            stage: self.statement.stage,
            base: self.base,
            m: self.m,
            positions: self.n,
            ids: &self.ids,
            constraints: &self.constraints,
            groups: [self.advice[0]; 3],
        }
    }
    /// Complete canonical expected statement payload size.
    pub fn statement_size(&self) -> usize {
        self.statement_bytes
    }
    /// Complete constraint roster payload size.
    pub fn constraints_size(&self) -> usize {
        self.constraints_bytes
    }
    /// Exact outer proof length, including the signed matmul suffix.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes
    }
    /// Complete local absorb payload cap, excluding imports and challenge framing.
    pub fn public_bytes(&self) -> usize {
        self.public_bytes
    }
    /// Local verifier H maximum; not an adversarial query cap or observed work.
    pub fn max_local_hashes(&self) -> u64 {
        self.local_hashes
    }
    /// Separate signed matmul allowance 5*L*d+n+o, in K entries.
    pub fn retained_row_entries(&self) -> usize {
        self.matmul.retained_entries
    }
    /// Encode expected parameters and exact original/range/advice identities.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let s = self.statement;
        let mut out = buffer(self.statement_bytes)?;
        put(&mut out, &[1, K::DEGREE as u8])?;
        put(&mut out, &s.stage.to_le_bytes())?;
        put(&mut out, &s.bits)?;
        put(&mut out, &(s.mantissa as u16).to_le_bytes())?;
        put(
            &mut out,
            &[
                s.shift as u8,
                match s.format {
                    Format::Int8 => 8,
                    Format::Int16 => 16,
                },
                s.repetitions,
                s.advice_blowup,
            ],
        )?;
        let bounds = self.schema.semantic().bounds().as_bytes();
        put(&mut out, &(bounds.len() as u16).to_le_bytes())?;
        put(&mut out, bounds)?;
        put(&mut out, &self.schema.bound().to_le_bytes())?;
        for range in s.originals {
            put(&mut out, &range.original().record().source().bytes())?;
            put(&mut out, &range.original().record().id())?;
            put(&mut out, &[1])?;
            put(&mut out, &range.lookup().parameters().id.to_le_bytes())?;
            put(&mut out, &[s.repetitions])?;
            for mu in range.multiplicities() {
                put(&mut out, &mu.record().source().bytes())?;
                put(&mut out, &mu.record().id())?;
            }
        }
        put(&mut out, &self.advice[0].record().source().bytes())?;
        put(&mut out, &self.advice[0].record().id())?;
        for value in s.point.iter().chain(core::iter::once(&s.value)) {
            put(&mut out, value.to_le_bytes().as_ref())?;
        }
        Ok(out)
    }
    /// Encode every complete unsampled constraint in the fixed roster order.
    pub fn encode_constraints(&self) -> Result<Vec<u8>, Error> {
        self.arithmetic()
            .encode_constraints(self.constraints_bytes)
            .map_err(Error::from)
    }
    /// Check all wire shapes and arithmetic prefixes, including the point-free suffix.
    /// Response authentication and column decoding remain in their actual A9 consumers.
    pub fn preflight(&self, proof: &[u8]) -> Result<(), Error> {
        self.wire(proof).map(|_| ())
    }
    fn wire<'b>(&self, proof: &'b [u8]) -> Result<Wire<'b>, Error> {
        if proof.len() != self.proof_bytes || proof.get(..2) != Some(&[1, K::DEGREE as u8]) {
            return Err(Error::ProofShape);
        }
        let mut parts = [&[][..]; 8];
        let mut at = 34;
        for (part, len) in parts.iter_mut().zip(self.parts) {
            *part = &proof[at..at + len];
            at += len;
        }
        let advice = self.advice[0].record().source();
        advice
            .parse(ProofKind::Certificate, parts[0])
            .map_err(Error::Pcs)?;
        self.lookup()?.preflight(parts[1]).map_err(Error::Lookup)?;
        for index in [2, 5] {
            for word in parts[index].chunks_exact(4) {
                M31::from_le_bytes(word.try_into().map_err(|_| Error::NoncanonicalField)?)
                    .ok_or(Error::NoncanonicalField)?;
            }
        }
        for index in [3, 4, 6] {
            advice
                .parse(ProofKind::Opening, parts[index])
                .map_err(Error::Pcs)?;
        }
        self.matmul
            .preflight(self.statement.originals.map(ByteRange::original), parts[7])
            .map_err(matmul_error)?;
        Ok(Wire {
            root: proof[2..34].try_into().map_err(|_| Error::ProofShape)?,
            parts,
        })
    }
}
