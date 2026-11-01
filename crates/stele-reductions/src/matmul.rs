//! RFC-0007 A2 / formal/native-matmul §§1–6: conditional original-source matmul.
//! A4 contributes O(L*d) folding and its existing coefficient/partial costs;
//! both A9 consumers retain their full encoding, authentication and storage costs.
use alloc::vec::Vec;
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked,
};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{CodeField, OpeningRecord, ProofKind, Usage, VerifiedCertificate};
use stele_sumcheck::{Proof, ScRecord, Term};

/// Expected statement fixed by the caller, never decoded from the proof.
#[derive(Clone, Copy)]
pub struct Statement<'a, K> {
    /// Stage identity within the enclosing expected statement.
    pub id: u64,
    /// Output C identity, distinct from both originals and the coefficient.
    pub output_id: u64,
    /// Public layer-equality coefficient identity.
    pub coefficient_id: u64,
    /// Original X,W tensor identities, in that order.
    pub inputs: [u64; 2],
    /// Exponents h,a,b,c of the exact L,n,d,m powers of two.
    pub bits: [u8; 4],
    /// Canonical output coordinates r_l || r_i || r_j.
    pub point: &'a [K],
    /// Expected output value at that point.
    pub value: K,
}

/// Invalid expected data, malformed wire, capacity or actual consuming-protocol error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Expected identities, exponents or output point are invalid.
    InvalidMatmul,
    /// Original certificate identities or physical source layouts disagree.
    SourceRoster,
    /// Outer/A9 version or complete proof length disagrees with the expected shape.
    ProofShape,
    /// An A1 or OpeningRow field limb is noncanonical.
    NoncanonicalField,
    /// A checked size, caller cap or allocation cannot be satisfied.
    Capacity,
    /// The actual A4/A1/A7 reduction rejected.
    Stacked(stacked::Error),
    /// The actual original-source consumer rejected.
    Pcs(stele_pcs::Error),
    /// Production transcript validation or accounting rejected.
    Transcript(stele_hash::Error),
}

/// Abort the whole attempt; usage never authorizes continuation after an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// The actual rejecting cause.
    pub cause: Error,
    /// One cumulative transcript snapshot plus disjoint local hash work.
    pub usage: Usage,
}

/// Conditional field relation after A1, A7 and both original A9 consumers finish.
/// No integer, privacy or profile admission follows. Construction is private:
/// ```compile_fail,E0599
/// use stele_field::QM31;
/// let fake = stele_reductions::matmul::Record::<QM31>::from_digest([0; 32]);
/// ```
/// Neither original certificate can be released while this record is retained:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_gkr::stacked::Limits;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::matmul::{verify, Record, Statement};
/// fn escape(x: VerifiedCertificate<QM31>, w: &'static VerifiedCertificate<QM31>,
///     t: &mut Transcript<QM31>, s: &Statement<'_, QM31>, wire: &[u8], limits: Limits)
///     -> Record<'static, QM31> {
///     verify(t, s, [&x, w], wire, limits).unwrap().0
/// }
/// ```
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_gkr::stacked::Limits;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::matmul::{verify, Record, Statement};
/// fn escape(x: &'static VerifiedCertificate<QM31>, w: VerifiedCertificate<QM31>,
///     t: &mut Transcript<QM31>, s: &Statement<'_, QM31>, wire: &[u8], limits: Limits)
///     -> Record<'static, QM31> {
///     verify(t, s, [x, &w], wire, limits).unwrap().0
/// }
/// ```
/// Temporary statements and proof bytes supply no authority and need not survive:
/// ```
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_gkr::stacked::Limits;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::matmul::{verify, Record, Statement};
/// fn keep<'cert>(certs: [&'cert VerifiedCertificate<QM31>; 2],
///     t: &mut Transcript<QM31>, s: Statement<'_, QM31>, wire: Vec<u8>, limits: Limits)
///     -> Record<'cert, QM31> {
///     verify(t, &s, certs, &wire, limits).unwrap().0
/// }
/// ```
#[must_use = "retain actual SC and both original certificate/opening obligations"]
pub struct Record<'cert, K: ChallengeField> {
    sc: ScRecord,
    openings: [OpeningRecord<'cert, K>; 2],
    points: [Vec<K>; 2],
    values: [K; 2],
}
impl<K: ChallengeField> Record<'_, K> {
    /// Actual degree-three A1 accounting, including zero-round records.
    pub fn sc(&self) -> &ScRecord {
        &self.sc
    }
    /// Both actual original consumers, retaining their certificate losses.
    pub fn openings(&self) -> &[OpeningRecord<'_, K>; 2] {
        &self.openings
    }
    /// Consumed physical X(i,l,k) and W(j,l,k) points, in that order.
    pub fn points(&self) -> [&[K]; 2] {
        [&self.points[0], &self.points[1]]
    }
    /// Actual partial-row finals consumed at the two restored original points.
    pub fn values(&self) -> &[K; 2] {
        &self.values
    }
}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Capacity)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Capacity)
}
fn reserve<T>(values: &mut Vec<T>, count: usize) -> Result<(), Error> {
    values.try_reserve_exact(count).map_err(|_| Error::Capacity)
}
fn pcs_error(error: stele_pcs::Error) -> Error {
    match error {
        stele_pcs::Error::Capacity => Error::Capacity,
        stele_pcs::Error::ProofShape => Error::ProofShape,
        stele_pcs::Error::NoncanonicalField => Error::NoncanonicalField,
        error => Error::Pcs(error),
    }
}
fn stacked_error(error: stacked::Error) -> Error {
    if error == stacked::Error::Capacity {
        Error::Capacity
    } else {
        Error::Stacked(error)
    }
}

// Expected geometry and untrusted wire framing only; no verification authority.
struct Context<'a, K> {
    expected: &'a Statement<'a, K>,
    axes: [Axis; 2],
    output_axes: [Axis; 3],
    selectors: [Option<&'a [K]>; 2],
    terms: [Term<K>; 1],
    frame: Vec<u8>,
    limits: stacked::Limits,
    opening_sizes: [usize; 2],
    rounds: usize,
    wire_size: usize,
    maximum_hashes: u64,
}

/// Bind the expected statement, run A4/A1/A7 and consume X then W through A9.
/// Both consumers run even for zero factors. Limits retain the scopes in §6;
/// any failure aborts the attempt and returns no conditional record.
pub fn verify<'cert, K: ChallengeField + CodeField + Eq>(
    t: &mut Transcript<K>,
    expected: &Statement<'_, K>,
    certificates: [&'cert VerifiedCertificate<K>; 2],
    wire: &[u8],
    limits: stacked::Limits,
) -> Result<(Record<'cert, K>, Usage), Failure>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut hashes = 0u64;
    let result = (|| {
        let context = Context::new(expected, certificates, limits)?;
        let statement = context.statement();
        let prepared = stacked::Prepared::for_certified_sources(&statement, context.limits)
            .map_err(stacked_error)?;
        let (proof, openings) = context.parse(certificates, wire)?;
        stele_sumcheck::preflight(prepared.instance(), &proof)
            .map_err(|error| Error::Stacked(stacked::Error::Sumcheck(error)))?;
        let [h, a, _, c] = expected.bits.map(usize::from);
        let mut points = [Vec::new(), Vec::new()];
        for (point, outer) in points
            .iter_mut()
            .zip([&expected.point[h..h + a], &expected.point[h + a..h + a + c]])
        {
            reserve(point, add(outer.len(), context.rounds)?)?;
            point.extend_from_slice(outer);
        }
        t.absorb(AbsorbLabel::MatmulStatement, &context.frame)
            .map_err(Error::Transcript)?;
        let (reduction, _) = prepared
            .verify_reduction(t, &proof)
            .map_err(|failure| stacked_error(failure.cause))?;
        for point in &mut points {
            point.extend_from_slice(&reduction.point);
        }
        // The fixed A4 instance has exactly X,W plus its independently consumed coefficient.
        let values = [reduction.claims[0].1, reduction.claims[1].1];
        let mut consume = |index: usize| {
            let result = stele_pcs::verify_point(
                t,
                certificates[index],
                expected.inputs[index],
                &points[index],
                values[index],
                openings[index],
            );
            let usage = match &result {
                Ok((_, usage)) => usage,
                Err(failure) => &failure.usage,
            };
            // Context checked both maximum path counts before replay, including failing prefixes.
            hashes += usage.non_transcript.hash_evaluations;
            debug_assert!(hashes <= context.maximum_hashes);
            result
                .map(|(record, _)| record)
                .map_err(|failure| pcs_error(failure.cause))
        };
        let openings = [consume(0)?, consume(1)?];
        Ok(Record {
            sc: reduction.sc,
            openings,
            points,
            values,
        })
    })();
    let usage = Usage {
        transcript: t.usage(),
        non_transcript: HashUsage {
            hash_evaluations: hashes,
            ..HashUsage::default()
        },
    };
    result
        .map(|record| (record, usage))
        .map_err(|cause| Failure { cause, usage })
}

impl<'a, K: ChallengeField> Context<'a, K> {
    fn new(
        s: &'a Statement<'a, K>,
        certificates: [&VerifiedCertificate<K>; 2],
        mut limits: stacked::Limits,
    ) -> Result<Self, Error> {
        let [h, a, b, c] = s.bits.map(usize::from);
        let ids = [s.inputs[0], s.inputs[1], s.output_id, s.coefficient_id];
        // RFC-0010 A9 allows ell<=30 and m<=29; A4 bounds the output layout by 63.
        // These bounded u8 sums fit usize before any shift or allocation.
        if a > 30
            || c > 30
            || h + b > 29
            || h + a + c > 63
            || s.point.len() != h + a + c
            || ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id))
        {
            return Err(Error::InvalidMatmul);
        }
        let width = mul(4, K::DEGREE)?;
        let frame_size = add(304, mul(width, add(s.point.len(), 1)?)?)?;
        limits.descriptor_bytes = limits
            .descriptor_bytes
            .checked_sub(frame_size)
            .ok_or(Error::Capacity)?;
        limits.proof_bytes = limits.proof_bytes.checked_sub(1).ok_or(Error::Capacity)?;
        let mut opening_sizes = [0; 2];
        let mut maximum_hashes = 0u64;
        for (index, (certificate, row_bits)) in certificates.iter().zip([a, c]).enumerate() {
            let source = certificate.record().source();
            if source.descriptor().id != s.inputs[index]
                || source.rows() != 1usize << row_bits
                || source.columns() != 1usize << (h + b)
            {
                return Err(Error::SourceRoster);
            }
            limits.descriptor_bytes = limits
                .descriptor_bytes
                .checked_sub(source.opening_frame_size().map_err(pcs_error)?)
                .ok_or(Error::Capacity)?;
            opening_sizes[index] = source.proof_size(ProofKind::Opening).map_err(pcs_error)?;
            limits.proof_bytes = limits
                .proof_bytes
                .checked_sub(opening_sizes[index])
                .ok_or(Error::Capacity)?;
            let height = u64::try_from(source.path_height()).map_err(|_| Error::Capacity)?;
            let hashes = u64::from(source.queries(ProofKind::Opening))
                .checked_mul(height.checked_add(1).ok_or(Error::Capacity)?)
                .ok_or(Error::Capacity)?;
            maximum_hashes = maximum_hashes.checked_add(hashes).ok_or(Error::Capacity)?;
        }
        let rounds = h + b;
        let wire_size = add(
            add(1, mul(width, add(mul(4, rounds)?, 3)?)?)?,
            add(opening_sizes[0], opening_sizes[1])?,
        )?;
        let axis = |bits: u8| Axis {
            bits,
            real: 1u64 << bits,
        };
        let mut factors = Vec::new();
        reserve(&mut factors, 2)?;
        factors.extend_from_slice(&[0, 1]);
        let mut frame = Vec::new();
        reserve(&mut frame, frame_size)?;
        frame.extend_from_slice(&[1, K::DEGREE as u8]);
        for id in [s.id, s.output_id, s.coefficient_id] {
            frame.extend_from_slice(&id.to_le_bytes());
        }
        frame.extend_from_slice(&s.bits);
        for value in s.point.iter().chain(core::iter::once(&s.value)) {
            frame.extend_from_slice(value.to_le_bytes().as_ref());
        }
        for certificate in certificates {
            frame.extend_from_slice(&certificate.record().source().bytes());
            frame.extend_from_slice(&certificate.record().id());
        }
        Ok(Self {
            expected: s,
            axes: [axis(s.bits[0]), axis(s.bits[2])],
            output_axes: [axis(s.bits[0]), axis(s.bits[1]), axis(s.bits[3])],
            selectors: [Some(&s.point[..h]), None],
            terms: [Term {
                coefficient: K::from_i64(1),
                factors,
            }],
            frame,
            limits,
            opening_sizes,
            rounds,
            wire_size,
            maximum_hashes,
        })
    }

    fn statement(&self) -> stacked::Statement<'_, K> {
        let s = self.expected;
        stacked::Statement {
            id: s.id,
            axes: &self.axes,
            order: stacked::Order::LayerFirst,
            output: stacked::Claim {
                id: s.output_id,
                axes: &self.output_axes,
                point: s.point,
                value: s.value,
            },
            coefficient_id: s.coefficient_id,
            inputs: &s.inputs,
            terms: &self.terms,
            selectors: &self.selectors,
            kind: Kind::Eq,
            source_id: None,
        }
    }

    fn parse<'wire>(
        &self,
        certificates: [&VerifiedCertificate<K>; 2],
        bytes: &'wire [u8],
    ) -> Result<(Proof<K>, [&'wire [u8]; 2]), Error>
    where
        for<'b> K::Bytes: TryFrom<&'b [u8]>,
    {
        if bytes.len() != self.wire_size || bytes.first() != Some(&1) {
            return Err(Error::ProofShape);
        }
        let width = mul(4, K::DEGREE)?;
        let round_end = add(1, mul(mul(self.rounds, 4)?, width)?)?;
        let first = add(round_end, mul(3, width)?)?;
        let second = add(first, self.opening_sizes[0])?;
        let openings = [&bytes[first..second], &bytes[second..]];
        let decode = |raw: &[u8]| -> Result<Vec<K>, Error> {
            let mut values = Vec::new();
            reserve(&mut values, raw.len() / width)?;
            for field in raw.chunks_exact(width) {
                values.push(
                    K::from_le_bytes(
                        K::Bytes::try_from(field).map_err(|_| Error::NoncanonicalField)?,
                    )
                    .ok_or(Error::NoncanonicalField)?,
                );
            }
            Ok(values)
        };
        let mut rounds = Vec::new();
        reserve(&mut rounds, self.rounds)?;
        for row in bytes[1..round_end].chunks_exact(mul(4, width)?) {
            rounds.push(decode(row)?);
        }
        let final_values = decode(&bytes[round_end..first])?;
        // Both A9 row encodings are preflighted before any outer/A4 transcript operation.
        for (certificate, wire) in certificates.iter().zip(openings) {
            certificate
                .record()
                .source()
                .parse(ProofKind::Opening, wire)
                .map_err(pcs_error)?;
        }
        Ok((
            Proof {
                rounds,
                final_values,
            },
            openings,
        ))
    }
}
