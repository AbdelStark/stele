//! RFC-0024 §§2.3,4–5: actual consumers and conditional point-equality accounting.
use super::{buffer, matmul_error, ByteRange, Descriptor, Error};
use crate::{lookup, matmul, requant};
use alloc::vec::Vec;
use requant::arithmetic::{add_local, arithmetic, copied};
use stele_hash::{certificate_id, AbsorbLabel, ChallengeField, HashUsage, LossLine, Transcript};
use stele_pcs::{CodeField, Usage, VerifiedCertificate};
use stele_sumcheck::zerocheck;

/// Abort the whole attempt, retaining only actual consumed-prefix work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Actual outer or child cause.
    pub cause: Error,
    /// One cumulative transcript plus disjoint local hash work.
    pub usage: Usage,
}
/// Failed separate mu import; no partial handles escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationFailure {
    /// Actual admission or A9 import cause.
    pub cause: Error,
    /// Ordered attempts, including the failed attempt.
    pub registrations: [Option<Usage>; 2],
}
/// Conditional SZ event from the actual A3 tail, including its scalar zero record.
/// No additional sumcheck, independent-weight RLC or Fiat–Shamir theorem is claimed.
pub struct PointEqualityRecord<K> {
    stage: u32,
    aggregate_id: u64,
    point: Vec<K>,
}
impl<K: ChallengeField> PointEqualityRecord<K> {
    /// Expected enclosing operation identity.
    pub fn stage(&self) -> u32 {
        self.stage
    }
    /// Actual point origin is the skip-zero tail of this aggregate A3 id.
    pub fn aggregate_id(&self) -> u64 {
        self.aggregate_id
    }
    /// Actual retained q, unchanged through the signed matmul consumer.
    pub fn point(&self) -> &[K] {
        &self.point
    }
    /// Explicit accounting family, separate from all child SC and RLC records.
    pub fn family(&self) -> LossLine {
        LossLine::Sz
    }
    /// Individual-degree-one equality has total degree m; zero when m=0.
    pub fn numerator(&self) -> u64 {
        self.point.len() as u64
    }
    /// Actual field extension degree.
    pub fn field_degree(&self) -> u8 {
        K::DEGREE as u8
    }
}
/// Complete conditional operation; every original range and certificate owner survives.
/// This supplies no configured model, privacy or profile admission.
/// No digest can construct this record:
/// ```compile_fail,E0599
/// use stele_field::QM31;
/// let fake = stele_reductions::integer_linear::Record::<QM31>::from_digest([0;32]);
/// ```
/// A completed original range event itself must outlive the returned record:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_gkr::stacked;
/// use stele_reductions::{byte_range::ByteRange, integer_linear::*, lookup};
/// fn escape(s:Statement<'_,'static,QM31>, x:ByteRange<'static,QM31>,
///     a:&'static VerifiedCertificate<QM31>, mu:&[&'static VerifiedCertificate<QM31>],
///     t:&mut Transcript<QM31>, proof:&[u8], l:lookup::Limits, m:stacked::Limits)
///     ->Record<'static,QM31> {
///     Descriptor::new(Statement{originals:[&x,s.originals[1]],..s},a,l,m)
///         .unwrap().verify(t,mu,proof).unwrap().0
/// }
/// ```
/// W's completed range event independently owns the result's lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_gkr::stacked;
/// use stele_reductions::{byte_range::ByteRange, integer_linear::*, lookup};
/// fn escape(s:Statement<'_,'static,QM31>, w:ByteRange<'static,QM31>,
///     a:&'static VerifiedCertificate<QM31>, mu:&[&'static VerifiedCertificate<QM31>],
///     t:&mut Transcript<QM31>, proof:&[u8], l:lookup::Limits, m:stacked::Limits)
///     ->Record<'static,QM31> {
///     Descriptor::new(Statement{originals:[s.originals[0],&w],..s},a,l,m)
///         .unwrap().verify(t,mu,proof).unwrap().0
/// }
/// ```
/// The genuine advice owner remains borrowed after the descriptor is gone:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_gkr::stacked;
/// use stele_reductions::{integer_linear::*, lookup};
/// fn escape(s:Statement<'_,'static,QM31>, a:VerifiedCertificate<QM31>,
///     mu:&[&'static VerifiedCertificate<QM31>], t:&mut Transcript<QM31>,
///     proof:&[u8], l:lookup::Limits, m:stacked::Limits)->Record<'static,QM31> {
///     Descriptor::new(s,&a,l,m).unwrap().verify(t,mu,proof).unwrap().0
/// }
/// ```
/// Every advice-mu owner independently constrains the result's lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::integer_linear::*;
/// fn escape(d:&Descriptor<'_,'static,QM31>, mu:VerifiedCertificate<QM31>,
///     t:&mut Transcript<QM31>, proof:&[u8])->Record<'static,QM31> {
///     d.verify(t,&[&mu],proof).unwrap().0
/// }
/// ```
#[must_use = "retain actual source/range, arithmetic, SZ, RLC and all opening obligations"]
pub struct Record<'cert, K: ChallengeField> {
    originals: [&'cert ByteRange<'cert, K>; 2],
    lookup: lookup::LookupRecord<'cert, K>,
    zero: zerocheck::Reduction<K>,
    output: stele_sumcheck::Reduction<K>,
    groups: [requant::GroupRecord<'cert, K>; 3],
    rlc: [requant::RlcRecord<K>; 4],
    equality: PointEqualityRecord<K>,
    matmul: matmul::Record<'cert, K>,
}
impl<'cert, K: ChallengeField> Record<'cert, K> {
    /// Exact original X,W range events, without copying or deduplication.
    pub fn originals(&self) -> [&'cert ByteRange<'cert, K>; 2] {
        self.originals
    }
    /// Actual whole-advice A5 and every mu/certificate obligation.
    pub fn lookup(&self) -> &lookup::LookupRecord<'cert, K> {
        &self.lookup
    }
    /// Actual aggregate A3 with all three SC records and complete original finals.
    pub fn zerocheck(&self) -> &zerocheck::Reduction<K> {
        &self.zero
    }
    /// Actual output A1, whose public coefficient and advice finals were consumed.
    pub fn output(&self) -> &stele_sumcheck::Reduction<K> {
        &self.output
    }
    /// Independent ordered groups 0,1,2, all opened against the genuine advice owner.
    pub fn groups(&self) -> &[requant::GroupRecord<'cert, K>; 3] {
        &self.groups
    }
    /// Constraint weights and three distinct group-weight losses.
    pub fn rlc(&self) -> &[requant::RlcRecord<K>; 4] {
        &self.rlc
    }
    /// Actual-tail equality event, including its scalar zero numerator.
    pub fn point_equality(&self) -> &PointEqualityRecord<K> {
        &self.equality
    }
    /// Actual signed A4/A1/A7 and both raw original A9 openings.
    pub fn matmul(&self) -> &matmul::Record<'cert, K> {
        &self.matmul
    }
}

impl<'a, 'original, K: ChallengeField + CodeField + lookup::TableField + Eq>
    Descriptor<'a, 'original, K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    /// Import the one advice A5 roster through its complete genuine A9 helper.
    #[allow(clippy::result_large_err)]
    pub fn register_multiplicities(
        &self,
        proof: &[u8],
        max_public_bytes: usize,
    ) -> Result<lookup::RegisteredMultiplicities<K>, RegistrationFailure> {
        let mut registrations = [None; 2];
        let result = (|| {
            let wire = self.wire(proof)?;
            match self
                .lookup()?
                .register_multiplicities(wire.parts[1], max_public_bytes)
            {
                Ok((owners, usage)) => {
                    registrations = usage;
                    Ok(owners)
                }
                Err(f) => {
                    registrations = f.registrations;
                    Err(Error::Lookup(f.cause))
                }
            }
        })();
        result
            .map(|owners| (owners, registrations))
            .map_err(|cause| RegistrationFailure {
                cause,
                registrations,
            })
    }
    /// Close the complete expected operation; every error aborts without a record.
    pub fn verify<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: &[&'cert VerifiedCertificate<K>],
        proof: &[u8],
    ) -> Result<(Record<'cert, K>, Usage), Failure>
    where
        'original: 'cert,
    {
        let mut hashes = HashUsage::default();
        let result = self.verify_inner(t, multiplicities, proof, &mut hashes);
        let usage = Usage {
            transcript: t.usage(),
            non_transcript: hashes,
        };
        result
            .map(|record| (record, usage))
            .map_err(|cause| Failure { cause, usage })
    }
    fn verify_inner<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: &[&'cert VerifiedCertificate<K>],
        proof: &[u8],
        hashes: &mut HashUsage,
    ) -> Result<Record<'cert, K>, Error>
    where
        'original: 'cert,
    {
        let wire = self.wire(proof)?;
        let s = self.statement;
        let advice = self.advice[0];
        if wire.root != advice.record().source().root()
            || multiplicities.len() != usize::from(s.repetitions)
        {
            return Err(Error::CertificateContext);
        }
        if certificate_id(&advice.record().source().bytes(), wire.parts[0], hashes)
            .map_err(Error::Transcript)?
            != advice.record().id()
        {
            return Err(Error::CertificateIdentity);
        }
        t.absorb(AbsorbLabel::LinearStatement, &self.encode()?)
            .map_err(Error::Transcript)?;
        let result = self.lookup()?.verify(t, multiplicities, wire.parts[1]);
        add_local(
            hashes,
            match &result {
                Ok((_, u)) => *u,
                Err(f) => f.usage,
            },
        )?;
        let lookup = result.map_err(|f| Error::Lookup(f.cause))?.0;
        t.absorb(AbsorbLabel::RequantConstraints, &self.encode_constraints()?)
            .map_err(Error::Transcript)?;
        let common = self.arithmetic();
        let rlc0 = common.weights(t, 0, self.constraints.equations().len())?;
        let aggregate = common.aggregate(rlc0.weights())?;
        let packet = arithmetic(wire.parts[2], self.m, self.ids.len())?;
        let zero = zerocheck::Zerocheck {
            instance: &aggregate,
            skip: 0,
        }
        .verify(
            &zerocheck::Proof {
                skip_values: Vec::new(),
                rounds: packet.rounds,
                final_values: packet.final_values,
            },
            t,
        )
        .map_err(Error::Sumcheck)?;
        drop(aggregate);
        let first = zero.claims.first().ok_or(Error::ArithmeticRoster)?;
        if zero.claims.len() != self.ids.len()
            || first.point.len() != usize::from(self.m)
            || zero
                .claims
                .iter()
                .zip(&self.ids)
                .any(|(claim, id)| claim.tensor != *id || claim.point != first.point)
        {
            return Err(Error::ArithmeticRoster);
        }
        common.coefficient(&first.point, self.n as u64, None, first.value)?;
        let mut input = buffer(4)?;
        for (row, claim) in zero.claims[1..5].iter().enumerate() {
            input.push((row as u32, claim.tensor, claim.value));
        }
        let (g0, rlc1, _) = common.group(t, 0, &first.point, input, wire.parts[3], hashes)?;
        let mut claims = buffer(self.schema.rows() - 4)?;
        for (row, claim) in zero.claims[5..].iter().enumerate() {
            claims.push(((row + 4) as u32, claim.tensor, claim.value));
        }
        let (g1, rlc2, _) = common.group(t, 1, &first.point, claims, wire.parts[4], hashes)?;
        // RFC-0024 §2.2: derive C from the four actually consumed U finals only.
        let point = copied(g0.point())?;
        let mut value = K::from_i64(-(1i64 << 31));
        let mut power = K::from_i64(1);
        for (_, _, v) in g0.claims() {
            value = value + power * *v;
            power = power * K::from_i64(256);
        }
        let packet = arithmetic(wire.parts[5], self.m, self.output.inputs.len())?;
        let output = stele_sumcheck::verify(&self.output, &packet, t).map_err(Error::Sumcheck)?;
        if output.point.len() != usize::from(self.m)
            || output.claims.len() != self.output.inputs.len()
            || output
                .claims
                .iter()
                .zip(&self.output.inputs)
                .any(|((id, _), expected)| id != expected)
        {
            return Err(Error::ArithmeticRoster);
        }
        common.coefficient(
            &output.point,
            self.n as u64,
            Some(s.point),
            output.claims[0].1,
        )?;
        let mut claims = buffer(output.claims.len() - 1)?;
        for (row, (id, v)) in core::iter::once(0)
            .chain(self.schema.semantic().values()[2].value())
            .zip(&output.claims[1..])
        {
            claims.push(((row + 4) as u32, *id, *v));
        }
        let (g2, rlc3, _) = common.group(t, 2, &output.point, claims, wire.parts[6], hashes)?;
        let expected = matmul::Statement {
            id: self.base + (1 << 22),
            output_id: self.base + (1 << 21),
            coefficient_id: self.base + (1 << 28) + 2,
            inputs: s
                .originals
                .map(|r| r.original().record().source().descriptor().id),
            bits: s.bits,
            point: &point,
            value,
        };
        let result = matmul::centered::verify_measured(
            t,
            &expected,
            s.originals.map(ByteRange::original),
            wire.parts[7],
            self.matmul_limits,
        );
        add_local(
            hashes,
            match &result {
                Ok((_, u, _)) => *u,
                Err(f) => f.usage,
            },
        )?;
        let matmul = result.map_err(|f| matmul_error(f.cause))?.0;
        Ok(Record {
            originals: s.originals,
            lookup,
            zero,
            output,
            groups: [g0, g1, g2],
            rlc: [rlc0, rlc1, rlc2, rlc3],
            equality: PointEqualityRecord {
                stage: s.stage,
                aggregate_id: self.base + 1024,
                point,
            },
            matmul,
        })
    }
}
