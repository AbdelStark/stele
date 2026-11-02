//! RFC-0023 §§2.4,4–5: complete integer Requant closure through actual A5/A3/A7/A9/A1.
//! T_misc is O(N+E+P+J+m), plus child costs. No partial record grants acceptance.
use super::{addressable, buffer, mul, put, sum, take, term, Descriptor, Error, Schema};
use crate::lookup::{LookupRecord, TableField};
use alloc::vec::Vec;
use stele_gkr::public_mle::{Axis, Coefficient, Kind};
use stele_hash::{
    certificate_id, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript,
};
use stele_pcs::{
    verify_certificate, verify_opening, CodeField, Functional, OpeningRecord, ProofKind, Usage,
    VerifiedCertificate,
};
use stele_sumcheck::{zerocheck, Instance};

/// Failed enclosing attempt, with cumulative transcript and disjoint local H.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Actual rejecting consumer or fixed outer contract condition.
    pub cause: Error,
    /// Consumed prefix; standalone certificate imports are separate.
    pub usage: Usage,
}
/// Failed standalone import; no partial multiplicity roster escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationFailure {
    /// Actual admission, preflight or certificate rejection.
    pub cause: Error,
    /// Input then advice, each in repetition order, including the failed attempt.
    pub registrations: [[Option<Usage>; 2]; 2],
}
// Shared fixed group construction; no public caller can supply a functional.
pub(super) struct GroupWeights<K> {
    pub(super) a: Vec<K>,
    pub(super) b: Vec<K>,
    pub(super) value: K,
    pub(super) rlc: RlcRecord<K>,
}
impl<K> GroupWeights<K> {
    pub(super) fn owned_field_bytes(&self) -> Result<[usize; 3], Error> {
        let w = core::mem::size_of::<K>();
        Ok([
            mul(self.a.capacity(), w)?,
            mul(self.b.capacity(), w)?,
            mul(self.rlc.weights.capacity(), w)?,
        ])
    }
}
/// Scoped actual simultaneous group coefficient capacities, never proof authority.
/// All other verifier allocations are excluded; complete process RSS is separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifierWork {
    /// Ordered groups, each actual a, b and independent-weight Vec capacity in bytes.
    pub group_coefficients_bytes: [[usize; 3]; 3],
}
// Actual closed group, independent RLC obligation, and scoped field capacities.
type GroupResult<'cert, K> = (GroupRecord<'cert, K>, RlcRecord<K>, [usize; 3]);
/// Caller-owned handles and separate attempted-import Usage, in fixed group order.
pub type RegisteredMultiplicities<K> = ([Vec<VerifiedCertificate<K>>; 2], [[Option<Usage>; 2]; 2]);

/// Independent-vector RLC obligation, distinct from A2 powers-of-one-gamma.
pub struct RlcRecord<K> {
    stage: u32,
    phase: u8,
    weights: Vec<K>,
}
impl<K: ChallengeField> RlcRecord<K> {
    /// Expected operation identity.
    pub fn stage(&self) -> u32 {
        self.stage
    }
    /// Constraint, input A3, advice A3, output advice: phases 0..3.
    pub fn phase(&self) -> u8 {
        self.phase
    }
    /// Actual independent draws, retaining zeros and their original order.
    pub fn weights(&self) -> &[K] {
        &self.weights
    }
    /// Actual field extension degree.
    pub fn field_degree(&self) -> u8 {
        K::DEGREE as u8
    }
    /// Conditional interactive loss is one over |K| for this fixed vector.
    pub fn numerator(&self) -> u64 {
        1
    }
}
/// Complete ordered source claim group, consumed by one genuine A9 opening.
pub struct GroupRecord<'cert, K: ChallengeField> {
    point: Vec<K>,
    claims: Vec<(u32, u64, K)>,
    opening: OpeningRecord<'cert, K>,
}
impl<K: ChallengeField> GroupRecord<'_, K> {
    /// Actual arithmetic position point, including an empty scalar point.
    pub fn point(&self) -> &[K] {
        &self.point
    }
    /// Fixed physical row, tensor id and value, including every zero claim.
    pub fn claims(&self) -> &[(u32, u64, K)] {
        &self.claims
    }
    /// Actual A9 obligation retaining its original certificate owner.
    pub fn opening(&self) -> &OpeningRecord<'_, K> {
        &self.opening
    }
}
/// Conditional closed integer record, retaining every actual child obligation.
/// No plan, matmul bridge, privacy or profile acceptance follows.
/// ```compile_fail,E0599
/// use stele_field::QM31;
/// let fake = stele_reductions::requant::Record::<QM31>::from_digest([0;32]);
/// ```
/// The expected input certificate owns the returned record's lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor,Statement,Limits,Record};
/// fn escape(s:Statement<'_,'static,QM31>, input:VerifiedCertificate<QM31>,
///     advice:&'static VerifiedCertificate<QM31>, mu:[&[&'static VerifiedCertificate<QM31>];2],
///     t:&mut Transcript<QM31>, proof:&[u8], limits:Limits) -> Record<'static,QM31> {
///     Descriptor::new(Statement{input:&input,..s},advice,limits).unwrap()
///         .verify(t,mu,proof).unwrap().0
/// }
/// ```
/// The advice certificate remains borrowed after the descriptor is dropped:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor,Statement,Limits,Record};
/// fn escape(s:Statement<'_,'static,QM31>, advice:VerifiedCertificate<QM31>,
///     mu:[&[&'static VerifiedCertificate<QM31>];2], t:&mut Transcript<QM31>,
///     proof:&[u8], limits:Limits) -> Record<'static,QM31> {
///     Descriptor::new(s,&advice,limits).unwrap().verify(t,mu,proof).unwrap().0
/// }
/// ```
/// Input multiplicity owners cannot be local to a returning call:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor,Record};
/// fn escape(d:&Descriptor<'_,'static,QM31>, mu:VerifiedCertificate<QM31>,
///     advice_mu:&[&'static VerifiedCertificate<QM31>], t:&mut Transcript<QM31>,
///     proof:&[u8]) -> Record<'static,QM31> {
///     d.verify(t,[&[&mu],advice_mu],proof).unwrap().0
/// }
/// ```
/// Advice multiplicity owners independently constrain that lifetime:
/// ```compile_fail,E0515
/// use stele_field::QM31;
/// use stele_hash::Transcript;
/// use stele_pcs::VerifiedCertificate;
/// use stele_reductions::requant::{Descriptor,Record};
/// fn escape(d:&Descriptor<'_,'static,QM31>, mu:VerifiedCertificate<QM31>,
///     input_mu:&[&'static VerifiedCertificate<QM31>], t:&mut Transcript<QM31>,
///     proof:&[u8]) -> Record<'static,QM31> {
///     d.verify(t,[input_mu,&[&mu]],proof).unwrap().0
/// }
/// ```
#[must_use = "retain all arithmetic, lookup, RLC and genuine certificate obligations"]
pub struct Record<'cert, K: ChallengeField> {
    lookups: [LookupRecord<'cert, K>; 2],
    zero: zerocheck::Reduction<K>,
    output: stele_sumcheck::Reduction<K>,
    groups: [GroupRecord<'cert, K>; 3],
    rlc: [RlcRecord<K>; 4],
}
impl<K: ChallengeField> Record<'_, K> {
    /// Actual input and advice range consumers, with all repetitions and openings.
    pub fn lookups(&self) -> &[LookupRecord<'_, K>; 2] {
        &self.lookups
    }
    /// Actual aggregate A3, including all claims and three separate SC records.
    pub fn zerocheck(&self) -> &zerocheck::Reduction<K> {
        &self.zero
    }
    /// Actual output A1, including all claims and its SC record.
    pub fn output(&self) -> &stele_sumcheck::Reduction<K> {
        &self.output
    }
    /// Input A3, advice A3 and output advice groups in order.
    pub fn groups(&self) -> &[GroupRecord<'_, K>; 3] {
        &self.groups
    }
    /// Four distinct independent-weight losses; no A2 execution is claimed.
    pub fn rlc(&self) -> &[RlcRecord<K>; 4] {
        &self.rlc
    }
}

impl Schema {
    /// Derive the fixed advice context and invoke actual A9 registration.
    /// The standalone cap counts constructor, row and response payloads once.
    /// Registration alone authenticates no Requant arithmetic or range claim.
    #[allow(clippy::too_many_arguments)]
    pub fn register_advice<K: ChallengeField + CodeField>(
        &self,
        stage: u32,
        n: u64,
        blowup: u8,
        root: [u8; 32],
        proof: &[u8],
        max_public_bytes: usize,
    ) -> Result<(VerifiedCertificate<K>, Usage), Failure>
    where
        for<'b> K::Bytes: TryFrom<&'b [u8]>,
    {
        let source = (|| {
            let source = self.advice_source::<K>(stage, n, blowup, root)?;
            let bytes = source
                .proof_size(ProofKind::Certificate)
                .map_err(Error::Pcs)?;
            if sum(&[
                b"stele/v0.1/pcs-certificate/public".len(),
                105,
                bytes.checked_sub(1).ok_or(Error::Capacity)?,
            ])? > max_public_bytes
            {
                return Err(Error::ResourceLimit);
            }
            addressable::<u8>(bytes)?;
            for count in [
                source.rows(),
                source.columns(),
                source.code().codeword_len(),
            ] {
                addressable::<K>(count)?;
            }
            source
                .parse(ProofKind::Certificate, proof)
                .map_err(Error::Pcs)?;
            Ok(source)
        })()
        .map_err(|cause| Failure {
            cause,
            usage: Usage::default(),
        })?;
        verify_certificate(source, proof).map_err(|f| Failure {
            cause: Error::Pcs(f.cause),
            usage: f.usage,
        })
    }
}

fn add_local(hashes: &mut HashUsage, usage: Usage) -> Result<(), Error> {
    // RFC-0023 §2.4: Descriptor bounds every prefix before work. Children use
    // only ordinary H locally; their cumulative transcript snapshots are NOT summed.
    hashes.hash_evaluations = hashes
        .hash_evaluations
        .checked_add(usage.non_transcript.hash_evaluations)
        .ok_or(Error::Capacity)?;
    Ok(())
}
fn copied<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = buffer(values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
fn arithmetic<K: ChallengeField>(
    raw: &[u8],
    m: u8,
    count: usize,
) -> Result<stele_sumcheck::Proof<K>, Error>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    fn values<K: ChallengeField>(bytes: &[u8]) -> Result<Vec<K>, Error>
    where
        for<'b> K::Bytes: TryFrom<&'b [u8]>,
    {
        let mut out = buffer(bytes.len() / (4 * K::DEGREE))?;
        for word in bytes.chunks_exact(4 * K::DEGREE) {
            out.push(
                K::from_le_bytes(K::Bytes::try_from(word).map_err(|_| Error::NoncanonicalField)?)
                    .ok_or(Error::NoncanonicalField)?,
            );
        }
        Ok(out)
    }
    let mut rest = raw;
    let mut rounds = buffer(usize::from(m))?;
    for _ in 0..m {
        rounds.push(values(take(&mut rest, 16 * K::DEGREE)?)?);
    }
    let final_values = values(take(&mut rest, mul(count, 4 * K::DEGREE)?)?)?;
    if !rest.is_empty() {
        return Err(Error::ProofShape);
    }
    Ok(stele_sumcheck::Proof {
        rounds,
        final_values,
    })
}

impl<'a, 'original, K: ChallengeField + CodeField + TableField + Eq> Descriptor<'a, 'original, K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    /// Register both actual A5 multiplicity rosters under one standalone import cap.
    /// A failure drops all partial handles but retains every attempted import Usage.
    #[allow(clippy::result_large_err)]
    pub fn register_multiplicities(
        &self,
        proof: &[u8],
        max_public_bytes: usize,
    ) -> Result<RegisteredMultiplicities<K>, RegistrationFailure> {
        let mut registrations = [[None; 2]; 2];
        let result = (|| {
            let wire = self.wire(proof)?;
            let descriptors = [self.lookup(0)?, self.lookup(1)?];
            let budgets = [
                descriptors[0].registration_bytes().map_err(Error::Lookup)?,
                descriptors[1].registration_bytes().map_err(Error::Lookup)?,
            ];
            if sum(&budgets)? > max_public_bytes {
                return Err(Error::ResourceLimit);
            }
            let mut handles = [Vec::new(), Vec::new()];
            for b in 0..2 {
                match descriptors[b].register_multiplicities(wire.parts[1 + b], budgets[b]) {
                    Ok((roster, usage)) => {
                        handles[b] = roster;
                        registrations[b] = usage;
                    }
                    Err(f) => {
                        registrations[b] = f.registrations;
                        return Err(Error::Lookup(f.cause));
                    }
                }
            }
            Ok(handles)
        })();
        result
            .map(|handles| (handles, registrations))
            .map_err(|cause| RegistrationFailure {
                cause,
                registrations,
            })
    }
    /// Execute the entire closed protocol. Every source owner outlives the result;
    /// this descriptor, proof, statement and temporary reference arrays need not.
    pub fn verify<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: [&[&'cert VerifiedCertificate<K>]; 2],
        proof: &[u8],
    ) -> Result<(Record<'cert, K>, Usage), Failure>
    where
        'original: 'cert,
    {
        self.verify_measured(t, multiplicities, proof)
            .map(|(record, usage, _)| (record, usage))
    }
    /// The same closed verifier with only the scoped capacity observations in VerifierWork.
    pub fn verify_measured<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: [&[&'cert VerifiedCertificate<K>]; 2],
        proof: &[u8],
    ) -> Result<(Record<'cert, K>, Usage, VerifierWork), Failure>
    where
        'original: 'cert,
    {
        let mut hashes = HashUsage::default();
        let mut work = VerifierWork::default();
        let result = self.verify_inner(t, multiplicities, proof, &mut hashes, &mut work);
        let usage = Usage {
            transcript: t.usage(),
            non_transcript: hashes,
        };
        result
            .map(|record| (record, usage, work))
            .map_err(|cause| Failure { cause, usage })
    }
    pub(super) fn weights(
        &self,
        t: &mut Transcript<K>,
        phase: u8,
        count: usize,
    ) -> Result<RlcRecord<K>, Error> {
        let mut weights = buffer(count)?;
        for _ in 0..count {
            weights.push(
                t.challenge(ChallengeLabel::RequantWeight)
                    .map_err(Error::Transcript)?,
            );
        }
        Ok(RlcRecord {
            stage: self.statement.stage,
            phase,
            weights,
        })
    }
    pub(super) fn aggregate(&self, weights: &[K]) -> Result<Instance<K>, Error> {
        let count = self
            .constraints
            .equations()
            .iter()
            .try_fold(0, |n, eq| sum(&[n, eq.len()]))?;
        let mut terms = buffer(count)?;
        for (equation, weight) in self.constraints.equations().iter().zip(weights) {
            for original in equation {
                terms.push(term(original.coefficient * *weight, &original.factors)?);
            }
        }
        Ok(Instance {
            id: self.base + 1024,
            num_vars: u32::from(self.m),
            inputs: copied(&self.ids)?,
            terms,
            claimed_sum: K::from_i64(0),
        })
    }
    fn coefficient(
        &self,
        point: &[K],
        real: u64,
        selector: Option<&[K]>,
        value: K,
    ) -> Result<(), Error> {
        let axes = [Axis { bits: self.m, real }];
        let selectors = [selector];
        let expected = Coefficient::new(
            &axes,
            &selectors,
            Kind::Eq,
            self.originals[0][0].record().source().columns(),
        )
        .and_then(|c| c.evaluate(point))
        .map_err(Error::PublicCoefficient)?;
        if value != expected {
            return Err(Error::CoefficientMismatch);
        }
        Ok(())
    }
    fn group<'cert>(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: Vec<(u32, u64, K)>,
        proof: &[u8],
        hashes: &mut HashUsage,
    ) -> Result<GroupResult<'cert, K>, Error>
    where
        'original: 'cert,
    {
        let weights = self.group_weights(t, group, point, &claims)?;
        let capacities = weights.owned_field_bytes()?;
        let certificate = self.originals[usize::from(group != 0)][0];
        let result = verify_opening(
            t,
            certificate,
            Functional {
                id: self.base + 3072 + u64::from(group),
                a: &weights.a,
                b: &weights.b,
                value: weights.value,
            },
            proof,
        );
        add_local(
            hashes,
            match &result {
                Ok((_, u)) => *u,
                Err(f) => f.usage,
            },
        )?;
        let opening = result.map_err(|f| Error::Pcs(f.cause))?.0;
        Ok((
            GroupRecord {
                point: copied(point)?,
                claims,
                opening,
            },
            weights.rlc,
            capacities,
        ))
    }
    pub(super) fn group_weights(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: &[(u32, u64, K)],
    ) -> Result<GroupWeights<K>, Error> {
        let certificate = self.originals[usize::from(group != 0)][0];
        let source = certificate.record().source();
        let width = 4 * usize::from(<K as CodeField>::DEGREE);
        let size = sum(&[
            147,
            mul(point.len(), width)?,
            mul(claims.len(), 12 + width)?,
        ])?;
        let mut frame = buffer(size)?;
        put(&mut frame, &self.statement.stage.to_le_bytes())?;
        put(&mut frame, &[group])?;
        put(&mut frame, &source.bytes())?;
        put(&mut frame, &certificate.record().id())?;
        put(&mut frame, &(claims.len() as u32).to_le_bytes())?;
        put(&mut frame, &[self.m])?;
        for v in point {
            put(&mut frame, v.to_le_bytes().as_ref())?;
        }
        for (row, id, value) in claims {
            put(&mut frame, &row.to_le_bytes())?;
            put(&mut frame, &id.to_le_bytes())?;
            put(&mut frame, value.to_le_bytes().as_ref())?;
        }
        t.absorb(AbsorbLabel::RequantClaims, &frame)
            .map_err(Error::Transcript)?;
        drop(frame);
        let rlc = self.weights(t, group + 1, claims.len())?;
        let mut a = buffer(source.rows())?;
        a.resize(source.rows(), K::from_i64(0));
        let mut value = K::from_i64(0);
        for ((row, _, v), weight) in claims.iter().zip(&rlc.weights) {
            a[*row as usize] = *weight;
            value = value + *weight * *v;
        }
        let b = stele_poly::eq_table(point).map_err(|_| Error::Capacity)?;
        Ok(GroupWeights { a, b, value, rlc })
    }
    fn verify_inner<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: [&[&'cert VerifiedCertificate<K>]; 2],
        proof: &[u8],
        hashes: &mut HashUsage,
        work: &mut VerifierWork,
    ) -> Result<Record<'cert, K>, Error>
    where
        'original: 'cert,
    {
        let wire = self.wire(proof)?;
        let s = self.statement;
        let advice = self.originals[1][0];
        let source = s
            .schema
            .advice_source::<K>(s.stage, s.n, s.advice_blowup, wire.root)?;
        if source.bytes() != advice.record().source().bytes()
            || multiplicities
                .iter()
                .any(|r| r.len() != usize::from(s.repetitions))
        {
            return Err(Error::CertificateContext);
        }
        if certificate_id(&source.bytes(), wire.parts[0], hashes).map_err(Error::Transcript)?
            != advice.record().id()
        {
            return Err(Error::CertificateIdentity);
        }
        t.absorb(AbsorbLabel::RequantStatement, &self.encode()?)
            .map_err(Error::Transcript)?;
        let mut lookups = buffer(2)?;
        for (b, roster) in multiplicities.iter().enumerate() {
            // Each actual A5 owns mu context/id fixation at its own boundary.
            let result = self.lookup(b)?.verify(t, roster, wire.parts[1 + b]);
            add_local(
                hashes,
                match &result {
                    Ok((_, u)) => *u,
                    Err(f) => f.usage,
                },
            )?;
            lookups.push(result.map_err(|f| Error::Lookup(f.cause))?.0);
        }
        t.absorb(AbsorbLabel::RequantConstraints, &self.encode_constraints()?)
            .map_err(Error::Transcript)?;
        let rlc0 = self.weights(t, 0, self.constraints.equations().len())?;
        let aggregate = self.aggregate(&rlc0.weights)?;
        let packet = arithmetic(wire.parts[3], self.m, self.ids.len())?;
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
        self.coefficient(&first.point, s.n, None, first.value)?;
        let mut input = buffer(4)?;
        for (row, claim) in zero.claims[1..5].iter().enumerate() {
            input.push((row as u32, claim.tensor, claim.value));
        }
        let (g0, rlc1, capacities) =
            self.group(t, 0, &first.point, input, wire.parts[4], hashes)?;
        work.group_coefficients_bytes[0] = capacities;
        let mut advice_claims = buffer(s.schema.rows())?;
        for (row, claim) in zero.claims[5..].iter().enumerate() {
            advice_claims.push((row as u32, claim.tensor, claim.value));
        }
        let (g1, rlc2, capacities) =
            self.group(t, 1, &first.point, advice_claims, wire.parts[5], hashes)?;
        work.group_coefficients_bytes[1] = capacities;
        let packet = arithmetic(wire.parts[6], self.m, self.output.inputs.len())?;
        let output = stele_sumcheck::verify(&self.output, &packet, t).map_err(Error::Sumcheck)?;
        if output.claims.len() != self.output.inputs.len()
            || output.point.len() != usize::from(self.m)
            || output
                .claims
                .iter()
                .zip(&self.output.inputs)
                .any(|((id, _), expected)| id != expected)
        {
            return Err(Error::ArithmeticRoster);
        }
        self.coefficient(
            &output.point,
            1u64 << self.m,
            Some(s.point),
            output.claims[0].1,
        )?;
        let mut claims = buffer(output.claims.len() - 1)?;
        for (row, (id, value)) in core::iter::once(0)
            .chain(s.schema.values()[2].value())
            .zip(&output.claims[1..])
        {
            claims.push((row as u32, *id, *value));
        }
        let (g2, rlc3, capacities) =
            self.group(t, 2, &output.point, claims, wire.parts[7], hashes)?;
        work.group_coefficients_bytes[2] = capacities;
        Ok(Record {
            lookups: lookups.try_into().map_err(|_| Error::ArithmeticRoster)?,
            zero,
            output,
            groups: [g0, g1, g2],
            rlc: [rlc0, rlc1, rlc2, rlc3],
        })
    }
}
