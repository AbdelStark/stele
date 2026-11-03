//! RFC-0023 §§2.2-2.4 and RFC-0024 §2.2: shared arithmetic and exact claim consumers.
//! These helpers confer no outer acceptance; each concrete descriptor owns its roster.
use super::codec::{mul, put, sum, take, term};
use super::{buffer, Constraints, Error};
use alloc::vec::Vec;
use stele_gkr::public_mle::{Axis, Coefficient, Kind};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_opening, CodeField, Functional, OpeningRecord, Usage, VerifiedCertificate};
use stele_sumcheck::{Dense, Instance, Summand};

pub(crate) struct Arithmetic<'a, 'cert, K: ChallengeField> {
    pub(crate) stage: u32,
    pub(crate) base: u64,
    pub(crate) m: u8,
    pub(crate) positions: usize,
    pub(crate) ids: &'a [u64],
    pub(crate) constraints: &'a Constraints<K>,
    pub(crate) groups: [&'cert VerifiedCertificate<K>; 3],
}
// Shared fixed group construction; no public caller can supply a functional.
pub(crate) struct GroupWeights<K> {
    pub(crate) a: Vec<K>,
    pub(crate) b: Vec<K>,
    pub(crate) value: K,
    pub(crate) rlc: RlcRecord<K>,
}
impl<K> GroupWeights<K> {
    pub(crate) fn owned_field_bytes(&self) -> Result<[usize; 3], Error> {
        let w = core::mem::size_of::<K>();
        Ok([
            mul(self.a.capacity(), w)?,
            mul(self.b.capacity(), w)?,
            mul(self.rlc.weights.capacity(), w)?,
        ])
    }
}
// Actual closed group, independent RLC obligation, and scoped field capacities.
pub(crate) type GroupResult<'cert, K> = (GroupRecord<'cert, K>, RlcRecord<K>, [usize; 3]);
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
pub(crate) fn add_local(hashes: &mut HashUsage, usage: Usage) -> Result<(), Error> {
    // RFC-0023 §2.4: Descriptor bounds every prefix before work. Children use
    // only ordinary H locally; their cumulative transcript snapshots are NOT summed.
    hashes.hash_evaluations = hashes
        .hash_evaluations
        .checked_add(usage.non_transcript.hash_evaluations)
        .ok_or(Error::Capacity)?;
    Ok(())
}
pub(crate) fn copied<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = buffer(values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
pub(crate) fn arithmetic<K: ChallengeField>(
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

impl<K: ChallengeField> Arithmetic<'_, '_, K> {
    /// Encode every unsampled constraint without dropping zero terms or inputs.
    pub(crate) fn encode_constraints(&self, bytes: usize) -> Result<Vec<u8>, Error> {
        let mut out = buffer(bytes)?;
        put(&mut out, &self.stage.to_le_bytes())?;
        put(&mut out, &[self.m])?;
        put(&mut out, &(self.ids.len() as u32).to_le_bytes())?;
        for id in self.ids {
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
}
impl<'a, 'source, K: ChallengeField + CodeField + Eq> Arithmetic<'a, 'source, K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    pub(crate) fn weights(
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
            stage: self.stage,
            phase,
            weights,
        })
    }
    pub(crate) fn aggregate(&self, weights: &[K]) -> Result<Instance<K>, Error> {
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
            inputs: copied(self.ids)?,
            terms,
            claimed_sum: K::from_i64(0),
        })
    }
    pub(crate) fn coefficient(
        &self,
        point: &[K],
        real: u64,
        selector: Option<&[K]>,
        value: K,
    ) -> Result<(), Error> {
        let axes = [Axis { bits: self.m, real }];
        let selectors = [selector];
        let expected = Coefficient::new(&axes, &selectors, Kind::Eq, self.positions)
            .and_then(|c| c.evaluate(point))
            .map_err(Error::PublicCoefficient)?;
        if value != expected {
            return Err(Error::CoefficientMismatch);
        }
        Ok(())
    }
    pub(crate) fn group<'cert>(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: Vec<(u32, u64, K)>,
        proof: &[u8],
        hashes: &mut HashUsage,
    ) -> Result<GroupResult<'cert, K>, Error>
    where
        'source: 'cert,
    {
        let weights = self.group_weights(t, group, point, &claims)?;
        let capacities = weights.owned_field_bytes()?;
        let certificate = self.groups[usize::from(group)];
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
    pub(crate) fn group_weights(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: &[(u32, u64, K)],
    ) -> Result<GroupWeights<K>, Error> {
        let certificate = self.groups[usize::from(group)];
        let source = certificate.record().source();
        let width = 4 * usize::from(<K as CodeField>::DEGREE);
        let size = sum(&[
            147,
            mul(point.len(), width)?,
            mul(claims.len(), 12 + width)?,
        ])?;
        let mut frame = buffer(size)?;
        put(&mut frame, &self.stage.to_le_bytes())?;
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
}

// RFC-0006 A1 owns each draw; the wrapper only retains actual fold arguments.
pub(crate) struct Capture<'a, K> {
    pub(crate) dense: Dense<K>,
    pub(crate) point: &'a mut Vec<K>,
}
impl<K: ChallengeField> Summand<K> for Capture<'_, K> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.round(i)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        if self.point.len() == self.point.capacity() {
            return Err(stele_sumcheck::Error::Capacity);
        }
        self.dense.fold(challenge)?;
        self.point.push(challenge);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.final_values()
    }
}
pub(crate) fn fields<K: ChallengeField>(
    out: &mut Vec<u8>,
    rows: &[Vec<K>],
    finals: &[K],
) -> Result<(), Error> {
    for v in rows.iter().flatten().chain(finals) {
        put(out, v.to_le_bytes().as_ref())?;
    }
    Ok(())
}
