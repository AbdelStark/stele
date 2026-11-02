//! RFC-0023 §§2.4,3: complete untrusted production through actual A5/A3/A1/A9.
//! Dense witness/constraint work is O((4+R+E)N); every full physical source is read.
use super::{addressable, buffer, lookup, mul, put, sum, Descriptor, Error};
use alloc::vec::Vec;
use stele_hash::{certificate_id, AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{CodeField, Functional, PreparedSource, ProofKind};
use stele_sumcheck::{zerocheck, Dense, Instance, Summand};

/// Producer admission, separate from the Descriptor's complete verifier limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerLimits {
    /// Outer payloads plus both actual A5 certificate production/import payloads.
    /// Caller-owned input/advice preparation and registration are separate.
    pub public_bytes: usize,
    /// Conservative requested M31-equivalent slots (d per K), not an observed peak.
    /// Wire, Merkle and metadata addressability remains separately checked.
    pub dense_elements: usize,
}
/// Actual work only; these observations grant no proof or certificate authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverUsage {
    /// Final cumulative shared transcript, including any failed prefix; count once.
    pub transcript: HashUsage,
    /// Advice packet identity, Table encoding and actual A5 preparation hashes.
    pub non_transcript: HashUsage,
    /// Separate ordered actual A5 multiplicity production/import attempts.
    pub registrations: [[Option<lookup::RegistrationUsage>; 2]; 2],
}
/// Abort the whole attempt; no wire, accepting record or continuation is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverFailure {
    /// Original wrapped child or admission cause.
    pub cause: Error,
    /// All observed work before failure, including disjoint registrations.
    pub usage: ProverUsage,
}
/// Scoped actual field/wire capacities and existing child observations.
/// Excludes caller owners, metadata, A3/A1 internal scratch and PCS opening scratch.
/// These disjoint snapshots are not a complete heap peak; whole-worker RSS is separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverWork {
    /// Full outer wire capacity, allocated before either child lookup.
    pub proof_bytes: usize,
    /// Actual A5 measurements; each retains its existing documented partial scope.
    pub lookups: [lookup::ProverWork; 2],
    /// Original A3 input-table field payload capacities, live through A3 production.
    pub aggregate_tables_bytes: usize,
    /// Actual A3 point retained through both A3 source groups.
    pub aggregate_point_bytes: usize,
    /// Original A1 input-table field payload capacities, owned by Dense while folding.
    pub output_tables_bytes: usize,
    /// Actual A1 captured point retained through the output source group.
    pub output_point_bytes: usize,
    /// Actual simultaneous a, b, independent-weight capacities for each ordered group.
    pub group_coefficients_bytes: [[usize; 3]; 3],
}
fn bytes<T>(v: &Vec<T>) -> Result<usize, Error> {
    mul(v.capacity(), core::mem::size_of::<T>())
}
fn tables_bytes<K>(v: &[Vec<K>]) -> Result<usize, Error> {
    v.iter().try_fold(0, |n, row| sum(&[n, bytes(row)?]))
}

// RFC-0006 A1 owns each draw; the wrapper only retains actual fold arguments.
struct Capture<'a, K> {
    dense: Dense<K>,
    point: &'a mut Vec<K>,
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
fn fields<K: ChallengeField>(
    out: &mut Vec<u8>,
    rows: &[Vec<K>],
    finals: &[K],
) -> Result<(), Error> {
    for v in rows.iter().flatten().chain(finals) {
        put(out, v.to_le_bytes().as_ref())?;
    }
    Ok(())
}
fn local(hashes: &mut HashUsage, delta: HashUsage) -> Result<(), Error> {
    // The actual children use ordinary H locally; shared snapshots stay disjoint.
    hashes.hash_evaluations = hashes
        .hash_evaluations
        .checked_add(delta.hash_evaluations)
        .ok_or(Error::Capacity)?;
    Ok(())
}

impl<K: ChallengeField + CodeField + lookup::TableField + Eq> Descriptor<'_, '_, K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    /// Complete call payload bound; earlier caller-owned source registrations are excluded.
    pub fn producer_public_bytes(&self) -> Result<usize, Error> {
        let mut bytes = self.public_bytes;
        for b in 0..2 {
            let d = self.lookup(b)?;
            bytes = sum(&[
                bytes,
                mul(2, d.registration_bytes().map_err(Error::Lookup)?)?,
            ])?;
        }
        Ok(bytes)
    }
    /// Conservative dense admission for this concrete implementation, not capacity/RSS.
    /// Charges both child bounds and overlapping A3 original/hybrid tables, retained
    /// proofs/finals, output tables and functional/point buffers in M31-equivalent slots.
    pub fn producer_dense_elements(&self) -> Result<usize, Error> {
        let n = self.originals[0][0].record().source().columns();
        let p = self.ids.len();
        let q = self.output.inputs.len();
        let terms = self
            .constraints
            .equations()
            .iter()
            .try_fold(0, |count, e| sum(&[count, e.len()]))?;
        let extension = sum(&[
            mul(sum(&[mul(2, p)?, q, 4])?, n)?,
            mul(6, p)?,
            mul(8, usize::from(self.m))?,
            self.constraints.equations().len(),
            terms,
            16,
        ])?;
        addressable::<K>(extension)?;
        addressable::<Vec<K>>(p)?;
        addressable::<Vec<K>>(q)?;
        let mut elements = mul(usize::from(<K as CodeField>::DEGREE), extension)?;
        for b in 0..2 {
            elements = sum(&[
                elements,
                self.lookup(b)?
                    .producer_dense_elements()
                    .map_err(Error::Lookup)?,
            ])?;
        }
        Ok(elements)
    }
    /// Produce the entire canonical wire from matching prepared input/advice sources.
    /// `advice_packet` is the already-produced exact registered certificate, never
    /// an independently regenerated identity. Every failure aborts without rollback.
    #[allow(clippy::result_large_err)]
    pub fn prove(
        &self,
        t: &mut Transcript<K>,
        sources: [&PreparedSource<'_, K>; 2],
        advice_packet: &[u8],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage), ProverFailure> {
        self.prove_measured(t, sources, advice_packet, limits)
            .map(|(wire, usage, _)| (wire, usage))
    }
    /// The same complete producer, exposing only the scoped observations in ProverWork.
    #[allow(clippy::result_large_err)]
    pub fn prove_measured(
        &self,
        t: &mut Transcript<K>,
        sources: [&PreparedSource<'_, K>; 2],
        advice_packet: &[u8],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage, ProverWork), ProverFailure> {
        let mut usage = ProverUsage::default();
        let mut work = ProverWork::default();
        let result = (|| {
            for (prepared, certificate) in sources.iter().zip(self.originals) {
                if prepared.source().bytes() != certificate[0].record().source().bytes() {
                    return Err(Error::CertificateContext);
                }
            }
            let advice = self.originals[1][0];
            advice
                .record()
                .source()
                .parse(ProofKind::Certificate, advice_packet)
                .map_err(Error::Pcs)?;
            if self.producer_public_bytes()? > limits.public_bytes
                || self.producer_dense_elements()? > limits.dense_elements
            {
                return Err(Error::ResourceLimit);
            }
            if certificate_id(
                &advice.record().source().bytes(),
                advice_packet,
                &mut usage.non_transcript,
            )
            .map_err(Error::Transcript)?
                != advice.record().id()
            {
                return Err(Error::CertificateIdentity);
            }
            self.produce(t, sources, advice_packet, &mut usage, &mut work)
        })();
        usage.transcript = t.usage();
        result
            .map(|wire| (wire, usage, work))
            .map_err(|cause| ProverFailure { cause, usage })
    }
    fn produce(
        &self,
        t: &mut Transcript<K>,
        sources: [&PreparedSource<'_, K>; 2],
        advice_packet: &[u8],
        usage: &mut ProverUsage,
        work: &mut ProverWork,
    ) -> Result<Vec<u8>, Error> {
        let mut wire = buffer(self.proof_bytes)?;
        work.proof_bytes = wire.capacity();
        put(&mut wire, &[1, <K as CodeField>::DEGREE])?;
        put(&mut wire, &sources[1].source().root())?;
        put(&mut wire, advice_packet)?;
        t.absorb(AbsorbLabel::RequantStatement, &self.encode()?)
            .map_err(Error::Transcript)?;
        for (b, source) in sources.iter().enumerate() {
            let d = self.lookup(b)?;
            let limits = lookup::ProducerLimits {
                public_bytes: d.producer_public_bytes().map_err(Error::Lookup)?,
                dense_elements: d.producer_dense_elements().map_err(Error::Lookup)?,
            };
            let result = d.prove_measured(t, &[*source], limits);
            let observed = match &result {
                Ok((_, u, w)) => {
                    work.lookups[b] = *w;
                    *u
                }
                Err(f) => f.usage,
            };
            usage.registrations[b] = observed.registrations;
            local(&mut usage.non_transcript, observed.non_transcript)?;
            put(&mut wire, &result.map_err(|f| Error::Lookup(f.cause))?.0)?;
        }
        t.absorb(AbsorbLabel::RequantConstraints, &self.encode_constraints()?)
            .map_err(Error::Transcript)?;
        let weights = self.weights(t, 0, self.constraints.equations().len())?;
        let aggregate = self.aggregate(weights.weights())?;
        drop(weights);
        let n = sources[0].source().columns();
        let mut tables = buffer(self.ids.len())?;
        let mut sigma = buffer(n)?;
        for i in 0..n {
            sigma.push(K::from_i64(i64::from((i as u64) < self.statement.n)));
        }
        tables.push(sigma);
        for source in sources {
            for row in source.message().chunks_exact(n) {
                let mut table = buffer(n)?;
                table.extend(row.iter().map(|v| K::from_i64(i64::from(v.as_u32()))));
                tables.push(table);
            }
        }
        let (zero, point) = zerocheck::Zerocheck {
            instance: &aggregate,
            skip: 0,
        }
        .prove_with_point(&tables, t)
        .map_err(Error::Sumcheck)?;
        work.aggregate_tables_bytes = tables_bytes(&tables)?;
        work.aggregate_point_bytes = bytes(&point)?;
        drop(tables);
        drop(aggregate);
        fields(&mut wire, &zero.rounds, &zero.final_values)?;
        for (b, source) in sources.iter().enumerate() {
            let start = if b == 0 { 1 } else { 5 };
            let count = source.source().rows();
            let mut claims = buffer(count)?;
            for row in 0..count {
                claims.push((
                    row as u32,
                    self.ids[start + row],
                    zero.final_values[start + row],
                ));
            }
            work.group_coefficients_bytes[b] =
                self.produce_group(t, b as u8, &point, &claims, source, &mut wire, usage)?;
        }
        drop(zero);
        drop(point);
        let mut tables = buffer(self.output.inputs.len())?;
        tables.push(stele_poly::eq_table(self.statement.point).map_err(|_| Error::Capacity)?);
        for row in core::iter::once(0).chain(self.statement.schema.values()[2].value()) {
            let mut values = buffer(n)?;
            values.extend(
                sources[1].message()[row * n..(row + 1) * n]
                    .iter()
                    .map(|v| K::from_i64(i64::from(v.as_u32()))),
            );
            tables.push(values);
        }
        let mut point = buffer(usize::from(self.m))?;
        work.output_tables_bytes = tables_bytes(&tables)?;
        let dense = Dense::new(&self.output, tables).map_err(Error::Sumcheck)?;
        let output = stele_sumcheck::prove(
            &self.output,
            Capture {
                dense,
                point: &mut point,
            },
            t,
        )
        .map_err(Error::Sumcheck)?;
        work.output_point_bytes = bytes(&point)?;
        fields(&mut wire, &output.rounds, &output.final_values)?;
        let mut claims = buffer(self.output.inputs.len() - 1)?;
        for (k, row) in core::iter::once(0)
            .chain(self.statement.schema.values()[2].value())
            .enumerate()
        {
            claims.push((
                row as u32,
                self.output.inputs[k + 1],
                output.final_values[k + 1],
            ));
        }
        work.group_coefficients_bytes[2] =
            self.produce_group(t, 2, &point, &claims, sources[1], &mut wire, usage)?;
        self.preflight(&wire)?;
        Ok(wire)
    }
    #[allow(clippy::too_many_arguments)]
    fn produce_group(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: &[(u32, u64, K)],
        source: &PreparedSource<'_, K>,
        wire: &mut Vec<u8>,
        usage: &mut ProverUsage,
    ) -> Result<[usize; 3], Error> {
        let weights = self.group_weights(t, group, point, claims)?;
        let capacities = weights.owned_field_bytes()?;
        let result = source.opening(
            t,
            self.originals[usize::from(group != 0)][0],
            Functional {
                id: self.base + 3072 + u64::from(group),
                a: &weights.a,
                b: &weights.b,
                value: weights.value,
            },
        );
        let observed = match &result {
            Ok((_, u)) => *u,
            Err(f) => f.usage,
        };
        local(&mut usage.non_transcript, observed.non_transcript)?;
        put(wire, &result.map_err(|f| Error::Pcs(f.cause))?.0)?;
        Ok(capacities)
    }
}
