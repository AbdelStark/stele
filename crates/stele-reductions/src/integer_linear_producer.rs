//! RFC-0024 §§2.4,3: fixed captured advice followed by one actual retained-row pass.
use super::{addressable, buffer, matmul_error, mul, put, sum, ByteRange, Descriptor, Error};
use crate::{
    lookup, matmul,
    requant::arithmetic::{add_local, fields, Capture},
};
use alloc::vec::Vec;
use stele_hash::{certificate_id, AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{CodeField, Functional, PreparedSource, ProofKind, Usage};
use stele_sumcheck::{zerocheck, Dense};

/// Separate complete producer admission; earlier capture and registration remain outside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerLimits {
    /// All outer payloads and both actual advice-mu production/import payloads.
    pub public_bytes: usize,
    /// Requested arithmetic/A5 M31-equivalent slots; A4 retains its separate limits.
    pub dense_elements: usize,
    /// Separately checked signed retained-row allowance, in K entries.
    pub retained_row_entries: usize,
}
/// Actual work, including failed prefixes; no evidence or profile authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverUsage {
    /// One final cumulative shared transcript snapshot.
    pub transcript: HashUsage,
    /// Actual advice identity and child non-transcript hashes.
    pub non_transcript: HashUsage,
    /// Actual ordered advice-mu production/import attempts.
    pub registrations: [Option<lookup::RegistrationUsage>; 2],
}
/// Actual signed-child observations from this execution, not a whole-operation heap peak.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverWork {
    /// Includes actual original source visits, retained rows, folding and original openings.
    pub matmul: matmul::Work,
    /// Actual capacities of the two centered copies, separately from retained raw rows.
    pub signed_input_bytes: [usize; 2],
    /// Signed-child preparation overlap; excludes outer and caller-owned allocations.
    pub affine_preparation_peak_bytes: usize,
}
/// Failed whole attempt; no partial wire or continuation escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverFailure {
    /// Actual rejecting cause.
    pub cause: Error,
    /// Every observed prefix and standalone child registration attempt.
    pub usage: ProverUsage,
}

impl<K: ChallengeField + CodeField + lookup::TableField + Eq> Descriptor<'_, '_, K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    /// Complete local payload cap, including actual child certificate production/import.
    pub fn producer_public_bytes(&self) -> Result<usize, Error> {
        sum(&[
            self.public_bytes,
            mul(
                2,
                self.lookup()?.registration_bytes().map_err(Error::Lookup)?,
            )?,
        ])
    }
    /// Conservative arithmetic/A5 slots, distinct from A4 and retained-row caps.
    pub fn producer_dense_elements(&self) -> Result<usize, Error> {
        let p = self.ids.len();
        let q = self.output.inputs.len();
        let terms = self
            .constraints
            .equations()
            .iter()
            .try_fold(0usize, |n, e| sum(&[n, e.len()]))?;
        let extension = sum(&[
            mul(sum(&[mul(2, p)?, q, 4])?, self.n)?,
            mul(6, p)?,
            mul(8, usize::from(self.m))?,
            self.constraints.equations().len(),
            terms,
            16,
            usize::from(self.m) + 1,
        ])?;
        addressable::<K>(extension)?;
        sum(&[
            mul(<K as CodeField>::DEGREE as usize, extension)?,
            self.lookup()?
                .producer_dense_elements()
                .map_err(Error::Lookup)?,
        ])
    }
    /// Produce the full untrusted wire from already-captured, genuinely registered advice.
    /// This call never recomputes X*W or scans W before its final retained-row constructor.
    #[allow(clippy::result_large_err)]
    pub fn prove(
        &self,
        t: &mut Transcript<K>,
        originals: [&PreparedSource<'_, K>; 2],
        advice: &PreparedSource<'_, K>,
        advice_packet: &[u8],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage), ProverFailure> {
        self.prove_measured(t, originals, advice, advice_packet, limits)
            .map(|(wire, usage, _)| (wire, usage))
    }
    /// The ordinary producer loop, returning its already-observed signed-child work.
    /// Capture, registrations, outer A5/A3/A1 and complete live memory remain separate scopes.
    #[allow(clippy::result_large_err)]
    pub fn prove_measured(
        &self,
        t: &mut Transcript<K>,
        originals: [&PreparedSource<'_, K>; 2],
        advice: &PreparedSource<'_, K>,
        advice_packet: &[u8],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage, ProverWork), ProverFailure> {
        let mut usage = ProverUsage::default();
        let result = (|| {
            for (prepared, certificate) in
                originals.into_iter().chain(core::iter::once(advice)).zip(
                    self.statement
                        .originals
                        .map(ByteRange::original)
                        .into_iter()
                        .chain(self.advice),
                )
            {
                if prepared.source().bytes() != certificate.record().source().bytes() {
                    return Err(Error::CertificateContext);
                }
            }
            self.advice[0]
                .record()
                .source()
                .parse(ProofKind::Certificate, advice_packet)
                .map_err(Error::Pcs)?;
            if self.producer_public_bytes()? > limits.public_bytes
                || self.producer_dense_elements()? > limits.dense_elements
            {
                return Err(Error::ResourceLimit);
            }
            if self.matmul.retained_entries > limits.retained_row_entries {
                return Err(Error::Capacity);
            }
            if certificate_id(
                &self.advice[0].record().source().bytes(),
                advice_packet,
                &mut usage.non_transcript,
            )
            .map_err(Error::Transcript)?
                != self.advice[0].record().id()
            {
                return Err(Error::CertificateIdentity);
            }
            self.produce(t, originals, advice, advice_packet, limits, &mut usage)
        })();
        usage.transcript = t.usage();
        result
            .map(|(wire, work)| (wire, usage, work))
            .map_err(|cause| ProverFailure { cause, usage })
    }
    fn produce(
        &self,
        t: &mut Transcript<K>,
        originals: [&PreparedSource<'_, K>; 2],
        advice: &PreparedSource<'_, K>,
        advice_packet: &[u8],
        limits: ProducerLimits,
        usage: &mut ProverUsage,
    ) -> Result<(Vec<u8>, ProverWork), Error> {
        let mut wire = buffer(self.proof_bytes)?;
        put(&mut wire, &[1, <K as CodeField>::DEGREE])?;
        put(&mut wire, &advice.source().root())?;
        put(&mut wire, advice_packet)?;
        t.absorb(AbsorbLabel::LinearStatement, &self.encode()?)
            .map_err(Error::Transcript)?;
        let a5 = self.lookup()?;
        let result = a5.prove(
            t,
            &[advice],
            lookup::ProducerLimits {
                public_bytes: a5.producer_public_bytes().map_err(Error::Lookup)?,
                dense_elements: a5.producer_dense_elements().map_err(Error::Lookup)?,
            },
        );
        let observed = match &result {
            Ok((_, u)) => *u,
            Err(f) => f.usage,
        };
        usage.registrations = observed.registrations;
        add_local(
            &mut usage.non_transcript,
            Usage {
                transcript: observed.transcript,
                non_transcript: observed.non_transcript,
            },
        )?;
        put(&mut wire, &result.map_err(|f| Error::Lookup(f.cause))?.0)?;
        t.absorb(AbsorbLabel::RequantConstraints, &self.encode_constraints()?)
            .map_err(Error::Transcript)?;
        let common = self.arithmetic();
        let weights = common.weights(t, 0, self.constraints.equations().len())?;
        let aggregate = common.aggregate(weights.weights())?;
        drop(weights);
        let mut tables = buffer(self.ids.len())?;
        let mut sigma = buffer(self.n)?;
        sigma.resize(self.n, K::from_i64(1));
        tables.push(sigma);
        for row in advice.message().chunks_exact(self.n) {
            let mut values = buffer(self.n)?;
            values.extend(row.iter().map(|v| K::from_i64(i64::from(v.as_u32()))));
            tables.push(values);
        }
        let (zero, point) = zerocheck::Zerocheck {
            instance: &aggregate,
            skip: 0,
        }
        .prove_with_point(&tables, t)
        .map_err(Error::Sumcheck)?;
        drop(tables);
        drop(aggregate);
        fields(&mut wire, &zero.rounds, &zero.final_values)?;
        for (group, start, end) in [(0, 0, 4), (1, 4, self.schema.rows())] {
            let mut claims = buffer(end - start)?;
            for row in start..end {
                claims.push((row as u32, self.ids[1 + row], zero.final_values[1 + row]));
            }
            self.produce_group(t, group, &point, &claims, advice, &mut wire, usage)?;
        }
        // Retain the actual A3 q and U-derived value through output A1 and its opening.
        let mut value = K::from_i64(-(1i64 << 31));
        let mut power = K::from_i64(1);
        for v in &zero.final_values[1..5] {
            value = value + power * *v;
            power = power * K::from_i64(256);
        }
        drop(zero);
        let mut tables = buffer(self.output.inputs.len())?;
        tables.push(stele_poly::eq_table(self.statement.point).map_err(|_| Error::Capacity)?);
        for row in core::iter::once(0).chain(self.schema.semantic().values()[2].value()) {
            let mut values = buffer(self.n)?;
            values.extend(
                advice.message()[(4 + row) * self.n..(5 + row) * self.n]
                    .iter()
                    .map(|v| K::from_i64(i64::from(v.as_u32()))),
            );
            tables.push(values);
        }
        let mut output_point = buffer(usize::from(self.m))?;
        let dense = Dense::new(&self.output, tables).map_err(Error::Sumcheck)?;
        let output = stele_sumcheck::prove(
            &self.output,
            Capture {
                dense,
                point: &mut output_point,
            },
            t,
        )
        .map_err(Error::Sumcheck)?;
        fields(&mut wire, &output.rounds, &output.final_values)?;
        let mut claims = buffer(self.output.inputs.len() - 1)?;
        for (k, row) in core::iter::once(0)
            .chain(self.schema.semantic().values()[2].value())
            .enumerate()
        {
            claims.push((
                (row + 4) as u32,
                self.output.inputs[k + 1],
                output.final_values[k + 1],
            ));
        }
        self.produce_group(t, 2, &output_point, &claims, advice, &mut wire, usage)?;
        drop(claims);
        drop(output);
        drop(output_point);
        let s = self.statement;
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
        let result = matmul::centered::prove_measured(
            t,
            &expected,
            originals,
            s.originals.map(ByteRange::original),
            self.matmul_limits,
            limits.retained_row_entries,
        );
        add_local(
            &mut usage.non_transcript,
            match &result {
                Ok((_, u, _)) => *u,
                Err(f) => f.usage,
            },
        )?;
        let (child, _, work) = result.map_err(|f| matmul_error(f.cause))?;
        put(&mut wire, &child)?;
        drop(child);
        self.preflight(&wire)?;
        Ok((
            wire,
            ProverWork {
                matmul: work.inner,
                signed_input_bytes: work.signed_input_bytes,
                affine_preparation_peak_bytes: work.preparation_peak_bytes,
            },
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn produce_group(
        &self,
        t: &mut Transcript<K>,
        group: u8,
        point: &[K],
        claims: &[(u32, u64, K)],
        advice: &PreparedSource<'_, K>,
        wire: &mut Vec<u8>,
        usage: &mut ProverUsage,
    ) -> Result<(), Error> {
        let weights = self.arithmetic().group_weights(t, group, point, claims)?;
        let result = advice.opening(
            t,
            self.advice[0],
            Functional {
                id: self.base + 3072 + u64::from(group),
                a: &weights.a,
                b: &weights.b,
                value: weights.value,
            },
        );
        add_local(
            &mut usage.non_transcript,
            match &result {
                Ok((_, u)) => *u,
                Err(f) => f.usage,
            },
        )?;
        put(wire, &result.map_err(|f| Error::Pcs(f.cause))?.0)?;
        Ok(())
    }
}
