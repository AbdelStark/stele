//! RFC-0008 A5 §§2–6: complete untrusted producer using the actual A3/A9 engines.
//! T_misc includes sorted real-row indexing O(t log t + N log t), source lifts,
//! grouped histograms and prefix functionals. Actual A3/A9 calls own their costs.
use super::{
    absorb, addressable, draw, eq, functionals, mul, phase, reserve, sum, zeros, Descriptor, Error,
    TableField,
};
use alloc::vec::Vec;
use stele_field::{Field, Serialize, M31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_lookup::fraction::{self, LeafDescriptor, SelectedProduct};
use stele_pcs::{verify_certificate, CodeField, Functional, PreparedSource};

#[path = "lookup_resources.rs"]
mod resources;
#[path = "lookup_work.rs"]
mod work;
pub use work::{ProverWork, RepetitionWork};

/// Caller admission for the complete producer, separate from codec/verifier limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerLimits {
    /// All absorb payloads: outer work plus actual certificate production/verification.
    pub public_bytes: usize,
    /// Conservative requested dense storage in M31-equivalent slots (d per K).
    /// Includes encoded field columns; excludes wire/Merkle/metadata bytes, checked
    /// separately for addressability. This is not observed capacity or process RSS.
    pub dense_elements: usize,
}
/// Independent work of one attempted genuine multiplicity registration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistrationUsage {
    /// Certificate producer's own cumulative transcript snapshot.
    pub production: HashUsage,
    /// Actual certificate verifier's separate transcript and local hashes.
    pub verification: stele_pcs::Usage,
}
/// Observations only; none of these fields grants lookup verification authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProverUsage {
    /// Final shared outer snapshot, including the prefix of any failed attempt.
    pub transcript: HashUsage,
    /// Only this call's Table encoding and actual multiplicity preparation hashes.
    pub non_transcript: HashUsage,
    /// Ordered attempted registrations; None means that phase was not reached.
    pub registrations: [Option<RegistrationUsage>; 2],
}
/// Aborted attempt, with every observed prefix and no proof or partial handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverFailure {
    /// Preserve the original outer or wrapped actual engine failure.
    pub cause: Error,
    /// Work executed before the error; permits no retry or continuation.
    pub usage: ProverUsage,
}
impl<K: ChallengeField + CodeField + TableField + Eq> Descriptor<'_, '_, K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    /// Complete absorb-payload admission, including both actual registration calls.
    /// Like the codec bound, excludes hash framing and challenge requests.
    pub fn producer_public_bytes(&self) -> Result<usize, Error> {
        sum(&[self.public_bytes, mul(2, self.registration_bytes()?)?])
    }
    /// Conservative dense-slot admission for this implementation; not measured memory.
    /// Also checks known non-field allocations before execution.
    pub fn producer_dense_elements(&self) -> Result<usize, Error> {
        resources::elements(self)
    }
    /// Produce the complete untrusted wire using genuine preparation/registration.
    /// The fixed prefix must not depend on mu roots or the complete proof. Every
    /// failure aborts the caller's whole attempt; no hidden retry or rollback occurs.
    // A5 §5: keep both registration prefixes without allocating on an error path.
    #[allow(clippy::result_large_err)]
    pub fn prove(
        &self,
        t: &mut Transcript<K>,
        originals: &[&PreparedSource<'_, K>],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage), ProverFailure> {
        self.prove_measured(t, originals, limits)
            .map(|(proof, usage, _)| (proof, usage))
    }
    /// The same complete producer with actual A5 §6 capacity observations.
    /// Success-only Work adds neither authority nor transcript operations.
    #[allow(clippy::result_large_err)]
    pub fn prove_measured(
        &self,
        t: &mut Transcript<K>,
        originals: &[&PreparedSource<'_, K>],
        limits: ProducerLimits,
    ) -> Result<(Vec<u8>, ProverUsage, ProverWork), ProverFailure> {
        let mut usage = ProverUsage::default();
        let mut work = ProverWork::default();
        let result = (|| {
            if originals.len() != self.statement.originals.len() {
                return Err(Error::SourceRoster);
            }
            for (prepared, certificate) in originals.iter().zip(self.statement.originals) {
                if prepared.source().bytes() != certificate.record().source().bytes() {
                    return Err(Error::Pcs(stele_pcs::Error::CertificateContext));
                }
            }
            if self.producer_public_bytes()? > limits.public_bytes
                || self.producer_dense_elements()? > limits.dense_elements
            {
                return Err(Error::ResourceLimit);
            }
            self.produce(t, originals, &mut usage, &mut work)
        })();
        // No post-mutation ? may bypass the actual shared transcript observation.
        usage.transcript = t.usage();
        result
            .map(|proof| (proof, usage, work))
            .map_err(|cause| ProverFailure { cause, usage })
    }
    fn produce(
        &self,
        t: &mut Transcript<K>,
        originals: &[&PreparedSource<'_, K>],
        usage: &mut ProverUsage,
        work: &mut ProverWork,
    ) -> Result<Vec<u8>, Error> {
        let s = &self.statement;
        let (r, c) = (s.multiplicities.len(), s.originals.len());
        let n = s.table.descriptor().shape().padded() as usize;
        let real = s.table.descriptor().shape().rows() as usize;
        let d = <K as CodeField>::DEGREE as usize;
        let mut out = reserve(self.proof_bytes)?;
        work.proof_bytes = work::bytes(&out)?;
        out.extend_from_slice(&[1, d as u8]);
        let statement = self.encode(&mut usage.non_transcript)?;
        work.wire(statement.capacity());
        work.local(&[out.capacity(), statement.capacity()])?;
        absorb(t, AbsorbLabel::LookupStatement, &statement)?;
        drop(statement);

        // A5 §4: finish every independent unit vector before any mu binding.
        let mut theta: [Vec<K>; 2] = [Vec::new(), Vec::new()];
        for (j, units) in theta[..r].iter_mut().enumerate() {
            *units = reserve(usize::from(s.m - s.b))?;
            absorb(t, AbsorbLabel::LookupUnits, &phase(s.id, j, 0)[..9])?;
            for _ in 0..s.m - s.b {
                units.push(draw(t, ChallengeLabel::LookupUnit)?);
            }
        }
        work.units_bytes = work::vectors(&theta)?;
        // Signed Table keys use canonical M31 residues. This separate sorted
        // index never changes Table bytes or histogram row order.
        let mut index = reserve(real)?;
        for (i, row) in s.table.entries().chunks_exact(c).take(real).enumerate() {
            let mut key = [0; 2];
            for (key, value) in key.iter_mut().zip(row) {
                *key = M31::from_i64(i64::from(*value)).as_u32();
            }
            index.push((key, i));
        }
        index.sort_unstable();
        work.index_bytes = work::bytes(&index)?;
        let mut mu: [Vec<K>; 2] = [Vec::new(), Vec::new()];
        let mut limbs: [Vec<M31>; 2] = [Vec::new(), Vec::new()];
        for j in 0..r {
            mu[j] = zeros(n)?;
            let weights = eq(&theta[j])?;
            for (i, selected) in s.selector.iter().enumerate() {
                if *selected == 0 {
                    continue;
                }
                let mut key = [0; 2];
                for (key, original) in key.iter_mut().zip(originals) {
                    *key = original.message()[i].as_u32();
                }
                // Unmatched selected tuples stay in the actual lookup leaves.
                // Their equality-sum histogram has no row; actual roots decide.
                if let Ok(position) = index.binary_search_by_key(&key, |entry| entry.0) {
                    let row = index[position].1;
                    mu[j][row] = mu[j][row] + weights[i >> s.b];
                }
            }
            limbs[j] = reserve(mul(n, d)?)?;
            for value in &mu[j] {
                for word in value.to_le_bytes().as_ref().chunks_exact(4) {
                    limbs[j].push(
                        M31::from_le_bytes(word.try_into().map_err(|_| Error::Capacity)?)
                            .ok_or(Error::Fraction(fraction::Error::NoncanonicalField))?,
                    );
                }
            }
            work.mu_values_bytes = work::vectors(&mu)?;
            work.mu_limbs_bytes = work::vectors(&limbs)?;
            work.group_weights_bytes = work.group_weights_bytes.max(work::bytes(&weights)?);
            work.local(&[
                out.capacity(),
                work.units_bytes,
                work.index_bytes,
                work.mu_values_bytes,
                work.mu_limbs_bytes,
                work::bytes(&weights)?,
            ])?;
        }
        drop(index);
        // Every owning limb buffer is stable before any PreparedSource borrows.
        let mut prepared = reserve(r)?;
        let mut handles = reserve(r)?;
        let mut bundle = reserve(sum(&[9, mul(138, r)?])?)?;
        bundle.extend_from_slice(&s.id.to_le_bytes());
        bundle.push(r as u8);
        work.wire(bundle.capacity());
        let preparation_base = sum(&[
            out.capacity(),
            work.units_bytes,
            work.mu_values_bytes,
            work.mu_limbs_bytes,
            bundle.capacity(),
        ])?;
        for (j, message) in limbs[..r].iter().enumerate() {
            let layout = s.multiplicities[j];
            let columns = self.mu[j].columns().trailing_zeros() as u8;
            let p = PreparedSource::<K>::new(
                layout.id,
                layout.ell,
                columns,
                layout.blowup,
                message,
                &mut usage.non_transcript,
            )
            .map_err(Error::Pcs)?;
            let preparation = p.work();
            work.child(
                sum(&[preparation_base, work.prepared_bytes])?,
                preparation.peak_owned_bytes,
            )?;
            work.prepared_bytes = sum(&[
                work.prepared_bytes,
                preparation.encoded_columns_bytes,
                preparation.merkle_nodes_bytes,
            ])?;
            work.preparations[j] = Some(preparation);
            let registration = usage.registrations[j].insert(RegistrationUsage::default());
            let (certificate, production) = p.certificate().map_err(|failure| {
                registration.production = failure.usage;
                Error::Pcs(failure.cause)
            })?;
            registration.production = production;
            work.wire(certificate.capacity());
            work.local(&[
                preparation_base,
                work.prepared_bytes,
                certificate.capacity(),
            ])?;
            let (handle, verification) =
                verify_certificate(*p.source(), &certificate).map_err(|failure| {
                    registration.verification = failure.usage;
                    Error::Pcs(failure.cause)
                })?;
            registration.verification = verification;
            bundle.push(j as u8);
            bundle.extend_from_slice(&p.source().bytes());
            bundle.extend_from_slice(&handle.record().id());
            out.extend_from_slice(&p.source().root());
            out.extend_from_slice(&certificate);
            prepared.push(p);
            handles.push(handle);
        }
        absorb(t, AbsorbLabel::LookupMultiplicities, &bundle)?;
        drop(bundle);
        let mut pairs = [[K::from_i64(0); 2]; 2];
        for (j, pair) in pairs[..r].iter_mut().enumerate() {
            absorb(t, AbsorbLabel::LookupRepetition, &phase(s.id, j, 0))?;
            *pair = [
                draw(t, ChallengeLabel::LookupBeta)?,
                draw(t, ChallengeLabel::LookupAlpha)?,
            ];
        }
        let mut sigma = reserve(s.selector.len())?;
        sigma.extend(s.selector.iter().map(|v| K::from_i64(i64::from(*v))));
        let mut xs = [Vec::new(), Vec::new()];
        let mut ids = [0; 2];
        for (i, original) in originals.iter().enumerate() {
            xs[i] = reserve(s.selector.len())?;
            xs[i].extend(
                original
                    .message()
                    .iter()
                    .map(|v| K::from_i64(i64::from(v.as_u32()))),
            );
            ids[i] = original.source().descriptor().id;
        }
        work.selector_bytes = work::bytes(&sigma)?;
        work.originals_bytes = work::vectors(&xs)?;
        // These exact outer buffers remain live and unchanged during each A3 call.
        let base = sum(&[
            out.capacity(),
            work.units_bytes,
            work.mu_values_bytes,
            work.mu_limbs_bytes,
            work.prepared_bytes,
            work.selector_bytes,
            work.originals_bytes,
        ])?;
        work.local(&[base])?;
        for j in 0..r {
            let [beta, alpha] = pairs[j];
            absorb(t, AbsorbLabel::LookupRepetition, &phase(s.id, j, 1))?;
            let tree_id = 4 * s.id + 2 * j as u64;
            let leaf_id = 8 * s.id + 4 * j as u64;
            let left = fraction::Descriptor::new(
                tree_id,
                u32::from(s.m),
                u32::from(s.b),
                [leaf_id, leaf_id + 1],
                &theta[j],
            )
            .map_err(Error::Fraction)?;
            let right = fraction::Descriptor::new(
                tree_id + 1,
                u32::from(self.k),
                u32::from(self.k),
                [leaf_id + 2, leaf_id + 3],
                &[],
            )
            .map_err(Error::Fraction)?;
            let mut leaves = reserve(s.selector.len())?;
            for (i, selected) in sigma.iter().enumerate() {
                let value = xs[..c]
                    .iter()
                    .rev()
                    .fold(K::from_i64(0), |v, x| v * beta + x[i]);
                leaves.push([
                    *selected,
                    K::from_i64(1) - *selected + *selected * (alpha - value),
                ]);
            }
            let (left_proof, lookup, lookup_work) =
                left.prove_measured(&leaves, t).map_err(Error::Fraction)?;
            work.child(
                sum(&[base, work::bytes(&leaves)?])?,
                lookup_work.peak_observed_bytes,
            )?;
            let left_root = left_proof.root;
            let encoded = left_proof.encode(&left).map_err(Error::Fraction)?;
            let lookup_point = work::bytes(&lookup.point)?;
            work.wire(encoded.capacity());
            work.local(&[
                base,
                work::bytes(&leaves)?,
                work::tree(&left_proof)?,
                lookup_point,
                encoded.capacity(),
            ])?;
            out.extend_from_slice(&encoded);
            drop(encoded);
            drop(left_proof);
            drop(leaves);
            let mut leaves = reserve(n)?;
            for (i, row) in s.table.entries().chunks_exact(c).enumerate() {
                let value = row
                    .iter()
                    .rev()
                    .fold(K::from_i64(0), |v, x| v * beta + K::from_i64(i64::from(*x)));
                leaves.push(if i < real {
                    [mu[j][i], alpha - value]
                } else {
                    [K::from_i64(0), K::from_i64(1)]
                });
            }
            let (right_proof, table, table_work) =
                right.prove_measured(&leaves, t).map_err(Error::Fraction)?;
            work.child(
                sum(&[base, lookup_point, work::bytes(&leaves)?])?,
                table_work.peak_observed_bytes,
            )?;
            let right_root = right_proof.root;
            let encoded = right_proof.encode(&right).map_err(Error::Fraction)?;
            let table_point = work::bytes(&table.point)?;
            work.wire(encoded.capacity());
            work.local(&[
                base,
                lookup_point,
                work::bytes(&leaves)?,
                work::tree(&right_proof)?,
                table_point,
                encoded.capacity(),
            ])?;
            out.extend_from_slice(&encoded);
            drop(encoded);
            drop(right_proof);
            drop(leaves);
            fraction::check_roots(left_root, right_root).map_err(Error::Fraction)?;
            let actual = s.table.evaluate(&table.point).map_err(Error::Table)?;
            let compressed = actual
                .columns()
                .iter()
                .rev()
                .fold(K::from_i64(0), |v, x| v * beta + *x);
            if table.claims[1].1
                != K::from_i64(1) + (alpha - K::from_i64(1)) * actual.valid_rows() - compressed
            {
                return Err(Error::TableDenominatorMismatch);
            }
            let leaf = LeafDescriptor::new(&left, &ids[..c]).map_err(Error::Fraction)?;
            let selected = SelectedProduct::new(leaf, &lookup, &sigma, alpha, beta)
                .map_err(Error::Fraction)?;
            let (proof, reduction, selected_work) = selected
                .prove_measured(&xs[..c], t)
                .map_err(Error::Fraction)?;
            work.child(
                sum(&[base, lookup_point, table_point])?,
                selected_work.peak_observed_bytes,
            )?;
            let encoded = leaf.encode(&proof).map_err(Error::Fraction)?;
            let opening_base = sum(&[
                base,
                lookup_point,
                table_point,
                work::bytes(&reduction.point)?,
            ])?;
            work.wire(encoded.capacity());
            work.local(&[opening_base, work::proof(&proof)?, encoded.capacity()])?;
            out.extend_from_slice(&encoded);
            drop(encoded);
            drop(proof);
            for (i, (id, value)) in reduction.claims.iter().enumerate() {
                let (proof, _) = originals[i]
                    .opening_point(t, s.originals[i], *id, &reduction.point, *value)
                    .map_err(|f| Error::Pcs(f.cause))?;
                // Actual opening production reuses prepared responses; local H is zero.
                work.wire(proof.capacity());
                work.local(&[opening_base, proof.capacity()])?;
                out.extend_from_slice(&proof);
            }
            let pieces = functionals::pieces(prepared[j].source(), &table.point, real)?;
            let coefficients = pieces
                .iter()
                .try_fold(0, |n, p| sum(&[n, work::bytes(&p.a)?, work::bytes(&p.b)?]))?;
            work.coefficients_bytes = work.coefficients_bytes.max(coefficients);
            let mut values = [K::from_i64(0); 2];
            let mut total = K::from_i64(0);
            for (i, piece) in pieces.iter().enumerate() {
                values[i] = piece.value(prepared[j].message());
                total = total + values[i];
            }
            if total != table.claims[0].1 {
                return Err(Error::PieceSumMismatch);
            }
            let mut claims = reserve(sum(&[
                10,
                mul(4 * d, table.point.len() + 1)?,
                mul(pieces.len(), 1 + 4 * d)?,
            ])?)?;
            work.wire(claims.capacity());
            work.local(&[opening_base, coefficients, claims.capacity()])?;
            claims.extend_from_slice(&phase(s.id, j, pieces.len() as u8));
            for value in table.point.iter().chain([&table.claims[0].1]) {
                claims.extend_from_slice(value.to_le_bytes().as_ref());
            }
            for (piece, value) in pieces.iter().zip(values) {
                claims.push(piece.id);
                claims.extend_from_slice(value.to_le_bytes().as_ref());
                out.extend_from_slice(value.to_le_bytes().as_ref());
            }
            absorb(t, AbsorbLabel::LookupMultiplicityClaims, &claims)?;
            drop(claims);
            for (piece, value) in pieces.iter().zip(values) {
                let (proof, _) = prepared[j]
                    .opening(
                        t,
                        &handles[j],
                        Functional {
                            id: u64::from(piece.id),
                            a: &piece.a,
                            b: &piece.b,
                            value,
                        },
                    )
                    .map_err(|f| Error::Pcs(f.cause))?;
                work.wire(proof.capacity());
                work.local(&[opening_base, coefficients, proof.capacity()])?;
                out.extend_from_slice(&proof);
            }
            work.repetitions[j] = Some(RepetitionWork {
                lookup: lookup_work,
                table: table_work,
                selected: selected_work,
            });
        }
        if out.len() != self.proof_bytes {
            return Err(Error::ProofShape);
        }
        Ok(out)
    }
}
