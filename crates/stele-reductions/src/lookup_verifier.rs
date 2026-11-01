//! RFC-0008 A5 §§2–6: close actual A3 claims through immutable Table and A9 consumers.
//! T_misc includes full selector conversion, Table evaluation and prefix coefficients;
//! actual A3/A9 verifiers retain their own costs and conditional loss records.
use super::{absorb, draw, functionals, mul, phase, reserve, sum, Descriptor, Error, TableField};
use alloc::vec::Vec;
use stele_hash::{
    certificate_id, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript,
};
use stele_lookup::fraction::{self, LeafDescriptor, SelectedProduct};
use stele_pcs::{
    verify_certificate, verify_opening, verify_point, CodeField, Functional, OpeningRecord, Usage,
    VerifiedCertificate,
};

#[path = "lookup_records.rs"]
mod records;
pub use records::{LookupParameters, LookupRecord, RepetitionRecord};

/// Failed complete outer attempt; no conditional record or permission to continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Preserve the actual rejecting consumer or outer contract condition.
    pub cause: Error,
    /// Cumulative outer transcript and only this call's disjoint local hashes.
    pub usage: Usage,
}
/// Failed independent registration; no partial handle roster escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationFailure {
    /// Preserve the actual shape/admission or A9 import failure.
    pub cause: Error,
    /// Ordered actual attempted imports, including the failing call's prefix.
    pub registrations: [Option<Usage>; 2],
}
/// Independently verified handles and the disjoint usage of their ordered imports.
pub type RegisteredMultiplicities<K> = (Vec<VerifiedCertificate<K>>, [Option<Usage>; 2]);
fn opened<'cert, K: ChallengeField>(
    result: Result<(OpeningRecord<'cert, K>, Usage), stele_pcs::Failure>,
    hashes: &mut HashUsage,
) -> Result<OpeningRecord<'cert, K>, Error> {
    let usage = match &result {
        Ok((_, usage)) => usage,
        Err(f) => &f.usage,
    };
    // A9 contributes only Merkle H locally. Descriptor's checked maximum bounds
    // every executed prefix, including failed calls, before any work begins.
    hashes.hash_evaluations = hashes
        .hash_evaluations
        .checked_add(usage.non_transcript.hash_evaluations)
        .ok_or(Error::Capacity)?;
    result
        .map(|(record, _)| record)
        .map_err(|f| Error::Pcs(f.cause))
}
impl<'input, 'original, K: ChallengeField + CodeField + TableField + Eq>
    Descriptor<'input, 'original, K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    /// Independently verify every packet against its expected layout and packet root.
    /// The cap covers these standalone public/row/response payloads once, separately
    /// from outer Limits. No outer transcript, lookup record or partial handles escape.
    // A5 §5: fixed bounded failure observations must not allocate on the error path.
    #[allow(clippy::result_large_err)]
    pub fn register_multiplicities(
        &self,
        proof: &[u8],
        max_public_bytes: usize,
    ) -> Result<RegisteredMultiplicities<K>, RegistrationFailure> {
        let mut registrations = [None; 2];
        let result = (|| {
            if self.registration_bytes()? > max_public_bytes {
                return Err(Error::ResourceLimit);
            }
            let wire = self.wire(proof)?;
            let r = self.statement.multiplicities.len();
            let mut handles = reserve(r)?;
            for (j, packet) in wire.registrations[..r].iter().enumerate() {
                let source = self.multiplicity_source(j, packet.root)?;
                let result = verify_certificate(source, packet.certificate);
                registrations[j] = Some(match &result {
                    Ok((_, usage)) => *usage,
                    Err(f) => f.usage,
                });
                handles.push(result.map_err(|f| Error::Pcs(f.cause))?.0);
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
    /// Verify the complete lookup with caller-owned, genuinely verified certificates.
    /// The caller prefix must not depend on mu roots or the whole proof. Any failure
    /// aborts the enclosing attempt; no rollback, alternate layout or retry is permitted.
    pub fn verify<'cert>(
        &self,
        t: &mut Transcript<K>,
        multiplicities: &[&'cert VerifiedCertificate<K>],
        proof: &[u8],
    ) -> Result<(LookupRecord<'cert, K>, Usage), Failure>
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
    ) -> Result<LookupRecord<'cert, K>, Error>
    where
        'original: 'cert,
    {
        // Construction already checked every known buffer and the complete local-H
        // maximum. The complete wire parser preserves authentication-before-column decoding.
        let wire = self.wire(proof)?;
        let s = &self.statement;
        let (r, c) = (s.multiplicities.len(), s.originals.len());
        if multiplicities.len() != r {
            return Err(Error::CertificateContext);
        }
        let mut sources = self.mu;
        for (j, certificate) in multiplicities.iter().enumerate() {
            sources[j] = self.multiplicity_source(j, wire.registrations[j].root)?;
            if sources[j].bytes() != certificate.record().source().bytes() {
                return Err(Error::CertificateContext);
            }
        }
        // Finish all context checks before any packet identity hash or outer mutation.
        for (j, certificate) in multiplicities.iter().enumerate() {
            let id = certificate_id(
                &sources[j].bytes(),
                wire.registrations[j].certificate,
                hashes,
            )
            .map_err(Error::Transcript)?;
            if id != certificate.record().id() {
                return Err(Error::CertificateIdentity);
            }
        }
        let h = s.m - s.b;
        let positions = 1u64 << s.m;
        let rows = s.table.descriptor().shape().rows();
        let numerator = u64::from(h)
            .checked_add(positions)
            .and_then(|v| v.checked_add(c as u64 * u64::from(rows)))
            .and_then(|v| v.checked_sub(1))
            .ok_or(Error::Capacity)?;
        let parameters = LookupParameters {
            id: s.id,
            degree: <K as CodeField>::DEGREE,
            positions,
            table_rows: rows,
            columns: c as u8,
            group_bits: s.b,
            unit_bits: h,
            repetitions: r as u8,
            identity_numerator: numerator,
        };
        let mut repetitions = reserve(r)?;
        let statement = self.encode(hashes)?;
        absorb(t, AbsorbLabel::LookupStatement, &statement)?;
        drop(statement);
        let mut theta = [Vec::new(), Vec::new()];
        for (j, units) in theta[..r].iter_mut().enumerate() {
            *units = reserve(h as usize)?;
            absorb(t, AbsorbLabel::LookupUnits, &phase(s.id, j, 0)[..9])?;
            for _ in 0..h {
                units.push(draw(t, ChallengeLabel::LookupUnit)?);
            }
        }
        let mut bundle = reserve(sum(&[9, mul(138, r)?])?)?;
        bundle.extend_from_slice(&s.id.to_le_bytes());
        bundle.push(r as u8);
        for (j, certificate) in multiplicities.iter().enumerate() {
            bundle.push(j as u8);
            bundle.extend_from_slice(&sources[j].bytes());
            bundle.extend_from_slice(&certificate.record().id());
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
        let mut ids = [0; 2];
        for (id, original) in ids.iter_mut().zip(s.originals) {
            *id = original.record().source().descriptor().id;
        }
        for j in 0..r {
            let [beta, alpha] = pairs[j];
            let packet = &wire.repetitions[j];
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
            let left_proof =
                fraction::Proof::decode(&left, packet.lookup).map_err(Error::Fraction)?;
            let lookup = left.verify(&left_proof, t).map_err(Error::Fraction)?;
            let left_root = left_proof.root;
            drop(left_proof);
            let right_proof =
                fraction::Proof::decode(&right, packet.table).map_err(Error::Fraction)?;
            let table = right.verify(&right_proof, t).map_err(Error::Fraction)?;
            let right_root = right_proof.root;
            drop(right_proof);
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
                .map_err(Error::Fraction)?
                .verify(&leaf.decode(packet.selected).map_err(Error::Fraction)?, t)
                .map_err(Error::Fraction)?;
            let mut originals = reserve(c)?;
            for (a, (id, value)) in selected.claims.iter().enumerate() {
                originals.push(opened(
                    verify_point(
                        t,
                        s.originals[a],
                        *id,
                        &selected.point,
                        *value,
                        packet.originals[a],
                    ),
                    hashes,
                )?);
            }
            let d = usize::from(<K as CodeField>::DEGREE);
            let mut values = [K::from_i64(0); 2];
            let mut total = K::from_i64(0);
            for (value, bytes) in values.iter_mut().zip(packet.values.chunks_exact(4 * d)) {
                *value =
                    K::from_le_bytes(K::Bytes::try_from(bytes).map_err(|_| Error::ProofShape)?)
                        .ok_or(Error::ProofShape)?;
                total = total + *value;
            }
            if total != table.claims[0].1 {
                return Err(Error::PieceSumMismatch);
            }
            let pieces = functionals::pieces(&sources[j], &table.point, rows as usize)?;
            let mut claims = reserve(sum(&[
                10,
                mul(4 * d, table.point.len() + 1)?,
                mul(pieces.len(), 1 + 4 * d)?,
            ])?)?;
            claims.extend_from_slice(&phase(s.id, j, pieces.len() as u8));
            for value in table.point.iter().chain([&table.claims[0].1]) {
                claims.extend_from_slice(value.to_le_bytes().as_ref());
            }
            for (piece, value) in pieces.iter().zip(values) {
                claims.push(piece.id);
                claims.extend_from_slice(value.to_le_bytes().as_ref());
            }
            absorb(t, AbsorbLabel::LookupMultiplicityClaims, &claims)?;
            drop(claims);
            let mut mu_openings = reserve(pieces.len())?;
            for (a, (piece, value)) in pieces.iter().zip(values).enumerate() {
                mu_openings.push(opened(
                    verify_opening(
                        t,
                        multiplicities[j],
                        Functional {
                            id: u64::from(piece.id),
                            a: &piece.a,
                            b: &piece.b,
                            value,
                        },
                        packet.multiplicities[a],
                    ),
                    hashes,
                )?);
            }
            repetitions.push(RepetitionRecord {
                lookup,
                table,
                selected,
                originals,
                multiplicities: mu_openings,
            });
        }
        Ok(LookupRecord {
            parameters,
            repetitions,
        })
    }
}
