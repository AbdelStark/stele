//! RFC-0007 A2 §§2,3,6: one original-source visit, retained A/B and actual A4/A9.
//! Partial preparation costs L*n*d + L*d*m base-to-K MACs. Dense folding and
//! coefficient/partial costs remain A4's; both A9 openings keep their full wires.
use super::{
    add, bytes, mul, pcs_error, reserve, stacked_error, Context, Error, Failure, Statement,
};
use alloc::vec::Vec;
use stele_gkr::stacked;
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    Functional, PreparedSource, RetainedRow, RetainedRowWork, Usage, VerifiedCertificate,
};

/// Success-only actual owned Vec capacities and child work, never proof authority.
/// Excludes borrowed sources/certificates/statement, stack (including round slots),
/// allocator metadata and process RSS. Registration remains a separate obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Work {
    /// Actual X,W retained-row constructors, including zero-weight source rows.
    pub retained_rows: [RetainedRowWork; 2],
    /// Actual A4 folding execution, sampled before its tables are dropped.
    pub dense: stacked::Work,
    /// Expected frame and inline term's heap factor buffer.
    pub context_bytes: usize,
    /// Actual A4 descriptor and nested Instance buffers, dropped after folding.
    pub prepared_bytes: usize,
    /// Full outer wire capacity, reserved before row construction.
    pub proof_bytes: usize,
    /// Actual X,W row-weight capacities, retained throughout.
    pub row_weights_bytes: [usize; 2],
    /// Full Dense tables, heap headers and captured-point capacity during folding.
    pub dense_bytes: usize,
    /// Captured point moved out of Dense before opening preparation.
    pub captured_point_bytes: usize,
    /// Shared column weights, allocated after dropping the logical A1 proof.
    pub column_weights_bytes: usize,
    /// Actual A1 execution, including scalar Instance/Final events.
    pub a1: stele_sumcheck::ProverWork,
    /// Maximum paired A1 prefix + Dense partial + shared result capacity.
    pub round_scratch_peak_bytes: usize,
    /// Actual X,W retained openings, called sequentially.
    pub openings: [stele_pcs::ProverWork; 2],
    /// Stable fold ownership plus the largest actual A1 or paired scratch event.
    pub fold_peak_bytes: usize,
    /// Live opening parent storage plus only that current child's peak.
    pub opening_peak_bytes: [usize; 2],
    /// Largest simultaneously live owned capacity across the successful call.
    pub peak_owned_bytes: usize,
}

fn retained_entries<K>(size: usize, n: usize, m: usize) -> Result<usize, Error> {
    let total = add(mul(3, size)?, add(n, m)?)?;
    for entries in [size, n, m] {
        if mul(entries, core::mem::size_of::<K>())? > isize::MAX as usize {
            return Err(Error::Capacity);
        }
    }
    Ok(total)
}

/// Produce the canonical untrusted wire from the two matching original sources.
/// `retained_row_entries` admits 3*L*d+n+m K entries: A/B, one shared column-eq
/// vector and both immutable row-weight vectors. A4 limits retain their own scopes.
/// Every failure aborts the whole attempt; no verifier replay or record is returned.
pub fn prove<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    expected: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certificates: [&VerifiedCertificate<K>; 2],
    limits: stacked::Limits,
    retained_row_entries: usize,
) -> Result<(Vec<u8>, Usage), Failure> {
    prove_measured(
        t,
        expected,
        sources,
        certificates,
        limits,
        retained_row_entries,
    )
    .map(|(wire, usage, _)| (wire, usage))
}

/// The same producer with the scoped, non-authorizing observations in [`Work`].
pub fn prove_measured<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    expected: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certificates: [&VerifiedCertificate<K>; 2],
    limits: stacked::Limits,
    retained_row_entries: usize,
) -> Result<(Vec<u8>, Usage, Work), Failure> {
    let mut hashes = 0u64;
    let result = (|| {
        let context = Context::new(expected, certificates, limits)?;
        // Check both owners before either RetainedRow traverses an original message.
        for (source, certificate) in sources.iter().zip(certificates) {
            if source.source().bytes() != certificate.record().source().bytes() {
                return Err(Error::Pcs(stele_pcs::Error::CertificateContext));
            }
        }
        let statement = context.statement();
        let prepared = stacked::Prepared::for_certified_sources(&statement, context.limits)
            .map_err(stacked_error)?;
        let [h, a, b, c] = expected.bits.map(usize::from);
        let [size, n, m] = [1usize << (h + b), 1usize << a, 1usize << c];
        if retained_entries::<K>(size, n, m)? > retained_row_entries {
            return Err(Error::Capacity);
        }
        let mut wire = Vec::new();
        reserve(&mut wire, context.wire_size)?;
        let eq = |point: &[K]| stele_poly::eq_table(point).map_err(|_| Error::Capacity);
        let weights = [
            eq(&expected.point[h..h + a])?,
            eq(&expected.point[h + a..h + a + c])?,
        ];
        let rows = [
            RetainedRow::new(sources[0], &weights[0]).map_err(pcs_error)?,
            RetainedRow::new(sources[1], &weights[1]).map_err(pcs_error)?,
        ];
        let mut dense = prepared
            .strategy(&[rows[0].values(), rows[1].values()])
            .map_err(stacked_error)?;
        t.absorb(AbsorbLabel::MatmulStatement, &context.frame)
            .map_err(Error::Transcript)?;
        // A2 bounds h+b by 29; observation storage stays on the stack.
        let mut a1_rounds = [stele_sumcheck::RoundWork::default(); 29];
        let mut dense_rounds = [stacked::DenseRoundWork::default(); 29];
        let (proof, a1) = dense
            .prove_measured(
                t,
                &mut a1_rounds[..context.rounds],
                &mut dense_rounds[..context.rounds],
            )
            .map_err(|failure| stacked_error(failure.cause))?;
        let mut round_scratch_peak_bytes = 0;
        for (a1, dense) in a1_rounds[..context.rounds]
            .iter()
            .zip(&dense_rounds[..context.rounds])
        {
            debug_assert_eq!(a1.values_bytes, dense.values_bytes);
            round_scratch_peak_bytes = round_scratch_peak_bytes.max(add(
                a1.proof_prefix_bytes,
                add(dense.partial_bytes, dense.values_bytes)?,
            )?);
        }
        let mut work = Work {
            retained_rows: rows.each_ref().map(RetainedRow::work),
            dense: dense.work(),
            context_bytes: context.owned_bytes()?,
            prepared_bytes: prepared.owned_bytes().map_err(stacked_error)?,
            proof_bytes: bytes(&wire)?,
            row_weights_bytes: [bytes(&weights[0])?, bytes(&weights[1])?],
            dense_bytes: dense.owned_bytes().map_err(stacked_error)?,
            captured_point_bytes: 0,
            column_weights_bytes: 0,
            a1,
            round_scratch_peak_bytes,
            openings: [stele_pcs::ProverWork::default(); 2],
            fold_peak_bytes: 0,
            opening_peak_bytes: [0; 2],
            peak_owned_bytes: 0,
        };
        let baseline = add(
            add(work.context_bytes, work.proof_bytes)?,
            add(
                add(work.row_weights_bytes[0], work.row_weights_bytes[1])?,
                add(
                    work.retained_rows[0].retained_bytes,
                    work.retained_rows[1].retained_bytes,
                )?,
            )?,
        )?;
        work.fold_peak_bytes = add(
            add(baseline, add(work.prepared_bytes, work.dense_bytes)?)?,
            a1.peak_owned_bytes.max(round_scratch_peak_bytes),
        )?;
        work.peak_owned_bytes = work.fold_peak_bytes;
        let point = dense.into_point().map_err(stacked_error)?;
        work.captured_point_bytes = bytes(&point)?;
        drop(prepared);
        // Serialization allocates nothing; its remaining owners are a subset of the fold peak.
        wire.push(1);
        for value in proof.rounds.iter().flatten().chain(&proof.final_values) {
            wire.extend_from_slice(value.to_le_bytes().as_ref());
        }
        // The actual A1 producer checked exactly X,W and coefficient finals.
        let values = [proof.final_values[0], proof.final_values[1]];
        drop(proof);
        let columns = eq(&point)?;
        work.column_weights_bytes = bytes(&columns)?;
        let opening_baseline = add(
            baseline,
            add(work.captured_point_bytes, work.column_weights_bytes)?,
        )?;
        for index in 0..2 {
            let result = rows[index].opening_measured(
                t,
                certificates[index],
                Functional {
                    id: expected.inputs[index],
                    a: &weights[index],
                    b: &columns,
                    value: values[index],
                },
            );
            let usage = match &result {
                Ok((_, usage, _)) => usage,
                Err(failure) => &failure.usage,
            };
            // A9 production copies prepared paths; its actual ordinary hash count is zero.
            hashes += usage.non_transcript.hash_evaluations;
            debug_assert!(hashes <= context.maximum_hashes);
            let (opening, _, child) = result.map_err(|failure| pcs_error(failure.cause))?;
            work.openings[index] = child;
            work.opening_peak_bytes[index] = add(opening_baseline, child.peak_owned_bytes)?;
            work.peak_owned_bytes = work.peak_owned_bytes.max(work.opening_peak_bytes[index]);
            wire.extend_from_slice(&opening);
        }
        if wire.len() != context.wire_size {
            return Err(Error::ProofShape);
        }
        Ok((wire, work))
    })();
    let usage = Usage {
        transcript: t.usage(),
        non_transcript: HashUsage {
            hash_evaluations: hashes,
            ..HashUsage::default()
        },
    };
    result
        .map(|(wire, work)| (wire, usage, work))
        .map_err(|cause| Failure { cause, usage })
}

#[cfg(test)]
#[test]
fn rejects_retained_allocation_sizes() {
    use stele_field::OM31;
    assert_eq!(retained_entries::<OM31>(4, 2, 8), Ok(22));
    assert_eq!(
        retained_entries::<OM31>(usize::MAX, 1, 1),
        Err(Error::Capacity)
    );
    assert_eq!(
        retained_entries::<OM31>(1, usize::MAX, 1),
        Err(Error::Capacity)
    );
    let oversized = isize::MAX as usize / core::mem::size_of::<OM31>() + 1;
    assert_eq!(
        retained_entries::<OM31>(1, oversized, 1),
        Err(Error::Capacity)
    );
}
