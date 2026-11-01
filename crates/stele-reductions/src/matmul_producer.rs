//! RFC-0007 A2 §§2,3,6: one original-source visit, retained A/B and actual A4/A9.
//! Partial preparation costs L*n*d + L*d*m base-to-K MACs. Dense folding and
//! coefficient/partial costs remain A4's; both A9 openings keep their full wires.
use super::{add, mul, pcs_error, reserve, stacked_error, Context, Error, Failure, Statement};
use alloc::vec::Vec;
use stele_gkr::stacked;
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    Functional, PreparedSource, RetainedRow, RetainedRowWork, Usage, VerifiedCertificate,
};

/// Success-only child observations, never proof authority or a complete memory ledger.
/// Retained rows count original message visits and their own payload capacities;
/// Dense retains its documented field-only scope. A1/A9/codec/metadata overlaps,
/// registration, verifier allocations and process RSS remain separate obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Work {
    /// Actual X,W retained-row constructors, including zero-weight source rows.
    pub retained_rows: [RetainedRowWork; 2],
    /// Actual A4 folding execution, sampled before its tables are dropped.
    pub dense: stacked::Work,
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
        let proof = dense
            .prove(t)
            .map_err(|failure| stacked_error(failure.cause))?;
        let work = Work {
            retained_rows: rows.each_ref().map(RetainedRow::work),
            dense: dense.work(),
        };
        let point = dense.into_point().map_err(stacked_error)?;
        drop(prepared);
        wire.push(1);
        for value in proof.rounds.iter().flatten().chain(&proof.final_values) {
            wire.extend_from_slice(value.to_le_bytes().as_ref());
        }
        // The actual A1 producer checked exactly X,W and coefficient finals.
        let values = [proof.final_values[0], proof.final_values[1]];
        drop(proof);
        let columns = eq(&point)?;
        for index in 0..2 {
            let result = rows[index].opening(
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
                Ok((_, usage)) => usage,
                Err(failure) => &failure.usage,
            };
            // A9 production copies prepared paths; its actual ordinary hash count is zero.
            hashes += usage.non_transcript.hash_evaluations;
            debug_assert!(hashes <= context.maximum_hashes);
            let opening = result.map_err(|failure| pcs_error(failure.cause))?.0;
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
