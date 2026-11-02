//! RFC-0024 §§2.2,2.4: actual affine consumers, not complete outer-control credit.
use super::*;
use crate::matmul::{Error, Statement};
use alloc::vec::Vec;
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};

const LIMITS: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 12,
    partial_entries: 1 << 12,
    axis_entries: 0,
};

fn check<K: ChallengeField + CodeField + Eq>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for (bits, zero) in [
        ([0, 0, 0, 0], 2),
        ([0, 2, 0, 1], 0),
        ([1, 1, 1, 2], 2),
        ([1, 1, 1, 2], 1),
    ] {
        let [h, a, b, c] = bits;
        let [layers, rows, inner, columns] = bits.map(|n| 1usize << n);
        let size = layers * inner;
        let point: Vec<_> = (0..h + a + c)
            .map(|i| K::from_i64(i64::from(i) + 2))
            .collect();
        let x: Vec<_> = (0..rows * size)
            .map(|i| {
                M31::from_i64(if zero == 0 {
                    128
                } else {
                    (17 * i + 121) as i64 % 256
                })
            })
            .collect();
        let w: Vec<_> = (0..columns * size)
            .map(|i| {
                M31::from_i64(if zero == 1 {
                    128
                } else {
                    (23 * i + 133) as i64 % 256
                })
            })
            .collect();
        let eq = [
            stele_poly::eq_table(&point[..usize::from(h)]).expect("valid fixed fixture"),
            stele_poly::eq_table(&point[usize::from(h)..usize::from(h + a)])
                .expect("valid fixed fixture"),
            stele_poly::eq_table(&point[usize::from(h + a)..]).expect("valid fixed fixture"),
        ];
        // Fixture forward computation is separate from the online source visit.
        let mut value = K::from_i64(0);
        for (l, el) in eq[0].iter().enumerate() {
            for (i, ei) in eq[1].iter().enumerate() {
                for (j, ej) in eq[2].iter().enumerate() {
                    for k in 0..inner {
                        let xi = i64::from(x[i * size + l * inner + k].as_u32()) - 128;
                        let wi = i64::from(w[j * size + l * inner + k].as_u32()) - 128;
                        value = value + *el * *ei * *ej * K::from_i64(xi * wi);
                    }
                }
            }
        }
        let px = PreparedSource::<K>::new(101, a, h + b, 1, &x, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let pw = PreparedSource::<K>::new(102, c, h + b, 2, &w, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let cx = verify_certificate(
            *px.source(),
            &px.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let cw = verify_certificate(
            *pw.source(),
            &pw.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let statement = Statement {
            id: 105,
            output_id: 103,
            coefficient_id: 104,
            inputs: [101, 102],
            bits,
            point: &point,
            value,
        };
        let cap = 5 * size + rows + columns;
        let geometry = Geometry::new(bits, [&cx, &cw], LIMITS).expect("valid fixed fixture");
        assert_eq!(geometry.retained_entries, cap);
        let transcript =
            || Transcript::<K>::new(b"private centered matmul").expect("valid fixed fixture");
        let mut pt = transcript();
        let (wire, usage, work) =
            prove_measured(&mut pt, &statement, [&px, &pw], [&cx, &cw], LIMITS, cap)
                .expect("valid fixed fixture");
        assert_eq!(geometry.wire_bytes, wire.len());
        assert_eq!(geometry.preflight([&cx, &cw], &wire), Ok(()));
        assert_eq!(
            geometry.preflight([&cx, &cw], &wire[..wire.len() - 1]),
            Err(Error::ProofShape)
        );
        let mut malformed = wire.clone();
        malformed[1..5].copy_from_slice(&((1u32 << 31) - 1).to_le_bytes());
        assert_eq!(
            geometry.preflight([&cx, &cw], &malformed),
            Err(Error::NoncanonicalField)
        );
        // Compare point-free sizing with the actual instantiated child descriptors.
        let context = crate::matmul::Context::new(
            &statement,
            [&cx, &cw],
            LIMITS,
            crate::matmul::Mode::Centered,
        )
        .expect("valid fixed fixture");
        let child_statement = context.statement();
        let prepared = stacked::Prepared::for_certified_sources(&child_statement, context.limits)
            .expect("valid fixed fixture");
        let arithmetic = prepared
            .instance()
            .encoded_len()
            .expect("valid fixed fixture")
            + 12
            + 3 * core::mem::size_of::<K>()
            + usize::from(h + b) * (12 + 4 * core::mem::size_of::<K>());
        let stack_frame = 110 + core::mem::size_of::<K>() * (point.len() + usize::from(h) + 2);
        let opening_payloads: usize = [px.source(), pw.source()]
            .iter()
            .map(|s| {
                s.opening_frame_size().expect("valid fixed fixture")
                    + s.proof_size(ProofKind::Opening)
                        .expect("valid fixed fixture")
                    - 1
            })
            .sum();
        assert_eq!(
            geometry.public_bytes,
            context.frame.len() + stack_frame + arithmetic + opening_payloads
        );
        for (row, count) in work.inner.retained_rows.iter().zip([x.len(), w.len()]) {
            assert_eq!(row.source_visits, 1);
            assert_eq!(row.source_elements, count);
        }
        assert!(work
            .signed_input_bytes
            .iter()
            .all(|n| *n >= size * core::mem::size_of::<K>()));
        assert!(
            work.preparation_peak_bytes
                >= work.signed_input_bytes.iter().sum::<usize>() + work.inner.dense_bytes
        );
        assert!(work.inner.peak_owned_bytes >= work.preparation_peak_bytes);
        let mut vt = transcript();
        let (record, consumed, observed) =
            verify_measured(&mut vt, &statement, [&cx, &cw], &wire, LIMITS)
                .expect("valid fixed fixture");
        assert_eq!(usage.transcript, consumed.transcript);
        assert_eq!(
            geometry.local_hashes,
            consumed.non_transcript.hash_evaluations
        );
        assert!(pt.challenge(ChallengeLabel::Sumcheck) == vt.challenge(ChallengeLabel::Sumcheck));
        assert_eq!(record.sc().numerator, 3 * u64::from(h + b));
        for index in 0..2 {
            let original = if index == 0 { &x } else { &w };
            let weights =
                stele_poly::eq_table(record.points()[index]).expect("valid fixed fixture");
            let raw = weights
                .iter()
                .zip(original)
                .fold(K::from_i64(0), |s, (e, v)| {
                    s + *e * K::from_i64(i64::from(v.as_u32()))
                });
            assert!(*record.values().get(index).expect("valid fixed fixture") == raw);
            assert!(core::ptr::eq(
                record.openings()[index].certificate(),
                [&cx, &cw][index].record()
            ));
            assert!(observed.openings[index].weights_bytes > 0);
            assert_eq!(work.inner.openings[index].source_elements, 0);
        }
        let mut capped = transcript();
        let before = capped.usage();
        let failure = prove_measured(
            &mut capped,
            &statement,
            [&px, &pw],
            [&cx, &cw],
            LIMITS,
            cap - 1,
        )
        .expect_err("retained-row cap must reject before mutation");
        assert_eq!(failure.cause, Error::Capacity);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        if h + a + b + c == 0 {
            let width = core::mem::size_of::<K>();
            let first_opening = 1 + 3 * width;
            let second_opening = first_opening
                + px.source()
                    .proof_size(ProofKind::Opening)
                    .expect("valid fixed fixture");
            for index in 0..2 {
                // Scalar nonzero opposite factor isolates the actual A1 product check.
                let mut changed = wire.clone();
                let final_at = 1 + index * width;
                let raw = if index == 0 { 121 } else { 133 };
                changed[final_at..final_at + width]
                    .copy_from_slice(K::from_i64(raw - 127).to_le_bytes().as_ref());
                let failure =
                    verify_measured(&mut transcript(), &statement, [&cx, &cw], &changed, LIMITS)
                        .err()
                        .expect("actual rejecting consumer");
                assert_eq!(
                    failure.cause,
                    Error::Stacked(stacked::Error::Sumcheck(
                        stele_sumcheck::Error::FinalEvaluationMismatch
                    ))
                );
                // Honest signed finals survive; exactly one raw OpeningRow cell changes.
                let mut changed = wire.clone();
                let at = [first_opening, second_opening][index] + 1;
                changed[at..at + width]
                    .copy_from_slice(K::from_i64(raw - 128).to_le_bytes().as_ref());
                let mut t = transcript();
                let failure = verify_measured(&mut t, &statement, [&cx, &cw], &changed, LIMITS)
                    .err()
                    .expect("valid fixed fixture");
                assert_eq!(failure.cause, Error::Pcs(stele_pcs::Error::ValueMismatch));
                assert_eq!(failure.usage.transcript, t.usage());
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    if index == 0 {
                        0
                    } else {
                        u64::from(px.source().queries(ProofKind::Opening))
                            * (1 + px.source().path_height() as u64)
                    }
                );
            }
        }
    }
}

#[test]
fn matches_reference_qm31_centered() {
    check::<QM31>();
}
#[test]
fn matches_reference_om31_centered() {
    check::<OM31>();
}
