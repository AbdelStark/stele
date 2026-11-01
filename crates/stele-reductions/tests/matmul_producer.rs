//! RFC-0007 A2 §§2,3,6: native retained rows, exact caps and complete consumers.
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked::Limits;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource};
use stele_reductions::matmul::{self, Error, Statement};

const LIMITS: Limits = Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 12,
    partial_entries: 1 << 12,
    axis_entries: 0,
};

fn producer<K: ChallengeField + CodeField + Eq>()
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
            .map(|i| M31::from_i64(if zero == 0 { 0 } else { (3 * i + 1) as i64 }))
            .collect();
        let w: Vec<_> = (0..columns * size)
            .map(|i| M31::from_i64(if zero == 1 { 0 } else { (5 * i + 2) as i64 }))
            .collect();
        // Direct logical X*W evaluation is fixture work, independent of the producer's partial rows.
        let eq = [
            stele_poly::eq_table(&point[..usize::from(h)]).expect("valid fixture"),
            stele_poly::eq_table(&point[usize::from(h)..usize::from(h + a)])
                .expect("valid fixture"),
            stele_poly::eq_table(&point[usize::from(h + a)..]).expect("valid fixture"),
        ];
        let mut value = K::from_i64(0);
        for (l, el) in eq[0].iter().enumerate() {
            for (i, ei) in eq[1].iter().enumerate() {
                for (j, ej) in eq[2].iter().enumerate() {
                    for k in 0..inner {
                        let product = x[i * size + l * inner + k] * w[j * size + l * inner + k];
                        value = value + *el * *ei * *ej * K::from_i64(i64::from(product.as_u32()));
                    }
                }
            }
        }
        let px = PreparedSource::<K>::new(101, a, h + b, 1, &x, &mut HashUsage::default())
            .expect("valid fixture");
        let pw = PreparedSource::<K>::new(102, c, h + b, 2, &w, &mut HashUsage::default())
            .expect("valid fixture");
        let cx = verify_certificate(*px.source(), &px.certificate().expect("valid fixture").0)
            .expect("valid fixture")
            .0;
        let cw = verify_certificate(*pw.source(), &pw.certificate().expect("valid fixture").0)
            .expect("valid fixture")
            .0;
        let expected = Statement {
            id: 105,
            output_id: 103,
            coefficient_id: 104,
            inputs: [101, 102],
            bits,
            point: &point,
            value,
        };
        let retained_entries = 3 * size + rows + columns;
        let mut pt = Transcript::<K>::new(b"matmul native producer").expect("valid fixture");
        let (wire, usage, work) = matmul::prove_measured(
            &mut pt,
            &expected,
            [&px, &pw],
            [&cx, &cw],
            LIMITS,
            retained_entries,
        )
        .expect("valid fixture");
        for (observed, elements) in work.retained_rows.iter().zip([x.len(), w.len()]) {
            assert_eq!(observed.source_visits, 1);
            assert_eq!(observed.source_elements, elements);
            assert!(observed.retained_bytes >= size * core::mem::size_of::<K>());
        }
        assert_eq!(work.dense.rounds, usize::from(h + b));
        assert_eq!(usage.transcript, pt.usage());
        assert_eq!(usage.non_transcript, HashUsage::default());
        let mut vt = Transcript::<K>::new(b"matmul native producer").expect("valid fixture");
        let (record, consumed) =
            matmul::verify(&mut vt, &expected, [&cx, &cw], &wire, LIMITS).expect("valid fixture");
        assert_eq!(usage.transcript, consumed.transcript);
        assert_eq!(record.sc().numerator, 3 * u64::from(h + b));
        assert_eq!(record.openings()[0].id(), 101);
        assert_eq!(record.openings()[1].id(), 102);
        assert_eq!(record.points()[0].len(), usize::from(a + h + b));
        assert_eq!(record.points()[1].len(), usize::from(c + h + b));
        assert!(pt.challenge(ChallengeLabel::Sumcheck) == vt.challenge(ChallengeLabel::Sumcheck));
        let mut repeat = Transcript::<K>::new(b"matmul native producer").expect("valid fixture");
        assert_eq!(
            matmul::prove(
                &mut repeat,
                &expected,
                [&px, &pw],
                [&cx, &cw],
                LIMITS,
                retained_entries
            )
            .expect("valid fixture"),
            (wire, usage)
        );

        let mut different_x = x.clone();
        let mut different_w = w.clone();
        different_x[0] = different_x[0] + M31::from_i64(1);
        different_w[0] = different_w[0] + M31::from_i64(1);
        let wrong_x =
            PreparedSource::<K>::new(101, a, h + b, 1, &different_x, &mut HashUsage::default())
                .expect("valid fixture");
        let wrong_w =
            PreparedSource::<K>::new(102, c, h + b, 2, &different_w, &mut HashUsage::default())
                .expect("valid fixture");
        assert_ne!(wrong_x.source().root(), px.source().root());
        assert_ne!(wrong_w.source().root(), pw.source().root());
        for (sources, limit, cap, cause) in [
            (
                [&wrong_x, &pw],
                LIMITS,
                retained_entries,
                Error::Pcs(stele_pcs::Error::CertificateContext),
            ),
            (
                [&px, &wrong_w],
                LIMITS,
                retained_entries,
                Error::Pcs(stele_pcs::Error::CertificateContext),
            ),
            (
                [&pw, &px],
                LIMITS,
                retained_entries,
                Error::Pcs(stele_pcs::Error::CertificateContext),
            ),
            ([&px, &pw], LIMITS, retained_entries - 1, Error::Capacity),
            (
                [&px, &pw],
                Limits {
                    prepared_entries: 0,
                    ..LIMITS
                },
                retained_entries,
                Error::Capacity,
            ),
            (
                [&px, &pw],
                Limits {
                    proof_bytes: 0,
                    ..LIMITS
                },
                retained_entries,
                Error::Capacity,
            ),
        ] {
            let mut t = Transcript::<K>::new(b"matmul producer preflight").expect("valid fixture");
            let before = t.usage();
            let error = matmul::prove(&mut t, &expected, sources, [&cx, &cw], limit, cap)
                .expect_err("invalid producer input");
            assert_eq!(error.cause, cause);
            assert_eq!(error.usage.transcript, before);
            assert_eq!(error.usage.non_transcript, HashUsage::default());
            assert_eq!(t.usage(), before);
        }
        let mut t = Transcript::<K>::new(b"matmul wrong claimed value").expect("valid fixture");
        let before = t.usage();
        let false_claim = Statement {
            value: value + K::from_i64(1),
            ..expected
        };
        let error = matmul::prove(
            &mut t,
            &false_claim,
            [&px, &pw],
            [&cx, &cw],
            LIMITS,
            retained_entries,
        )
        .expect_err("invalid producer input");
        let cause = if h + b == 0 {
            stele_sumcheck::Error::FinalEvaluationMismatch
        } else {
            stele_sumcheck::Error::RoundSumMismatch
        };
        assert_eq!(
            error.cause,
            Error::Stacked(stele_gkr::stacked::Error::Sumcheck(cause))
        );
        assert_eq!(error.usage.transcript, t.usage());
        let mut prefix = before;
        prefix.hash_evaluations += 3;
        prefix.state_updates += 3;
        assert_eq!(t.usage(), prefix);
        assert_eq!(error.usage.non_transcript, HashUsage::default());
    }
}

#[test]
fn matches_reference_qm31_matmul_producer() {
    producer::<QM31>();
}

#[test]
fn matches_reference_om31_matmul_producer() {
    producer::<OM31>();
}
