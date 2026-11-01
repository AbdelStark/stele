//! RFC-0006 A4 §§3–5: complete certified closure and preflight/failure observations.
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{Claim, Limits, Order, Prepared, Statement},
};
use stele_hash::{merkle, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind, VerifiedCertificate};
use stele_reductions::{
    prove_stacked_sources, verify_stacked_sources, StackedError, StackedFailure,
};
use stele_sumcheck::Term;

const LIMITS: Limits = Limits {
    descriptor_bytes: 1_000_000,
    proof_bytes: 1_000_000,
    prepared_entries: 4096,
    partial_entries: 1024,
    axis_entries: 128,
};
fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"certified stacked integration").expect("fixture")
}
fn certify<K: ChallengeField + CodeField>(source: &PreparedSource<'_, K>) -> VerifiedCertificate<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (bytes, _) = source.certificate().expect("produce certificate");
    verify_certificate(*source.source(), &bytes)
        .expect("verify certificate")
        .0
}
fn untouched<K: ChallengeField + Eq + core::fmt::Debug, T>(
    action: impl FnOnce(&mut Transcript<K>) -> Result<T, StackedFailure>,
    expected: StackedError,
) {
    let mut t = transcript::<K>();
    let before = t.usage();
    let failure = action(&mut t).err().expect("preflight rejects");
    assert_eq!(failure.cause, expected);
    assert_eq!(failure.usage.transcript, before);
    assert_eq!(failure.usage.non_transcript, HashUsage::default());
    assert_eq!(t.usage(), before);
    assert_eq!(
        t.challenge(ChallengeLabel::Sumcheck).expect("next"),
        transcript::<K>()
            .challenge(ChallengeLabel::Sumcheck)
            .expect("untouched next")
    );
}
fn agreement<K: ChallengeField + CodeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    // Scalar, zero-width layer, all-layer, mixed axes, and a genuinely empty roster.
    for (m, ell, count) in [(0u8, 0u8, 2), (2, 0, 2), (2, 2, 2), (3, 1, 2), (2, 1, 0)] {
        let axes = [
            Axis {
                bits: ell,
                real: 1 << ell,
            },
            Axis {
                bits: m - ell,
                real: 1 << (m - ell),
            },
        ];
        let ids: Vec<_> = (0..count).map(|i| 41 + i as u64).collect();
        let messages: Vec<Vec<_>> = (0..count)
            .map(|i| {
                (0..1 << m)
                    .map(|j| M31::from_i64((j + 2 * i + 1) as i64))
                    .collect()
            })
            .collect();
        let sources: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(i, message)| {
                let row_bits = if i == 0 { m } else { 0 };
                PreparedSource::<K>::new(
                    ids[i],
                    row_bits,
                    m - row_bits,
                    1,
                    message,
                    &mut HashUsage::default(),
                )
                .expect("prepare source")
            })
            .collect();
        let certificates: Vec<_> = sources.iter().map(certify).collect();
        let material: Vec<_> = sources.iter().collect();
        let handles: Vec<_> = certificates.iter().collect();
        let selected = vec![K::from_i64(2); usize::from(ell)];
        for order in [Order::LayerFirst, Order::LayerLast] {
            for coefficient in [None, Some(0), Some(3)] {
                if count == 0 && coefficient.is_some() {
                    continue;
                }
                let terms: Vec<_> = coefficient
                    .into_iter()
                    .map(|c| Term {
                        coefficient: K::from_i64(c),
                        factors: vec![0, 0, 0],
                    })
                    .collect();
                let value = (0..1 << m).fold(K::from_i64(0), |sum, index| {
                    let a = (0..ell).fold(K::from_i64(1), |product, bit| {
                        product
                            * K::from_i64(if index >> (m - 1 - bit) & 1 == 1 {
                                2
                            } else {
                                -1
                            })
                    });
                    let p = coefficient.map_or(K::from_i64(0), |c| {
                        let x = K::from_i64(i64::from(messages[0][index].as_u32()));
                        K::from_i64(c) * x * x * x
                    });
                    sum + a * p
                });
                let record = {
                    let s = Statement {
                        id: 31,
                        axes: &axes,
                        order,
                        output: Claim {
                            id: 50,
                            axes: &[],
                            point: &[],
                            value,
                        },
                        coefficient_id: 90,
                        inputs: &ids,
                        terms: &terms,
                        selectors: &[Some(&selected), None],
                        kind: Kind::Eq,
                        source_id: None,
                    };
                    let mut producer = transcript();
                    let (proof, produced) =
                        prove_stacked_sources(&mut producer, &s, &material, &handles, LIMITS)
                            .expect("actual producer");
                    let openings: Vec<_> = proof.openings.iter().map(Vec::as_slice).collect();
                    let mut verifier = transcript();
                    let (record, observed) = verify_stacked_sources(
                        &mut verifier,
                        &s,
                        &handles,
                        &proof.sumcheck,
                        &openings,
                        LIMITS,
                    )
                    .expect("actual closed consumer");
                    assert_eq!(record.sc().m, u32::from(m));
                    assert_eq!(
                        record.sc().degree,
                        if coefficient.is_some() { 4 } else { 0 }
                    );
                    assert_eq!(
                        record.sc().numerator,
                        u64::from(m) * u64::from(record.sc().degree)
                    );
                    assert_eq!(record.openings().len(), count);
                    let work: u64 = certificates
                        .iter()
                        .map(|c| {
                            let source = c.record().source();
                            u64::from(source.queries(ProofKind::Opening))
                                * (1 + source.path_height() as u64)
                        })
                        .sum();
                    assert_eq!(observed.non_transcript.hash_evaluations, work);
                    assert_eq!(produced.non_transcript, HashUsage::default());
                    assert_eq!(produced.transcript, observed.transcript);
                    assert_eq!(
                        producer.challenge(ChallengeLabel::Sumcheck).expect("next"),
                        verifier.challenge(ChallengeLabel::Sumcheck).expect("next")
                    );
                    record
                };
                for (i, opening) in record.openings().iter().enumerate() {
                    assert_eq!(opening.id(), ids[i]);
                    assert!(core::ptr::eq(
                        opening.certificate(),
                        certificates[i].record()
                    ));
                }
            }
        }
    }
}
fn failures<K: ChallengeField + CodeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [1, 2, 3, 4].map(M31::from_i64);
    let a = PreparedSource::<K>::new(41, 0, 2, 1, &message, &mut HashUsage::default()).expect("A");
    let b = PreparedSource::<K>::new(42, 2, 0, 1, &message, &mut HashUsage::default()).expect("B");
    let ca = certify(&a);
    let cb = certify(&b);
    let s = Statement {
        id: 31,
        axes: &[Axis { bits: 1, real: 2 }; 2],
        order: Order::LayerLast,
        output: Claim {
            id: 50,
            axes: &[],
            point: &[],
            value: K::from_i64(0),
        },
        coefficient_id: 90,
        inputs: &[41, 42],
        terms: &[],
        selectors: &[None, None],
        kind: Kind::Eq,
        source_id: None,
    };
    let (proof, _) = prove_stacked_sources(&mut transcript(), &s, &[&a, &b], &[&ca, &cb], LIMITS)
        .expect("baseline");
    let opens: Vec<_> = proof.openings.iter().map(Vec::as_slice).collect();
    for handles in [vec![&ca], vec![&ca, &cb, &ca], vec![&cb, &ca]] {
        untouched(
            |t| verify_stacked_sources(t, &s, &handles, &proof.sumcheck, &opens, LIMITS),
            StackedError::SourceRoster,
        );
    }
    untouched(
        |t| verify_stacked_sources(t, &s, &[&ca, &cb], &proof.sumcheck, &opens[..1], LIMITS),
        StackedError::SourceRoster,
    );
    untouched(
        |t| {
            verify_stacked_sources(
                t,
                &s,
                &[&ca, &cb],
                &proof.sumcheck,
                &[opens[0], opens[1], opens[0]],
                LIMITS,
            )
        },
        StackedError::SourceRoster,
    );
    let short = PreparedSource::<K>::new(41, 0, 1, 1, &message[..2], &mut HashUsage::default())
        .expect("same identity, wrong dimension");
    let short_certificate = certify(&short);
    untouched(
        |t| {
            verify_stacked_sources(
                t,
                &s,
                &[&short_certificate, &cb],
                &proof.sumcheck,
                &opens,
                LIMITS,
            )
        },
        StackedError::SourceRoster,
    );
    let mut bad_a1 = proof.sumcheck.clone();
    bad_a1.final_values.pop();
    untouched(
        |t| verify_stacked_sources(t, &s, &[&ca, &cb], &bad_a1, &opens, LIMITS),
        StackedError::Stacked(stele_gkr::stacked::Error::Sumcheck(
            stele_sumcheck::Error::ProofShape,
        )),
    );
    bad_a1 = proof.sumcheck.clone();
    bad_a1.rounds[0].clear();
    untouched(
        |t| verify_stacked_sources(t, &s, &[&ca, &cb], &bad_a1, &opens, LIMITS),
        StackedError::Stacked(stele_gkr::stacked::Error::Sumcheck(
            stele_sumcheck::Error::ProofShape,
        )),
    );
    let mut malformed = proof.openings[1].clone();
    malformed[0] = 2;
    untouched(
        |t| {
            verify_stacked_sources(
                t,
                &s,
                &[&ca, &cb],
                &proof.sumcheck,
                &[opens[0], &malformed],
                LIMITS,
            )
        },
        StackedError::Pcs(stele_pcs::Error::ProofShape),
    );
    malformed = proof.openings[1].clone();
    malformed[1..5].copy_from_slice(&M31::MODULUS.to_le_bytes());
    untouched(
        |t| {
            verify_stacked_sources(
                t,
                &s,
                &[&ca, &cb],
                &proof.sumcheck,
                &[opens[0], &malformed],
                LIMITS,
            )
        },
        StackedError::Pcs(stele_pcs::Error::NoncanonicalField),
    );
    for limits in [
        Limits {
            descriptor_bytes: 0,
            ..LIMITS
        },
        Limits {
            proof_bytes: 0,
            ..LIMITS
        },
        Limits {
            prepared_entries: 0,
            ..LIMITS
        },
        Limits {
            partial_entries: 0,
            ..LIMITS
        },
    ] {
        untouched(
            |t| verify_stacked_sources(t, &s, &[&ca, &cb], &proof.sumcheck, &opens, limits),
            StackedError::Capacity,
        );
        untouched(
            |t| prove_stacked_sources(t, &s, &[&a, &b], &[&ca, &cb], limits),
            StackedError::Capacity,
        );
    }
    let prepared = Prepared::for_certified_sources(&s, LIMITS).expect("mode-1 sizes");
    let descriptor_bytes = prepared.bytes().len()
        + prepared.instance().encoded_len().expect("A1 bytes")
        + 14
        + 2 * 137
        + a.source().opening_frame_size().expect("A frame")
        + b.source().opening_frame_size().expect("B frame");
    let k = 4 * usize::from(<K as CodeField>::DEGREE);
    let proof_bytes = proof
        .sumcheck
        .rounds
        .iter()
        .map(|r| 12 + r.len() * k)
        .sum::<usize>()
        + 12
        + proof.sumcheck.final_values.len() * k
        + proof.openings.iter().map(Vec::len).sum::<usize>();
    let exact = Limits {
        descriptor_bytes,
        proof_bytes,
        ..LIMITS
    };
    let _ = verify_stacked_sources(
        &mut transcript(),
        &s,
        &[&ca, &cb],
        &proof.sumcheck,
        &opens,
        exact,
    )
    .expect("exact complete budgets");
    let (again, _) = prove_stacked_sources(&mut transcript(), &s, &[&a, &b], &[&ca, &cb], exact)
        .expect("exact producer budgets");
    assert_eq!(again, proof);
    for limit in [
        Limits {
            descriptor_bytes: descriptor_bytes - 1,
            ..exact
        },
        Limits {
            proof_bytes: proof_bytes - 1,
            ..exact
        },
    ] {
        untouched(
            |t| verify_stacked_sources(t, &s, &[&ca, &cb], &proof.sumcheck, &opens, limit),
            StackedError::Capacity,
        );
        untouched(
            |t| prove_stacked_sources(t, &s, &[&a, &b], &[&ca, &cb], limit),
            StackedError::Capacity,
        );
    }
    untouched(
        |t| prove_stacked_sources(t, &s, &[&a], &[&ca, &cb], LIMITS),
        StackedError::SourceRoster,
    );
    untouched(
        |t| prove_stacked_sources(t, &s, &[&b, &a], &[&ca, &cb], LIMITS),
        StackedError::Pcs(stele_pcs::Error::CertificateContext),
    );
    let mut later = proof.openings[1].clone();
    let row_end = 1 + 4 * usize::from(<K as CodeField>::DEGREE) * b.source().columns();
    later[row_end] ^= 1;
    let mut t = transcript();
    let failure = verify_stacked_sources(
        &mut t,
        &s,
        &[&ca, &cb],
        &proof.sumcheck,
        &[opens[0], &later],
        LIMITS,
    )
    .err()
    .expect("later path");
    assert_eq!(
        failure.cause,
        StackedError::Pcs(stele_pcs::Error::Merkle(merkle::Error::RootMismatch))
    );
    let first_work =
        u64::from(a.source().queries(ProofKind::Opening)) * (1 + a.source().path_height() as u64);
    assert_eq!(
        failure.usage.non_transcript.hash_evaluations,
        first_work + 1 + b.source().path_height() as u64
    );
    assert_eq!(failure.usage.transcript, t.usage());
    let onehot = Statement {
        id: s.id,
        axes: s.axes,
        order: s.order,
        output: Claim {
            id: 50,
            axes: &[],
            point: &[],
            value: K::from_i64(0),
        },
        coefficient_id: 90,
        inputs: s.inputs,
        terms: &[],
        selectors: s.selectors,
        kind: Kind::OnehotSparse {
            row: 0,
            column: 1,
            indices: &[0, 1],
        },
        source_id: Some(99),
    };
    let (onehot_proof, _) =
        prove_stacked_sources(&mut transcript(), &onehot, &[&a, &b], &[&ca, &cb], LIMITS)
            .expect("public coefficient and certified originals");
    let onehot_openings: Vec<_> = onehot_proof.openings.iter().map(Vec::as_slice).collect();
    let axis_limit = Limits {
        axis_entries: 4,
        ..LIMITS
    };
    let _ = verify_stacked_sources(
        &mut transcript(),
        &onehot,
        &[&ca, &cb],
        &onehot_proof.sumcheck,
        &onehot_openings,
        axis_limit,
    )
    .expect("exact two-axis storage");
    untouched(
        |t| {
            verify_stacked_sources(
                t,
                &onehot,
                &[&ca, &cb],
                &onehot_proof.sumcheck,
                &onehot_openings,
                Limits {
                    axis_entries: 3,
                    ..LIMITS
                },
            )
        },
        StackedError::Capacity,
    );
    let padded = Statement {
        axes: &[Axis { bits: 1, real: 1 }, Axis { bits: 1, real: 2 }],
        ..s
    };
    untouched(
        |t| verify_stacked_sources(t, &padded, &[&ca, &cb], &proof.sumcheck, &opens, LIMITS),
        StackedError::SourceRoster,
    );
}
#[test]
fn accepts_qm31_certified_stacked_sources() {
    agreement::<QM31>();
}
#[test]
fn accepts_om31_certified_stacked_sources() {
    agreement::<OM31>();
}
#[test]
fn rejects_qm31_malformed_certified_stacked_sources() {
    failures::<QM31>();
}
#[test]
fn rejects_om31_malformed_certified_stacked_sources() {
    failures::<OM31>();
}
