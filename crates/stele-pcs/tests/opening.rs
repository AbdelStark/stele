//! RFC-0010 A9 §4: native functional openings against independent complete bytes.
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, verify_opening, verify_opening_measured, verify_point,
    verify_point_measured, Error, Failure, Functional, PreparedSource, ProofKind, RetainedRow,
    VerifiedCertificate,
};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}
fn fields<K: ChallengeField>(text: &str) -> Vec<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    unhex(text)
        .chunks_exact(4 * K::DEGREE)
        .map(|bytes| {
            K::from_le_bytes(K::Bytes::try_from(bytes).ok().expect("width")).expect("field")
        })
        .collect()
}
fn corpus<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut cases = 0;
    for (index, line) in include_str!("fixtures/field-wire.jsonl")
        .lines()
        .enumerate()
    {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if v["degree"].as_u64().expect("degree") != u64::from(<K as CodeField>::DEGREE) {
            continue;
        }
        let (ell, m, blowup) = (
            v["ell"].as_u64().expect("ell") as u8,
            v["m"].as_u64().expect("m") as u8,
            v["blowup"].as_u64().expect("b") as u8,
        );
        let message: Vec<_> = (0..1 << ell)
            .flat_map(|i| (0..1 << m).map(move |j| M31::from_i64((i + 2) * (j + 3))))
            .collect();
        let prepared =
            PreparedSource::<K>::new(41, ell, m, blowup, &message, &mut HashUsage::default())
                .expect("prepare");
        let (certificate, _) = prepared.certificate().expect("certificate");
        let (verified, _) = verify_certificate(*prepared.source(), &certificate).expect("verified");
        let (a, b, value) = (
            fields::<K>(v["a"].as_str().expect("a")),
            fields::<K>(v["b"].as_str().expect("b")),
            fields::<K>(v["value"].as_str().expect("value"))[0],
        );
        let functional = Functional {
            id: 12,
            a: &a,
            b: &b,
            value,
        };
        let mut prover = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (proof, produced) = prepared
            .opening(&mut prover, &verified, functional)
            .expect("opening");
        assert_eq!(proof, unhex(v["opening"].as_str().expect("proof")));
        let retained = RetainedRow::new(&prepared, &a).expect("retained row");
        let pointer = retained.values().as_ptr();
        let work = retained.work();
        assert_eq!(work.source_visits, 1);
        assert_eq!(work.source_elements, message.len());
        assert!(work.retained_bytes >= core::mem::size_of_val(retained.values()));
        let row_bytes: Vec<_> = retained
            .values()
            .iter()
            .flat_map(|value| value.to_le_bytes().as_ref().to_vec())
            .collect();
        assert_eq!(
            row_bytes,
            prepared
                .source()
                .parse(ProofKind::Opening, &proof)
                .expect("wire")
                .row_bytes()
        );
        let mut retained_prover = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (retained_proof, retained_usage) = retained
            .opening(&mut retained_prover, &verified, functional)
            .expect("retained opening");
        assert_eq!(retained_proof, proof);
        assert_eq!(retained_usage, produced);
        let mut measured_prover = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (measured_proof, measured_usage, produced_work) = retained
            .opening_measured(&mut measured_prover, &verified, functional)
            .expect("measured opening");
        assert_eq!((&measured_proof, measured_usage), (&proof, produced));
        let source = prepared.source();
        let path = prepared.response(0).expect("path");
        assert_eq!(produced_work.proof_bytes, measured_proof.capacity());
        assert!(produced_work.frame_bytes >= source.opening_frame_size().expect("frame size"));
        assert_eq!(produced_work.weights_bytes, 0);
        assert_eq!(produced_work.source_elements, 0);
        assert_eq!(produced_work.row_values, source.columns());
        assert_eq!(
            produced_work.responses,
            usize::from(source.queries(ProofKind::Opening))
        );
        assert_eq!(produced_work.path_peak_bytes, path.siblings.capacity() * 32);
        assert_eq!(
            produced_work.peak_owned_bytes,
            produced_work.proof_bytes
                + produced_work.frame_bytes.max(produced_work.path_peak_bytes)
        );
        assert_eq!(
            produced_work.column_bytes_copied,
            produced_work.responses * path.payload.len()
        );
        assert_eq!(
            produced_work.path_bytes_copied,
            produced_work.responses * 32 * source.path_height()
        );
        let mut measured_verifier = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (measured_record, verified_usage, verified_work) = verify_opening_measured(
            &mut measured_verifier,
            &verified,
            functional,
            &measured_proof,
        )
        .expect("measured verifier");
        assert!(core::ptr::eq(
            measured_record.certificate(),
            verified.record()
        ));
        assert_eq!(verified_work.weights_bytes, 0);
        assert!(verified_work.frame_bytes >= source.opening_frame_size().expect("frame size"));
        assert!(verified_work.row_bytes >= core::mem::size_of_val(retained.values()));
        let encoded = stele_code::Encoder::from_code_id(&source.code().code_id())
            .expect("encoder")
            .encode_measured(retained.values())
            .expect("encoding");
        assert_eq!(verified_work.encoder, encoded.work);
        assert_eq!(
            verified_work.encoded_bytes,
            encoded.values.capacity() * core::mem::size_of::<K>()
        );
        assert_eq!(
            verified_work.peak_owned_bytes,
            verified_work
                .frame_bytes
                .max(verified_work.row_bytes + verified_work.encoder.peak_owned_bytes)
                .max(verified_work.encoded_bytes)
        );
        assert_eq!(verified_work.responses, produced_work.responses);
        assert_eq!(
            verified_work.column_bytes_authenticated,
            produced_work.column_bytes_copied
        );
        assert_eq!(
            verified_work.column_bytes_decoded,
            produced_work.column_bytes_copied
        );
        assert_eq!(
            verified_work.path_bytes_copied,
            produced_work.path_bytes_copied
        );
        assert_eq!(verified_work.encoded_values_read, verified_work.responses);
        let mut verifier = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (record, usage) =
            verify_opening(&mut verifier, &verified, functional, &retained_proof).expect("opening");
        assert!(core::ptr::eq(record.certificate(), verified.record()));
        assert_eq!(record.id(), 12);
        assert_eq!(verified_usage, usage);
        assert_eq!(measured_record.id(), record.id());
        assert_eq!(measured_record.queries(), record.queries());
        assert_eq!(measured_record.kind(), record.kind());
        assert_eq!(
            record.queries(),
            prepared.source().queries(ProofKind::Opening)
        );
        assert_eq!(record.kind(), ProofKind::Opening);
        // Only the original certificate owns the record's lifetime.
        let independent = {
            let (a, b, proof) = (a.clone(), b.clone(), proof.clone());
            let mut temporary = Transcript::<K>::new(b"field wire oracle").expect("transcript");
            verify_opening(
                &mut temporary,
                &verified,
                Functional {
                    a: &a,
                    b: &b,
                    ..functional
                },
                &proof,
            )
            .expect("temporary inputs")
            .0
        };
        assert!(core::ptr::eq(independent.certificate(), verified.record()));
        assert_eq!(usage.transcript, produced.transcript);
        assert_eq!(produced.non_transcript, HashUsage::default());
        assert_eq!(
            usage.non_transcript.hash_evaluations,
            u64::from(record.queries()) * (1 + prepared.source().path_height() as u64)
        );
        let expected = include_str!("fixtures/opening-continuation.txt")
            .lines()
            .nth(index)
            .expect("next");
        let next = verifier.challenge(ChallengeLabel::Sumcheck).expect("next");
        assert_eq!(next.to_le_bytes().as_ref(), unhex(expected));
        for t in [&mut measured_prover, &mut measured_verifier] {
            assert_eq!(
                next.to_le_bytes().as_ref(),
                t.challenge(ChallengeLabel::Sumcheck)
                    .expect("measured continuation")
                    .to_le_bytes()
                    .as_ref()
            );
        }
        assert_eq!(
            next.to_le_bytes().as_ref(),
            retained_prover
                .challenge(ChallengeLabel::Sumcheck)
                .expect("next")
                .to_le_bytes()
                .as_ref()
        );
        assert_eq!(
            next.to_le_bytes().as_ref(),
            prover
                .challenge(ChallengeLabel::Sumcheck)
                .expect("next")
                .to_le_bytes()
                .as_ref()
        );
        let (second, produced_again) = prepared
            .opening(
                &mut prover,
                &verified,
                Functional {
                    id: 13,
                    ..functional
                },
            )
            .expect("reuse");
        let copied_weights = a.clone();
        let (retained_second, retained_again) = retained
            .opening(
                &mut retained_prover,
                &verified,
                Functional {
                    id: 13,
                    a: &copied_weights,
                    ..functional
                },
            )
            .expect("retained reuse with equal weights");
        assert_eq!(retained_second, second);
        assert_eq!(retained_again, produced_again);
        let (measured_second, second_usage, second_work) = retained
            .opening_measured(
                &mut measured_prover,
                &verified,
                Functional {
                    id: 13,
                    ..functional
                },
            )
            .expect("measured reuse");
        assert_eq!(
            (measured_second, second_usage),
            (second.clone(), produced_again)
        );
        assert_eq!(second_work, produced_work);
        assert_eq!(retained.values().as_ptr(), pointer);
        assert_eq!(retained.work(), work);
        let (reused, observed_again) = verify_opening(
            &mut verifier,
            &verified,
            Functional {
                id: 13,
                ..functional
            },
            &second,
        )
        .expect("reuse");
        assert!(core::ptr::eq(reused.certificate(), record.certificate()));
        assert_eq!(reused.id(), 13);
        assert_eq!(observed_again.transcript, produced_again.transcript);
        assert!(observed_again.transcript.hash_evaluations > usage.transcript.hash_evaluations);
        assert_eq!(observed_again.non_transcript, usage.non_transcript);
        for short in [
            Functional {
                a: &a[..a.len() - 1],
                ..functional
            },
            Functional {
                b: &b[..b.len() - 1],
                ..functional
            },
        ] {
            let before = verifier.usage();
            let failed = verify_opening(&mut verifier, &verified, short, &proof)
                .err()
                .expect("shape");
            assert_eq!(failed.cause, Error::FunctionalShape);
            assert_eq!(failed.usage.transcript, before);
            assert_eq!(failed.usage.non_transcript, HashUsage::default());
            assert_eq!(verifier.usage(), before);
        }
        let mut t = Transcript::<K>::new(b"wrong scalar").expect("transcript");
        let before = t.usage();
        let wrong = Functional {
            value: value + K::from_i64(1),
            ..functional
        };
        let failed = verify_opening(&mut t, &verified, wrong, &proof)
            .err()
            .expect("value");
        assert_eq!(failed.cause, Error::ValueMismatch);
        assert_eq!(
            failure_pair(&verified, wrong, &proof).cause,
            Error::ValueMismatch
        );
        assert_eq!(failed.usage.transcript.xof_requests, before.xof_requests);
        assert_eq!(
            failed.usage.transcript.hash_evaluations,
            before.hash_evaluations + 2
        );
        assert_eq!(failed.usage.non_transcript, HashUsage::default());
        let other =
            PreparedSource::<K>::new(42, ell, m, blowup, &message, &mut HashUsage::default())
                .expect("other");
        let mut t = Transcript::<K>::new(b"context").expect("transcript");
        let before = t.usage();
        let failed = other
            .opening(&mut t, &verified, functional)
            .expect_err("context");
        assert_eq!(failed.cause, Error::CertificateContext);
        assert_eq!(failed.usage.transcript, before);
        let other_row = RetainedRow::new(&other, &a).expect("other retained row");
        let failed = other_row
            .opening(&mut t, &verified, functional)
            .expect_err("retained source context");
        assert_eq!(failed.cause, Error::RowContext);
        assert_eq!(
            other_row
                .opening_measured(&mut t, &verified, functional)
                .expect_err("measured context"),
            failed
        );
        assert_eq!(failed.usage.transcript, before);
        let mut wrong_weights = a.clone();
        wrong_weights[0] = wrong_weights[0] + K::from_i64(1);
        for weights in [&wrong_weights[..], &a[..a.len() - 1]] {
            let failed = retained
                .opening(
                    &mut t,
                    &verified,
                    Functional {
                        a: weights,
                        ..functional
                    },
                )
                .expect_err("retained weights");
            assert_eq!(failed.cause, Error::RowContext);
            assert_eq!(
                retained
                    .opening_measured(
                        &mut t,
                        &verified,
                        Functional {
                            a: weights,
                            ..functional
                        }
                    )
                    .expect_err("measured weights"),
                failed
            );
            assert_eq!(failed.usage.transcript, before);
            assert_eq!(failed.usage.non_transcript, HashUsage::default());
            assert_eq!(t.usage(), before);
        }
        assert_eq!(
            RetainedRow::new(&prepared, &a[..a.len() - 1])
                .err()
                .expect("short weights"),
            Error::FunctionalShape
        );
        let failed = retained
            .opening(
                &mut t,
                &verified,
                Functional {
                    b: &b[..b.len() - 1],
                    ..functional
                },
            )
            .expect_err("retained columns");
        assert_eq!(failed.cause, Error::FunctionalShape);
        assert_eq!(t.usage(), before);
        let mut ordinary = Transcript::<K>::new(b"wrong retained scalar").expect("transcript");
        let mut cached = Transcript::<K>::new(b"wrong retained scalar").expect("transcript");
        assert_eq!(
            retained
                .opening(&mut cached, &verified, wrong)
                .expect_err("retained value"),
            prepared
                .opening(&mut ordinary, &verified, wrong)
                .expect_err("ordinary value")
        );
        let mut measured = Transcript::<K>::new(b"wrong retained scalar").expect("transcript");
        let mut ordinary = Transcript::<K>::new(b"wrong retained scalar").expect("transcript");
        assert_eq!(
            retained
                .opening_measured(&mut measured, &verified, wrong)
                .expect_err("measured value"),
            retained
                .opening(&mut ordinary, &verified, wrong)
                .expect_err("ordinary value")
        );
        let zeros = vec![K::from_i64(0); a.len()];
        let zero_row = RetainedRow::new(&prepared, &zeros).expect("zero weights");
        assert_eq!(zero_row.work().source_elements, message.len());
        assert_eq!(zero_row.work().source_visits, 1);
        let zero = Functional {
            a: &zeros,
            value: K::from_i64(0),
            ..functional
        };
        let mut zp = Transcript::<K>::new(b"zero retained row").expect("transcript");
        let mut zo = Transcript::<K>::new(b"zero retained row").expect("transcript");
        let mut zv = Transcript::<K>::new(b"zero retained row").expect("transcript");
        let (zero_proof, zero_usage, zero_work) = zero_row
            .opening_measured(&mut zp, &verified, zero)
            .expect("zero retained");
        assert_eq!(
            (zero_proof.clone(), zero_usage),
            prepared
                .opening(&mut zo, &verified, zero)
                .expect("zero ordinary")
        );
        let verified_zero =
            verify_opening(&mut zv, &verified, zero, &zero_proof).expect("zero verified");
        assert_eq!(verified_zero.1.transcript, zero_usage.transcript);
        assert_eq!(zero_work, produced_work);
        // Deterministic bounded arbitrary-byte mutation and truncation over every wire region.
        let mut seed = 0x3141_5926_5358_9793u64;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let row_end = 1 + 4 * usize::from(<K as CodeField>::DEGREE) * prepared.source().columns();
        if record.queries() > 1 {
            let stride = (proof.len() - row_end) / usize::from(record.queries());
            let responses = &proof[row_end..];
            let different = responses
                .chunks_exact(stride)
                .position(|block| block != &responses[..stride])
                .expect("distinct query responses");
            let mut reordered = proof.clone();
            let (first, rest) = reordered[row_end..].split_at_mut(different * stride);
            first[..stride].swap_with_slice(&mut rest[..stride]);
            let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
            let failure = verify_opening(&mut t, &verified, functional, &reordered)
                .err()
                .expect("order");
            assert_eq!(
                failure.cause,
                Error::Merkle(stele_hash::merkle::Error::RootMismatch)
            );
        }
        for (offset, cause) in [
            (1, Error::NoncanonicalField),
            (
                row_end,
                Error::Merkle(stele_hash::merkle::Error::RootMismatch),
            ),
        ] {
            let mut changed = proof.clone();
            changed[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
            let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
            let before = t.usage();
            let failure = verify_opening(&mut t, &verified, functional, &changed)
                .err()
                .expect("bad limb");
            assert_eq!(failure.cause, cause);
            assert_eq!(failure_pair(&verified, functional, &changed), failure);
            if offset == 1 {
                assert_eq!(failure.usage.transcript, before);
            } else {
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    1 + prepared.source().path_height() as u64
                );
            }
        }
        let mut late = proof.clone();
        *late.last_mut().expect("last path") ^= 1;
        let failure = failure_pair(&verified, functional, &late);
        assert_eq!(
            failure.cause,
            Error::Merkle(stele_hash::merkle::Error::RootMismatch)
        );
        assert_eq!(
            failure.usage.non_transcript.hash_evaluations,
            u64::from(record.queries()) * (1 + source.path_height() as u64)
        );
        assert_eq!(
            failure_pair(&verified, functional, &proof[..proof.len() - 1]).cause,
            Error::ProofShape
        );
        point_observations(&prepared, &verified);
        for trial in 0..128 {
            let mut changed = proof.clone();
            let offset = match trial % 3 {
                0 => 0,
                1 => 1 + random() as usize % (row_end - 1),
                _ => row_end + random() as usize % (proof.len() - row_end),
            };
            changed[offset] ^= 1 + (random() % 255) as u8;
            let mut t = Transcript::<K>::new(b"field wire oracle").expect("transcript");
            assert!(verify_opening(&mut t, &verified, functional, &changed).is_err());
            let end = random() as usize % proof.len();
            let mut t = Transcript::<K>::new(b"truncated").expect("transcript");
            let before = t.usage();
            let failed = verify_opening(&mut t, &verified, functional, &proof[..end])
                .err()
                .expect("short");
            assert_eq!(failed.cause, Error::ProofShape);
            assert_eq!(failed.usage.transcript, before);
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}
fn failure_pair<K: ChallengeField + CodeField>(
    certificate: &VerifiedCertificate<K>,
    functional: Functional<'_, K>,
    proof: &[u8],
) -> Failure
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut ordinary = Transcript::<K>::new(b"field wire oracle").expect("transcript");
    let mut measured = Transcript::<K>::new(b"field wire oracle").expect("transcript");
    let failed = verify_opening(&mut ordinary, certificate, functional, proof)
        .err()
        .expect("reject");
    assert_eq!(
        verify_opening_measured(&mut measured, certificate, functional, proof)
            .err()
            .expect("measured reject"),
        failed
    );
    assert_eq!(ordinary.usage(), measured.usage());
    failed
}
fn point_observations<K: ChallengeField + CodeField>(
    prepared: &PreparedSource<'_, K>,
    certificate: &VerifiedCertificate<K>,
) where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let source = prepared.source();
    let ell = source.rows().trailing_zeros() as usize;
    let n = ell + source.columns().trailing_zeros() as usize;
    let point: Vec<_> = (0..n).map(|i| K::from_i64(2 + i as i64)).collect();
    let a = stele_poly::eq_table(&point[..ell]).expect("a");
    let b = stele_poly::eq_table(&point[ell..]).expect("b");
    let row = RetainedRow::new(prepared, &a).expect("row");
    let value = row
        .values()
        .iter()
        .zip(&b)
        .fold(K::from_i64(0), |s, (x, y)| s + *x * *y);
    let functional = Functional {
        id: 21,
        a: &a,
        b: &b,
        value,
    };
    let fresh = || Transcript::<K>::new(b"point allocation parity").expect("transcript");
    let (proof, produced) = prepared
        .opening_point(&mut fresh(), certificate, 21, &point, value)
        .expect("point proof");
    let mut functional_t = fresh();
    let mut point_t = fresh();
    let mut ordinary_t = fresh();
    let (fr, fu, fw) = verify_opening_measured(&mut functional_t, certificate, functional, &proof)
        .expect("functional");
    let (pr, pu, pw) =
        verify_point_measured(&mut point_t, certificate, 21, &point, value, &proof).expect("point");
    let (ordinary, usage) =
        verify_point(&mut ordinary_t, certificate, 21, &point, value, &proof).expect("ordinary");
    assert_eq!((pu, usage), (fu, fu));
    assert_eq!(pu.transcript, produced.transcript);
    assert!(core::ptr::eq(fr.certificate(), pr.certificate()));
    assert!(core::ptr::eq(pr.certificate(), ordinary.certificate()));
    assert_eq!(
        (pr.id(), pr.queries(), pr.kind()),
        (fr.id(), fr.queries(), fr.kind())
    );
    let weights = (a.capacity() + b.capacity()) * core::mem::size_of::<K>();
    assert_eq!(
        pw,
        stele_pcs::VerifierWork {
            weights_bytes: weights,
            peak_owned_bytes: weights + fw.peak_owned_bytes,
            ..fw
        }
    );
    let next = functional_t
        .challenge(ChallengeLabel::Sumcheck)
        .expect("next");
    for t in [&mut point_t, &mut ordinary_t] {
        assert_eq!(
            next.to_le_bytes().as_ref(),
            t.challenge(ChallengeLabel::Sumcheck)
                .expect("next")
                .to_le_bytes()
                .as_ref()
        );
    }
    let mut wrong_point = point.clone();
    wrong_point.push(K::from_i64(0));
    let mut late = proof.clone();
    *late.last_mut().expect("path") ^= 1;
    for (p, v, bytes) in [
        (&wrong_point[..], value, &proof[..]),
        (&point, value, &proof[..proof.len() - 1]),
        (&point, value + K::from_i64(1), &proof),
        (&point, value, &late),
    ] {
        let expected = verify_point(&mut fresh(), certificate, 21, p, v, bytes)
            .err()
            .expect("reject");
        assert_eq!(
            verify_point_measured(&mut fresh(), certificate, 21, p, v, bytes)
                .err()
                .expect("measured reject"),
            expected
        );
    }
}

#[test]
fn matches_reference_qm31_openings() {
    corpus::<QM31>();
}
#[test]
fn matches_reference_om31_openings() {
    corpus::<OM31>();
}
