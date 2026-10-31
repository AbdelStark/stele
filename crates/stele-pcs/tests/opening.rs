//! RFC-0010 A9 §4: native functional openings against independent complete bytes.
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, verify_opening, Error, Functional, PreparedSource, ProofKind};

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
        let mut verifier = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (record, usage) =
            verify_opening(&mut verifier, &verified, functional, &proof).expect("opening");
        assert!(core::ptr::eq(record.certificate(), verified.record()));
        assert_eq!(record.id(), 12);
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
            if offset == 1 {
                assert_eq!(failure.usage.transcript, before);
            } else {
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    1 + prepared.source().path_height() as u64
                );
            }
        }
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
#[test]
fn matches_reference_qm31_openings() {
    corpus::<QM31>();
}
#[test]
fn matches_reference_om31_openings() {
    corpus::<OM31>();
}
