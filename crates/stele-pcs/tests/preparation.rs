//! RFC-0010 A9 §1: canonical producer columns against the independent full-wire oracle.
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{merkle, ChallengeField, HashUsage};
use stele_pcs::{Error, PreparedSource, ProofKind};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}
fn corpus<K: ChallengeField>() {
    let mut cases = 0;
    for line in include_str!("fixtures/field-wire.jsonl").lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture JSON");
        if v["degree"].as_u64().expect("degree") != K::DEGREE as u64 {
            continue;
        }
        let (ell, m, b) = (
            v["ell"].as_u64().expect("ell") as u8,
            v["m"].as_u64().expect("m") as u8,
            v["blowup"].as_u64().expect("b") as u8,
        );
        // Same explicit inputs as the independent Python fixture generator.
        let message: Vec<_> = (0..1 << ell)
            .flat_map(|i| (0..1 << m).map(move |j| M31::from_i64((i + 2) * (j + 3))))
            .collect();
        let mut usage = HashUsage::default();
        let prepared =
            PreparedSource::<K>::new(41, ell, m, b, &message, &mut usage).expect("source");
        let source = prepared.source();
        let expected = unhex(v["source"].as_str().expect("source bytes"));
        assert_eq!(&source.bytes()[..], expected);
        assert!(core::ptr::eq(prepared.message(), message.as_slice()));
        let root: [u8; 32] = expected[73..].try_into().expect("root");
        let n = source.descriptor().count;
        assert_eq!(usage.hash_evaluations, 2 * n - 1);
        let proof = unhex(v["certificate"].as_str().expect("certificate"));
        let wire = source
            .parse(ProofKind::Certificate, &proof)
            .expect("oracle wire");
        for index in 0..n {
            let column = prepared.response(index).expect("column");
            let siblings: Vec<u8> = column.siblings.iter().flatten().copied().collect();
            assert!(wire
                .responses()
                .any(|r| r.payload == column.payload && r.siblings == siblings));
            assert_eq!(
                merkle::verify(
                    source.descriptor(),
                    &root,
                    index,
                    merkle::Opening {
                        payload: column.payload,
                        siblings: &column.siblings
                    }
                ),
                Ok(())
            );
            let repeated = prepared.response(index).expect("repeated response");
            assert_eq!(repeated.payload, column.payload);
            assert_eq!(repeated.siblings, column.siblings);
        }
        assert_eq!(usage.hash_evaluations, 2 * n - 1); // Producing paths hashes nothing.
        let work = prepared.work();
        assert_eq!(work.borrowed_message_bytes, 4 * message.len());
        assert!(work.encoded_columns_bytes >= 4 * source.rows() * n as usize);
        assert!(
            work.encoder_peak_bytes
                >= 8 * n as usize - 4 + source.path_height() * core::mem::size_of::<Vec<M31>>()
        );
        assert!(work.merkle_nodes_bytes >= 32 * (2 * n as usize - 1));
        assert!(work.leaf_references_bytes >= n as usize * core::mem::size_of::<&[u8]>());
        assert_eq!(
            work.peak_owned_bytes,
            work.encoded_columns_bytes
                + work
                    .encoder_peak_bytes
                    .max(work.leaf_references_bytes + work.merkle_nodes_bytes)
        );
        let mut changed = message.clone();
        changed[0] = changed[0] + M31::ONE;
        let other =
            PreparedSource::<K>::new(41, ell, m, b, &changed, &mut usage).expect("changed source");
        assert_ne!(other.source().bytes(), source.bytes());
        let column = other.response(0).expect("changed response");
        assert_eq!(
            merkle::verify(
                source.descriptor(),
                &root,
                0,
                merkle::Opening {
                    payload: column.payload,
                    siblings: &column.siblings
                }
            ),
            Err(merkle::Error::RootMismatch)
        );
        for index in [n, u64::MAX] {
            assert_eq!(
                prepared.response(index).err(),
                Some(Error::Merkle(merkle::Error::InvalidIndex))
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}
#[test]
fn matches_reference_qm31_prepared_columns() {
    corpus::<QM31>();
}
#[test]
fn matches_reference_om31_prepared_columns() {
    corpus::<OM31>();
}

#[test]
fn rejects_preparation_shape_and_hash_overflow() {
    let mut usage = HashUsage::default();
    assert_eq!(
        PreparedSource::<QM31>::new(41, 0, 0, 1, &[M31::ONE; 2], &mut usage).err(),
        Some(Error::MessageShape)
    );
    assert_eq!(usage, HashUsage::default());
    for (ell, m, b, expected) in [
        (0, 0, 1, Error::MessageShape),
        (0, 29, 1, Error::MessageShape),
        (31, 0, 1, Error::UnsupportedSource),
        (0, 30, 1, Error::UnsupportedSource),
    ] {
        assert_eq!(
            PreparedSource::<QM31>::new(41, ell, m, b, &[], &mut usage).err(),
            Some(expected)
        );
        assert_eq!(usage, HashUsage::default());
    }
    usage.hash_evaluations = u64::MAX - 2;
    let before = usage;
    assert_eq!(
        PreparedSource::<OM31>::new(41, 0, 0, 1, &[M31::ONE], &mut usage).err(),
        Some(Error::Merkle(merkle::Error::UsageOverflow))
    );
    assert_eq!(usage, before);
}

#[test]
fn matches_reference_owned_prepared_source() {
    use stele_hash::Transcript;
    use stele_pcs::{verify_certificate, verify_opening, verify_point, Policy, RetainedRow};
    let (ell, m, b) = (2u8, 4u8, 2u8);
    let message: Vec<M31> = (0..1 << (ell + m))
        .map(|i| M31::from_i64(i as i64 * 7 - 19))
        .collect();
    let base_source = stele_pcs::Source::<QM31>::new(77, ell, m, b, [0; 32]).expect("source");
    let code = base_source.code_id().to_vec();
    let point: Vec<QM31> = (0..(ell + m) as i64)
        .map(|i| QM31::from_i64(i + 5))
        .collect();
    let value = stele_poly::Mle::new(
        message
            .iter()
            .map(|&v| QM31::from_i64(i64::from(v.as_u32())))
            .collect(),
    )
    .expect("mle")
    .partial_evaluate(&point)
    .expect("eval")
    .values()[0];

    for development in [false, true] {
        let mut usage_borrowed = HashUsage::default();
        let mut usage_owned = HashUsage::default();
        let borrowed = if development {
            PreparedSource::<QM31>::from_code_id_development(
                77,
                ell,
                &code,
                &message,
                &mut usage_borrowed,
            )
            .expect("borrowed dev")
        } else {
            PreparedSource::<QM31>::from_code_id_policy(
                77,
                ell,
                &code,
                &message,
                &mut usage_borrowed,
                Policy::One,
            )
            .expect("borrowed p1")
        };
        let owned: PreparedSource<'static, QM31> = if development {
            PreparedSource::<QM31>::from_code_id_development_owned(
                77,
                ell,
                &code,
                message.clone(),
                &mut usage_owned,
            )
            .expect("owned dev")
        } else {
            PreparedSource::<QM31>::from_code_id_policy_owned(
                77,
                ell,
                &code,
                message.clone(),
                &mut usage_owned,
                Policy::One,
            )
            .expect("owned p1")
        };
        assert_eq!(usage_owned, usage_borrowed);
        assert_eq!(owned.source().bytes(), borrowed.source().bytes());
        assert_eq!(owned.message(), message.as_slice());
        assert_eq!(borrowed.message(), message.as_slice());
        assert_eq!(owned.message_reads(), message.len());
        assert_eq!(owned.message_reads(), borrowed.message_reads());
        assert_eq!(owned.work().borrowed_message_bytes, 0);
        assert_eq!(
            owned.work().peak_owned_bytes,
            borrowed.work().peak_owned_bytes + 4 * message.len()
        );
        let (cert_b, _) = borrowed.certificate().expect("cert b");
        let (cert_o, _) = owned.certificate().expect("cert o");
        assert_eq!(cert_o, cert_b);
        assert_eq!(owned.message_reads(), borrowed.message_reads());
        let (verified, _) = verify_certificate(*owned.source(), &cert_o).expect("verify cert");
        let mut tb = Transcript::<QM31>::new(b"owned-test").expect("tb");
        let mut to = Transcript::<QM31>::new(b"owned-test").expect("to");
        let (open_b, _) = borrowed
            .opening_point(&mut tb, &verified, 0, &point, value)
            .expect("open b");
        let (open_o, _) = owned
            .opening_point(&mut to, &verified, 0, &point, value)
            .expect("open o");
        assert_eq!(open_o, open_b);
        assert_eq!(owned.message_reads(), borrowed.message_reads());
        assert!(owned.message_reads() >= 3 * message.len());
        let mut tv = Transcript::<QM31>::new(b"owned-test").expect("tv");
        verify_point(&mut tv, &verified, 0, &point, value, &open_o).expect("verify owned");

        // RetainedRow over PreparedSource<'static, QM31> reads zero extra source elements at opening.
        let a: Vec<QM31> = (0..1 << ell)
            .map(|i| QM31::from_i64(i as i64 + 3))
            .collect();
        let b_vec: Vec<QM31> = (0..1 << m).map(|i| QM31::from_i64(i as i64 + 11)).collect();
        let retained = RetainedRow::new(&owned, &a).expect("retained");
        let retained_val: QM31 = retained
            .values()
            .iter()
            .zip(&b_vec)
            .fold(QM31::ZERO, |acc, (&r, &bv)| acc + r * bv);
        let functional = stele_pcs::Functional {
            id: 1,
            a: &a,
            b: &b_vec,
            value: retained_val,
        };
        let mut tr = Transcript::<QM31>::new(b"retained-owned").expect("tr");
        let (ropen, _, work) = retained
            .opening_measured(&mut tr, &verified, functional)
            .expect("retained open");
        assert_eq!(work.source_elements, 0);
        let mut trv = Transcript::<QM31>::new(b"retained-owned").expect("trv");
        verify_opening(&mut trv, &verified, functional, &ropen).expect("verify retained");

        // Spare Vec capacity is counted in owned peak bytes.
        let mut over = Vec::with_capacity(message.len() + 64);
        over.extend_from_slice(&message);
        let cap = over.capacity();
        assert!(cap >= message.len() + 64);
        let mut usage_over = HashUsage::default();
        let owned_over = if development {
            PreparedSource::<QM31>::from_code_id_development_owned(
                77,
                ell,
                &code,
                over,
                &mut usage_over,
            )
            .expect("owned over dev")
        } else {
            PreparedSource::<QM31>::from_code_id_policy_owned(
                77,
                ell,
                &code,
                over,
                &mut usage_over,
                Policy::One,
            )
            .expect("owned over p1")
        };
        assert_eq!(
            owned_over.work().peak_owned_bytes,
            borrowed.work().peak_owned_bytes + 4 * cap
        );
    }

    // Wrong message length rejected cleanly on both owned constructors.
    let mut usage = HashUsage::default();
    assert_eq!(
        PreparedSource::<QM31>::from_code_id_development_owned(
            77,
            ell,
            &code,
            vec![M31::ONE],
            &mut usage,
        )
        .err(),
        Some(Error::MessageShape)
    );
    assert_eq!(usage, HashUsage::default());
    assert_eq!(
        PreparedSource::<QM31>::from_code_id_policy_owned(
            77,
            ell,
            &code,
            vec![M31::ONE],
            &mut usage,
            Policy::One,
        )
        .err(),
        Some(Error::MessageShape)
    );
    assert_eq!(usage, HashUsage::default());
}
