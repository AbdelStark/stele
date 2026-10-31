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
        assert_eq!(source.bytes().as_slice(), expected);
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
