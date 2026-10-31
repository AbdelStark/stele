//! RFC-0010 A9 §§1,3,4: source bytes and unverified wire parsing only.
use stele_field::{OM31, QM31};
use stele_hash::ChallengeField;
use stele_pcs::{Error, ProofKind, Source};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("fixture ASCII"), 16)
                .expect("fixture hex")
        })
        .collect()
}

fn corpus<K: ChallengeField>() {
    for line in include_str!("fixtures/field-wire.jsonl").lines() {
        let case: serde_json::Value = serde_json::from_str(line).expect("fixture JSON");
        if case["degree"].as_u64().expect("fixture integer") as usize != K::DEGREE {
            continue;
        }
        let expected = unhex(case["source"].as_str().expect("fixture hex string"));
        let root = expected[expected.len() - 32..]
            .try_into()
            .expect("32-byte fixture root");
        let source = Source::<K>::new(
            41,
            case["ell"].as_u64().expect("fixture integer") as u8,
            case["m"].as_u64().expect("fixture integer") as u8,
            case["blowup"].as_u64().expect("fixture integer") as u8,
            root,
        )
        .expect("valid fixture source");
        assert_eq!(source.bytes().as_slice(), expected);
        for (key, kind) in [
            ("certificate", ProofKind::Certificate),
            ("opening", ProofKind::Opening),
        ] {
            let bytes = unhex(case[key].as_str().expect("fixture hex string"));
            let wire = source.parse(kind, &bytes).expect("valid fixture wire");
            assert_eq!(source.proof_size(kind).expect("fixture size"), bytes.len());
            assert_eq!(wire.row_bytes().len(), 4 * K::DEGREE * source.columns());
            assert_eq!(wire.responses().len(), usize::from(source.queries(kind)));
            for response in wire.responses() {
                assert_eq!(response.payload.len(), 4 * source.rows());
                assert_eq!(response.siblings.len(), 32 * source.path_height());
            }
            assert_eq!(
                source.parse(kind, &bytes[..bytes.len() - 1]).err(),
                Some(Error::ProofShape)
            );
            let mut changed = bytes.clone();
            changed.push(0);
            assert_eq!(source.parse(kind, &changed).err(), Some(Error::ProofShape));
            changed = bytes.clone();
            changed[0] = 2;
            assert_eq!(source.parse(kind, &changed).err(), Some(Error::ProofShape));
            for offset in (1..1 + 4 * K::DEGREE * source.columns()).step_by(4) {
                changed = bytes.clone();
                changed[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
                assert_eq!(
                    source.parse(kind, &changed).err(),
                    Some(Error::NoncanonicalField)
                );
            }
            // Payload interpretation follows authentication in the actual consumer.
            changed = bytes;
            let payload = 1 + 4 * K::DEGREE * source.columns();
            changed[payload..payload + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
            assert!(source.parse(kind, &changed).is_ok());
        }
    }
}

#[test]
fn matches_reference_qm31_source_and_wire() {
    corpus::<QM31>();
}

#[test]
fn matches_reference_om31_source_and_wire() {
    corpus::<OM31>();
}

#[test]
fn rejects_unsupported_sources_without_allocation() {
    for (ell, m, blowup) in [(31, 0, 1), (0, 30, 1), (0, 29, 2), (0, 0, 0), (0, 0, 3)] {
        assert_eq!(
            Source::<QM31>::new(1, ell, m, blowup, [0; 32]).err(),
            Some(Error::UnsupportedSource)
        );
    }
}

#[test]
fn accepts_maximum_source_shape_without_domain_allocation() {
    let source = Source::<OM31>::new(u64::MAX, 30, 29, 1, [255; 32]).expect("maximum source");
    assert_eq!(source.rows(), 1 << 30);
    assert_eq!(source.columns(), 1 << 29);
    assert_eq!(source.descriptor().count, 1 << 30);
    assert_eq!(source.descriptor().width, 1 << 32);
    assert_eq!(source.queries(ProofKind::Certificate), 495);
    assert_eq!(source.queries(ProofKind::Opening), 223);
    let expected = usize::try_from(2_143_189_155_905u64).map_err(|_| Error::Capacity);
    assert_eq!(source.proof_size(ProofKind::Certificate), expected);
}
