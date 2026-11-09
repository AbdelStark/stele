//! RFC-0010 A3 items 2-4/10: version-2 sources, Policy 1 and pinned proof sizes.
use stele_code::CodeField;
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{certificate_id, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, verify_point, Error, PreparedSource, ProofKind, Source};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}
fn manifest(j: u8, seed: &[u8]) -> Vec<u8> {
    let mut id = b"stele/expander-seed/v2".to_vec();
    id.push(j);
    id.extend_from_slice(seed);
    id
}

fn corpus<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut cases = 0;
    for line in include_str!("fixtures/expander-wire.jsonl").lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if v["degree"].as_u64() != Some(u64::from(<K as CodeField>::DEGREE)) {
            continue;
        }
        let (ell, j) = (
            v["ell"].as_u64().expect("ell") as u8,
            v["j"].as_u64().expect("j") as u8,
        );
        let code = manifest(j, &unhex(v["seed"].as_str().expect("seed")));
        let message: Vec<_> = (0..1i64 << ell)
            .flat_map(|i| (0..1i64 << (2 * j)).map(move |k| M31::from_i64((i + 2) * (k + 3))))
            .collect();
        let prepared =
            PreparedSource::<K>::from_code_id(41, ell, &code, &message, &mut HashUsage::default())
                .expect("prepare");
        let expected = unhex(v["source"].as_str().expect("source"));
        assert_eq!(&prepared.source().bytes()[..], expected);
        let parsed = Source::<K>::from_bytes(&expected).expect("expected statement bytes");
        assert_eq!(parsed.bytes(), prepared.source().bytes());
        let (certificate, _) = prepared.certificate().expect("certificate");
        assert_eq!(
            Some(certificate.len() as u64),
            v["certificate_bytes"].as_u64()
        );
        let (verified, _) = verify_certificate(parsed, &certificate).expect("v2 consumer");
        assert_eq!(
            verified.record().id().to_vec(),
            unhex(v["certificate_id"].as_str().expect("id"))
        );
        let point: Vec<K> = (0..usize::from(ell + 2 * j))
            .map(|i| {
                let limbs: Vec<u8> = (0..usize::from(<K as CodeField>::DEGREE))
                    .flat_map(|k| (((i + 1) * (k + 2)) as u32).to_le_bytes())
                    .collect();
                K::from_le_bytes(K::Bytes::try_from(&limbs[..]).ok().expect("width"))
                    .expect("canonical")
            })
            .collect();
        let value_bytes = unhex(v["value"].as_str().expect("value"));
        let value = K::from_le_bytes(K::Bytes::try_from(&value_bytes[..]).ok().expect("width"))
            .expect("canonical");
        let mut prover = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        let (opening, _) = prepared
            .opening_point(&mut prover, &verified, 12, &point, value)
            .expect("opening");
        let mut verifier = Transcript::<K>::new(b"field wire oracle").expect("transcript");
        verify_point(&mut verifier, &verified, 12, &point, value, &opening).expect("v2 opening");
        assert_eq!(Some(opening.len() as u64), v["opening_bytes"].as_u64());
        let digest = certificate_id(&expected, &opening, &mut HashUsage::default()).expect("id");
        assert_eq!(
            digest.to_vec(),
            unhex(v["opening_digest"].as_str().expect("digest"))
        );
        let next = verifier.challenge(ChallengeLabel::Sumcheck).expect("next");
        assert_eq!(
            next.to_le_bytes().as_ref(),
            unhex(v["continuation"].as_str().expect("continuation"))
        );
        assert_eq!(
            prover
                .challenge(ChallengeLabel::Sumcheck)
                .expect("next")
                .to_le_bytes()
                .as_ref(),
            next.to_le_bytes().as_ref()
        );
        cases += 1;
    }
    assert_eq!(cases, 1);
}

#[test]
fn matches_reference_qm31_v2_wire() {
    corpus::<QM31>();
}

#[test]
fn matches_reference_om31_v2_wire() {
    corpus::<OM31>();
}

// A3 items 4 and 10: N, D, e, q_c, q_o and complete proof bytes are pinned per J at
// R=1, QM31: 1 + 16*C row bytes plus q*(4R+32*log2 N) response bytes.
#[test]
fn matches_reference_v2_policy_and_proof_sizes() {
    const PINNED: [(u8, u64, u64, u16, u16, usize, usize); 12] = [
        (3, 128, 64, 478, 221, 110_009, 51_413),
        (4, 512, 11, 11489, 5722, 3_358_885, 1_674_921),
        (5, 2048, 41, 13137, 6546, 4_693_157, 2_346_761),
        (6, 8192, 164, 13377, 6666, 5_683_877, 2_865_257),
        (7, 32768, 656, 13438, 6697, 6_766_137, 3_503_493),
        (8, 131072, 2622, 13469, 6708, 8_429_589, 4_724_561),
        (9, 524288, 10486, 13469, 6713, 12_437_333, 8_302_661),
        (10, 2097152, 41944, 13471, 6713, 25_883_613, 21_315_205),
        (11, 8388608, 167773, 13472, 6713, 77_078_145, 72_076_485),
        (12, 33554432, 671089, 13472, 6714, 279_266_945, 273_833_513),
        (
            13,
            134217728,
            2684355,
            13472,
            6714,
            1_085_435_521,
            1_079_569_577,
        ),
        (
            14,
            536870912,
            10737419,
            13472,
            6714,
            4_307_523_201,
            4_301_224_745,
        ),
    ];
    for (j, n, d, q_c, q_o, certificate, opening) in PINNED {
        let source = Source::<QM31>::from_code_id(7, 0, &manifest(j, &[9; 32]), [0; 32])
            .expect("admitted v2 identity");
        let p = source.parameters();
        assert_eq!((p.length, p.distance, p.radius), (n, d, (d - 1) / 3));
        assert_eq!((p.certificate_queries, p.opening_queries), (q_c, q_o));
        assert_eq!(p.setup_term, j >= 4, "RFC-0012 A15 setup term");
        assert_eq!(source.columns() as u64, n / 2);
        assert_eq!(source.proof_size(ProofKind::Certificate), Ok(certificate));
        assert_eq!(source.proof_size(ProofKind::Opening), Ok(opening));
        assert_eq!(source.bytes().len(), 139);
        assert_eq!(
            source.opening_frame_size(),
            Ok(8 + 139 + 32 + 16 * (n as usize / 2 + 2))
        );
    }
    // Circle rate 1/4 comparison (A3 item 10): 314 and 130 responses at m>=7.
    let circle = Source::<QM31>::new(7, 0, 20, 2, [0; 32]).expect("Circle");
    assert_eq!(circle.queries(ProofKind::Certificate), 314);
    assert_eq!(circle.queries(ProofKind::Opening), 130);
    assert_eq!(circle.bytes().len(), 105);
    assert!(!circle.parameters().setup_term);
}

#[test]
fn rejects_unsupported_v2_contexts_before_transcript_work() {
    for j in [0u8, 2, 15, 16] {
        assert_eq!(
            Source::<QM31>::from_code_id(7, 0, &manifest(j, &[9; 32]), [0; 32]).err(),
            Some(Error::UnsupportedSource)
        );
    }
    let mut prefix = manifest(4, &[9; 32]);
    prefix[0] ^= 1;
    for code in [&prefix[..], &manifest(4, &[9; 31])[..], &[][..]] {
        assert_eq!(
            Source::<QM31>::from_code_id(7, 0, code, [0; 32]).err(),
            Some(Error::UnsupportedSource)
        );
    }
    let honest = Source::<QM31>::from_code_id(7, 1, &manifest(4, &[9; 32]), [3; 32])
        .expect("admitted")
        .bytes();
    assert_eq!(
        Source::<QM31>::from_bytes(&honest).map(|s| s.bytes()),
        Ok(honest)
    );
    assert_eq!(
        Source::<OM31>::from_bytes(&honest).err(),
        Some(Error::UnsupportedSource),
        "degree is part of the statement"
    );
    // Version, J=15, rows, columns, layout and policy offsets in the 139-byte layout.
    for (offset, value) in [
        (23, 1),
        (23, 3),
        (56, 15),
        (89, 4),
        (98, 0),
        (105, 1),
        (106, 2),
    ] {
        let mut changed = honest.to_vec();
        changed[offset] = value;
        assert_eq!(
            Source::<QM31>::from_bytes(&changed).err(),
            Some(Error::UnsupportedSource),
            "offset {offset}"
        );
    }
    assert_eq!(
        Source::<QM31>::from_bytes(&honest[..138]).err(),
        Some(Error::UnsupportedSource)
    );
    let circle = Source::<QM31>::new(7, 1, 6, 1, [3; 32])
        .expect("Circle")
        .bytes();
    assert_eq!(
        Source::<QM31>::from_bytes(&circle).map(|s| s.bytes()),
        Ok(circle)
    );
}
