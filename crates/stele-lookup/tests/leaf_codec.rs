//! Selected-product wire shape and exact field order, RFC-0008 A3.
use stele_field::{OM31, QM31};
use stele_hash::ChallengeField;
use stele_lookup::fraction::{Descriptor, Error, LeafDescriptor};
use stele_sumcheck::Proof;
fn check<K: ChallengeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for m in [0, 1, 3, 63] {
        let tree = Descriptor::<K>::new(u64::MAX, m, m, [3, 4], &[]).expect("tree");
        for ids in [&[2u64][..], &[u64::MAX, 2, 3][..]] {
            let leaf = LeafDescriptor::new(&tree, ids).expect("descriptor");
            assert_eq!(leaf.tree(), &tree);
            assert_eq!(leaf.source_ids(), ids);
            let proof = Proof {
                rounds: (0..m)
                    .map(|k| (0..4).map(|i| K::from_i64(i64::from(4 * k + i))).collect())
                    .collect(),
                final_values: (0..ids.len() + 2)
                    .map(|i| K::from_i64(100 + i as i64))
                    .collect(),
            };
            let bytes = leaf.encode(&proof).expect("encode");
            let expected: Vec<_> = proof
                .rounds
                .iter()
                .flatten()
                .chain(&proof.final_values)
                .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
                .collect();
            assert_eq!(bytes, expected);
            assert_eq!(
                leaf.proof_size().expect("bounded size"),
                4 * K::DEGREE * (4 * m as usize + ids.len() + 2)
            );
            assert_eq!(leaf.decode(&bytes).expect("decode"), proof);
            for length in 0..bytes.len() {
                assert_eq!(
                    leaf.decode(&bytes[..length]).expect_err("truncated"),
                    Error::ProofShape
                );
            }
            let mut extra = bytes.clone();
            extra.push(0);
            assert_eq!(
                leaf.decode(&extra).expect_err("trailing byte"),
                Error::ProofShape
            );
            for offset in (0..bytes.len()).step_by(4) {
                let mut bad = bytes.clone();
                bad[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
                assert_eq!(
                    leaf.decode(&bad).expect_err("canonical limbs required"),
                    Error::NoncanonicalField
                );
            }
            let mut bad = proof.clone();
            bad.final_values.pop();
            assert_eq!(leaf.encode(&bad), Err(Error::ProofShape));
            let mut bad = proof.clone();
            bad.rounds.push(vec![K::from_i64(0); 4]);
            assert_eq!(leaf.encode(&bad), Err(Error::ProofShape));
            if m > 0 {
                let mut bad = proof.clone();
                bad.rounds[0].pop();
                assert_eq!(leaf.encode(&bad), Err(Error::ProofShape));
            }
        }
        for ids in [&[][..], &[0][..], &[1][..], &[2, 2][..]] {
            assert_eq!(
                LeafDescriptor::new(&tree, ids).expect_err("invalid source identities"),
                Error::InvalidDescriptor
            );
        }
    }
}
#[test]
fn rejects_qm31_leaf_codec_boundaries() {
    check::<QM31>();
}
#[test]
fn rejects_om31_leaf_codec_boundaries() {
    check::<OM31>();
}

fn hex(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_str()
        .expect("hex fixture")
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex digit")
        })
        .collect()
}
fn fields<K: ChallengeField>(value: &serde_json::Value) -> Vec<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    value
        .as_array()
        .expect("field list")
        .iter()
        .map(|v| {
            let bytes = hex(v);
            K::from_le_bytes(
                K::Bytes::try_from(bytes.as_slice())
                    .ok()
                    .expect("field size"),
            )
            .expect("canonical field")
        })
        .collect()
}
fn reference<K: ChallengeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut count = 0;
    for line in include_str!("fixtures/leaf-codec.jsonl").lines() {
        let row: serde_json::Value = serde_json::from_str(line).expect("fixture");
        if row["degree"].as_u64().expect("degree") != K::DEGREE as u64 {
            continue;
        }
        let m = row["m"].as_u64().expect("depth") as u32;
        let tree = Descriptor::<K>::new(row["id"].as_u64().expect("id"), m, m, [11, 12], &[])
            .expect("tree");
        let ids: Vec<_> = row["sources"]
            .as_array()
            .expect("source ids")
            .iter()
            .map(|v| v.as_u64().expect("u64 id"))
            .collect();
        let leaf = LeafDescriptor::new(&tree, &ids).expect("leaf shape");
        let expected = Proof {
            rounds: row["rounds"]
                .as_array()
                .expect("rounds")
                .iter()
                .map(fields::<K>)
                .collect(),
            final_values: fields::<K>(&row["final"]),
        };
        let bytes = hex(&row["payload_hex"]);
        assert_eq!(leaf.decode(&bytes).expect("decoded fields"), expected);
        assert_eq!(leaf.encode(&expected).expect("exact bytes"), bytes);
        count += 1;
    }
    assert_eq!(count, 6);
}
#[test]
fn matches_reference_qm31_selected_product_codec() {
    reference::<QM31>();
}
#[test]
fn matches_reference_om31_selected_product_codec() {
    reference::<OM31>();
}
