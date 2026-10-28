//! RFC-0008 A3 codecs: proof bytes are unverified until all reduction consumers run.
use serde_json::Value;
use std::fmt::Debug;
use stele_field::{OM31, QM31};
use stele_hash::ChallengeField;
use stele_lookup::fraction::{Descriptor, Error, Proof};
use stele_sumcheck::Proof as SumcheckProof;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("valid codec fixture"), 16)
                .expect("valid codec fixture")
        })
        .collect()
}
fn field<K: ChallengeField>(value: &Value) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes = hex(value.as_str().expect("valid codec fixture"));
    K::from_le_bytes(
        K::Bytes::try_from(bytes.as_slice())
            .ok()
            .expect("valid codec fixture"),
    )
    .expect("valid codec fixture")
}
fn values<K: ChallengeField>(value: &Value) -> Vec<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    value
        .as_array()
        .expect("valid codec fixture")
        .iter()
        .map(field::<K>)
        .collect()
}
fn vectors<K: ChallengeField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut count = 0;
    for line in include_str!("fixtures/fraction-codec.jsonl").lines() {
        let record: Value = serde_json::from_str(line).expect("valid codec fixture");
        if record["degree"].as_u64().expect("valid codec fixture") as usize != K::DEGREE {
            continue;
        }
        let s = &record["descriptor"];
        let descriptor = Descriptor::new(
            s["id"].as_u64().expect("valid codec fixture"),
            s["m"].as_u64().expect("valid codec fixture") as u32,
            s["b"].as_u64().expect("valid codec fixture") as u32,
            [
                s["leaves"][0].as_u64().expect("leaf id"),
                s["leaves"][1].as_u64().expect("leaf id"),
            ],
            &values::<K>(&s["theta"]),
        )
        .expect("valid codec fixture");
        assert_eq!(
            descriptor.encode().expect("valid codec fixture"),
            hex(record["descriptor_hex"]
                .as_str()
                .expect("valid codec fixture"))
        );
        let steps = record["proof"]["steps"]
            .as_array()
            .expect("valid codec fixture")
            .iter()
            .map(|step| SumcheckProof {
                rounds: step["rounds"]
                    .as_array()
                    .expect("valid codec fixture")
                    .iter()
                    .map(values::<K>)
                    .collect(),
                final_values: values::<K>(&step["final"]),
            })
            .collect();
        let expected = Proof {
            root: values::<K>(&record["proof"]["root"])
                .try_into()
                .expect("valid codec fixture"),
            steps,
        };
        let payload = hex(record["payload_hex"].as_str().expect("valid codec fixture"));
        assert_eq!(
            Proof::decode(&descriptor, &payload).expect("valid codec fixture"),
            expected
        );
        assert_eq!(
            expected.encode(&descriptor).expect("valid codec fixture"),
            payload
        );
        assert_eq!(
            descriptor.proof_size().expect("valid codec fixture"),
            payload.len()
        );
        count += 1;
    }
    assert_eq!(count, 6);
}
#[test]
fn matches_reference_qm31_fraction_codec() {
    vectors::<QM31>();
}
#[test]
fn matches_reference_om31_fraction_codec() {
    vectors::<OM31>();
}

fn shape<K: ChallengeField>(m: u32) -> Proof<K> {
    let zero = K::from_i64(0);
    Proof {
        root: [zero; 2],
        steps: (0..m)
            .map(|k| SumcheckProof {
                rounds: vec![vec![zero; 4]; k as usize],
                final_values: vec![zero; 5],
            })
            .collect(),
    }
}
fn boundaries<K: ChallengeField + Eq + Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let zero = K::from_i64(0);
    for (m, b, ids, theta) in [
        (64, 64, [1, 2], vec![]),
        (1, 2, [1, 2], vec![]),
        (1, 0, [1, 1], vec![zero]),
        (1, 0, [1, 2], vec![]),
    ] {
        assert_eq!(
            Descriptor::new(9, m, b, ids, &theta).expect_err("malformed input must reject"),
            Error::InvalidDescriptor
        );
    }
    let mut theta = vec![K::from_i64(7)];
    let d = Descriptor::new(9, 2, 1, [3, 4], &theta).expect("valid codec fixture");
    theta[0] = zero;
    assert_eq!(
        (d.id(), d.num_vars(), d.group_bits(), d.leaf_ids()),
        (9, 2, 1, [3, 4])
    );
    assert_eq!(d.theta(), &[K::from_i64(7)]);
    let proof = shape::<K>(2);
    let bytes = proof.encode(&d).expect("valid codec fixture");
    for length in 0..bytes.len() {
        assert_eq!(
            Proof::decode(&d, &bytes[..length]).expect_err("malformed input must reject"),
            Error::ProofShape
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        Proof::decode(&d, &extra).expect_err("malformed input must reject"),
        Error::ProofShape
    );
    for invalid in [0x7fff_ffffu32, 0x8000_0000, u32::MAX] {
        for offset in (0..bytes.len()).step_by(4) {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&invalid.to_le_bytes());
            assert_eq!(
                Proof::decode(&d, &bad).expect_err("malformed input must reject"),
                Error::NoncanonicalField
            );
        }
    }
    let maximum: Vec<_> = (0..bytes.len() / 4)
        .flat_map(|_| 0x7fff_fffeu32.to_le_bytes())
        .collect();
    assert_eq!(
        Proof::decode(&d, &maximum)
            .expect("canonical endpoints")
            .encode(&d)
            .expect("canonical endpoints"),
        maximum
    );
    let other = Descriptor::<K>::new(9, 1, 1, [3, 4], &[]).expect("valid codec fixture");
    assert_eq!(
        Proof::decode(&other, &bytes).expect_err("malformed input must reject"),
        Error::ProofShape
    );
    for mutate in 0..4 {
        let mut bad = proof.clone();
        match mutate {
            0 => {
                bad.steps.pop();
            }
            1 => {
                bad.steps[1].rounds.pop();
            }
            2 => {
                bad.steps[1].rounds[0].pop();
            }
            _ => {
                bad.steps[0].final_values.pop();
            }
        }
        assert_eq!(
            bad.encode(&d).expect_err("malformed input must reject"),
            Error::ProofShape
        );
    }
}
#[test]
fn rejects_fraction_codec_boundaries() {
    boundaries::<QM31>();
    boundaries::<OM31>();
}
#[test]
fn accepts_maximum_verifier_shape_without_domain_allocation() {
    let d =
        Descriptor::<OM31>::new(u64::MAX, 63, 63, [u64::MAX, 0], &[]).expect("valid codec fixture");
    let proof = shape::<OM31>(63);
    let bytes = proof.encode(&d).expect("valid codec fixture");
    assert_eq!(bytes.len(), 32 * (2 + 2 * 63 * 63 + 3 * 63));
    assert_eq!(
        Proof::decode(&d, &bytes).expect("valid codec fixture"),
        proof
    );
}
