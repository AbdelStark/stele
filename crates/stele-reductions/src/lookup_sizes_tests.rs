//! RFC-0008 A5 §6: compare admission formulas with the actual A3/A1 codecs.
use super::*;
use alloc::vec;
use stele_field::{OM31, QM31};
use stele_sumcheck::{message_size, Instance, Term};

fn sizes<K: ChallengeField>() {
    let w = 4 * K::DEGREE;
    for m in [0usize, 1, 4, 59] {
        for b in [0, m] {
            let d = fraction::Descriptor::<K>::new(
                7,
                m as u32,
                b as u32,
                [14, 15],
                &vec![K::from_i64(0); m - b],
            )
            .expect("symbolic tree");
            assert_eq!(
                tree_size(m, w).expect("size"),
                d.proof_size().expect("A3 size")
            );
            let mut payload = d.encode().expect("actual descriptor").len() + 2 * w;
            for i in 0..m {
                let instance = Instance {
                    id: i as u64,
                    num_vars: i as u32,
                    inputs: vec![0, 1, 2, 3, 4],
                    terms: [[0, 3, 4], [2, 1, 4], [1, 3, 4]]
                        .iter()
                        .map(|f| Term {
                            coefficient: K::from_i64(0),
                            factors: f.to_vec(),
                        })
                        .collect(),
                    claimed_sum: K::from_i64(0),
                };
                payload += message_size::<K>(i + 2).expect("layer")
                    + instance.encode().expect("instance").len()
                    + i * message_size::<K>(4).expect("round")
                    + message_size::<K>(5).expect("final");
            }
            assert_eq!(tree_payload(m, m - b, w), Ok(payload));
            for c in [1usize, 2] {
                let instance = Instance {
                    id: 7,
                    num_vars: m as u32,
                    inputs: (0..c as u64 + 2).collect(),
                    terms: (0..c as u32)
                        .map(|i| Term {
                            coefficient: K::from_i64(0),
                            factors: vec![0, 1, i + 2],
                        })
                        .collect(),
                    claimed_sum: K::from_i64(0),
                };
                let leaf = d.encode().expect("tree descriptor").len()
                    + 4
                    + 8 * c
                    + w * (m + 4)
                    + instance.encode().expect("leaf instance").len()
                    + m * message_size::<K>(4).expect("leaf round")
                    + message_size::<K>(c + 2).expect("leaf final");
                assert_eq!(leaf_payload(m, m - b, c, w), Ok(leaf));
            }
        }
    }
    let maximum = isize::MAX as usize / size_of::<K>();
    assert_eq!(addressable::<K>(maximum), Ok(()));
    assert_eq!(addressable::<K>(maximum + 1), Err(Error::Capacity));
    assert_eq!(mul(usize::MAX, 2), Err(Error::Capacity));
    assert_eq!(sum(&[usize::MAX, 1]), Err(Error::Capacity));
    assert_eq!(tree_size(usize::MAX, w), Err(Error::Capacity));
}
#[test]
fn matches_reference_qm31_lookup_sizes() {
    sizes::<QM31>();
}
#[test]
fn matches_reference_om31_lookup_sizes() {
    sizes::<OM31>();
}
