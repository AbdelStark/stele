//! RFC-0006 A3: 1,000 seeded naive/dense proofs per degree and challenge field.
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{zerocheck::Zerocheck, Instance, Term};
#[path = "support/zero_reference.rs"]
mod reference;
fn random<K: ChallengeField>(seed: &mut u64) -> K
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes: Vec<u8> = (0..K::from_i64(0).to_le_bytes().as_ref().len() / 4)
        .flat_map(|_| {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((*seed >> 32) as u32 % K::MODULUS).to_le_bytes()
        })
        .collect();
    K::from_le_bytes(bytes.try_into().ok().expect("width")).expect("canonical")
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>()
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    for degree in 0..=4 {
        let mut shapes = [[0; 5]; 5];
        for case in 0..1000 {
            let m = case % 5;
            let k = if degree == 0 { 0 } else { (case / 5) % (m + 1) };
            shapes[m][k] += 1;
            let mut seed = 1 + (degree * 1000 + case) as u64;
            let mut tables: Vec<Vec<K>> = (0..4)
                .map(|_| {
                    (0..1usize << m)
                        .map(|_| {
                            let value = random::<K>(&mut seed);
                            if case % 8 == 0 {
                                K::from_i64((seed & 1) as i64)
                            } else {
                                value
                            }
                        })
                        .collect()
                })
                .collect();
            let factors: Vec<_> = (0..degree).map(|n| ((case + n) % 2) as u32).collect();
            let coefficient = if case % 5 == 0 {
                K::from_i64(0)
            } else {
                random(&mut seed)
            };
            let constant = random::<K>(&mut seed);
            let mut terms = vec![];
            if degree > 0 {
                for column in 0..1usize << m {
                    tables[2][column] = factors
                        .iter()
                        .fold(coefficient, |v, index| v * tables[*index as usize][column])
                        + constant;
                }
                terms = vec![
                    Term {
                        coefficient,
                        factors,
                    },
                    Term {
                        coefficient: constant,
                        factors: vec![],
                    },
                    Term {
                        coefficient: K::from_i64(-1),
                        factors: vec![2],
                    },
                    Term {
                        coefficient: K::from_i64(0),
                        factors: vec![1; degree],
                    },
                ];
                if case % 2 == 0 {
                    terms.reverse();
                }
            }
            let i = Instance {
                id: seed,
                num_vars: m as u32,
                inputs: vec![11, 12, 13, 14],
                terms,
                claimed_sum: K::from_i64(0),
            };
            let z = Zerocheck {
                instance: &i,
                skip: k as u8,
            };
            let new = || Transcript::<K>::new(&seed.to_le_bytes()).expect("public");
            let (mut rt, mut pt, mut vt) = (new(), new(), new());
            let expected = reference::prove(&z, &tables, &mut rt);
            let actual = z.prove(&tables, &mut pt).expect("true row assertion");
            assert_eq!(actual, expected, "degree={degree} case={case} m={m} k={k}");
            let result = z
                .verify_public(&actual, &tables, &mut vt)
                .expect("every original claim");
            assert_eq!(result.claims.len(), i.inputs.len() * (1 << k));
            let next = rt
                .challenge(ChallengeLabel::Sumcheck)
                .expect("continuation");
            assert_eq!(
                pt.challenge(ChallengeLabel::Sumcheck)
                    .expect("continuation"),
                next
            );
            assert_eq!(
                vt.challenge(ChallengeLabel::Sumcheck)
                    .expect("continuation"),
                next
            );
        }
        for (m, counts) in shapes.iter().enumerate() {
            for count in &counts[..if degree == 0 { 1 } else { m + 1 }] {
                assert!(*count > 0);
            }
        }
    }
}
#[test]
fn matches_reference_naive_zerocheck_qm31() {
    check::<QM31>();
}
#[test]
fn matches_reference_naive_zerocheck_om31() {
    check::<OM31>();
}
