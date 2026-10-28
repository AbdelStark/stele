//! RFC-0006 A5: 1,000 seeded direct-reference comparisons per degree and field.
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{prove, verify_public, Dense, Instance, Small, SmallTable, Term};
#[path = "support/small_reference.rs"]
mod reference;
fn random(seed: &mut u64) -> u32 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*seed >> 32) as u32
}
fn field<K: ChallengeField>(seed: &mut u64) -> K
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes: Vec<_> = (0..K::from_i64(0).to_le_bytes().as_ref().len() / 4)
        .flat_map(|_| (random(seed) % K::MODULUS).to_le_bytes())
        .collect();
    K::from_le_bytes(bytes.try_into().ok().expect("width")).expect("canonical field")
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>()
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let shapes = [(2, 2), (3, 2), (3, 3), (4, 2), (4, 3), (4, 4), (5, 4)];
    for degree in 0..=4 {
        let mut coverage = [0; 7];
        for case in 0..1000 {
            let shape = if case == 999 { 6 } else { case % 6 };
            let (m, k) = shapes[shape];
            coverage[shape] += 1;
            let mut seed = 1 + (degree * 1000 + case) as u64;
            let mut source = vec![];
            let mut tables = vec![];
            for index in 0..3 {
                let signed: Vec<i16> = (0..1usize << m)
                    .map(|j| {
                        if case % 11 == 0 {
                            [i16::MIN, -1, 0, i16::MAX][j % 4]
                        } else {
                            i16::try_from(i64::from(random(&mut seed) % 65536) - 32768)
                                .expect("signed range")
                        }
                    })
                    .collect();
                let unsigned: Vec<u16> = (0..1usize << m)
                    .map(|j| {
                        if case % 11 == 0 {
                            [u16::MAX, 0, 1, 32768][j % 4]
                        } else {
                            u16::try_from(random(&mut seed) % 65536).expect("unsigned range")
                        }
                    })
                    .collect();
                if (index + case) % 2 == 0 {
                    tables.push(
                        signed
                            .iter()
                            .map(|v| K::from_i64(i64::from(*v)))
                            .collect::<Vec<_>>(),
                    );
                    source.push(SmallTable::Signed(signed));
                } else {
                    tables.push(
                        unsigned
                            .iter()
                            .map(|v| K::from_i64(i64::from(*v)))
                            .collect(),
                    );
                    source.push(SmallTable::Unsigned(unsigned));
                }
            }
            let coefficient = if case % 5 == 0 {
                K::from_i64(0)
            } else {
                field::<K>(&mut seed)
            };
            let mut terms = vec![
                Term {
                    coefficient,
                    factors: (0..degree)
                        .map(|factor| {
                            if case % 2 == 0 {
                                0
                            } else {
                                (factor % 2) as u32
                            }
                        })
                        .collect(),
                },
                Term {
                    coefficient: field::<K>(&mut seed),
                    factors: vec![],
                },
            ];
            if degree > 0 {
                terms.push(Term {
                    coefficient: field::<K>(&mut seed),
                    factors: vec![1],
                });
                terms.push(Term {
                    coefficient: K::from_i64(0),
                    factors: vec![1; degree],
                });
            } else if case % 7 == 0 {
                terms.clear();
                if case % 2 == 0 {
                    source.clear();
                    tables.clear();
                }
            }
            if case % 2 == 0 {
                terms.reverse();
            }
            let mut i = Instance {
                id: seed,
                num_vars: m,
                inputs: (0..tables.len()).map(|v| v as u64 + 11).collect(),
                terms,
                claimed_sum: K::from_i64(0),
            };
            for column in 0..1usize << m {
                for term in &i.terms {
                    i.claimed_sum = i.claimed_sum
                        + term
                            .factors
                            .iter()
                            .fold(term.coefficient, |p, f| p * tables[*f as usize][column]);
                }
            }
            let new = || Transcript::<K>::new(&seed.to_le_bytes()).expect("public seed");
            let (mut rt, mut dt, mut pt, mut vt) = (new(), new(), new(), new());
            let expected = prove(
                &i,
                reference::Reference {
                    instance: &i,
                    tables: &tables,
                    point: vec![],
                },
                &mut rt,
            )
            .expect("direct reference");
            let dense = prove(&i, Dense::new(&i, tables.clone()).expect("shape"), &mut dt)
                .expect("dense reference");
            let actual = prove(&i, Small::new(&i, source, k).expect("typed shape"), &mut pt)
                .expect("small proof");
            assert_eq!(actual, expected, "degree={degree} case={case} m={m} k={k}");
            assert_eq!(actual, dense);
            let receipt =
                verify_public(&i, &actual, &tables, &mut vt).expect("all original claims");
            assert_eq!(receipt.point.len(), m as usize);
            assert_eq!(
                receipt.claims,
                i.inputs
                    .iter()
                    .copied()
                    .zip(actual.final_values)
                    .collect::<Vec<_>>()
            );
            assert_eq!(receipt.sc.id, i.id);
            assert_eq!(receipt.sc.m, m);
            assert_eq!(receipt.sc.degree, degree as u8);
            assert_eq!(
                receipt.sc.field_degree,
                (K::from_i64(0).to_le_bytes().as_ref().len() / 4) as u8
            );
            assert_eq!(receipt.sc.numerator, u64::from(m) * degree as u64);
            let next = rt
                .challenge(ChallengeLabel::Sumcheck)
                .expect("reference continuation");
            for transcript in [&mut dt, &mut pt, &mut vt] {
                assert_eq!(
                    transcript
                        .challenge(ChallengeLabel::Sumcheck)
                        .expect("continuation"),
                    next
                );
            }
        }
        assert!(coverage.iter().all(|count| *count > 0));
        assert_eq!(coverage.iter().sum::<usize>(), 1000);
    }
}
#[test]
fn matches_reference_naive_small_qm31() {
    check::<QM31>();
}
#[test]
fn matches_reference_naive_small_om31() {
    check::<OM31>();
}
