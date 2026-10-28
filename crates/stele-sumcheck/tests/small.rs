//! RFC-0006 A5: typed boundaries and unchanged A1 proof/consumer/continuation.
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    prove, verify_public, Dense, Error, Instance, Small, SmallTable, Summand, Term,
};

fn instance<K: Field>(m: u32, degree: usize) -> Instance<K> {
    Instance {
        id: 204,
        num_vars: m,
        inputs: vec![11, 12, 13],
        terms: vec![Term {
            coefficient: K::from_i64(3),
            factors: vec![0; degree],
        }],
        claimed_sum: K::from_i64(0),
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    for degree in 0..=4 {
        for k in 2..=4 {
            for m in [k, k + 1] {
                let mut i = instance::<K>(m, degree);
                // Non-base coefficients must survive base-field grid accumulation.
                i.terms[0].coefficient = Transcript::<K>::new(b"coefficient")
                    .expect("valid small-strategy fixture")
                    .challenge(ChallengeLabel::Sumcheck)
                    .expect("valid small-strategy fixture");
                i.terms.push(Term {
                    coefficient: K::from_i64(0),
                    factors: vec![1; degree],
                });
                i.terms.push(Term {
                    coefficient: K::from_i64(-7),
                    factors: vec![],
                });
                if degree > 0 {
                    i.terms.push(Term {
                        coefficient: K::from_i64(-2),
                        factors: if degree > 1 { vec![0, 1] } else { vec![1] },
                    });
                }
                let signed: Vec<i16> = (0..1usize << m)
                    .map(|j| {
                        if j < 4 {
                            [i16::MIN, -1, 0, i16::MAX][j]
                        } else {
                            i16::try_from(
                                i32::try_from((j * 7919) % 65536)
                                    .expect("valid small-strategy fixture")
                                    - 32768,
                            )
                            .expect("valid small-strategy fixture")
                        }
                    })
                    .collect();
                let unsigned: Vec<u16> = (0..1usize << m)
                    .map(|j| {
                        if j < 4 {
                            [u16::MAX, 0, 1, 32768][j]
                        } else {
                            u16::try_from((j * 3121) % 65536).expect("valid small-strategy fixture")
                        }
                    })
                    .collect();
                let tables = vec![
                    signed
                        .iter()
                        .map(|v| K::from_i64(i64::from(*v)))
                        .collect::<Vec<_>>(),
                    unsigned
                        .iter()
                        .map(|v| K::from_i64(i64::from(*v)))
                        .collect(),
                    signed.iter().map(|v| K::from_i64(i64::from(*v))).collect(),
                ];
                for column in 0..1usize << m {
                    for term in &i.terms {
                        i.claimed_sum = i.claimed_sum
                            + term.factors.iter().fold(term.coefficient, |p, index| {
                                p * tables[*index as usize][column]
                            });
                    }
                }
                let source = vec![
                    SmallTable::Signed(signed.clone()),
                    SmallTable::Unsigned(unsigned),
                    SmallTable::Signed(signed),
                ];
                let new =
                    || Transcript::<K>::new(b"small parity").expect("valid small-strategy fixture");
                let (mut a, mut b, mut c) = (new(), new(), new());
                let expected = prove(
                    &i,
                    Dense::new(&i, tables.clone()).expect("valid small-strategy fixture"),
                    &mut a,
                )
                .expect("valid small-strategy fixture");
                let actual = prove(
                    &i,
                    Small::new(&i, source, k as u8).expect("valid small-strategy fixture"),
                    &mut b,
                )
                .expect("valid small-strategy fixture");
                assert_eq!(actual, expected, "degree={degree} m={m} k={k}");
                let receipt = verify_public(&i, &actual, &tables, &mut c)
                    .expect("valid small-strategy fixture");
                assert_eq!(receipt.claims.len(), 3);
                assert_eq!(receipt.sc.numerator, u64::from(m) * degree as u64);
                let next = a
                    .challenge(ChallengeLabel::Sumcheck)
                    .expect("valid small-strategy fixture");
                assert_eq!(
                    b.challenge(ChallengeLabel::Sumcheck)
                        .expect("valid small-strategy fixture"),
                    next
                );
                assert_eq!(
                    c.challenge(ChallengeLabel::Sumcheck)
                        .expect("valid small-strategy fixture"),
                    next
                );
            }
        }
    }
    for terms in [
        vec![],
        vec![Term {
            coefficient: K::from_i64(5),
            factors: vec![],
        }],
    ] {
        let mut i = instance::<K>(4, 0);
        i.inputs.clear();
        i.claimed_sum = K::from_i64(if terms.is_empty() { 0 } else { 80 });
        i.terms = terms;
        let mut a = Transcript::<K>::new(b"empty small").expect("valid small-strategy fixture");
        let mut b = Transcript::<K>::new(b"empty small").expect("valid small-strategy fixture");
        let proof = prove(
            &i,
            Small::new(&i, vec![], 4).expect("valid small-strategy fixture"),
            &mut a,
        )
        .expect("valid small-strategy fixture");
        let _ = verify_public(&i, &proof, &[], &mut b).expect("valid small-strategy fixture");
        assert_eq!(
            a.challenge(ChallengeLabel::Sumcheck)
                .expect("valid small-strategy fixture"),
            b.challenge(ChallengeLabel::Sumcheck)
                .expect("valid small-strategy fixture")
        );
    }
}
#[test]
fn matches_reference_small_qm31() {
    check::<QM31>();
}
#[test]
fn matches_reference_small_om31() {
    check::<OM31>();
}
#[test]
fn rejects_small_constructor_and_cached_instance() {
    let i = instance::<QM31>(2, 2);
    let source = || vec![SmallTable::Signed(vec![1; 4]); 3];
    for k in [0, 1, 3, 4, 5, u8::MAX] {
        assert!(matches!(
            Small::new(&i, source(), k),
            Err(Error::InvalidSmallValue)
        ));
    }
    assert!(matches!(Small::new(&i, vec![], 2), Err(Error::PublicShape)));
    assert!(matches!(
        Small::new(&i, vec![SmallTable::Unsigned(vec![0; 3]); 3], 2),
        Err(Error::PublicShape)
    ));
    let mut malformed = i.clone();
    malformed.terms[0].factors = vec![0; 5];
    assert!(matches!(
        Small::new(&malformed, source(), 2),
        Err(Error::InvalidInstance)
    ));
    malformed = i.clone();
    malformed.num_vars = usize::BITS;
    assert!(matches!(
        Small::new(&malformed, source(), 2),
        Err(Error::Capacity)
    ));
    let small = Small::new(&i, source(), 2).expect("valid small-strategy fixture");
    assert!(small.round(&i.clone()).is_ok());
    malformed = i.clone();
    malformed.terms[0].coefficient = QM31::from_i64(4);
    assert_eq!(small.round(&malformed), Err(Error::InvalidSmallValue));
    assert_eq!(small.final_values(), Err(Error::PublicShape));
    assert!(i16::try_from(32768i64).is_err());
    assert!(u16::try_from(65536i64).is_err());
}
#[test]
fn matches_reference_small_zero_one_folds() {
    let i = instance::<QM31>(3, 2);
    let values = vec![i16::MIN, -7, 0, 1, 9, i16::MAX, -33, 17];
    let input = vec![
        values
            .iter()
            .map(|v| QM31::from_i64(i64::from(*v)))
            .collect();
        3
    ];
    for challenges in [[0, 1, 0], [1, 0, 1]] {
        let mut small = Small::new(&i, vec![SmallTable::Signed(values.clone()); 3], 2)
            .expect("valid small-strategy fixture");
        let mut dense = Dense::new(&i, input.clone()).expect("valid small-strategy fixture");
        for value in challenges {
            assert_eq!(
                small.round(&i).expect("valid small-strategy fixture"),
                dense.round(&i).expect("valid small-strategy fixture")
            );
            small
                .fold(QM31::from_i64(value))
                .expect("valid small-strategy fixture");
            dense
                .fold(QM31::from_i64(value))
                .expect("valid small-strategy fixture");
        }
        assert_eq!(
            small.final_values().expect("valid small-strategy fixture"),
            dense.final_values().expect("valid small-strategy fixture")
        );
        assert_eq!(small.round(&i), Err(Error::PublicShape));
        assert_eq!(small.fold(QM31::from_i64(1)), Err(Error::PublicShape));
    }
}
