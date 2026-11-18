//! RFC-0013 A5 items 2 and 5. Evaluate verifier-derived occurrence weights
//! on the source data face using the offsets from the verifier's own plan.

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::QM31;

    #[test]
    fn matches_reference_shifted_equality_for_all_small_intervals() {
        let one = QM31::from_i64(1);
        let zero = QM31::from_i64(0);
        let basis = basis::<QM31>(1).unwrap();
        for n in 0..=6 {
            let z: Vec<_> = (0..n).map(|i| basis + QM31::from_i64(3 + i as i64)).collect();
            let z_table = stele_poly::eq_table(&z).unwrap();
            for m in 0..=n {
                let free: Vec<_> = (0..m).map(|i| basis * QM31::from_i64(4 + i as i64)).collect();
                for q in [free, (0..m).map(|i| if i % 2 == 0 { one } else { zero }).collect()] {
                    let weights = stele_poly::eq_table(&q).unwrap();
                    for at in 0..=z_table.len() - weights.len() {
                        let expected = weights.iter().zip(&z_table[at..])
                            .fold(zero, |s, (a,b)| s + *a * *b);
                        assert_eq!(shifted_eq(&z, at, &q), Ok(expected), "n={n}, m={m}, at={at}");
                    }
                    assert_eq!(shifted_eq(&z, z_table.len() - weights.len() + 1, &q), Err(Error::Statement));
                }
            }
            assert_eq!(shifted_eq(&z, usize::MAX, &[]), Err(Error::Statement));
            assert_eq!(shifted_eq(&z, 0, &vec![one;n+1]), Err(Error::Statement));
        }
    }
}
