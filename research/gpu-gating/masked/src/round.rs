//! RFC-0013 A5 item 3 / RFC-0014 §5: checked term data for the fixed masked round.
use crate::K;

pub(crate) struct Terms {
    pub offsets: Vec<u32>,
    pub factors: Vec<u32>,
}

impl Terms {
    pub fn new(
        factor_count: usize,
        terms: &[(K, Vec<u32>)],
        nodes: usize,
    ) -> Result<Self, &'static str> {
        if !(1..=32).contains(&nodes)
            || u32::try_from(factor_count).is_err()
            || u32::try_from(terms.len()).is_err()
        {
            return Err("round descriptor count");
        }
        let mut offsets = vec![0];
        let mut factors = Vec::new();
        for (_, term) in terms {
            if term.iter().any(|&i| i as usize >= factor_count) {
                return Err("round factor index");
            }
            let count = factors
                .len()
                .checked_add(term.len())
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("round descriptor count")?;
            factors.extend_from_slice(term);
            offsets.push(count);
        }
        Ok(Self { offsets, factors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;

    #[test]
    fn accepts_constant_and_repeated_factors_in_order() {
        let terms = Terms::new(
            3,
            &[(K::from_i64(1), vec![]), (K::from_i64(0), vec![2, 1, 2])],
            32,
        )
        .unwrap();
        assert_eq!(terms.offsets, [0, 0, 3]);
        assert_eq!(terms.factors, [2, 1, 2]);
        assert_eq!(Terms::new(0, &[], 1).unwrap().offsets, [0]);
    }

    #[test]
    fn rejects_invalid_descriptors_even_with_zero_coefficient() {
        assert!(Terms::new(1, &[(K::from_i64(0), vec![1])], 2).is_err());
        assert!(Terms::new(0, &[(K::from_i64(1), vec![0])], 2).is_err());
        for nodes in [0, 33, usize::MAX] {
            assert!(Terms::new(1, &[], nodes).is_err());
        }
        assert!(Terms::new(usize::MAX, &[], 1).is_err());
    }
}
