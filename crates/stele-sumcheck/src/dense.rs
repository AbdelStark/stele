//! Dense leading-coordinate reference, RFC-0006 A1. No padding or reordering.
use crate::{parallel, reserve, Error, Instance, Summand};
use alloc::vec::Vec;
use stele_hash::ChallengeField;

pub(crate) fn check_tables<K: ChallengeField>(
    i: &Instance<K>,
    tables: &[Vec<K>],
) -> Result<(), Error> {
    i.validate()?;
    if tables.len() != i.inputs.len()
        || tables
            .iter()
            .any(|t| !t.len().is_power_of_two() || t.len().trailing_zeros() != i.num_vars)
    {
        return Err(Error::PublicShape);
    }
    Ok(())
}
/// Owns and folds dense input tables in place, retaining at most their initial capacity.
pub struct Dense<K> {
    tables: Vec<Vec<K>>,
    remaining: u32,
}
impl<K: ChallengeField> Dense<K> {
    // RFC-0006 A5: a materialized prefix tail keeps the original A1 instance.
    pub(crate) fn from_folded(tables: Vec<Vec<K>>, remaining: u32) -> Result<Self, Error> {
        if tables
            .iter()
            .any(|t| !t.len().is_power_of_two() || t.len().trailing_zeros() != remaining)
        {
            return Err(Error::PublicShape);
        }
        Ok(Self { tables, remaining })
    }
    // RFC-0006 A2: inactive prefixes use the computed sum, not a claimed sum.
    pub(crate) fn sum(&self, i: &Instance<K>) -> Result<K, Error> {
        if self.remaining == 0 {
            return Ok(i.evaluate(&self.final_values()?));
        }
        let row = self.round(i)?;
        Ok(row[0] + row[if row.len() == 1 { 0 } else { 1 }])
    }
    /// Validate all shapes before taking the first challenge.
    pub fn new(i: &Instance<K>, tables: Vec<Vec<K>>) -> Result<Self, Error> {
        check_tables(i, &tables)?;
        Ok(Self {
            tables,
            remaining: i.num_vars,
        })
    }
}
impl<K: ChallengeField> Summand<K> for Dense<K> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining, self.tables.len())
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        let degree = i.validate()?;
        let mut result = Vec::new();
        reserve(&mut result, degree + 1)?;
        result.resize(degree + 1, K::from_i64(0));
        self.round_into(i, &mut result)?;
        Ok(result)
    }
    fn fold(&mut self, challenge: K) -> Result<(), Error> {
        if self.remaining == 0 {
            return Err(Error::PublicShape);
        }
        for table in &mut self.tables {
            parallel::fold(table, challenge);
        }
        self.remaining -= 1;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        if self.remaining != 0 {
            return Err(Error::PublicShape);
        }
        let mut result = Vec::new();
        reserve(&mut result, self.tables.len())?;
        result.extend(self.tables.iter().map(|table| table[0]));
        Ok(result)
    }
    // RFC-0006 A6: evaluate factors directly, without an a-element temporary allocation.
    fn round_into(&self, i: &Instance<K>, out: &mut [K]) -> Result<(), Error> {
        let degree = i.validate()?;
        if self.remaining == 0 || self.tables.len() != i.inputs.len() {
            return Err(Error::PublicShape);
        }
        if out.len() != degree + 1 {
            return Err(Error::ProofShape);
        }
        if self.tables.is_empty() {
            let mut value = i.evaluate(&[]);
            for _ in 1..self.remaining {
                value = value + value;
            }
            out.fill(value);
            return Ok(());
        }
        let half = self.tables[0].len() / 2;
        // Field addition is exact, so any split of the column range into partial sums
        // gives the same round values as the sequential sum (RFC-0006 A1 is unchanged).
        // One pass per column: the node-x value of each input is t + x·(t' − t), built
        // by repeated addition of the difference, so no product by x is needed.
        let inputs = self.tables.len();
        let partial = |range: core::ops::Range<usize>, out: &mut [K]| {
            out.fill(K::from_i64(0));
            let mut values = Vec::new();
            let mut steps = Vec::new();
            reserve(&mut values, inputs)?;
            reserve(&mut steps, inputs)?;
            values.resize(inputs, K::from_i64(0));
            steps.resize(inputs, K::from_i64(0));
            for column in range {
                for ((value, step), table) in values.iter_mut().zip(&mut steps).zip(&self.tables) {
                    *value = table[column];
                    *step = table[column + half] - table[column];
                }
                for (node, result) in out.iter_mut().enumerate() {
                    if node > 0 {
                        for (value, step) in values.iter_mut().zip(&steps) {
                            *value = *value + *step;
                        }
                    }
                    *result = *result + i.evaluate(&values);
                }
            }
            Ok(())
        };
        parallel::sum_ranges(half, out, partial)?;
        Ok(())
    }
    fn final_values_into(&self, out: &mut [K]) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::PublicShape);
        }
        if out.len() != self.tables.len() {
            return Err(Error::ProofShape);
        }
        for (value, table) in out.iter_mut().zip(&self.tables) {
            *value = table[0];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Term;
    use stele_field::{Field, QM31};

    #[test]
    fn matches_reference_split_and_sequential_dense_rounds() {
        // 2^13 rows: with `std` the round is split across workers; the expected values
        // are the plain sequential loop over every column.
        let n = 1usize << 13;
        let table = |seed: i64| -> Vec<QM31> {
            (0..n as i64)
                .map(|i| QM31::from_i64((i * 7919 + seed) % 2_147_483_629 - 1000))
                .collect()
        };
        let tables = alloc::vec![table(1), table(2), table(3)];
        let instance = Instance {
            id: 9,
            num_vars: 13,
            inputs: alloc::vec![0, 1, 2],
            terms: alloc::vec![
                Term {
                    coefficient: QM31::from_i64(3),
                    factors: alloc::vec![0, 1, 2],
                },
                Term {
                    coefficient: QM31::from_i64(-5),
                    factors: alloc::vec![1],
                },
            ],
            claimed_sum: QM31::from_i64(0),
        };
        let dense = Dense::new(&instance, tables.clone()).expect("dense");
        let actual = dense.round(&instance).expect("round");
        let half = n / 2;
        let mut expected = alloc::vec![QM31::from_i64(0); 4];
        for (node, value) in expected.iter_mut().enumerate() {
            let x = QM31::from_i64(node as i64);
            for column in 0..half {
                let v: Vec<QM31> = tables
                    .iter()
                    .map(|t| t[column] + x * (t[column + half] - t[column]))
                    .collect();
                *value = *value + instance.evaluate(&v);
            }
        }
        assert_eq!(actual, expected);
    }
}
