//! Dense leading-coordinate reference, RFC-0006 A1. No padding or reordering.
use crate::{reserve, Error, Instance, Summand};
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
        if self.remaining == 0 || self.tables.len() != i.inputs.len() {
            return Err(Error::PublicShape);
        }
        let mut result = Vec::new();
        reserve(&mut result, degree + 1)?;
        let mut values = Vec::new();
        reserve(&mut values, self.tables.len())?;
        values.resize(self.tables.len(), K::from_i64(0));
        for node in 0..=degree {
            let x = K::from_i64(node as i64);
            let mut sum = K::from_i64(0);
            if self.tables.is_empty() {
                sum = i.evaluate(&[]);
                for _ in 1..self.remaining {
                    sum = sum + sum;
                }
            } else {
                let half = self.tables[0].len() / 2;
                for column in 0..half {
                    for (out, table) in values.iter_mut().zip(&self.tables) {
                        *out = table[column] + x * (table[column + half] - table[column]);
                    }
                    sum = sum + i.evaluate(&values);
                }
            }
            result.push(sum);
        }
        Ok(result)
    }
    fn fold(&mut self, challenge: K) -> Result<(), Error> {
        if self.remaining == 0 {
            return Err(Error::PublicShape);
        }
        for table in &mut self.tables {
            let half = table.len() / 2;
            for j in 0..half {
                table[j] = table[j] + challenge * (table[j + half] - table[j]);
            }
            table.truncate(half);
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
}
