//! Dense leading-coordinate reference, RFC-0006 A1/A5. No padding or reordering.
use crate::{parallel, reserve, Error, Instance, Summand};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::ChallengeField;

/// One input table of [`Dense`]: base-field `M31` before the first fold, or extension-field `K`
/// (RFC-0006 A5, task E20-01).
#[derive(Clone, Debug)]
pub enum DenseTable<K> {
    /// Unfolded base-field values (4 bytes/element); folded into `Ext` on round 0.
    Base(Vec<M31>),
    /// Extension-field values (`4 * deg(K)` bytes/element).
    Ext(Vec<K>),
}
impl<K> DenseTable<K> {
    fn len(&self) -> usize {
        match self {
            Self::Base(v) => v.len(),
            Self::Ext(v) => v.len(),
        }
    }
    fn is_base(&self) -> bool {
        matches!(self, Self::Base(_))
    }
}

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
    tables: Vec<DenseTable<K>>,
    remaining: u32,
}
impl<K: ChallengeField> Dense<K> {
    // RFC-0006 A5: a materialized prefix tail keeps the original A1 instance.
    pub fn from_folded(tables: Vec<Vec<K>>, remaining: u32) -> Result<Self, Error> {
        if tables
            .iter()
            .any(|t| !t.len().is_power_of_two() || t.len().trailing_zeros() != remaining)
        {
            return Err(Error::PublicShape);
        }
        let mut wrapped = Vec::new();
        reserve(&mut wrapped, tables.len())?;
        for t in tables {
            wrapped.push(DenseTable::Ext(t));
        }
        Ok(Self {
            tables: wrapped,
            remaining,
        })
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
        let mut wrapped = Vec::new();
        reserve(&mut wrapped, tables.len())?;
        for t in tables {
            wrapped.push(DenseTable::Ext(t));
        }
        Ok(Self {
            tables: wrapped,
            remaining: i.num_vars,
        })
    }
    /// Validate mixed base-field (`M31`) and extension-field (`K`) tables (RFC-0006 A5, E20-01).
    /// Base-field tables stay in `M31` through round 0 and fold directly into half-sized `K`
    /// tables on the first fold; output proof bytes are bit-identical to [`Self::new`].
    pub fn new_mixed(i: &Instance<K>, tables: Vec<DenseTable<K>>) -> Result<Self, Error> {
        i.validate()?;
        if tables.len() != i.inputs.len()
            || tables
                .iter()
                .any(|t| !t.len().is_power_of_two() || t.len().trailing_zeros() != i.num_vars)
        {
            return Err(Error::PublicShape);
        }
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
            match table {
                DenseTable::Base(base) => {
                    let folded = parallel::fold_base(base, challenge)?;
                    *table = DenseTable::Ext(folded);
                }
                DenseTable::Ext(ext) => parallel::fold(ext, challenge),
            }
        }
        self.remaining -= 1;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        if self.remaining != 0 {
            return Err(Error::PublicShape);
        }
        let one = K::from_i64(1);
        let mut result = Vec::new();
        reserve(&mut result, self.tables.len())?;
        result.extend(self.tables.iter().map(|table| match table {
            DenseTable::Base(b) => one.mul_m31(b[0]),
            DenseTable::Ext(e) => e[0],
        }));
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
        let inputs = self.tables.len();
        if self.tables.iter().any(DenseTable::is_base) {
            let partial = |range: core::ops::Range<usize>, out: &mut [K]| {
                out.fill(K::from_i64(0));
                let mut base_vals = Vec::new();
                let mut base_steps = Vec::new();
                let mut ext_vals = Vec::new();
                let mut ext_steps = Vec::new();
                reserve(&mut base_vals, inputs)?;
                reserve(&mut base_steps, inputs)?;
                reserve(&mut ext_vals, inputs)?;
                reserve(&mut ext_steps, inputs)?;
                base_vals.resize(inputs, M31::ZERO);
                base_steps.resize(inputs, M31::ZERO);
                ext_vals.resize(inputs, K::from_i64(0));
                ext_steps.resize(inputs, K::from_i64(0));
                for column in range {
                    for (idx, table) in self.tables.iter().enumerate() {
                        match table {
                            DenseTable::Base(b) => {
                                base_vals[idx] = b[column];
                                base_steps[idx] = b[column + half] - b[column];
                            }
                            DenseTable::Ext(e) => {
                                ext_vals[idx] = e[column];
                                ext_steps[idx] = e[column + half] - e[column];
                            }
                        }
                    }
                    for (node, result) in out.iter_mut().enumerate() {
                        if node > 0 {
                            for (idx, table) in self.tables.iter().enumerate() {
                                match table {
                                    DenseTable::Base(_) => {
                                        base_vals[idx] = base_vals[idx] + base_steps[idx];
                                    }
                                    DenseTable::Ext(_) => {
                                        ext_vals[idx] = ext_vals[idx] + ext_steps[idx];
                                    }
                                }
                            }
                        }
                        let mut sum = K::from_i64(0);
                        for term in &i.terms {
                            let mut base_prod = M31::ONE;
                            let mut has_base = false;
                            let mut ext_prod = term.coefficient;
                            for &f in &term.factors {
                                let fi = f as usize;
                                if self.tables[fi].is_base() {
                                    base_prod = base_prod * base_vals[fi];
                                    has_base = true;
                                } else {
                                    ext_prod = ext_prod * ext_vals[fi];
                                }
                            }
                            if has_base {
                                ext_prod = ext_prod.mul_m31(base_prod);
                            }
                            sum = sum + ext_prod;
                        }
                        *result = *result + sum;
                    }
                }
                Ok(())
            };
            parallel::sum_ranges(half, out, partial)?;
            return Ok(());
        }
        // All tables are extension-field `Ext`.
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
                    let DenseTable::Ext(table) = table else {
                        unreachable!()
                    };
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
        let one = K::from_i64(1);
        for (value, table) in out.iter_mut().zip(&self.tables) {
            *value = match table {
                DenseTable::Base(b) => one.mul_m31(b[0]),
                DenseTable::Ext(e) => e[0],
            };
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

        // Mixed Base/Ext tables produce identical proof bytes to all-Ext tables.
        let m31_t0: Vec<M31> = (0..n as i64)
            .map(|i| M31::from_i64((i * 7919 + 1) % 2_147_483_629 - 1000))
            .collect();
        let m31_t2: Vec<M31> = (0..n as i64)
            .map(|i| M31::from_i64((i * 7919 + 3) % 2_147_483_629 - 1000))
            .collect();
        let mixed = Dense::new_mixed(
            &instance,
            alloc::vec![
                DenseTable::Base(m31_t0),
                DenseTable::Ext(tables[1].clone()),
                DenseTable::Base(m31_t2),
            ],
        )
        .expect("mixed");
        let sum = mixed.sum(&instance).expect("sum");
        let mut inst_s = instance;
        inst_s.claimed_sum = sum;
        let mut t1 = stele_hash::Transcript::new(b"e20-01/mixed").expect("t");
        let mut t2 = stele_hash::Transcript::new(b"e20-01/mixed").expect("t");
        let p_ref =
            crate::prove(&inst_s, Dense::new(&inst_s, tables).expect("d"), &mut t1).expect("ref");
        let p_mix = crate::prove(&inst_s, mixed, &mut t2).expect("mix");
        assert_eq!(p_mix, p_ref);
    }
}
