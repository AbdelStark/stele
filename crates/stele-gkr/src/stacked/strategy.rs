//! RFC-0006 A4 §4: restrict inputs before nonlinear P; one owned current state.
use super::{reserve, zeros, Error, Order, Prepared};
use crate::public_mle::Kind;
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_sumcheck::{Instance, Summand};

/// Dense reference strategy. Partials use the same routine as the actual A1 round.
pub struct Dense<'p, 'a, K> {
    prepared: &'p Prepared<'a, K>,
    tables: Vec<Vec<K>>,
    remaining: usize,
}
impl<'a, K: ChallengeField + Eq> Prepared<'a, K> {
    // A Boolean predicate/table and selector product; independent of A7's MLE evaluator.
    fn boolean(&self, index: usize) -> K {
        let s = self.statement;
        let coordinates = self.coordinates(index);
        if !self.valid(&coordinates) {
            return K::from_i64(0);
        }
        let value = match s.kind {
            Kind::Eq => 1,
            Kind::CausalMask { row, column } => i64::from(coordinates[column] <= coordinates[row]),
            Kind::WindowMask { row, column, width } => i64::from(
                coordinates[column] <= coordinates[row]
                    && coordinates[row] - coordinates[column] < width,
            ),
            Kind::OnehotSparse {
                row,
                column,
                indices,
            } => i64::from(coordinates[column] == indices[coordinates[row] as usize]),
            Kind::GqaBroadcast { head, group } => i64::from(
                coordinates[group] == coordinates[head] / (s.axes[head].real / s.axes[group].real),
            ),
            Kind::RopeTables { axes, values } => {
                let index = axes.iter().fold(0, |i, a| {
                    i * s.axes[*a].real as usize + coordinates[*a] as usize
                });
                i64::from(values[index].as_u32())
            }
        };
        let mut result = K::from_i64(value);
        for (coordinate, z) in coordinates.iter().zip(s.selectors) {
            if let Some(z) = z {
                for (bit, value) in z.iter().rev().enumerate() {
                    result = result
                        * if coordinate >> bit & 1 == 1 {
                            *value
                        } else {
                            K::from_i64(1) - *value
                        };
                }
            }
        }
        result
    }
    /// Prepare originals and A once, in the expected draw order, without a transcript.
    pub fn strategy(&self, tables: &[&[K]]) -> Result<Dense<'_, 'a, K>, Error> {
        self.check_tables(tables)?;
        let mut current = Vec::new();
        reserve(&mut current, tables.len() + 1)?;
        let ell = usize::from(self.statement.axes[0].bits);
        let inner = self.instance.num_vars as usize - ell;
        for input in 0..=tables.len() {
            let mut table = zeros(self.n)?;
            for (index, value) in table.iter_mut().enumerate() {
                let canonical = if self.statement.order == Order::LayerFirst {
                    index
                } else {
                    ((index & ((1usize << ell) - 1)) << inner) | (index >> ell)
                };
                *value = if input == tables.len() {
                    self.boolean(canonical)
                } else {
                    tables[input][canonical]
                };
            }
            current.push(table);
        }
        Ok(Dense {
            prepared: self,
            tables: current,
            remaining: self.instance.num_vars as usize,
        })
    }
}
impl<K: ChallengeField + Eq> Dense<'_, '_, K> {
    /// Actual retained field capacity, including the folded-away tail of each table.
    pub fn capacity_entries(&self) -> Result<usize, Error> {
        self.tables.iter().try_fold(0usize, |sum, t| {
            sum.checked_add(t.capacity()).ok_or(Error::Capacity)
        })
    }
    /// Block-major delta+1 entries for every original padded layer slot.
    pub fn partials(&self) -> Result<Vec<K>, Error> {
        if self.remaining == 0 {
            return Err(Error::InvalidStacked);
        }
        let p = self.prepared;
        let mut partials = zeros(p.partial_count)?;
        let half = self.tables[0].len() / 2;
        let ell = usize::from(p.statement.axes[0].bits);
        let inner = p.instance.num_vars as usize - ell;
        let round = p.instance.num_vars as usize - self.remaining;
        for suffix in 0..half {
            // Representative surviving layer bits, with all eliminated layer bits zero.
            let owner = match p.statement.order {
                Order::LayerFirst => {
                    if round < ell {
                        suffix >> inner
                    } else {
                        0
                    }
                }
                Order::LayerLast => {
                    if round < inner {
                        suffix & ((1usize << ell) - 1)
                    } else {
                        suffix
                    }
                }
            };
            for node in 0..=p.degree {
                let x = K::from_i64(node as i64);
                let value = p.instance.terms.iter().fold(K::from_i64(0), |sum, term| {
                    sum + term
                        .factors
                        .iter()
                        .fold(term.coefficient, |product, input| {
                            let t = &self.tables[*input as usize];
                            product * (t[suffix] + x * (t[suffix + half] - t[suffix]))
                        })
                });
                let out = &mut partials[owner * (p.degree + 1) + node];
                *out = *out + value;
            }
        }
        Ok(partials)
    }
}
impl<K: ChallengeField + Eq> Summand<K> for &mut Dense<'_, '_, K> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining as u32, self.tables.len())
    }
    fn validate_instance(&self, i: &Instance<K>) -> Result<(), stele_sumcheck::Error> {
        if i != self.prepared.instance() || self.remaining != i.num_vars as usize {
            return Err(stele_sumcheck::Error::InvalidInstance);
        }
        Ok(())
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        if i != self.prepared.instance() {
            return Err(stele_sumcheck::Error::InvalidInstance);
        }
        let partials = self.partials().map_err(|e| {
            if e == Error::Capacity {
                stele_sumcheck::Error::Capacity
            } else {
                stele_sumcheck::Error::PublicShape
            }
        })?;
        let width = self.prepared.degree + 1;
        let mut result = zeros(width).map_err(|_| stele_sumcheck::Error::Capacity)?;
        for block in partials.chunks_exact(width) {
            for (out, value) in result.iter_mut().zip(block) {
                *out = *out + *value;
            }
        }
        Ok(result)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        if self.remaining == 0 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        for table in &mut self.tables {
            let half = table.len() / 2;
            for j in 0..half {
                table[j] = table[j] + r * (table[j + half] - table[j]);
            }
            table.truncate(half);
        }
        self.remaining -= 1;
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if self.remaining != 0 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let mut result = Vec::new();
        reserve(&mut result, self.tables.len()).map_err(|_| stele_sumcheck::Error::Capacity)?;
        result.extend(self.tables.iter().map(|t| t[0]));
        Ok(result)
    }
}
