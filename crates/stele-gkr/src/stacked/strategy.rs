//! RFC-0006 A4 §4: restrict inputs before nonlinear P; one owned current state.
use super::{observed, reserve, zeros, Error, Failure, Order, Prepared};
use crate::public_mle::Kind;
use alloc::vec::Vec;
use core::cell::Cell;
use stele_field::{Field, M31};
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};
use stele_sumcheck::{Instance, Proof, Summand};

/// Successful dense execution observations (A4 §§4,6), never proof authority.
/// Field entries only: excludes Vec headers, Prepared, other retained proof/descriptor storage,
/// A7/A9 temporaries, caller inputs, allocator metadata and process memory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// Actual retained table capacities plus the reserved captured-point capacity.
    pub dense_entries: usize,
    /// Largest actual partial-vector capacity used by a production round.
    pub partial_entries: usize,
    /// Largest actual returned round-vector capacity.
    pub round_entries: usize,
    /// Largest simultaneous partial-plus-result capacity within one round.
    pub round_scratch_entries: usize,
    /// Successful production round calls; diagnostic partials() calls are excluded.
    pub rounds: usize,
}
/// Dense reference strategy. Partials use the same routine as the actual A1 round.
pub struct Dense<'p, 'a, K> {
    prepared: &'p Prepared<'a, K>,
    tables: Vec<Vec<K>>,
    remaining: usize,
    point: Vec<K>,
    work: Cell<Work>,
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
        self.check_tables(tables, K::from_i64(0))?;
        self.prepare_tables(tables.len(), |input, index| tables[input][index])
    }
    /// Embed immutable A9 message values directly into their final dense slots;
    /// no additional full extension-field copy is retained.
    pub fn strategy_m31(&self, tables: &[&[M31]]) -> Result<Dense<'_, 'a, K>, Error> {
        self.check_tables(tables, M31::from_i64(0))?;
        self.prepare_tables(tables.len(), |input, index| {
            K::from_i64(i64::from(tables[input][index].as_u32()))
        })
    }
    fn prepare_tables<F: Fn(usize, usize) -> K>(
        &self,
        count: usize,
        value: F,
    ) -> Result<Dense<'_, 'a, K>, Error> {
        let mut point = Vec::new();
        reserve(&mut point, self.instance.num_vars as usize)?;
        let mut current = Vec::new();
        reserve(&mut current, count + 1)?;
        let ell = usize::from(self.statement.axes[0].bits);
        let inner = self.instance.num_vars as usize - ell;
        for input in 0..=count {
            let mut table = zeros(self.n)?;
            for (index, out) in table.iter_mut().enumerate() {
                let canonical = if self.statement.order == Order::LayerFirst {
                    index
                } else {
                    ((index & ((1usize << ell) - 1)) << inner) | (index >> ell)
                };
                *out = if input == count {
                    self.boolean(canonical)
                } else {
                    value(input, canonical)
                };
            }
            current.push(table);
        }
        let dense = Dense {
            prepared: self,
            tables: current,
            remaining: self.instance.num_vars as usize,
            point,
            work: Cell::new(Work::default()),
        };
        dense.work.set(Work {
            dense_entries: dense.capacity_entries()?,
            ..Work::default()
        });
        Ok(dense)
    }
}
impl<K: ChallengeField + Eq> Dense<'_, '_, K> {
    /// Observed capacities from this actual strategy; not a complete stage peak.
    pub fn work(&self) -> Work {
        self.work.get()
    }
    /// Actual retained field capacity, including the folded-away tail of each table.
    pub fn capacity_entries(&self) -> Result<usize, Error> {
        self.tables
            .iter()
            .try_fold(self.point.capacity(), |sum, t| {
                sum.checked_add(t.capacity()).ok_or(Error::Capacity)
            })
    }
    /// Absorb Stack and run the actual A1 producer on pristine prepared state.
    /// The enclosing consumer must have fixed all originals before this segment.
    pub fn prove(&mut self, t: &mut Transcript<K>) -> Result<Proof<K>, Failure> {
        let result = (|| {
            if self.remaining != self.prepared.instance.num_vars as usize || !self.point.is_empty()
            {
                return Err(Error::InvalidStacked);
            }
            t.absorb(AbsorbLabel::Stack, self.prepared.bytes())
                .map_err(Error::Transcript)?;
            stele_sumcheck::prove(self.prepared.instance(), &mut *self, t).map_err(Error::Sumcheck)
        })();
        observed(result, t).map(|(proof, _)| proof)
    }
    /// Consume the completed strategy and move out its captured fold arguments.
    /// In the closed producer these are exactly the actual A1 challenges; this
    /// unclosed strategy method grants no transcript or source authority itself.
    /// Retained tables are dropped here, before the producer prepares PCS openings.
    pub fn into_point(mut self) -> Result<Vec<K>, Error> {
        if self.remaining != 0 || self.point.len() != self.prepared.instance.num_vars as usize {
            return Err(Error::InvalidStacked);
        }
        if self.prepared.statement.order == Order::LayerLast {
            self.point
                .rotate_right(usize::from(self.prepared.statement.axes[0].bits));
        }
        Ok(self.point)
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
        // A4 §6: observe the actual coexisting buffers, without replay/allocation.
        let mut work = self.work.get();
        work.partial_entries = work.partial_entries.max(partials.capacity());
        work.round_entries = work.round_entries.max(result.capacity());
        work.round_scratch_entries = work.round_scratch_entries.max(
            partials
                .capacity()
                .checked_add(result.capacity())
                .ok_or(stele_sumcheck::Error::Capacity)?,
        );
        work.rounds = work
            .rounds
            .checked_add(1)
            .ok_or(stele_sumcheck::Error::Capacity)?;
        self.work.set(work);
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
        // A4 §3: the closed producer gets this argument from the actual A1 engine.
        // All m slots were reserved before any transcript absorb.
        self.point.push(r);
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
