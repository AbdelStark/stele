//! RFC-0006 A4 §4: restrict inputs before nonlinear P; one owned current state.
use super::{observed, reserve, zeros, Error, Failure, Order, Prepared};
use crate::public_mle::Kind;
use alloc::vec::Vec;
use core::{
    cell::{Cell, RefCell},
    mem::size_of,
};
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
/// Actual simultaneous scratch allocations in one A4 production round.
/// Pair with that round's A1 proof prefix; values are the same returned vector.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DenseRoundWork {
    /// Partial-vector capacity in bytes, before it is dropped.
    pub partial_bytes: usize,
    /// Result-vector capacity in bytes, transferred to A1 without copying.
    pub values_bytes: usize,
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
    /// Actual table headers, full table capacities and captured-point capacity.
    /// Excludes borrowed Prepared, stack, temporary rounds and allocator metadata.
    pub fn owned_bytes(&self) -> Result<usize, Error> {
        super::add(
            super::mul(self.capacity_entries()?, size_of::<K>())?,
            super::mul(self.tables.capacity(), size_of::<Vec<K>>())?,
        )
    }
    fn begin(&self, t: &mut Transcript<K>) -> Result<(), Error> {
        if self.remaining != self.prepared.instance.num_vars as usize || !self.point.is_empty() {
            return Err(Error::InvalidStacked);
        }
        t.absorb(AbsorbLabel::Stack, self.prepared.bytes())
            .map_err(Error::Transcript)
    }
    /// Absorb Stack and run the actual A1 producer on pristine prepared state.
    /// The enclosing consumer must have fixed all originals before this segment.
    pub fn prove(&mut self, t: &mut Transcript<K>) -> Result<Proof<K>, Failure> {
        let result = (|| {
            self.begin(t)?;
            stele_sumcheck::prove(self.prepared.instance(), &mut *self, t).map_err(Error::Sumcheck)
        })();
        observed(result, t).map(|(proof, _)| proof)
    }
    /// The same A4/A1 execution, recording both sides of each actual round.
    /// Both slices must have exactly m slots; bad counts reject before Stack.
    /// Returned work covers A1 only; add owned Prepared/Dense and paired scratch
    /// at their actual lifetimes. Discard all observations on any failure.
    pub fn prove_measured(
        &mut self,
        t: &mut Transcript<K>,
        a1_rounds: &mut [stele_sumcheck::RoundWork],
        dense_rounds: &mut [DenseRoundWork],
    ) -> Result<(Proof<K>, stele_sumcheck::ProverWork), Failure> {
        let result = (|| {
            let instance = self.prepared.instance();
            if a1_rounds.len() != instance.num_vars as usize
                || dense_rounds.len() != instance.num_vars as usize
            {
                return Err(Error::Capacity);
            }
            self.begin(t)?;
            dense_rounds.fill(DenseRoundWork::default());
            stele_sumcheck::prove_measured(
                instance,
                Measured {
                    dense: self,
                    rounds: RefCell::new(dense_rounds),
                },
                t,
                a1_rounds,
            )
            .map_err(Error::Sumcheck)
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
        self.round_with_work(i).map(|(values, _)| values)
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

impl<K: ChallengeField + Eq> Dense<'_, '_, K> {
    fn round_with_work(
        &self,
        i: &Instance<K>,
    ) -> Result<(Vec<K>, DenseRoundWork), stele_sumcheck::Error> {
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
        let observation = DenseRoundWork {
            partial_bytes: partials
                .capacity()
                .checked_mul(size_of::<K>())
                .ok_or(stele_sumcheck::Error::Capacity)?,
            values_bytes: result
                .capacity()
                .checked_mul(size_of::<K>())
                .ok_or(stele_sumcheck::Error::Capacity)?,
        };
        Ok((result, observation))
    }
}

// A4 §6: one borrowed recorder, no heap allocation or protocol callback.
struct Measured<'d, 'p, 'a, 'o, K> {
    dense: &'d mut Dense<'p, 'a, K>,
    rounds: RefCell<&'o mut [DenseRoundWork]>,
}
impl<K: ChallengeField + Eq> Summand<K> for Measured<'_, '_, '_, '_, K> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn validate_instance(&self, i: &Instance<K>) -> Result<(), stele_sumcheck::Error> {
        self.dense.validate_instance(i)
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        let index = (i.num_vars as usize)
            .checked_sub(self.dense.remaining)
            .ok_or(stele_sumcheck::Error::Capacity)?;
        let (values, work) = self.dense.round_with_work(i)?;
        let mut rounds = self
            .rounds
            .try_borrow_mut()
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        *rounds
            .get_mut(index)
            .ok_or(stele_sumcheck::Error::Capacity)? = work;
        Ok(values)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        self.dense.fold(r)
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.final_values()
    }
}
