//! RFC-0006 A6 / formal/streaming.md: sequential windows and one reusable arena.
use crate::{interpolation_weight, reserve, Error, Instance, Summand};
use alloc::vec::Vec;
use stele_hash::ChallengeField;

/// Replayable bit-reversed rows, not authentication of the original inputs.
/// Implementations must fill every element and reject malformed records.
/// The bounded path requires allocation-free rewind/reads; account for source storage separately.
pub trait Source<K> {
    /// Ordered original input identities.
    fn input_ids(&self) -> &[u64];
    /// Original hypercube dimension.
    fn num_vars(&self) -> u32;
    /// Restart the same logical rows; failure aborts the proof attempt.
    fn rewind(&mut self) -> Result<(), Error>;
    /// Fill one complete row, or return false at EOF. Never silently zero-fill.
    fn next_row(&mut self, out: &mut [K]) -> Result<bool, Error>;
}
pub(crate) fn pow2(m: u32) -> Result<usize, Error> {
    if m > 63 {
        return Err(Error::Capacity);
    }
    1usize.checked_shl(m).ok_or(Error::Capacity)
}
pub(crate) fn reverse(index: usize, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
fn eq<K: ChallengeField>(point: &[K], bits: usize) -> K {
    point
        .iter()
        .enumerate()
        .fold(K::from_i64(1), |value, (j, r)| {
            value
                * if bits >> (point.len() - j - 1) & 1 == 1 {
                    *r
                } else {
                    K::from_i64(1) - *r
                }
        })
}
/// A1 source strategy. Owns the full supplied arena capacity; never grows it.
/// Source, descriptor, schedule, proof and process memory must be accounted separately.
pub struct Streaming<'a, K, S> {
    instance: &'a Instance<K>,
    source: S,
    windows: &'a [u32],
    work: Vec<K>,
    point: [K; 64],
    fixed: usize,
    window: usize,
    window_left: u32,
    grid_len: usize,
    degree: usize,
    width: usize,
}
impl<'a, K: ChallengeField + Eq, S: Source<K>> Streaming<'a, K, S> {
    /// Checked sufficient logical arena length; this is not total process memory.
    pub fn workspace_len(i: &Instance<K>, windows: &[u32]) -> Result<usize, Error> {
        let degree = i.validate()?;
        pow2(i.num_vars)?;
        let a = i.inputs.len();
        let mut fixed = 0u32;
        let mut required = 0;
        for &w in windows {
            if w == 0 {
                return Err(Error::InvalidStreaming);
            }
            fixed = fixed.checked_add(w).ok_or(Error::InvalidStreaming)?;
            if fixed > i.num_vars {
                return Err(Error::InvalidStreaming);
            }
            let grid = (degree + 1).max(2).checked_pow(w).ok_or(Error::Capacity)?;
            let cells = a
                .checked_mul(pow2(w)?.checked_add(2).ok_or(Error::Capacity)?)
                .and_then(|v| v.checked_add(grid))
                .ok_or(Error::Capacity)?;
            required = required.max(cells);
        }
        let tail = a
            .checked_mul(
                pow2(i.num_vars - fixed)?
                    .checked_add(1)
                    .ok_or(Error::Capacity)?,
            )
            .ok_or(Error::Capacity)?;
        Ok(required.max(tail))
    }
    /// Validate the schedule and actual retained arena capacity before source access.
    /// `budget` counts K cells of the arena only; source/preparation allocations are separate.
    pub fn new(
        i: &'a Instance<K>,
        source: S,
        windows: &'a [u32],
        work: Vec<K>,
        budget: usize,
    ) -> Result<Self, Error> {
        let required = Self::workspace_len(i, windows)?;
        if work.len() < required || work.capacity() > budget {
            return Err(Error::Capacity);
        }
        let degree = i.validate()?;
        let mut state = Self {
            instance: i,
            source,
            windows,
            work,
            point: [K::from_i64(0); 64],
            fixed: 0,
            window: 0,
            window_left: 0,
            grid_len: 0,
            degree,
            width: (degree + 1).max(2),
        };
        state.metadata()?;
        state.materialize()?;
        Ok(state)
    }
    /// Entire retained allocation, including unused capacity, in K cells.
    pub fn workspace_capacity(&self) -> usize {
        self.work.capacity()
    }
    /// Read source metadata/counters; contents remain subject to the original consumer.
    pub fn source(&self) -> &S {
        &self.source
    }
    fn metadata(&self) -> Result<(), Error> {
        if self.source.num_vars() != self.instance.num_vars
            || self.source.input_ids() != self.instance.inputs
        {
            return Err(Error::PublicShape);
        }
        Ok(())
    }
    fn materialize(&mut self) -> Result<(), Error> {
        let w = self.windows.get(self.window).copied().unwrap_or(0);
        self.window_left = w;
        self.grid_len = if w == 0 { 0 } else { self.width.pow(w) };
        let a = self.instance.inputs.len();
        let suffix = self.instance.num_vars - self.fixed as u32 - w;
        let boolean = pow2(w)?;
        let row_at = if w == 0 {
            a * pow2(suffix)?
        } else {
            self.grid_len + a * boolean
        };
        self.work[..row_at].fill(K::from_i64(0));
        if a == 0 {
            let mut value = self.instance.evaluate(&[]);
            for _ in 0..suffix {
                value = value + value;
            }
            self.work[..self.grid_len].fill(value);
            return Ok(());
        }
        self.metadata()?;
        self.source.rewind()?;
        self.metadata()?;
        for block in 0..pow2(suffix)? {
            if w > 0 {
                self.work[self.grid_len..row_at].fill(K::from_i64(0));
            }
            for physical in 0..pow2(self.fixed as u32 + w)? {
                let index = reverse(physical, self.fixed as u32 + w);
                let prefix = index >> w;
                let v = index & (boolean - 1);
                let weight = eq(&self.point[..self.fixed], prefix);
                if !self.source.next_row(&mut self.work[row_at..row_at + a])? {
                    return Err(Error::Source);
                }
                for input in 0..a {
                    let at = if w == 0 {
                        input * pow2(suffix)? + reverse(block, suffix)
                    } else {
                        self.grid_len + v * a + input
                    };
                    self.work[at] = self.work[at] + weight * self.work[row_at + input];
                }
            }
            if w > 0 {
                for node in 0..self.grid_len {
                    self.work[row_at + a..row_at + 2 * a].fill(K::from_i64(0));
                    for v in 0..boolean {
                        let mut weight = K::from_i64(1);
                        let mut digits = node;
                        for bit in 0..w {
                            let x = K::from_i64((digits % self.width) as i64);
                            digits /= self.width;
                            weight = weight
                                * if v >> bit & 1 == 1 {
                                    x
                                } else {
                                    K::from_i64(1) - x
                                };
                        }
                        for input in 0..a {
                            let at = row_at + a + input;
                            self.work[at] =
                                self.work[at] + weight * self.work[self.grid_len + v * a + input];
                        }
                    }
                    self.work[node] = self.work[node]
                        + self
                            .instance
                            .evaluate(&self.work[row_at + a..row_at + 2 * a]);
                }
            }
        }
        if self.source.next_row(&mut self.work[row_at..row_at + a])? {
            return Err(Error::Source);
        }
        Ok(())
    }
}
impl<K: ChallengeField + Eq, S: Source<K>> Summand<K> for Streaming<'_, K, S> {
    fn shape(&self) -> (u32, usize) {
        (
            self.instance.num_vars - self.fixed as u32,
            self.instance.inputs.len(),
        )
    }
    fn validate_instance(&self, i: &Instance<K>) -> Result<(), Error> {
        if i != self.instance {
            return Err(Error::InvalidStreaming);
        }
        if self.shape() != (i.num_vars, i.inputs.len()) {
            return Err(Error::PublicShape);
        }
        Ok(())
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        let mut out = Vec::new();
        reserve(&mut out, self.degree + 1)?;
        out.resize(self.degree + 1, K::from_i64(0));
        self.round_into(i, &mut out)?;
        Ok(out)
    }
    fn round_into(&self, i: &Instance<K>, out: &mut [K]) -> Result<(), Error> {
        if i != self.instance {
            return Err(Error::InvalidStreaming);
        }
        let remaining = self.shape().0;
        if remaining == 0 {
            return Err(Error::PublicShape);
        }
        if out.len() != self.degree + 1 {
            return Err(Error::ProofShape);
        }
        for (node, value) in out.iter_mut().enumerate() {
            *value = K::from_i64(0);
            if self.window_left > 0 {
                for bits in 0..pow2(self.window_left - 1)? {
                    let mut at = node;
                    for bit in (0..self.window_left - 1).rev() {
                        at = at * self.width + ((bits >> bit) & 1);
                    }
                    *value = *value + self.work[at];
                }
            } else if i.inputs.is_empty() {
                *value = i.evaluate(&[]);
                for _ in 1..remaining {
                    *value = *value + *value;
                }
            } else {
                let half = pow2(remaining - 1)?;
                let x = K::from_i64(node as i64);
                for column in 0..half {
                    *value = *value
                        + i.evaluate_with(|input| {
                            let at = input as usize * half * 2 + column;
                            self.work[at] + x * (self.work[at + half] - self.work[at])
                        });
                }
            }
        }
        Ok(())
    }
    fn fold(&mut self, challenge: K) -> Result<(), Error> {
        let remaining = self.shape().0;
        if remaining == 0 {
            return Err(Error::PublicShape);
        }
        if self.window_left > 0 {
            let mut weights = [K::from_i64(0); 5];
            for (node, weight) in weights[..self.width].iter_mut().enumerate() {
                *weight = interpolation_weight(self.width, node, challenge)?;
            }
            let stride = self.grid_len / self.width;
            for column in 0..stride {
                let mut value = K::from_i64(0);
                for (node, weight) in weights[..self.width].iter().enumerate() {
                    value = value + *weight * self.work[node * stride + column];
                }
                self.work[column] = value;
            }
            self.grid_len = stride;
            self.window_left -= 1;
        } else {
            let half = pow2(remaining - 1)?;
            // A6 §4: forward compaction writes only behind unread source cells.
            for input in 0..self.instance.inputs.len() {
                for column in 0..half {
                    let from = input * 2 * half + column;
                    self.work[input * half + column] =
                        self.work[from] + challenge * (self.work[from + half] - self.work[from]);
                }
            }
        }
        self.point[self.fixed] = challenge;
        self.fixed += 1;
        if self.grid_len > 0 && self.window_left == 0 {
            self.window += 1;
            self.materialize()?;
        }
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        let mut out = Vec::new();
        reserve(&mut out, self.instance.inputs.len())?;
        out.resize(self.instance.inputs.len(), K::from_i64(0));
        self.final_values_into(&mut out)?;
        Ok(out)
    }
    fn final_values_into(&self, out: &mut [K]) -> Result<(), Error> {
        if self.shape().0 != 0 {
            return Err(Error::PublicShape);
        }
        if out.len() != self.instance.inputs.len() {
            return Err(Error::ProofShape);
        }
        out.copy_from_slice(&self.work[..out.len()]);
        Ok(())
    }
}
