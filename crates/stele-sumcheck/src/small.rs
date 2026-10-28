//! RFC-0006 A5: O(F*k*b^k*N/2^k) base work; typed inputs plus small grid and tail.
use crate::{interpolation_weights, reserve, Dense, Error, Instance, Summand};
use alloc::vec::Vec;
use stele_field::{Field, M31};
use stele_hash::ChallengeField;

/// Static optimization eligibility, not a range proof for an authenticated tensor.
#[derive(Clone, Debug)]
pub enum SmallTable {
    /// Exact signed values in [-32768,32767]; no observed-maximum inference.
    Signed(Vec<i16>),
    /// Exact unsigned values in [0,65535]; external narrowing must be checked.
    Unsigned(Vec<u16>),
}
impl SmallTable {
    fn len(&self) -> usize {
        match self {
            Self::Signed(v) => v.len(),
            Self::Unsigned(v) => v.len(),
        }
    }
    fn value(&self, index: usize) -> i64 {
        match self {
            Self::Signed(v) => i64::from(v[index]),
            Self::Unsigned(v) => i64::from(v[index]),
        }
    }
}
fn filled<T: Copy>(value: T, len: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, len)?;
    out.resize(len, value);
    Ok(out)
}
// RFC-0006 A5: extend MSB axes over fixed base nodes; no K challenge enters here.
fn factor_grid(
    table: &SmallTable,
    column: usize,
    suffix: usize,
    k: u8,
    b: usize,
) -> Result<Vec<M31>, Error> {
    let mut grid = Vec::new();
    reserve(&mut grid, 1usize << k)?;
    for prefix in 0..1usize << k {
        grid.push(M31::from_i64(table.value(prefix * suffix + column)));
    }
    for axis in 0..u32::from(k) {
        let rest = 1usize << (u32::from(k) - axis - 1);
        let prefixes = b.pow(axis);
        let mut next = Vec::new();
        reserve(&mut next, prefixes * b * rest)?;
        for prefix in 0..prefixes {
            let offset = prefix * 2 * rest;
            for node in 0..b {
                let x = M31::from_i64(node as i64);
                for z in 0..rest {
                    next.push(grid[offset + z] + x * (grid[offset + rest + z] - grid[offset + z]));
                }
            }
        }
        grid = next;
    }
    Ok(grid)
}
fn prefix_grid<K: ChallengeField>(
    i: &Instance<K>,
    source: &[SmallTable],
    k: u8,
    b: usize,
    suffix: usize,
) -> Result<Vec<K>, Error> {
    let size = b.pow(u32::from(k));
    let mut result = filled(K::from_i64(0), size)?;
    for term in &i.terms {
        let mut accumulated = filled(M31::ZERO, size)?;
        if term.factors.is_empty() {
            accumulated.fill(M31::from_u64(
                u64::try_from(suffix).map_err(|_| Error::Capacity)?,
            ));
        } else {
            for column in 0..suffix {
                let mut product = filled(M31::ONE, size)?;
                for factor in &term.factors {
                    let grid = factor_grid(&source[*factor as usize], column, suffix, k, b)?;
                    for (p, v) in product.iter_mut().zip(grid) {
                        *p = *p * v;
                    }
                }
                for (sum, v) in accumulated.iter_mut().zip(product) {
                    *sum = *sum + v;
                }
            }
        }
        for (sum, v) in result.iter_mut().zip(accumulated) {
            *sum = *sum + term.coefficient * K::from_i64(i64::from(v.as_u32()));
        }
    }
    Ok(result)
}
/// A1 prover strategy retaining typed original tables through k prefix rounds.
/// All grid folds use K; k changes internal work, never proof bytes or obligations.
pub struct Small<'a, K> {
    instance: &'a Instance<K>,
    source: Vec<SmallTable>,
    grid: Vec<K>,
    point: Vec<K>,
    tail: Option<Dense<K>>,
    remaining: u32,
    prefix: u8,
    width: usize,
    degree: usize,
}
impl<'a, K: ChallengeField + Eq> Small<'a, K> {
    /// Check static representation, dimensions and prefix before computing any grid.
    pub fn new(i: &'a Instance<K>, source: Vec<SmallTable>, k: u8) -> Result<Self, Error> {
        let degree = i.validate()?;
        if !(2..=4).contains(&k) || u32::from(k) > i.num_vars {
            return Err(Error::InvalidSmallValue);
        }
        let size = 1usize.checked_shl(i.num_vars).ok_or(Error::Capacity)?;
        if source.len() != i.inputs.len() || source.iter().any(|table| table.len() != size) {
            return Err(Error::PublicShape);
        }
        let width = (degree + 1).max(2);
        let grid = prefix_grid(i, &source, k, width, size >> k)?;
        let mut point = Vec::new();
        reserve(&mut point, usize::from(k))?;
        Ok(Self {
            instance: i,
            source,
            grid,
            point,
            tail: None,
            remaining: i.num_vars,
            prefix: k,
            width,
            degree,
        })
    }
    fn materialize_tail(&mut self) -> Result<(), Error> {
        // RFC-0006 A5: no full-sized K input copy, and all unused inputs survive.
        self.grid = Vec::new();
        let weights = stele_poly::eq_table(&self.point).map_err(|_| Error::Capacity)?;
        let width = 1usize.checked_shl(self.remaining).ok_or(Error::Capacity)?;
        let mut tables = Vec::new();
        reserve(&mut tables, self.source.len())?;
        for source in &self.source {
            let mut out = Vec::new();
            reserve(&mut out, width)?;
            for column in 0..width {
                let mut value = K::from_i64(0);
                for (prefix, weight) in weights.iter().enumerate() {
                    value = value + *weight * K::from_i64(source.value(prefix * width + column));
                }
                out.push(value);
            }
            tables.push(out);
        }
        self.source = Vec::new();
        self.tail = Some(Dense::from_folded(tables, self.remaining)?);
        Ok(())
    }
}
impl<K: ChallengeField + Eq> Summand<K> for Small<'_, K> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining, self.instance.inputs.len())
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        if self.instance != i {
            return Err(Error::InvalidSmallValue);
        }
        if self.remaining == 0 {
            return Err(Error::PublicShape);
        }
        if let Some(tail) = &self.tail {
            return tail.round(i);
        }
        // Transition in fold ensures an unfixed prefix coordinate remains here.
        let rest = usize::from(self.prefix) - self.point.len() - 1;
        let mut result = Vec::new();
        reserve(&mut result, self.degree + 1)?;
        for node in 0..=self.degree {
            let mut value = K::from_i64(0);
            for bits in 0..1usize << rest {
                let mut index = node;
                for axis in (0..rest).rev() {
                    index = index * self.width + ((bits >> axis) & 1);
                }
                value = value + self.grid[index];
            }
            result.push(value);
        }
        Ok(result)
    }
    fn fold(&mut self, challenge: K) -> Result<(), Error> {
        if self.remaining == 0 {
            return Err(Error::PublicShape);
        }
        if let Some(tail) = &mut self.tail {
            tail.fold(challenge)?;
            self.remaining -= 1;
            return Ok(());
        }
        let weights = interpolation_weights(self.width, challenge)?;
        let stride = self.grid.len() / self.width;
        for column in 0..stride {
            let mut value = K::from_i64(0);
            for (node, weight) in weights.iter().enumerate() {
                value = value + *weight * self.grid[node * stride + column];
            }
            self.grid[column] = value;
        }
        self.grid.truncate(stride);
        self.point.push(challenge);
        self.remaining -= 1;
        if self.point.len() == usize::from(self.prefix) {
            self.materialize_tail()?;
        }
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        if self.remaining != 0 {
            return Err(Error::PublicShape);
        }
        self.tail.as_ref().ok_or(Error::PublicShape)?.final_values()
    }
}
