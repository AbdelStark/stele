//! MLEs and bucketed partial evaluation, RFC-0006 §5 and RFC-0007 §§1,5.
//! Tables are row-major: point[0] is the most significant index bit (RFC-0005 §2).
//! Partial evaluation fixes trailing coordinates, leaving one output per contiguous row.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
use alloc::vec::Vec;
use stele_field::Field;

/// Invalid polynomial input or a table too large to allocate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Evaluation tables must have nonzero power-of-two length.
    InvalidLength,
    /// More coordinates supplied than the table contains.
    PointDimension,
    /// An int4 value lies outside [-8, 7].
    Int4Range,
    /// Table size overflow or allocation failure.
    Capacity,
}

fn variables(len: usize) -> Result<usize, Error> {
    if !len.is_power_of_two() {
        return Err(Error::InvalidLength);
    }
    Ok(len.trailing_zeros() as usize)
}
fn zeros<K: Field>(len: usize) -> Result<Vec<K>, Error> {
    let mut values = Vec::new();
    values.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    values.resize(len, K::from_i64(0));
    Ok(values)
}

/// Evaluate eq(left, right) without allocation for the verifier (RFC-0006 §§5,6).
pub fn eq_evaluate<K: Field>(left: &[K], right: &[K]) -> Result<K, Error> {
    if left.len() != right.len() {
        return Err(Error::PointDimension);
    }
    let one = K::from_i64(1);
    Ok(left.iter().zip(right).fold(one, |product, (a, b)| {
        product * ((one - *a) * (one - *b) + *a * *b)
    }))
}

/// Build all eq(point, boolean_index) coefficients in index order.
/// Each split uses one multiplication and one subtraction: N-1 of each in total.
pub fn eq_table<K: Field>(point: &[K]) -> Result<Vec<K>, Error> {
    let shift = u32::try_from(point.len()).map_err(|_| Error::Capacity)?;
    let len = 1usize.checked_shl(shift).ok_or(Error::Capacity)?;
    let mut table = zeros(len)?;
    table[0] = K::from_i64(1);
    let mut width = 1;
    for r in point {
        // Descending order preserves parents until both children have been written.
        for index in (0..width).rev() {
            let parent = table[index];
            let right = parent * *r;
            table[2 * index] = parent - right;
            table[2 * index + 1] = right;
        }
        width *= 2;
    }
    Ok(table)
}

/// A dense multilinear evaluation table; length one represents a constant.
#[derive(Clone, Debug)]
pub struct Mle<K> {
    values: Vec<K>,
}
impl<K: Field> Mle<K> {
    /// Check the Boolean-hypercube shape without padding or reordering.
    pub fn new(values: Vec<K>) -> Result<Self, Error> {
        variables(values.len())?;
        Ok(Self { values })
    }
    /// Borrow evaluations in row-major Boolean index order.
    pub fn values(&self) -> &[K] {
        &self.values
    }
    /// Number of Boolean coordinates.
    pub fn num_vars(&self) -> usize {
        self.values.len().trailing_zeros() as usize
    }
    /// Fix trailing coordinates using the explicit eq-weighted sum.
    pub fn partial_evaluate(&self, point: &[K]) -> Result<Self, Error> {
        if point.len() > self.num_vars() {
            return Err(Error::PointDimension);
        }
        let eq = eq_table(point)?;
        let mut result = zeros(self.values.len() / eq.len())?;
        for (out, row) in result.iter_mut().zip(self.values.chunks_exact(eq.len())) {
            for (value, coefficient) in row.iter().zip(&eq) {
                *out = *out + *value * *coefficient;
            }
        }
        Self::new(result)
    }
}

/// Reference and small-value kernels for the same partial evaluation (RFC-0006 §5).
#[derive(Clone, Copy, Debug)]
pub enum Strategy {
    /// One signed-integer embedding and multiplication per table entry.
    Naive,
    /// Accumulate eq coefficients by signed value, then combine buckets.
    Bucketed,
}
#[derive(Debug)]
enum Storage {
    Int4(Vec<u8>),
    Int8(Vec<i8>),
    Int16(Vec<i16>),
}

/// A checked signed-integer MLE; int4 stores the first entry in the low nibble.
/// Range validation is at construction, not repeated during the weight pass.
#[derive(Debug)]
pub struct SmallMle {
    storage: Storage,
    len: usize,
}
impl SmallMle {
    /// Validate and pack signed int4 entries; an unused high nibble is zero.
    pub fn int4(values: Vec<i8>) -> Result<Self, Error> {
        variables(values.len())?;
        if values.iter().any(|v| !(-8..=7).contains(v)) {
            return Err(Error::Int4Range);
        }
        let len = values.len();
        let mut packed = Vec::new();
        packed
            .try_reserve_exact(len.div_ceil(2))
            .map_err(|_| Error::Capacity)?;
        for pair in values.chunks(2) {
            packed
                .push((pair[0] as u8 & 15) | ((pair.get(1).copied().unwrap_or(0) as u8 & 15) << 4));
        }
        Ok(Self {
            storage: Storage::Int4(packed),
            len,
        })
    }
    /// Take ownership of a signed int8 table, checking its shape.
    pub fn int8(values: Vec<i8>) -> Result<Self, Error> {
        variables(values.len())?;
        Ok(Self {
            len: values.len(),
            storage: Storage::Int8(values),
        })
    }
    /// Take ownership of a signed int16 table, checking its shape.
    pub fn int16(values: Vec<i16>) -> Result<Self, Error> {
        variables(values.len())?;
        Ok(Self {
            len: values.len(),
            storage: Storage::Int16(values),
        })
    }
    /// Bytes occupied by table entries, excluding allocator overhead and spare capacity.
    pub fn payload_bytes(&self) -> usize {
        match &self.storage {
            Storage::Int4(v) => v.len(),
            Storage::Int8(v) => v.len(),
            Storage::Int16(v) => v.len() * 2,
        }
    }
    fn bits(&self) -> u32 {
        match self.storage {
            Storage::Int4(_) => 4,
            Storage::Int8(_) => 8,
            Storage::Int16(_) => 16,
        }
    }
    fn value(&self, index: usize) -> i64 {
        match &self.storage {
            Storage::Int4(v) => {
                let nibble = (v[index / 2] >> (4 * (index % 2))) & 15;
                i64::from((nibble as i8) << 4 >> 4)
            }
            Storage::Int8(v) => i64::from(v[index]),
            Storage::Int16(v) => i64::from(v[index]),
        }
    }
    /// Fix trailing coordinates, reading each integer entry once per call.
    /// Buckets are reused across rows; outputs remain in the full challenge field K.
    pub fn partial_evaluate<K: Field>(
        &self,
        point: &[K],
        strategy: Strategy,
    ) -> Result<Mle<K>, Error> {
        if point.len() > self.len.trailing_zeros() as usize {
            return Err(Error::PointDimension);
        }
        let eq = eq_table(point)?;
        let mut result = zeros(self.len / eq.len())?;
        let bucket_count = 1usize << self.bits();
        let offset = (bucket_count / 2) as i64;
        let mut buckets = match strategy {
            Strategy::Naive => Vec::new(),
            Strategy::Bucketed => zeros(bucket_count)?,
        };
        for (row, out) in result.iter_mut().enumerate() {
            match strategy {
                Strategy::Naive => {
                    for (column, coefficient) in eq.iter().enumerate() {
                        *out =
                            *out + K::from_i64(self.value(row * eq.len() + column)) * *coefficient;
                    }
                }
                Strategy::Bucketed => {
                    buckets.fill(K::from_i64(0));
                    for (column, coefficient) in eq.iter().enumerate() {
                        let index = (self.value(row * eq.len() + column) + offset) as usize;
                        buckets[index] = buckets[index] + *coefficient;
                    }
                    // Sum j*b[j] via suffix sums; subtract offset*sum(b) to restore signed values.
                    let mut suffix = K::from_i64(0);
                    let mut weighted = K::from_i64(0);
                    for bucket in buckets[1..].iter().rev() {
                        suffix = suffix + *bucket;
                        weighted = weighted + suffix;
                    }
                    *out = weighted - K::from_i64(offset) * (suffix + buckets[0]);
                }
            }
        }
        Mle::new(result)
    }
}
