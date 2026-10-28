//! RFC-0006 A7 — checked public coefficient arithmetic, not source authentication.
//! Costs and the Boolean-table definitions are in formal/public-coefficient.md.
use alloc::vec::Vec;
use stele_field::{Field, M31};

/// A malformed descriptor, query or resource request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid layout, selector, primitive parameters or source shape.
    Shape,
    /// K must extend the M31 base field used by exact table entries.
    FieldMismatch,
    /// Query length differs from the admitted layout.
    PointDimension,
    /// Checked size, caller vector budget or allocation failed.
    Capacity,
}
/// One MSB-first axis; padding is outside `real` and evaluates to zero on the cube.
#[derive(Clone, Copy, Debug)]
pub struct Axis {
    /// Number of coordinate bits, at most 63.
    pub bits: u8,
    /// Real length, in 1..=2^bits.
    pub real: u64,
}
/// Boolean primitive, before multiplying validity and selected-axis weights.
/// Source slices are mathematical inputs, never evidence of authentication.
#[derive(Clone, Copy, Debug)]
pub enum Kind<'a> {
    /// Constant one; selectors supply any equality points.
    Eq,
    /// Indicator column <= row on two distinct equal-width axes.
    CausalMask { row: usize, column: usize },
    /// Causal indicator with row-column < positive width.
    WindowMask {
        row: usize,
        column: usize,
        width: u64,
    },
    /// One category index per real row.
    OnehotSparse {
        row: usize,
        column: usize,
        indices: &'a [u64],
    },
    /// Contiguous equal-sized groups of real heads.
    GqaBroadcast { head: usize, group: usize },
    /// Exact unpadded row-major table on strictly increasing source axes.
    /// This does not generate or authenticate CQIS rotation values.
    RopeTables {
        axes: &'a [usize],
        values: &'a [M31],
    },
}
/// An admitted immutable coefficient. Evaluation emits no claim or source receipt.
pub struct Coefficient<'a, K> {
    axes: &'a [Axis],
    selectors: &'a [Option<&'a [K]>],
    kind: Kind<'a>,
    offsets: [usize; 65],
}
impl<'a, K: Field> Coefficient<'a, K> {
    /// Validate the complete mathematical descriptor and total axis-vector budget.
    /// Protocol callers must separately authenticate sources and bind their plan.
    pub fn new(
        axes: &'a [Axis],
        selectors: &'a [Option<&'a [K]>],
        kind: Kind<'a>,
        max_vector_entries: usize,
    ) -> Result<Self, Error> {
        if K::MODULUS != M31::MODULUS {
            return Err(Error::FieldMismatch);
        }
        if axes.is_empty() || axes.len() > 64 || selectors.len() != axes.len() {
            return Err(Error::Shape);
        }
        let mut offsets = [0; 65];
        for (i, axis) in axes.iter().enumerate() {
            if axis.bits > 63
                || axis.real == 0
                || axis.real > 1u64 << axis.bits
                || selectors[i].is_some_and(|z| z.len() != usize::from(axis.bits))
            {
                return Err(Error::Shape);
            }
            offsets[i + 1] = offsets[i] + usize::from(axis.bits);
        }
        if offsets[axes.len()] > 63 {
            return Err(Error::Shape);
        }
        let pair = |a: usize, b: usize| {
            if a == b || a >= axes.len() || b >= axes.len() {
                Err(Error::Shape)
            } else {
                Ok(())
            }
        };
        match kind {
            Kind::Eq => (),
            Kind::CausalMask { row, column } | Kind::WindowMask { row, column, .. } => {
                pair(row, column)?;
                if axes[row].bits != axes[column].bits
                    || matches!(kind, Kind::WindowMask { width: 0, .. })
                {
                    return Err(Error::Shape);
                }
            }
            Kind::OnehotSparse {
                row,
                column,
                indices,
            } => {
                pair(row, column)?;
                if u64::try_from(indices.len()).map_err(|_| Error::Capacity)? != axes[row].real
                    || indices.iter().any(|i| *i >= axes[column].real)
                {
                    return Err(Error::Shape);
                }
            }
            Kind::GqaBroadcast { head, group } => {
                pair(head, group)?;
                if !axes[head].real.is_multiple_of(axes[group].real) {
                    return Err(Error::Shape);
                }
            }
            Kind::RopeTables {
                axes: chosen,
                values,
            } => {
                if chosen.is_empty()
                    || chosen.iter().any(|a| *a >= axes.len())
                    || chosen.windows(2).any(|a| a[0] >= a[1])
                {
                    return Err(Error::Shape);
                }
                let count = chosen.iter().try_fold(1u64, |n, a| {
                    n.checked_mul(axes[*a].real).ok_or(Error::Capacity)
                })?;
                if count != u64::try_from(values.len()).map_err(|_| Error::Capacity)? {
                    return Err(Error::Shape);
                }
            }
        }
        let c = Self {
            axes,
            selectors,
            kind,
            offsets,
        };
        let mut entries = 0usize;
        if matches!(
            kind,
            Kind::OnehotSparse { .. } | Kind::GqaBroadcast { .. } | Kind::RopeTables { .. }
        ) {
            for (a, axis) in axes.iter().enumerate() {
                if c.chosen(a) {
                    let size = 1usize
                        .checked_shl(u32::from(axis.bits))
                        .ok_or(Error::Capacity)?;
                    entries = entries.checked_add(size).ok_or(Error::Capacity)?;
                }
            }
        }
        if entries > max_vector_entries {
            return Err(Error::Capacity);
        }
        Ok(c)
    }
    fn chosen(&self, a: usize) -> bool {
        match self.kind {
            Kind::Eq => false,
            Kind::CausalMask { row, column }
            | Kind::WindowMask { row, column, .. }
            | Kind::OnehotSparse { row, column, .. } => a == row || a == column,
            Kind::GqaBroadcast { head, group } => a == head || a == group,
            Kind::RopeTables { axes, .. } => axes.binary_search(&a).is_ok(),
        }
    }
    fn weights(&self, a: usize, low_bit: usize, point: &[K]) -> [K; 2] {
        let bit = usize::from(self.axes[a].bits) - 1 - low_bit;
        let r = point[self.offsets[a] + bit];
        let one = K::from_i64(1);
        let mut pair = [one - r, r];
        if let Some(z) = self.selectors[a] {
            pair = [pair[0] * (one - z[bit]), pair[1] * z[bit]];
        }
        pair
    }
    fn bounded(&self, a: usize, point: &[K]) -> K {
        let zero = K::from_i64(0);
        let mut state = [K::from_i64(1), zero];
        for bit in 0..usize::from(self.axes[a].bits) {
            let weights = self.weights(a, bit, point);
            let mut out = [zero; 2];
            for (borrow, value) in state.iter().enumerate() {
                for (choice, weight) in weights.iter().enumerate() {
                    let next = usize::from(
                        ((self.axes[a].real - 1) >> bit & 1) < (choice + borrow) as u64,
                    );
                    out[next] = out[next] + *value * *weight;
                }
            }
            state = out;
        }
        state[0]
    }
    fn offset(&self, row: usize, column: usize, shift: u64, point: &[K]) -> K {
        let zero = K::from_i64(0);
        if shift >= 1u64 << self.axes[row].bits {
            return zero;
        }
        let mut state = [zero; 16];
        state[0] = K::from_i64(1);
        for bit in 0..usize::from(self.axes[row].bits) {
            let r = self.weights(row, bit, point);
            let s = self.weights(column, bit, point);
            let weights = [[r[0] * s[0], r[0] * s[1]], [r[1] * s[0], r[1] * s[1]]];
            let mut out = [zero; 16];
            // RFC-0006 A7: state is addition carry, comparison borrow, then
            // row/column-bound borrows. Every Boolean assignment occurs once.
            for (old, value) in state.iter().enumerate() {
                for (i, row_weights) in weights.iter().enumerate() {
                    for (j, weight) in row_weights.iter().enumerate() {
                        let added = j + ((shift >> bit & 1) as usize) + (old & 1);
                        let compare = usize::from(i < (added & 1) + ((old >> 1) & 1));
                        let rb = usize::from(
                            ((self.axes[row].real - 1) >> bit & 1) < (i + ((old >> 2) & 1)) as u64,
                        );
                        let cb = usize::from(
                            ((self.axes[column].real - 1) >> bit & 1)
                                < (j + ((old >> 3) & 1)) as u64,
                        );
                        let next = (added >> 1) | (compare << 1) | (rb << 2) | (cb << 3);
                        out[next] = out[next] + *value * *weight;
                    }
                }
            }
            state = out;
        }
        state[0]
    }
    fn vector(&self, a: usize, point: &[K]) -> Result<Vec<K>, Error> {
        let size = 1usize
            .checked_shl(u32::from(self.axes[a].bits))
            .ok_or(Error::Capacity)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        out.resize(size, K::from_i64(0));
        out[0] = K::from_i64(1);
        let mut width = 1;
        for bit in (0..usize::from(self.axes[a].bits)).rev() {
            let weights = self.weights(a, bit, point);
            for i in (0..width).rev() {
                let parent = out[i];
                out[2 * i] = parent * weights[0];
                out[2 * i + 1] = parent * weights[1];
            }
            width *= 2;
        }
        Ok(out)
    }
    /// Evaluate the specified MLE at a canonical-axis point. This authenticates
    /// neither this point nor any source and consumes no protocol obligation.
    pub fn evaluate(&self, point: &[K]) -> Result<K, Error> {
        if point.len() != self.offsets[self.axes.len()] {
            return Err(Error::PointDimension);
        }
        let mut broadcast = K::from_i64(1);
        for a in 0..self.axes.len() {
            if !self.chosen(a) {
                broadcast = broadcast * self.bounded(a, point);
            }
        }
        let value = match self.kind {
            Kind::Eq => K::from_i64(1),
            Kind::CausalMask { row, column } => self.offset(row, column, 0, point),
            Kind::WindowMask { row, column, width } => {
                self.offset(row, column, 0, point) - self.offset(row, column, width, point)
            }
            Kind::OnehotSparse { row, column, .. }
            | Kind::GqaBroadcast {
                head: row,
                group: column,
            } => {
                let r = self.vector(row, point)?;
                let s = self.vector(column, point)?;
                let mut sum = K::from_i64(0);
                for (i, weight) in r.iter().take(self.axes[row].real as usize).enumerate() {
                    let j = match self.kind {
                        Kind::OnehotSparse { indices, .. } => indices[i],
                        _ => i as u64 / (self.axes[row].real / self.axes[column].real),
                    };
                    sum = sum + *weight * s[j as usize];
                }
                sum
            }
            Kind::RopeTables { axes, values } => {
                let mut vectors = Vec::new();
                vectors
                    .try_reserve_exact(axes.len())
                    .map_err(|_| Error::Capacity)?;
                for a in axes {
                    vectors.push(self.vector(*a, point)?);
                }
                let mut sum = K::from_i64(0);
                for (index, value) in values.iter().enumerate() {
                    let mut remaining = index;
                    let mut term = K::from_i64(i64::from(value.as_u32()));
                    for (a, vector) in axes.iter().zip(&vectors).rev() {
                        let real = self.axes[*a].real as usize;
                        term = term * vector[remaining % real];
                        remaining /= real;
                    }
                    sum = sum + term;
                }
                sum
            }
        };
        Ok(broadcast * value)
    }
}
