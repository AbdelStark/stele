//! The Circle code over M31 (RFC-0010 A2), for the verifier's column checks (task
//! E8-02c).
//!
//! Provenance (#374 review): the transforms are written as the recursive circle and x
//! transforms on the canonical coset of RFC-0010 A2 and the Python reference
//! (`research/circle-code/check_circle.py`), not as `stele-code`'s iterative
//! butterflies. `Circle::new`'s size guard and `code_id` follow the A2 text and match
//! production character for character. The encoder is held to the shared vectors
//! (`research/circle-code/vectors.txt`, also read by `stele-code`'s own test), to the
//! A2 basis evaluated point by point, and to a matrix-solve interpolation oracle.
//!
//! A row of `2^m` values is a function on the coset `D_m`. Its coefficients in the
//! basis `y^{b_0}·x^{b_1}·π(x)^{b_2}·…` (`π(x) = 2x² − 1`) are interpolated on `D_m`
//! and evaluated on `D_{m+b}`, `b ∈ {1, 2}`. The map is M31-linear, so an extension
//! element is encoded limb by limb through `mul_m31`. Every buffer is allocated
//! fallibly.

use alloc::vec::Vec;
use stele_field::{Field, Inverse, M31};

/// Why an encoding was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The blowup is not 1 or 2, or `m + b` exceeds 30.
    InvalidSize,
    /// The row is not `2^m` long.
    RowShape,
    /// A requested column is outside the codeword.
    Column,
    /// The element field does not have characteristic `p = 2^31 − 1`.
    FieldMismatch,
    /// A size does not fit in memory.
    Capacity,
}

/// The Circle code `C(m, b)`: messages of `2^m`, codewords of `2^(m+b)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Circle {
    log_message: u32,
    log_blowup: u32,
}

/// The circle group's generator of order `2^31` (RFC-0010 A2).
const GENERATOR: (u32, u32) = (1_717_986_917, 1_288_490_189);

/// An empty vector with room for `n` values, or `Capacity`.
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}

fn m31(x: u32) -> M31 {
    M31::from_i64(i64::from(x))
}

fn mul(a: (M31, M31), b: (M31, M31)) -> (M31, M31) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

fn power(mut a: (M31, M31), mut n: u64) -> (M31, M31) {
    let mut r = (m31(1), m31(0));
    while n > 0 {
        if n & 1 == 1 {
            r = mul(r, a);
        }
        a = mul(a, a);
        n >>= 1;
    }
    r
}

/// The first half of the canonical coset `D_log` (`g^{(2i+1)·2^(30−log)}`, in order),
/// which is all the transforms read. `1 ≤ log ≤ 30` by the bound in [`Circle::new`],
/// so both shifts are in range.
fn half_domain(log: u32) -> Result<Vec<(M31, M31)>, Error> {
    let g = (m31(GENERATOR.0), m31(GENERATOR.1));
    let half = 1usize << (log - 1);
    let mut out = reserved(half)?;
    let step = power(g, 1u64 << (31 - log));
    let mut p = power(g, 1u64 << (30 - log));
    for _ in 0..half {
        out.push(p);
        p = mul(p, step);
    }
    Ok(out)
}

/// The fold coordinates of each level: level 0 is the `y`s of the first half of the
/// coset, level 1 its `x`s, and level `k + 1` is `π` of the first half of level `k`.
/// With `inverse`, each value is replaced by its inverse, once per level.
fn levels(log: u32, inverse: bool) -> Result<Vec<Vec<M31>>, Error> {
    let mut out: Vec<Vec<M31>> = reserved(log as usize)?;
    if log == 0 {
        return Ok(out);
    }
    let points = half_domain(log)?;
    let mut ys = reserved(points.len())?;
    let mut xs = reserved(points.len())?;
    for p in &points {
        ys.push(p.1);
        xs.push(p.0);
    }
    out.push(ys);
    if log > 1 {
        out.push(xs);
    }
    while out.len() < log as usize {
        let previous = &out[out.len() - 1];
        let mut next = reserved(previous.len() / 2)?;
        for x in &previous[..previous.len() / 2] {
            next.push(*x * *x + *x * *x - m31(1));
        }
        out.push(next);
    }
    if inverse {
        for level in &mut out {
            for v in level.iter_mut() {
                // Every coset coordinate used is nonzero (RFC-0010 A2's domain argument),
                // so this cannot fail on a valid size; a zero would be a size error.
                *v = v.inverse().ok_or(Error::InvalidSize)?;
            }
        }
    }
    Ok(out)
}

fn half() -> M31 {
    // (p + 1) / 2, the inverse of 2.
    m31(M31::MODULUS.div_ceil(2))
}

/// One fold of the transform on `values`, then the recursion on its halves with the
/// next level. `levels[k]` holds the fold coordinates (or their inverses) of depth `k`.
fn fold<K: Field>(values: &[K], levels: &[Vec<M31>], inverse: bool) -> Result<Vec<K>, Error> {
    let n = values.len();
    let mut out = reserved(n)?;
    if n == 1 {
        out.push(values[0]);
        return Ok(out);
    }
    let h = n / 2;
    let level = &levels[0];
    if inverse {
        let mut even = reserved(h)?;
        let mut odd = reserved(h)?;
        for j in 0..h {
            let (a, b) = (values[j], values[n - 1 - j]);
            even.push((a + b).mul_m31(half()));
            odd.push((a - b).mul_m31(half() * level[j]));
        }
        let (a, b) = (
            fold(&even, &levels[1..], true)?,
            fold(&odd, &levels[1..], true)?,
        );
        for (u, v) in a.into_iter().zip(b) {
            out.push(u);
            out.push(v);
        }
    } else {
        let mut evens = reserved(h)?;
        let mut odds = reserved(h)?;
        for pair in values.chunks_exact(2) {
            evens.push(pair[0]);
            odds.push(pair[1]);
        }
        let (a, b) = (
            fold(&evens, &levels[1..], false)?,
            fold(&odds, &levels[1..], false)?,
        );
        out.resize(n, K::from_i64(0));
        for j in 0..h {
            let t = b[j].mul_m31(level[j]);
            out[j] = a[j] + t;
            out[n - 1 - j] = a[j] - t;
        }
    }
    Ok(out)
}

impl Circle {
    /// `C(m, b)` with `b ∈ {1, 2}` and `m + b ≤ 30`.
    pub fn new(log_message: u32, log_blowup: u32) -> Result<Self, Error> {
        // RFC-0010 A2: blowup 1 or 2, and m + b ≤ 30.
        if !(1..=2).contains(&log_blowup) || log_message > 30 - log_blowup {
            return Err(Error::InvalidSize);
        }
        Ok(Circle {
            log_message,
            log_blowup,
        })
    }

    /// The canonical code identity `stele/circle-m31/v1 || u8 m || u8 b`.
    pub fn code_id(&self) -> [u8; 21] {
        let mut id = [0; 21];
        id[..19].copy_from_slice(b"stele/circle-m31/v1");
        id[19] = self.log_message as u8;
        id[20] = self.log_blowup as u8;
        id
    }

    pub fn message_len(&self) -> usize {
        1 << self.log_message
    }

    pub fn codeword_len(&self) -> usize {
        1 << (self.log_message + self.log_blowup)
    }

    /// The codeword of `row`: interpolate on `D_m`, zero-extend the coefficients,
    /// evaluate on `D_{m+b}`.
    pub fn encode<K: Field>(&self, row: &[K]) -> Result<Vec<K>, Error> {
        // RFC-0010 A2: the elements are M31 or an extension of it.
        if K::MODULUS != M31::MODULUS {
            return Err(Error::FieldMismatch);
        }
        // RFC-0010 A2: a message row has exactly 2^m values.
        if row.len() != self.message_len() {
            return Err(Error::RowShape);
        }
        let interpolated = fold(row, &levels(self.log_message, true)?, true)?;
        let mut coefficients = reserved(self.codeword_len())?;
        coefficients.extend_from_slice(&interpolated);
        coefficients.resize(self.codeword_len(), K::from_i64(0));
        let log = self.log_message + self.log_blowup;
        fold(&coefficients, &levels(log, false)?, false)
    }

    /// The codeword at `columns`, in order and with repeats.
    pub fn eval_row<K: Field>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error> {
        // RFC-0010 A2: the elements are M31 or an extension of it.
        if K::MODULUS != M31::MODULUS {
            return Err(Error::FieldMismatch);
        }
        // RFC-0010 A2: every requested column is inside the codeword.
        if columns.iter().any(|c| *c >= self.codeword_len()) {
            return Err(Error::Column);
        }
        let word = self.encode(row)?;
        let mut out = reserved(columns.len())?;
        out.extend(columns.iter().map(|c| word[*c]));
        Ok(out)
    }
}
