//! The Circle code over M31 (RFC-0010 A2), for the verifier's column checks (task
//! E8-02c).
//!
//! An independent re-implementation, written as the recursive circle and x
//! transforms on the canonical coset rather than as `stele-code`'s iterative
//! butterflies. It is held to the shared vectors (`research/circle-code/vectors.txt`,
//! which `stele-code`'s own test also reads) and to direct evaluation of the basis.
//!
//! A row of `2^m` values is a function on the coset `D_m`. Its coefficients in the
//! basis `y^{b_0}·x^{b_1}·π(x)^{b_2}·…` (`π(x) = 2x² − 1`) are interpolated on `D_m`
//! and evaluated on `D_{m+b}`, `b ∈ {1, 2}`. The map is M31-linear, so an extension
//! element is encoded limb by limb through `mul_m31`.

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

/// The canonical coset `D_log`: `g^{(2i+1)·2^(30−log)}`, `i = 0..2^log`, in order.
fn domain(log: u32) -> Result<Vec<(M31, M31)>, Error> {
    let g = (m31(GENERATOR.0), m31(GENERATOR.1));
    let n = 1usize << log;
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    let first = power(g, 1u64 << (30 - log));
    let step = power(g, 1u64 << (31 - log));
    let mut p = first;
    for _ in 0..n {
        out.push(p);
        p = mul(p, step);
    }
    Ok(out)
}

fn half() -> M31 {
    // (p + 1) / 2, the inverse of 2.
    m31(M31::MODULUS.div_ceil(2))
}

/// The x-transform on the folded coordinates `xs` (half of them used per level).
fn x_transform<K: Field>(values: &[K], xs: &[M31], inverse: bool) -> Result<Vec<K>, Error> {
    let n = values.len();
    if n == 1 {
        return Ok(values.to_vec());
    }
    let h = n / 2;
    let next: Vec<M31> = xs[..h].iter().map(|x| *x * *x + *x * *x - m31(1)).collect();
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    if inverse {
        let mut even = Vec::with_capacity(h);
        let mut odd = Vec::with_capacity(h);
        for j in 0..h {
            let (a, b) = (values[j], values[n - 1 - j]);
            even.push((a + b).mul_m31(half()));
            let inv = xs[j].inverse().ok_or(Error::Capacity)?;
            odd.push((a - b).mul_m31(half() * inv));
        }
        let (a, b) = (
            x_transform(&even, &next, true)?,
            x_transform(&odd, &next, true)?,
        );
        for (u, v) in a.into_iter().zip(b) {
            out.push(u);
            out.push(v);
        }
    } else {
        let evens: Vec<K> = values.iter().step_by(2).copied().collect();
        let odds: Vec<K> = values.iter().skip(1).step_by(2).copied().collect();
        let (a, b) = (
            x_transform(&evens, &next, false)?,
            x_transform(&odds, &next, false)?,
        );
        out.resize(n, K::from_i64(0));
        for j in 0..h {
            let t = b[j].mul_m31(xs[j]);
            out[j] = a[j] + t;
            out[n - 1 - j] = a[j] - t;
        }
    }
    Ok(out)
}

/// The circle transform on `points` (a canonical coset): interpolation (`inverse`)
/// to basis coefficients, or evaluation from them.
fn transform<K: Field>(
    values: &[K],
    points: &[(M31, M31)],
    inverse: bool,
) -> Result<Vec<K>, Error> {
    let n = values.len();
    if n == 1 {
        return Ok(values.to_vec());
    }
    let h = n / 2;
    let xs: Vec<M31> = points[..h].iter().map(|p| p.0).collect();
    let ys: Vec<M31> = points[..h].iter().map(|p| p.1).collect();
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    if inverse {
        let mut even = Vec::with_capacity(h);
        let mut odd = Vec::with_capacity(h);
        for j in 0..h {
            let (a, b) = (values[j], values[n - 1 - j]);
            even.push((a + b).mul_m31(half()));
            let inv = ys[j].inverse().ok_or(Error::Capacity)?;
            odd.push((a - b).mul_m31(half() * inv));
        }
        let (a, b) = (
            x_transform(&even, &xs, true)?,
            x_transform(&odd, &xs, true)?,
        );
        for (u, v) in a.into_iter().zip(b) {
            out.push(u);
            out.push(v);
        }
    } else {
        let evens: Vec<K> = values.iter().step_by(2).copied().collect();
        let odds: Vec<K> = values.iter().skip(1).step_by(2).copied().collect();
        let (a, b) = (
            x_transform(&evens, &xs, false)?,
            x_transform(&odds, &xs, false)?,
        );
        out.resize(n, K::from_i64(0));
        for j in 0..h {
            let t = b[j].mul_m31(ys[j]);
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
        // RFC-0010 A2: a message row has exactly 2^m values.
        if row.len() != self.message_len() {
            return Err(Error::RowShape);
        }
        let mut coefficients = transform(row, &domain(self.log_message)?, true)?;
        coefficients.resize(self.codeword_len(), K::from_i64(0));
        transform(
            &coefficients,
            &domain(self.log_message + self.log_blowup)?,
            false,
        )
    }

    /// The codeword at `columns`, in order and with repeats.
    pub fn eval_row<K: Field>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error> {
        // RFC-0010 A2: every requested column is inside the codeword.
        if columns.iter().any(|c| *c >= self.codeword_len()) {
            return Err(Error::Column);
        }
        let word = self.encode(row)?;
        Ok(columns.iter().map(|c| word[*c]).collect())
    }
}
