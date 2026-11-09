//! RFC-0026 §3.8/§5 rows 1-13 (task E16-03): the optional complete integer
//! Capture of one prefill, over RFC-0025 §2. Every column is a value the executor
//! itself computes, named by its RFC symbol (RFC-0004 A13/A15, RFC-0021 §2.3/A3/A4,
//! RFC-0025 §2.2–2.6, RFC-0009 A4, RFC-0003 A5). Nothing is committed here; E16-10
//! maps these columns onto each module's own Capture (RFC-0026 §3.8). CQIS execution
//! has no clamp or saturation: every out-of-range value rejects the whole request.
//! Shapes are row-major in the order stated on each field.
use super::{Error, Full};
use crate::{
    functions::{LayerParts, NormEvaluation},
    numerics,
    row::QuantisedRow,
};
use alloc::vec::Vec;

pub(super) fn put<T>(column: &mut Vec<T>, value: T) -> Result<(), Error> {
    column.try_reserve(1).map_err(|_| Error::Capacity)?;
    column.push(value);
    Ok(())
}

/// How a `Division` derives its quotient from numerator n and divisor d > 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Rounding {
    /// Nearest, ties away from zero: sign(n)*floor((2|n|+d)/(2d)) (RFC-0025 §2.2).
    #[default]
    Nearest,
    /// floor(n/d) for n >= 0.
    Floor,
    /// ceil(n/d) for n >= 0.
    Ceil,
}

/// Element-wise exact divisions with retained remainders:
/// numerator = quotient*divisor + remainder. A zero divisor marks the
/// canonical zero branch of a row conversion (quotient and remainder zero).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Division {
    /// The one rule every element of this column follows.
    pub rounding: Rounding,
    pub numerator: Vec<i128>,
    pub divisor: Vec<u128>,
    pub quotient: Vec<i64>,
    pub remainder: Vec<i128>,
}
impl Division {
    fn with(rounding: Rounding) -> Self {
        Self {
            rounding,
            ..Self::default()
        }
    }
    pub(super) fn push(
        &mut self,
        numerator: i128,
        divisor: u128,
        quotient: i64,
    ) -> Result<(), Error> {
        let product = i128::try_from(divisor)
            .ok()
            .and_then(|d| d.checked_mul(i128::from(quotient)))
            .ok_or(Error::Capacity)?;
        put(
            &mut self.remainder,
            numerator.checked_sub(product).ok_or(Error::Capacity)?,
        )?;
        put(&mut self.numerator, numerator)?;
        put(&mut self.divisor, divisor)?;
        put(&mut self.quotient, quotient)
    }
    /// Record the exact pair `numerics::scaled_sum` rounded to `quotient`.
    pub(super) fn scaled(
        &mut self,
        (left, le): (i128, i32),
        (right, re): (i128, i32),
        divisor: u64,
        quotient: i64,
    ) -> Result<(), Error> {
        // shortcut: a numerator beyond i128 (scaled_sum's wide-scratch path) is
        // rejected as Capacity; widen these columns when a Model reaches it.
        let (n, d) =
            numerics::scaled_parts(left, le, right, re, divisor)?.ok_or(Error::Capacity)?;
        self.push(n, d, quotient)
    }
}

/// Table lookups: `output[i] = table[input[i]]` for one RFC-0021 component.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Lookup {
    pub input: Vec<i64>,
    pub output: Vec<i64>,
}
impl Lookup {
    pub(super) fn push(&mut self, input: i64, output: i64) -> Result<(), Error> {
        put(&mut self.input, input)?;
        put(&mut self.output, output)
    }
}

/// R_0 for one position (RFC-0025 §2.5 model boundary): R((E[t]*m_t*2^(e_t+f0) + P[p]*m_p*2^(e_p+f0))/1).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Embedding {
    pub token: u32,
    /// [lane] token code times its row mantissa.
    pub token_term: Vec<i128>,
    /// [lane] position code times its row mantissa; zero in family 1.
    pub position_term: Vec<i128>,
    /// [lane] Nearest; quotient is R_0.
    pub output: Division,
}

/// One RMSNorm (family 1, RFC-0021 §2.3/A4) or exact-mean LayerNorm (family 0, A3) row.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Norm {
    /// [lane] X.
    pub input: Vec<i64>,
    /// [lane] gain H codes.
    pub gain: Vec<i64>,
    /// [lane] bias B codes; empty for RMSNorm.
    pub bias: Vec<i64>,
    /// LayerNorm S = sum X; zero for RMSNorm.
    pub sum: i64,
    /// sum X^2 (RMSNorm S, LayerNorm Q).
    pub squares: u64,
    /// LayerNorm V = dQ - S^2; RMSNorm S.
    pub variance: u64,
    /// (N, P), including the configured epsilon.
    pub ratio: (u128, u128),
    /// a, with 2^14 <= A/D < 2^16.
    pub exponent: i32,
    /// One Floor element: A = M*D + R.
    pub mantissa: Division,
    /// One rsqrt_q lookup: J = rsqrt(M).
    pub reciprocal: Lookup,
    /// Final signed shift e (negative means an exact left shift).
    pub shift: i32,
    /// [lane] RMSNorm X; LayerNorm d*X - S.
    pub centered: Vec<i64>,
    /// [lane] centered * H * J.
    pub product: Vec<i128>,
    /// [lane] Nearest; quotient is the int16 norm output.
    pub output: Division,
}
impl Norm {
    pub(super) fn rms(&mut self, x: &[i32], h: &[i16], e: &NormEvaluation) -> Result<(), Error> {
        self.base(x.iter().map(|v| i64::from(*v)), h)?;
        self.squares = e.statistic();
        self.variance = e.statistic();
        self.ratio = e.ratio();
        self.exponent = i32::from(e.exponent());
        let (a, d, _) = e.normalized_ratio();
        let a = i128::try_from(a).map_err(|_| Error::Capacity)?;
        self.scalars(a, d, i64::from(e.mantissa()), i64::from(e.reciprocal()))?;
        self.shift = e.shift();
        let (up, down) = (e.shift().min(0).unsigned_abs(), e.shift().max(0) as u32);
        for ((xi, hi), y) in x.iter().zip(h).zip(e.outputs()) {
            let product = i128::from(*xi) * i128::from(*hi) * i128::from(e.reciprocal());
            put(&mut self.centered, i64::from(*xi))?;
            put(&mut self.product, product)?;
            self.output
                .push(product << up, 1u128 << down, i64::from(*y))?;
        }
        Ok(())
    }
    pub(super) fn layer(
        &mut self,
        x: &[i16],
        (h, b): (&[i16], &[i16]),
        (p, outputs): (&LayerParts, &[i16]),
        (output_fraction, bias_fraction): (u8, u8),
    ) -> Result<(), Error> {
        self.base(x.iter().map(|v| i64::from(*v)), h)?;
        for v in b {
            put(&mut self.bias, i64::from(*v))?;
        }
        self.sum = p.sum;
        self.squares = p.squares;
        self.variance = p.variance;
        self.ratio = p.ratio;
        self.exponent = p.exponent;
        // A = N*4^-a, D = P*4^a exactly as the executor scales them.
        let shift = |v: u128, k: i32| {
            i128::try_from(v)
                .ok()
                .and_then(|v| v.checked_mul(1i128.checked_shl(2 * k.max(0) as u32)?))
                .ok_or(Error::Capacity)
        };
        let a = shift(p.ratio.0, -p.exponent)?;
        let d = u128::try_from(shift(p.ratio.1, p.exponent)?).map_err(|_| Error::Capacity)?;
        let j = i64::try_from(p.reciprocal).map_err(|_| Error::Arithmetic)?;
        self.scalars(a, d, i64::from(p.mantissa), j)?;
        self.shift = p.shift;
        let n = x.len() as i64;
        for (((xi, hi), bi), y) in x.iter().zip(h).zip(b).zip(outputs) {
            let centered = n * i64::from(*xi) - p.sum;
            let product = i128::from(centered) * i128::from(*hi) * p.reciprocal;
            put(&mut self.centered, centered)?;
            put(&mut self.product, product)?;
            self.output.scaled(
                (product, -p.shift),
                (
                    i128::from(n) * i128::from(*bi),
                    i32::from(output_fraction) - i32::from(bias_fraction),
                ),
                n as u64,
                i64::from(*y),
            )?;
        }
        Ok(())
    }
    fn base(&mut self, x: impl Iterator<Item = i64>, h: &[i16]) -> Result<(), Error> {
        self.mantissa.rounding = Rounding::Floor;
        for (xi, hi) in x.zip(h) {
            put(&mut self.input, xi)?;
            put(&mut self.gain, i64::from(*hi))?;
        }
        Ok(())
    }
    fn scalars(&mut self, a: i128, d: u128, m: i64, j: i64) -> Result<(), Error> {
        self.mantissa.push(a, d, m)?;
        self.reciprocal.push(m, j)
    }
}

/// One complete-row int8 conversion (RFC-0025 §2.2 flow §1; grouped RFC-0004 A15).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Quantised {
    /// [lane] X (int16, or the gated int32 product).
    pub input: Vec<i64>,
    /// [group] Ceil of max|X| over the group by 127; empty for a static policy.
    pub scale: Division,
    /// [group] the scale each code uses (one for policies 0/1).
    pub scales: Vec<u32>,
    /// Dynamic policy 0: (first attained index, max|X|); otherwise None.
    pub maximum: Option<(u16, u32)>,
    /// [lane] Floor of (2|X|+s)/(2s) to |q|.
    pub magnitude: Division,
    /// [lane] signed int8 codes q.
    pub codes: Vec<i64>,
}
impl Quantised {
    pub(super) fn record(input: &[i64], row: &QuantisedRow) -> Result<Self, Error> {
        let p = row.parameters();
        let g = if p.policy == 2 {
            p.scale as usize
        } else {
            usize::from(p.dimension)
        };
        let mut out = Self {
            scale: Division::with(Rounding::Ceil),
            magnitude: Division::with(Rounding::Floor),
            maximum: row.maximum(),
            ..Self::default()
        };
        for (k, s) in row.scales().iter().enumerate() {
            put(&mut out.scales, *s)?;
            if p.policy != 1 {
                let group = input.get(k * g..(k + 1) * g).ok_or(Error::Arithmetic)?;
                let m = group.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
                out.scale.push(i128::from(m), 127, i64::from(*s))?;
            }
        }
        for (i, (x, q)) in input.iter().zip(row.codes()).enumerate() {
            let s = u128::from(row.scales()[i / g]);
            let n = if s == 0 {
                0
            } else {
                2 * i128::from(x.unsigned_abs()) + s as i128
            };
            out.magnitude.push(n, 2 * s, i64::from(q.unsigned_abs()))?;
            put(&mut out.input, *x)?;
            put(&mut out.codes, i64::from(*q))?;
        }
        Ok(out)
    }
}

/// One affine projection (RFC-0025 §2.5; grouped input RFC-0004 A15).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Projection {
    /// [output] raw int accumulator: sum q_i*w_i, or A15's sum s_k(i)*q_i*w_i.
    pub accumulator: Vec<i128>,
    /// [output] accumulator * m_j (* s for a single-scale row).
    pub product: Vec<i128>,
    /// [output] bias code; zero when the Model has none.
    pub bias: Vec<i64>,
    /// [output] Nearest; quotient is the projection output.
    pub output: Division,
}
impl Projection {
    pub(super) fn push(
        &mut self,
        accumulator: i128,
        product: i128,
        bias: i16,
    ) -> Result<(), Error> {
        put(&mut self.accumulator, accumulator)?;
        put(&mut self.product, product)?;
        put(&mut self.bias, i64::from(bias))
    }
}

/// RoPE on Q or K (RFC-0025 §2.4); empty when the block has none.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Rotation {
    /// [pair j] coefficient table index j at this position.
    pub pair: Vec<u32>,
    /// [pair j] Q14 (cos, sin) coefficient values.
    pub cos: Vec<i64>,
    pub sin: Vec<i64>,
    /// [pair j][head] rotated lane indices.
    pub left: Vec<u32>,
    pub right: Vec<u32>,
    /// [pair j][head][left, right] Nearest over 16384: x*c - y*s, then x*s + y*c.
    pub rounding: Division,
    /// [lane] complete output row (unrotated lanes copied).
    pub output: Vec<i64>,
}

/// One exp_q evaluation per element (RFC-0025 §2.4; components RFC-0021 §2).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Exponential {
    /// [element] t <= 0.
    pub input: Vec<i64>,
    /// Lookups per Representation component, in component order: mode 0
    /// [direct(t)]; modes 1/2 [high(n >> k), low(n mod 2^k)], mode 2 also correction(t).
    pub components: Vec<Lookup>,
    /// [element] modes 1/2: Floor of high*low by 2^p2.
    pub product: Division,
    /// [element] the exp value.
    pub output: Vec<i64>,
}

/// Causal attention of one query position (RFC-0025 §2.4, RFC-0009 A4).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Attention {
    /// [head][key] int8 code dot q·k (every key, masked ones included).
    pub dot: Vec<i64>,
    /// [head][key] Nearest of dot*s_q*s_k*m by 2^shift; quotient is the score.
    pub score: Division,
    /// [head] maximum over the unmasked keys.
    pub maximum: Vec<i64>,
    /// [head][key <= position] exp of score - maximum: the P row.
    pub exp: Exponential,
    /// [head] Z = sum of P.
    pub normaliser: Vec<u128>,
    /// [head][lane][block] accumulation 1: Nearest of each 1024-key partial sum
    /// of P*s_v*v by 2^drop; empty for accumulation 0.
    pub block: Division,
    /// [head][lane] T, the PV accumulator.
    pub total: Vec<i128>,
    /// [head][lane] Nearest of T*2^(f_a-f_v+drop) by Z; quotient is the output.
    pub output: Division,
}

/// One position of one block, in execution order (RFC-0025 §2.5).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Block {
    pub first_norm: Norm,
    pub first_row: Quantised,
    pub query: Projection,
    pub key: Projection,
    pub value: Projection,
    pub query_rotation: Rotation,
    pub key_rotation: Rotation,
    pub query_row: Quantised,
    pub key_row: Quantised,
    pub value_row: Quantised,
    pub attention: Attention,
    pub attention_row: Quantised,
    pub output: Projection,
    /// [lane] Nearest residual add; quotient is the mid stream.
    pub mid: Division,
    pub second_norm: Norm,
    pub second_row: Quantised,
    pub up: Projection,
    /// Family 1 only.
    pub gate: Projection,
    /// [lane] SiLU (family 1, of gate) or GELU (family 0, of up) lookups.
    pub activation: Lookup,
    /// [lane] family 1: up * activation, the gated int32 product.
    pub gated: Vec<i64>,
    pub down_row: Quantised,
    pub down: Projection,
    /// [lane] Nearest residual add; quotient is the block output cut.
    pub residual: Division,
}

/// Final norm, head and greedy choice of one position.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Head {
    pub norm: Norm,
    pub row: Quantised,
    pub logits: Projection,
    /// Largest logit.
    pub maximum: i64,
    /// Greedy choice: the first index attaining `maximum`.
    pub argmax: u32,
}

/// Complete prefill capture: the unchanged `Full` result plus every intermediate.
#[derive(Debug)]
pub struct Capture {
    pub(super) full: Full,
    /// [position].
    pub embedding: Vec<Embedding>,
    /// [layer][position].
    pub blocks: Vec<Vec<Block>>,
    /// [position].
    pub head: Vec<Head>,
}
impl Capture {
    /// The same cuts, logits and cache `Executor::full` returns.
    pub fn full(&self) -> &Full {
        &self.full
    }
}
