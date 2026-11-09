//! Plain-checker tests of the embedding and rmsnorm_q modules (RFC-0026 §3.7, §5.2):
//! honest executor values pass; near misses of every output are rejected.

use super::embedding::{Embedding, EmbeddingCapture, EmbeddingPlan};
use super::rmsnorm::{RmsNorm, RmsNormPlan, RmsNormRow};
use alloc::vec;
extern crate std;
use alloc::vec::Vec;
use stele_cqis::functions::Descriptor;
use stele_ir::relation::{check, ColumnId, Kind, Module, Relation, Values, Width};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
}

fn parameters(d: u16, f: u8, g: u8, e: u8, en: u32, ed: u32) -> Vec<u8> {
    let mut p = d.to_le_bytes().to_vec();
    p.extend([f, g, e]);
    p.extend(en.to_le_bytes());
    p.extend(ed.to_le_bytes());
    p
}

struct Norm {
    descriptor: Descriptor,
    gains: Vec<i16>,
    xbits: u8,
}

impl Norm {
    fn new(version: u32, p: &[u8], gains: Vec<i16>) -> Self {
        Self {
            descriptor: Descriptor::new("rmsnorm_q", version, p).expect("descriptor"),
            gains,
            xbits: if version == 2 { 24 } else { 16 },
        }
    }

    fn rows(&self, inputs: &[Vec<i32>]) -> Vec<RmsNormRow> {
        inputs
            .iter()
            .map(|x| {
                let e = self
                    .descriptor
                    .evaluate_rmsnorm_wide(x, &self.gains)
                    .expect("executor row");
                RmsNormRow::new(x, &e)
            })
            .collect()
    }

    fn relation(&self, rows: usize) -> (Relation, RmsNorm, ColumnId) {
        let d = self.gains.len();
        let log = (rows * d.next_power_of_two()).trailing_zeros() as u8;
        let mut relation = Relation::default();
        let group = relation.add_group("L0/residual", log);
        let x = relation.add_column("R", Kind::Witness(group), Width::signed(self.xbits), log);
        let plan = RmsNormPlan {
            descriptor: self.descriptor,
            gains: self.gains.clone(),
            rows,
        };
        let mut module = RmsNorm::new(plan, x, "L0/norm1").expect("supported plan");
        module.declare(&mut relation);
        relation.validate().expect("static validity");
        (relation, module, x)
    }

    /// Assign `capture` and run the plain checker.
    fn check(&self, capture: &[RmsNormRow]) -> Result<(), stele_ir::relation::Violation> {
        let (relation, values) = self.assigned(capture)?;
        check(&relation, &values)
    }

    fn assigned(
        &self,
        capture: &[RmsNormRow],
    ) -> Result<(Relation, Values), stele_ir::relation::Violation> {
        let (relation, module, x) = self.relation(capture.len());
        let ld = self.gains.len().next_power_of_two();
        let mut input = vec![0; capture.len() * ld];
        for (t, row) in capture.iter().enumerate() {
            for (k, &v) in row.input.iter().enumerate() {
                input[t * ld + k] = i64::from(v);
            }
        }
        let mut values = Values::new(&relation);
        values.set(&relation, x, input).expect("input");
        module.assign(&relation, capture, &mut values)?;
        Ok((relation, values))
    }
}

/// Typical v1 parameters: F=8, G=12, E=8, epsilon 1e-5.
fn typical(rng: &mut Rng, d: u16) -> Norm {
    let gains = (0..d).map(|_| rng.range(-32768, 32767) as i16).collect();
    Norm::new(1, &parameters(d, 8, 12, 8, 1, 100_000), gains)
}

fn extreme_rows(rng: &mut Rng, d: usize, bits: u32) -> Vec<Vec<i32>> {
    let (low, high) = (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1);
    let mut spike = vec![0; d];
    spike[d / 3] = low as i32;
    vec![
        (0..d).map(|_| rng.range(low, high) as i32).collect(),
        vec![0; d],
        vec![high as i32; d],
        vec![low as i32; d],
        spike,
        (0..d).map(|_| rng.range(-3, 3) as i32).collect(),
        (0..d).map(|_| rng.range(low, high) as i32).collect(),
        (0..d)
            .map(|k| if k % 2 == 0 { high } else { low } as i32)
            .collect(),
    ]
}

#[test]
fn accepts_executor_rmsnorm_rows_random_and_extreme() {
    let mut rng = Rng(0x5eed_0004);
    for d in [1, 5, 64] {
        let norm = typical(&mut rng, d);
        let rows = norm.rows(&extreme_rows(&mut rng, d.into(), 16));
        norm.check(&rows).expect("honest rows pass");
    }
}

#[test]
fn accepts_executor_rmsnorm_exact_multiply_branch() {
    // F=G=0, E=14: small rows give e <= 0, the exact left shift of RFC-0021 §2.3.
    let mut rng = Rng(0x5eed_0005);
    let gains = (0..64).map(|_| rng.range(-1, 1) as i16).collect();
    let norm = Norm::new(1, &parameters(64, 0, 0, 14, 1, 1000), gains);
    let mut inputs: Vec<Vec<i32>> = (0..3)
        .map(|_| (0..64).map(|_| rng.range(-1, 1) as i32).collect())
        .collect();
    inputs.push(vec![0; 64]);
    let rows = norm.rows(&inputs);
    for (x, r) in inputs.iter().zip(&rows) {
        let e = norm
            .descriptor
            .evaluate_rmsnorm_wide(x, &norm.gains)
            .expect("row");
        assert!(e.shift() <= 0, "every row takes the exact branch");
        assert_eq!(r.output, e.outputs());
    }
    norm.check(&rows).expect("honest exact-branch rows pass");
}

#[test]
fn accepts_executor_rmsnorm_version_two_wide_rows() {
    let mut rng = Rng(0x5eed_0006);
    let gains = (0..32).map(|_| rng.range(-32768, 32767) as i16).collect();
    let norm = Norm::new(2, &parameters(32, 16, 12, 8, 1, 100_000), gains);
    let rows = norm.rows(&extreme_rows(&mut rng, 32, 24));
    norm.check(&rows).expect("honest int24 rows pass");
}

/// The tampered capture assigns (every auxiliary column follows it) and the plain
/// checker rejects the result.
fn tampered(norm: &Norm, rows: &[RmsNormRow], change: impl Fn(&mut RmsNormRow)) -> bool {
    let mut rows = rows.to_vec();
    change(&mut rows[0]);
    let (relation, values) = norm
        .assigned(&rows)
        .expect("a tampered capture still assigns");
    check(&relation, &values).is_err()
}

#[test]
fn rejects_rmsnorm_output_near_misses() {
    let mut rng = Rng(0x5eed_0007);
    let norm = typical(&mut rng, 16);
    let inputs = extreme_rows(&mut rng, 16, 16);
    let rows = norm.rows(&inputs[..4]);
    let p = norm.descriptor.parameters();
    for k in 0..16 {
        for delta in [-1, 1] {
            assert!(tampered(&norm, &rows, |r| r.output[k] =
                r.output[k].wrapping_add(delta)));
        }
        // The other rounding direction of the same exact product.
        let e = norm
            .descriptor
            .evaluate_rmsnorm_wide(&inputs[0], &norm.gains)
            .expect("row");
        let shift = e.shift();
        assert_eq!(
            shift,
            i32::from(p[2]) + i32::from(p[3]) + 21 + i32::from(e.exponent()) - i32::from(p[4])
        );
        let product =
            i64::from(inputs[0][k]) * i64::from(norm.gains[k]) * i64::from(e.reciprocal());
        if shift > 0 {
            let floor = product.unsigned_abs() >> shift;
            let honest = u64::from(rows[0].output[k].unsigned_abs());
            let other = if honest == floor { floor + 1 } else { floor };
            let other = if product < 0 {
                -(other as i64)
            } else {
                other as i64
            };
            assert!(tampered(&norm, &rows, |r| r.output[k] = other as i16));
        }
    }
}

#[test]
fn rejects_rmsnorm_wrong_exponent_mantissa_and_table_entry() {
    let mut rng = Rng(0x5eed_0008);
    let norm = typical(&mut rng, 16);
    let rows = norm.rows(&extreme_rows(&mut rng, 16, 16)[..2]);
    let p = norm.descriptor.parameters();
    let (en, ed) = (
        u128::from(u32::from_le_bytes([p[5], p[6], p[7], p[8]])),
        u128::from(u32::from_le_bytes([p[9], p[10], p[11], p[12]])),
    );
    let unit = 16u128 << (2 * p[2]);
    let statistic: u128 = rows[0]
        .input
        .iter()
        .map(|&x| (x as i128 * x as i128) as u128)
        .sum();
    let numerator = ed * statistic + en * unit;
    for delta in [-1i8, 1] {
        // Strongest assignment at a wrong exponent: the exact quotient and remainder of
        // that exponent, clipped into u16, with its table entry when one exists.
        assert!(tampered(&norm, &rows, |r| {
            let a = i32::from(r.exponent + delta);
            let (fa, fd) = (2 * (-a).max(0) as u32, 2 * a.max(0) as u32);
            let (an, dd) = (numerator << fa, (ed * unit) << fd);
            let m = (an / dd).min(65535);
            r.exponent += delta;
            r.mantissa = m as u16;
            r.divisor = dd as i128;
            r.remainder = (an - m * dd) as i128;
            r.reciprocal = rsqrt(m as u16).unwrap_or(r.reciprocal);
        }));
        assert!(tampered(&norm, &rows, |r| {
            let m = i32::from(r.mantissa) + i32::from(delta);
            r.mantissa = m as u16;
            r.remainder -= i128::from(delta) * r.divisor;
            r.reciprocal = rsqrt(m as u16).unwrap_or(r.reciprocal);
        }));
        assert!(tampered(&norm, &rows, |r| {
            r.reciprocal = (i32::from(r.reciprocal) + i32::from(delta)) as u16
        }));
    }
}

fn rsqrt(m: u16) -> Option<u16> {
    let table = stele_cqis::tables::Table::rsqrt().expect("table");
    table
        .entries()
        .chunks_exact(2)
        .find(|r| r[0] == i32::from(m))
        .map(|r| r[1] as u16)
}

#[test]
fn accepts_static_validity_at_realistic_widths() {
    for (version, d, rows) in [(1, 4096, 64), (1, 8192, 64), (2, 8192, 64), (1, 8192, 1)] {
        let gains = vec![i16::MIN; d];
        let norm = Norm::new(
            version,
            &parameters(d as u16, 30, 30, 0, 1, u32::MAX),
            gains,
        );
        norm.relation(rows);
        let norm = Norm::new(
            version,
            &parameters(d as u16, 0, 0, 14, u32::MAX, 1),
            vec![1; d],
        );
        norm.relation(rows);
    }
    for (vocabulary, width, rows, exponent) in [
        (32000, 4096, 64, -20),
        (128256, 8192, 64, 4),
        (32000, 512, 64, -40),
    ] {
        let plan = EmbeddingPlan {
            tokens: (0..rows).map(|i| (i * 7) as u32 % vocabulary).collect(),
            vocabulary,
            width,
            code_bits: 8,
            mantissas: vec![65535; vocabulary as usize],
            exponent,
            fraction: 8,
        };
        let mut relation = Relation::default();
        Embedding::new(plan, "G/embedding")
            .expect("plan")
            .declare(&mut relation);
        relation.validate().expect("embedding static validity");
    }
}

fn round(value: i64, shift: i32) -> i64 {
    if shift >= 0 {
        return value << shift;
    }
    let h = (-shift).min(62);
    let magnitude = (value.unsigned_abs() + (1 << (h - 1))) >> h;
    if value < 0 {
        -(magnitude as i64)
    } else {
        magnitude as i64
    }
}

fn largest(shift: i16, code_bits: u8) -> i64 {
    let room = 16 - i32::from(code_bits) - i32::from(shift);
    if room >= 16 {
        65535
    } else {
        (1i64 << room.max(0)).max(1)
    }
}

struct Gather {
    plan: EmbeddingPlan,
    weights: Vec<i16>,
}

impl Gather {
    fn new(rng: &mut Rng, rows: usize, exponent: i16, code_bits: u8) -> Self {
        let (vocabulary, width) = (11u32, 6u16);
        let half = 1i64 << (code_bits - 1);
        Self {
            plan: EmbeddingPlan {
                tokens: (0..rows).map(|_| rng.range(0, 10) as u32).collect(),
                vocabulary,
                width,
                code_bits,
                // Mantissas small enough that most rows fit int16 at this shift.
                mantissas: (0..vocabulary)
                    .map(|_| rng.range(1, largest(exponent + 6, code_bits)) as u16)
                    .collect(),
                exponent,
                fraction: 6,
            },
            weights: (0..vocabulary * u32::from(width))
                .map(|_| rng.range(-half, half - 1) as i16)
                .collect(),
        }
    }

    /// RFC-0025 §2.5 family 1: `R(e·m·2^(ee+f0))`, int16 or the executor's rejection.
    fn capture(&self) -> Option<EmbeddingCapture> {
        let d = usize::from(self.plan.width);
        let shift = i32::from(self.plan.exponent) + i32::from(self.plan.fraction);
        let mut capture = EmbeddingCapture {
            codes: Vec::new(),
            output: Vec::new(),
        };
        for &x in &self.plan.tokens {
            let codes = self.weights[x as usize * d..(x as usize + 1) * d].to_vec();
            let m = i64::from(self.plan.mantissas[x as usize]);
            let mut row = Vec::new();
            for &c in &codes {
                row.push(i16::try_from(round(i64::from(c) * m, shift)).ok()?);
            }
            capture.codes.push(codes);
            capture.output.push(row);
        }
        Some(capture)
    }

    fn check(&self, capture: &EmbeddingCapture) -> Result<(), stele_ir::relation::Violation> {
        let (relation, values) =
            self.assigned(capture, crate::development::embedding::MAX_BLOCK_VARS)?;
        check(&relation, &values)
    }

    /// Declare with matmul domains of at most `limit` bits (forces row blocks) and assign.
    fn assigned(
        &self,
        capture: &EmbeddingCapture,
        limit: u8,
    ) -> Result<(Relation, Values), stele_ir::relation::Violation> {
        let mut relation = Relation::default();
        let mut module = Embedding::new(self.plan.clone(), "G/embedding").expect("plan");
        module.limit = limit;
        module.declare(&mut relation);
        let mut values = Values::new(&relation);
        let d = usize::from(self.plan.width);
        let (dp, vp) = (
            d.next_power_of_two(),
            (self.plan.vocabulary as usize).next_power_of_two(),
        );
        let mut weights = vec![0; dp * vp];
        for (i, &w) in self.weights.iter().enumerate() {
            weights[(i / d) * dp + i % d] = i64::from(w);
        }
        values
            .set(&relation, module.weight().expect("declared"), weights)
            .expect("weights");
        module.assign(&relation, capture, &mut values)?;
        Ok((relation, values))
    }
}

#[test]
fn accepts_embedding_gather_at_every_shift_class() {
    let mut rng = Rng(0x5eed_0009);
    let mut checked = 0;
    for exponent in [-40, -30, -25, -22, -14, -7, -6, -5, 0, 2, 9, 20] {
        for bits in [4, 8] {
            let gather = Gather::new(&mut rng, 4, exponent, bits);
            if let Some(capture) = gather.capture() {
                gather.check(&capture).expect("honest embedding passes");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 20);
    let mut gather = Gather::new(&mut rng, 4, 20, 8);
    gather.weights.iter_mut().for_each(|w| *w = 0);
    let capture = gather.capture().expect("zero rows fit at any shift");
    gather
        .check(&capture)
        .expect("zero codes pass the capped multiplier");
}

#[test]
fn rejects_embedding_near_misses() {
    let mut rng = Rng(0x5eed_000a);
    for exponent in [-22, -14, -9, -6] {
        let gather = Gather::new(&mut rng, 2, exponent, 8);
        let honest = gather.capture().expect("in range");
        let shift = -(i32::from(exponent) + 6);
        for k in 0..6 {
            for delta in [-1, 1] {
                let mut capture = honest.clone();
                capture.output[1][k] += delta;
                assert!(gather.check(&capture).is_err());
            }
            let product = i64::from(honest.codes[1][k])
                * i64::from(gather.plan.mantissas[gather.plan.tokens[1] as usize]);
            let floor = (product.unsigned_abs() >> shift) as i64;
            let other = if honest.output[1][k].unsigned_abs() as i64 == floor {
                floor + 1
            } else {
                floor
            };
            let mut capture = honest.clone();
            capture.output[1][k] = if product < 0 { -other } else { other } as i16;
            assert!(gather.check(&capture).is_err());
        }
        let mut capture = honest.clone();
        capture.codes[0][0] += 1;
        assert!(
            gather.check(&capture).is_err(),
            "a code off the gathered row"
        );
    }
}

mod embedding_attacks;
mod mutation;
mod norm_attacks;
