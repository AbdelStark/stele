//! Power-of-two rows, projections and the gated product (RFC-0026 A32): executor values
//! pass the plain checker and each near miss fails it.

extern crate std;

use super::power::*;
use super::*;
use stele_cqis::bounds::arithmetic::Row;
use stele_cqis::row::Quantiser;
use stele_cqis::tables::{Descriptor, Table as CqisTable};
use stele_ir::relation::{check, eval_column, ColumnId, Module, Relation, Values};

/// Deterministic test stream (xorshift64*); not a protocol RNG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn range(&mut self, low: i64, high: i64) -> i64 {
        low + (self.next() % (high - low + 1) as u64) as i64
    }
}

fn padded(rows: &[Vec<i64>], log_rows: u8, log_lanes: u8) -> Vec<i64> {
    let mut out = vec![0; 1 << (log_rows + log_lanes)];
    for (r, row) in rows.iter().enumerate() {
        for (i, v) in row.iter().enumerate() {
            out[(r << log_lanes) | i] = *v;
        }
    }
    out
}

/// The executor's conversion of `inputs` under policy 3 with `scale = b + 256*amin`.
fn convert(scale: u32, inputs: &[Vec<i64>]) -> ConversionCapture {
    let quantiser = Quantiser::new(Row {
        dimension: inputs[0].len() as u16,
        kind: 0,
        fraction: 7,
        policy: 3,
        scale,
    })
    .expect("row parameters");
    let mut capture = ConversionCapture {
        inputs: inputs.to_vec(),
        ..ConversionCapture::default()
    };
    for row in inputs {
        let narrow: Vec<i16> = row.iter().map(|&v| v as i16).collect();
        let out = quantiser.convert_wide(&narrow).expect("int16 rows convert");
        capture
            .codes
            .push(out.wide_codes().iter().map(|&c| i64::from(c)).collect());
        capture.scales.push(out.scales().to_vec());
    }
    capture
}

/// RFC-0004 A16 projection of executor rows, written from its text.
fn project(
    rows: &ConversionCapture,
    weights: &[Vec<i64>],
    mantissas: &[u16],
    shift: i32,
    most: u8,
) -> Vec<Vec<i64>> {
    let lambda = |m: u16| shift - m.trailing_zeros() as i32;
    let low = mantissas.iter().map(|m| lambda(*m)).min().expect("channel");
    let cap = i32::from(most).min(low - 1);
    rows.codes
        .iter()
        .zip(&rows.scales)
        .map(|(codes, scale)| {
            let a = scale[0].trailing_zeros() as i32;
            let kept = a.min(cap);
            weights
                .iter()
                .zip(mantissas)
                .map(|(w, m)| {
                    let dot: i64 = codes.iter().zip(w).map(|(q, w)| q * w).sum();
                    let s = lambda(*m) - kept;
                    ((dot + (1 << (s - 1))) >> s) << (a - kept)
                })
                .collect()
        })
        .collect()
}

struct Setup {
    relation: Relation,
    values: Values,
    row: PowerOutput,
    projection: PowerProjection,
}

/// A row and one projection of it, honestly assigned.
fn build(scale: u32, inputs: &[Vec<i64>], weights: &[Vec<i64>], m: &[u16], shift: i32) -> Setup {
    let capture = convert(scale, inputs);
    let (t, ld) = (log2_ceil(inputs.len()), log2_ceil(inputs[0].len()));
    let lo = log2_ceil(weights.len());
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), t + ld);
    let mut row =
        PowerRow::new("L0/row", input, inputs.len(), inputs[0].len(), scale).expect("row plan");
    row.declare(&mut relation);
    let output = row.output().expect("declared");
    let plan = ProjectionPlan {
        rows: inputs.len(),
        inner: inputs[0].len(),
        outputs: weights.len(),
        weight_bits: 8,
        mantissas: m.to_vec(),
        shift: -shift,
        output_bits: 16,
    };
    let mut projection = PowerProjection::new("L0/q", output, None, plan).expect("projection");
    projection.declare(&mut relation);
    relation.validate().expect("valid relation");
    let mut values = Values::new(&relation);
    values
        .set(&relation, input, padded(inputs, t, ld))
        .expect("input");
    let weight = projection.weight().expect("weight");
    values
        .set(&relation, weight, padded(weights, lo, ld))
        .expect("weight");
    row.assign(&relation, &capture, &mut values)
        .expect("honest row");
    let outputs = project(&capture, weights, m, shift, output.most);
    let capture = ProjectionCapture {
        codes: capture.codes.clone(),
        scales: capture.scales.clone(),
        weights: weights.to_vec(),
        outputs,
    };
    projection
        .assign(&relation, &capture, &mut values)
        .expect("honest projection");
    Setup {
        relation,
        values,
        row: output,
        projection,
    }
}

/// Rows of mixed magnitude: zero, tiny, mid, the int16 extremes.
fn rows(rng: &mut Rng, count: usize, d: usize) -> Vec<Vec<i64>> {
    (0..count)
        .map(|r| {
            let peak = [0, 3, 300, 32767, 4000, 511, 512, 1023][r % 8];
            let mut row: Vec<i64> = (0..d).map(|_| rng.range(-peak, peak)).collect();
            match r % 8 {
                3 => row[d / 2] = -32768,
                5 => row[0] = 511,
                6 => row[0] = -512,
                _ => {}
            }
            row
        })
        .collect()
}

fn weights(rng: &mut Rng, outputs: usize, d: usize) -> Vec<Vec<i64>> {
    (0..outputs)
        .map(|_| (0..d).map(|_| rng.range(-127, 127)).collect())
        .collect()
}

impl Setup {
    fn column(&self, id: ColumnId) -> Vec<i64> {
        eval_column(&self.relation, &self.values, id).expect("column")
    }
    fn named(&self, name: &str) -> ColumnId {
        let index = self
            .relation
            .columns
            .iter()
            .position(|c| c.name == name)
            .unwrap_or_else(|| panic!("column {name}"));
        ColumnId(index as u32)
    }
    fn rejects(&self, changes: &[(ColumnId, usize, i64)]) -> bool {
        let mut values = self.values.clone();
        for &(id, index, v) in changes {
            let mut column = eval_column(&self.relation, &values, id).expect("column");
            column[index] = v;
            values.set(&self.relation, id, column).expect("set");
        }
        check(&self.relation, &values).is_err()
    }
}

#[test]
fn accepts_executor_power_rows_and_projections() {
    for (seed, scale, d, o) in [
        (1u64, 10u32, 8usize, 3usize),
        (2, 10, 13, 5),
        (3, 6, 16, 4),
        (4, 10 + 256 * 2, 8, 2),
        (5, 12, 5, 7),
    ] {
        let mut rng = Rng(seed);
        let inputs = rows(&mut rng, 8, d);
        let w = weights(&mut rng, o, d);
        // Shifts 8 to 11: the divisor is never below 2 and int16 holds every output.
        let m: Vec<u16> = (0..o).map(|j| 1 << (j % 4)).collect();
        let setup = build(scale, &inputs, &w, &m, 11);
        assert_eq!(check(&setup.relation, &setup.values), Ok(()), "seed {seed}");
        // The row's exponent is the least admissible one: codes reach past half range
        // on every row above the least exponent.
        let exponents = setup.column(setup.row.exponent);
        let codes = setup.column(setup.row.codes);
        let (bits, least) = ((scale & 255) as u8, i64::from(scale >> 8));
        let ld = setup.row.log_dimension;
        for (i, a) in exponents.iter().enumerate().take(inputs.len()) {
            let peak = codes[i << ld..(i + 1) << ld]
                .iter()
                .map(|q| q.abs())
                .max()
                .expect("lane");
            assert!(peak < 1 << (bits - 1));
            assert!(
                *a == least || peak >= 1 << (bits - 2),
                "row {i} of seed {seed}"
            );
        }
    }
}

#[test]
fn rejects_power_row_near_misses() {
    let mut rng = Rng(7);
    let inputs = rows(&mut rng, 8, 8);
    let w = weights(&mut rng, 2, 8);
    let s = build(10, &inputs, &w, &[1, 2], 11);
    assert_eq!(check(&s.relation, &s.values), Ok(()));
    let ld = s.row.log_dimension as usize;
    let exponents = s.column(s.row.exponent);
    let codes = s.column(s.row.codes);
    let (power, half, hit) = (
        s.named("L0/row/power"),
        s.named("L0/row/half"),
        s.named("L0/row/hit"),
    );
    let hits = s.column(hit);
    // Row 3 holds -32768: its exponent is above the least one and it has one flag.
    let row = 3;
    let a = exponents[row];
    assert!(
        a > 0
            && hits[row << ld..(row + 1) << ld]
                .iter()
                .filter(|h| **h != 0)
                .count()
                == 1
    );
    // A code off by one, with every other column kept.
    assert!(s.rejects(&[(s.row.codes, row << ld, codes[row << ld] + 1)]));
    assert!(s.rejects(&[(s.row.codes, row << ld, codes[row << ld] - 1)]));
    // The flag cleared, moved to a lane that does not qualify, or changed in kind.
    let lane = (row << ld)
        + hits[row << ld..]
            .iter()
            .position(|h| *h != 0)
            .expect("flag");
    assert!(s.rejects(&[(hit, lane, 0)]));
    let small = (row << ld..(row + 1) << ld)
        .find(|&x| codes[x].abs() < 1 << 8)
        .expect("a small code");
    assert!(s.rejects(&[(hit, lane, 0), (hit, small, 1)]));
    assert!(s.rejects(&[(hit, lane, 0), (hit, small, 2)]));
    assert!(s.rejects(&[(hit, lane, 0), (hit, small, 3)]));
    // One exponent up or down, with the power and the half that go with it.
    for other in [a - 1, a + 1] {
        assert!(s.rejects(&[
            (s.row.exponent, row, other),
            (power, row, 1 << other),
            (half, row, (1 << other) >> 1),
        ]));
    }
    // A power or a half that is not the exponent's.
    assert!(s.rejects(&[(power, row, 1 << (a - 1))]));
    assert!(s.rejects(&[(half, row, 0)]));
    // A flag on a row at the least exponent.
    let quiet = exponents.iter().position(|a| *a == 0).expect("a small row");
    assert!(s.rejects(&[(hit, quiet << ld, 1)]));
}

/// The strongest completion of a wrong exponent: every code and flag recomputed for it.
#[test]
fn rejects_recomputed_rows_at_another_exponent() {
    let inputs = vec![
        vec![2047, -3, 9, 0],
        vec![-2048, 1, 2, 3],
        vec![1022, -1023, 0, 5],
        vec![1023, 7, 0, 0],
    ];
    let w = vec![vec![1, -1, 2, 3]];
    let s = build(10, &inputs, &w, &[1], 12);
    assert_eq!(check(&s.relation, &s.values), Ok(()));
    let (power, half, hit) = (
        s.named("L0/row/power"),
        s.named("L0/row/half"),
        s.named("L0/row/hit"),
    );
    let exponents = s.column(s.row.exponent);
    // 2047 rounds to 1024 at exponent 1 and to 512 at 2, both past c = 511: exponent 3.
    // -2048 rounds to -512 at 2: exponent 3. 1022 and -1023 round to 511 and -511 at 1.
    // 1023 rounds to 512 at 1: exponent 2.
    assert_eq!(&exponents[..4], &[3, 3, 1, 2]);
    let ld = s.row.log_dimension as usize;
    for (row, x) in inputs.iter().enumerate() {
        for other in [exponents[row] - 1, exponents[row] + 1] {
            if other < 0 {
                continue;
            }
            let mut changes = vec![
                (s.row.exponent, row, other),
                (power, row, 1 << other),
                (half, row, (1 << other) >> 1),
            ];
            for (j, x) in x.iter().enumerate() {
                let q = (x + ((1i64 << other) >> 1)) >> other;
                changes.push((s.row.codes, (row << ld) + j, q));
            }
            // With no flag, and with each flag on each lane.
            for flagged in 0..=x.len() {
                for kind in 1..=3 {
                    let mut all = changes.clone();
                    for j in 0..x.len() {
                        all.push((
                            hit,
                            (row << ld) + j,
                            if j + 1 == flagged { kind } else { 0 },
                        ));
                    }
                    assert!(
                        s.rejects(&all),
                        "row {row} at {other}, flag {kind} on {flagged}"
                    );
                }
            }
        }
    }
}

#[test]
fn rejects_power_projection_near_misses() {
    let mut rng = Rng(11);
    // Rows up to exponent 3 and small weights: every output stays inside int16.
    let inputs: Vec<Vec<i64>> = [0, 3, 300, 4000, 511, 512, 1023, 2000]
        .iter()
        .map(|&peak| (0..8).map(|_| rng.range(-peak, peak)).collect())
        .collect();
    let w: Vec<Vec<i64>> = (0..3)
        .map(|_| (0..8).map(|_| rng.range(-3, 3)).collect())
        .collect();
    // Shift 6 at mantissa 1 and 2 at mantissa 16: the cap is 1, so rows above
    // exponent 1 use the row factor of the output.
    let s = build(10, &inputs, &w, &[1, 16, 4], 6);
    assert_eq!(check(&s.relation, &s.values), Ok(()));
    let output = s.projection.output().expect("output");
    let mantissa = s.named("L0/q/mantissa");
    assert_ne!(
        output, mantissa,
        "amax above the cap: the output is virtual"
    );
    let z = s.column(mantissa);
    let at = z.iter().position(|v| *v != 0).expect("a nonzero output");
    assert!(s.rejects(&[(mantissa, at, z[at] + 1)]));
    assert!(s.rejects(&[(mantissa, at, z[at] - 1)]));
    for name in ["scale", "kept", "grow"] {
        let id = s.named(&std::format!("L0/q/{name}"));
        let column = s.column(id);
        for row in 0..inputs.len() {
            assert!(
                s.rejects(&[(id, row, column[row] + 1)]),
                "{name} of row {row}"
            );
        }
    }
    // The executor's outputs are the column's values.
    let lo = log2_ceil(3) as usize;
    let capture = convert(10, &inputs);
    let expected = project(&capture, &w, &[1, 16, 4], 6, s.row.most);
    let got = s.column(output);
    for (i, row) in expected.iter().enumerate() {
        assert_eq!(&got[i << lo..(i << lo) + 3], &row[..]);
    }
}

#[test]
fn rejects_plans_outside_the_module() {
    let mut relation = Relation::default();
    let input = Builder::new(&mut relation, "L0/norm").witness("output", Width::signed(16), 3);
    for scale in [3, 13, 10 + 256 * 8, 1 << 16] {
        assert_eq!(
            PowerRow::new("L0/row", input, 2, 4, scale).err(),
            Some(Unsupported::Policy)
        );
    }
    let mut row = PowerRow::new("L0/row", input, 2, 4, 10).expect("row");
    row.declare(&mut relation);
    let output = row.output().expect("declared");
    let plan = |mantissas: Vec<u16>, shift: i32, output_bits: u8| ProjectionPlan {
        rows: 2,
        inner: 4,
        outputs: mantissas.len(),
        weight_bits: 8,
        mantissas,
        shift: -shift,
        output_bits,
    };
    let new = |p: ProjectionPlan| PowerProjection::new("L0/q", output, None, p).err();
    // A mantissa that is no power of two, and a channel shift below 1.
    assert_eq!(new(plan(vec![3], 8, 16)), Some(Unsupported::Policy));
    assert_eq!(new(plan(vec![4], 2, 16)), Some(Unsupported::Policy));
    // A divisor past 2^15, and an int24 output.
    assert_eq!(new(plan(vec![1], 16, 16)), Some(Unsupported::Domain));
    assert_eq!(new(plan(vec![1], 8, 24)), Some(Unsupported::Domain));
    // The bound rule: a divisor of 2^14 at the least exponent is past it, 2^13 is not.
    assert_eq!(new(plan(vec![1, 4], 14, 16)), Some(Unsupported::Domain));
    assert_eq!(new(plan(vec![1, 4], 13, 16)), None);
}

fn silu() -> CqisTable {
    let descriptor = Descriptor::new("silu_q", 1, &[7, 7]).expect("descriptor");
    CqisTable::generate(descriptor).expect("silu_q table")
}

struct Gated {
    relation: Relation,
    values: Values,
    module: PowerGated,
}

fn gated(
    table: &CqisTable,
    capture: &PowerGatedCapture,
    tokens: usize,
    hidden: usize,
    scale: u32,
) -> Gated {
    let mut relation = Relation::default();
    let (t, lh) = (log2_ceil(tokens), log2_ceil(hidden));
    let mut b = Builder::new(&mut relation, "L0/projection");
    let gate = b.witness("gate", Width::signed(16), t + lh);
    let up = b.witness("up", Width::signed(16), t + lh);
    let mut module = PowerGated::new(0, gate, up, tokens, hidden, table, scale).expect("plan");
    module.declare(&mut relation);
    relation.validate().expect("valid relation");
    let mut values = Values::new(&relation);
    for (id, raw) in [(gate, &capture.gate), (up, &capture.up)] {
        let rows: Vec<Vec<i64>> = raw
            .chunks(hidden)
            .map(|row| row.iter().map(|v| i64::from(*v)).collect())
            .collect();
        values
            .set(&relation, id, padded(&rows, t, lh))
            .expect("input");
    }
    module
        .assign(&relation, capture, &mut values)
        .expect("honest");
    Gated {
        relation,
        values,
        module,
    }
}

#[test]
fn accepts_executor_gated_rows_and_rejects_near_misses() {
    let table = silu();
    let entries = table.entries();
    let silu_of = |g: i16| i64::from(entries[2 * (i32::from(g) + 32768) as usize + 1]);
    for (seed, scale, tokens, hidden) in [
        (1u64, 10u32, 4usize, 6usize),
        (2, 10 + 256 * 3, 5, 8),
        (3, 9, 3, 4),
    ] {
        let mut rng = Rng(seed);
        let n = tokens * hidden;
        let mut capture = PowerGatedCapture {
            gate: (0..n).map(|_| rng.range(-600, 600) as i16).collect(),
            up: (0..n).map(|_| rng.range(-900, 900) as i16).collect(),
        };
        // One row of large products and one of zeros.
        for j in 0..hidden {
            capture.gate[j] = rng.range(9000, 11000) as i16;
            capture.up[j] = rng.range(-11000, 11000) as i16;
            capture.up[hidden + j] = 0;
        }
        let g = gated(&table, &capture, tokens, hidden, scale);
        assert_eq!(check(&g.relation, &g.values), Ok(()), "seed {seed}");
        // The codes are the executor's.
        let quantiser = Quantiser::new(Row {
            dimension: hidden as u16,
            kind: 1,
            fraction: 14,
            policy: 3,
            scale,
        })
        .expect("gated row");
        let out = g.module.output().expect("declared");
        let codes = eval_column(&g.relation, &g.values, out.codes).expect("codes");
        let exponents = eval_column(&g.relation, &g.values, out.exponent).expect("exponents");
        let lh = out.log_dimension as usize;
        for t in 0..tokens {
            let products: Vec<i32> = (0..hidden)
                .map(|j| {
                    let k = t * hidden + j;
                    (i64::from(capture.up[k]) * silu_of(capture.gate[k])) as i32
                })
                .collect();
            let row = quantiser.convert_gated(&products).expect("converts");
            assert_eq!(i64::from(row.exponent().expect("power row")), exponents[t]);
            let got = &codes[t << lh..(t << lh) + hidden];
            assert!(got
                .iter()
                .zip(row.wide_codes())
                .all(|(a, b)| *a == i64::from(*b)));
        }
        // Near misses on the first lane of the large row.
        let name = |n: &str| {
            let full = std::format!("L0/gated/{n}");
            ColumnId(
                g.relation
                    .columns
                    .iter()
                    .position(|c| c.name == full)
                    .expect("column") as u32,
            )
        };
        let rejects = |changes: &[(ColumnId, usize, i64)]| {
            let mut values = g.values.clone();
            for &(id, index, v) in changes {
                let mut column = eval_column(&g.relation, &values, id).expect("column");
                column[index] = v;
                values.set(&g.relation, id, column).expect("set");
            }
            check(&g.relation, &values).is_err()
        };
        let column = |id| eval_column(&g.relation, &g.values, id).expect("column");
        for n in ["silu", "codes", "low", "high"] {
            let id = name(n);
            let v = column(id)[0];
            assert!(rejects(&[(id, 0, v + 1)]), "{n} + 1");
            assert!(rejects(&[(id, 0, v - 1)]), "{n} - 1");
        }
        for n in ["exponent", "power", "half", "split"] {
            let id = name(n);
            let v = column(id)[0];
            assert!(rejects(&[(id, 0, v + 1)]), "{n} of the large row");
        }
        let hit = name("hit");
        let hits = column(hit);
        let lane = hits[..1 << lh].iter().position(|h| *h != 0).expect("flag");
        assert!(exponents[0] > i64::from(out.least) && rejects(&[(hit, lane, 0)]));
    }
}
