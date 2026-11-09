//! rmsnorm_q attackers for the mutation survey (see `mutation.rs`).
//!
//! Instance: `F = G = 0`, `E = 12`, epsilon `1/100`, `d = 4`, `T = 4`. Row 0 holds an exact
//! rounding tie at feature 0 (`H_0 = 2^(e−1)`, `J` odd), row 1 is zero (the exact-multiply
//! branch), and gains `H_2 = H_3 = 0` let the attacker choose `S` freely. A large `X_0`
//! overflows int16, which reaches the output positions above `Y`.

use super::mutation::*;
use super::*;
use crate::development::rmsnorm::RmsNorm;
use alloc::format;
use alloc::string::String;
use core::cell::Cell;

const SCOPE: &str = "L0/norm1";

const CHAINS: &[ChainSpec] = &[
    ChainSpec {
        name: "S",
        free: "S_",
        wide: None,
    },
    ChainSpec {
        name: "quotient",
        free: "R",
        wide: None,
    },
    ChainSpec {
        name: "remainder",
        free: "gap",
        wide: None,
    },
    ChainSpec {
        name: "Jg",
        free: "Jg",
        wide: None,
    },
    ChainSpec {
        name: "output",
        free: "Z",
        wide: Some("Y"),
    },
];

fn params() -> Vec<u8> {
    // ed = 100, en·unit = 4: remainders R = 100·j + 4 reach both edges of [0, D).
    parameters(4, 0, 0, 12, 1, 100)
}

/// The executor's intermediates of `x` (independent of the gains) and its true outputs,
/// unbounded: `R(X·H·J/2^e)` half away from zero, or the exact left shift.
fn evaluate(x: &[i32], gains: &[i16]) -> (RmsNormRow, Vec<i128>) {
    let descriptor = Descriptor::new("rmsnorm_q", 1, &params()).expect("descriptor");
    let e = descriptor.evaluate_rmsnorm_wide(x, &[0; 4]).expect("row");
    let mut row = RmsNormRow::new(x, &e);
    let shift = e.shift();
    let exact: Vec<i128> = x
        .iter()
        .zip(gains)
        .map(|(&x, &h)| {
            let p = i128::from(x) * i128::from(h) * i128::from(e.reciprocal());
            if shift <= 0 {
                p << -shift
            } else {
                let m = (p.abs() + (1 << (shift - 1))) >> shift;
                if p < 0 {
                    -m
                } else {
                    m
                }
            }
        })
        .collect();
    row.output = exact
        .iter()
        .map(|&y| i16::try_from(y).unwrap_or(0))
        .collect();
    (row, exact)
}

/// The instance: gains and honest rows, with the tie in row 0.
fn instance() -> (Norm, Vec<Vec<i32>>) {
    for x1 in 20000..21000 {
        let tie = vec![1, x1, -30000, 25000];
        let descriptor = Descriptor::new("rmsnorm_q", 1, &params()).expect("descriptor");
        let e = descriptor
            .evaluate_rmsnorm_wide(&tie, &[0; 4])
            .expect("row");
        if e.reciprocal().is_multiple_of(2) || !(1..=16).contains(&e.shift()) {
            continue;
        }
        let gains = vec![1 << (e.shift() - 1), 3, 0, 0];
        let rows = vec![
            tie,
            vec![0; 4],
            vec![1, 30000, -30000, 20000],
            vec![0, -7, 5, 3],
        ];
        let norm = Norm::new(1, &params(), gains);
        if rows.iter().all(|x| {
            norm.descriptor
                .evaluate_rmsnorm_wide(x, &norm.gains)
                .is_ok()
        }) {
            return (norm, rows);
        }
    }
    unreachable!("a tie row exists")
}

fn isqrt(n: i128) -> i128 {
    if n < 2 {
        return n;
    }
    let mut x = 1i128 << (128 - n.leading_zeros()).div_ceil(2);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

fn two_squares(s: i128) -> Option<(i32, i32)> {
    (0..=32767i128)
        .take_while(|a| 2 * a * a <= s)
        .find_map(|a| {
            let b = isqrt(s - a * a);
            (b * b == s - a * a && b <= 32767).then_some((a as i32, b as i32))
        })
}

struct NormAttack<'a> {
    norm: &'a Norm,
    module: &'a RmsNorm,
    x: ColumnId,
    r: &'a Relation,
    honest: &'a Values,
    inputs: &'a [Vec<i32>],
    solver: Solver<'a>,
    rsqrt: Vec<i64>,
    /// `(row, k·256^i)` subtracted from `A` in `rebase` (a removed quotient position).
    offset: Cell<Option<(usize, i128)>>,
}

impl NormAttack<'_> {
    fn col(&self, name: &str) -> ColumnId {
        column(self.r, &format!("{SCOPE}/{name}")).expect("declared column")
    }

    fn try_col(&self, name: &str) -> Option<ColumnId> {
        column(self.r, &format!("{SCOPE}/{name}"))
    }

    fn y(&self, v: &Values) -> Vec<i64> {
        v.get(self.r, self.col("Y")).expect("Y").to_vec()
    }

    /// An honest-shaped assignment for attacker-chosen inputs; outputs out of int16 are
    /// left 0 for the attack to set.
    fn fresh(&self, inputs: &[Vec<i32>]) -> Values {
        let rows: Vec<RmsNormRow> = inputs
            .iter()
            .map(|x| evaluate(x, &self.norm.gains).0)
            .collect();
        let mut v = Values::new(self.r);
        let mut input = vec![0; 16];
        for (t, row) in inputs.iter().enumerate() {
            for (k, &x) in row.iter().enumerate() {
                input[4 * t + k] = i64::from(x);
            }
        }
        v.set(self.r, self.x, input).expect("input");
        self.module.assign(self.r, &rows, &mut v).expect("assign");
        v
    }

    fn sum_bytes(&self, v: &Values, prefix: &str, t: usize) -> i128 {
        (0..64)
            .filter_map(|j| self.try_col(&format!("{prefix}{j}")).map(|c| (j, c)))
            .map(|(j, c)| get(self.r, v, c, t) << (8 * j))
            .sum()
    }

    /// `M = floor((A − offset)/D)` from the selected constant bytes and `S`, `J` from the
    /// table. Fails when `M` leaves the table's range.
    fn rebase(&self, v: &mut Values) -> Option<()> {
        let r = self.r;
        for t in 0..self.inputs.len() {
            let s = self.sum_bytes(v, "S_", t);
            let a = self.sum_bytes(v, "alpha", t) * s + self.sum_bytes(v, "beta", t);
            let d = self.sum_bytes(v, "gamma", t);
            let shift = self.offset.get().filter(|o| o.0 == t).map_or(0, |o| o.1);
            if d <= 0 {
                return None;
            }
            let m = (a - shift).div_euclid(d);
            if !(16384..65536).contains(&m) {
                return None;
            }
            let j = i128::from(self.rsqrt[(m - 16384) as usize]);
            for (name, value) in [
                ("M", m),
                ("M0", m & 255),
                ("M1", m >> 8),
                ("J", j),
                ("J0", j & 255),
                ("J1", j >> 8),
            ] {
                set(r, v, self.col(name), t, value);
            }
        }
        Some(())
    }

    /// Matmul outputs, `S`, then `M`/`J` from the constants, then every chain.
    fn rebased(&self, v: &mut Values, c: Constraint) -> Option<()> {
        recompute_matmuls(self.r, v, c);
        self.solver.chain(v, CHAINS[0], c)?;
        self.rebase(v)?;
        self.solver.solve(v, c)
    }

    fn emit(
        &self,
        how: String,
        v: Values,
        base: &[i64],
        found: &mut dyn FnMut(Attack) -> bool,
    ) -> bool {
        let output = self.y(&v) != base;
        found(Attack {
            how,
            values: v,
            output,
        })
    }

    fn search(&self, c: Constraint, found: &mut dyn FnMut(Attack) -> bool) {
        let base = self.y(self.honest);
        let _ = self.cells(c, &base, found)
            || self.tie(c, &base, found)
            || self.exponent(c, &base, found)
            || self.overflow(c, found)
            || self.quotient(c, &base, found)
            || self.statistic(c, &base, found)
            || self.near_edges(c, found);
    }

    /// Single-cell tampers of the constraint's own columns, then attacker repairs.
    fn cells(&self, c: Constraint, base: &[i64], found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        for col in referenced_witness(r, c) {
            let len = 1usize << r.columns[col.0 as usize].log_len;
            for i in 0..len.min(128) {
                for delta in [1i128, -1, 256, -256] {
                    for mode in [
                        "alone",
                        "solved",
                        "limbs+solved",
                        "M+J+solved",
                        "rebased",
                        "limbs+rebased",
                    ] {
                        if i >= 16 && mode != "alone"
                            || mode == "M+J+solved" && col != self.col("M")
                        {
                            continue;
                        }
                        let mut v = self.honest.clone();
                        let old = get(r, &v, col, i);
                        set(r, &mut v, col, i, old + delta);
                        self.solver.keep.set(Some(col));
                        if mode.starts_with("limbs") {
                            for (n, comp) in r.composes.iter().enumerate() {
                                if Constraint::Compose(n) != c && comp.column == col {
                                    derive_limbs(r, &mut v, n);
                                }
                            }
                        }
                        let ok = match mode {
                            "alone" => Some(()),
                            "M+J+solved" => {
                                let m = get(r, &v, col, i);
                                match self.rsqrt.get((m - 16384).max(0) as usize) {
                                    Some(&j) => {
                                        let j = i128::from(j);
                                        for (name, value) in [
                                            ("M0", m & 255),
                                            ("M1", m >> 8),
                                            ("J", j),
                                            ("J0", j & 255),
                                            ("J1", j >> 8),
                                        ] {
                                            set(r, &mut v, self.col(name), i, value);
                                        }
                                        recompute_matmuls(r, &mut v, c);
                                        self.solver.solve(&mut v, c)
                                    }
                                    None => None,
                                }
                            }
                            "solved" | "limbs+solved" => {
                                recompute_matmuls(r, &mut v, c);
                                self.solver.solve(&mut v, c)
                            }
                            _ => self.rebased(&mut v, c),
                        };
                        self.solver.keep.set(None);
                        let name = &r.columns[col.0 as usize].name;
                        if ok.is_some()
                            && self.emit(format!("{name}[{i}] {delta:+}, {mode}"), v, base, found)
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// The tie at row 0 feature 0 (`X = 1`): a negative top limb with the low limb out of
    /// range keeps `X`, sets `σX = 1`, and `Y` rounds toward zero.
    fn tie(&self, c: Constraint, base: &[i64], found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        let mut v = self.honest.clone();
        set(r, &mut v, self.col("X0"), 0, 257);
        set(r, &mut v, self.col("X1"), 0, -1);
        set(r, &mut v, self.col("sigmaX"), 0, 1);
        recompute_matmuls(r, &mut v, c);
        self.solver.solve(&mut v, c).is_some()
            && self.emit(
                "tie at X = 1: X0 = 257, X1 = -1, sigmaX = 1, solved".into(),
                v,
                base,
                found,
            )
    }

    /// Byte attacks on attacker-chosen rows near an edge, each in range one bit wider:
    /// - `X0`: the negative tie `X = −1` written as `X0 = −1`, `X1 = 0`, `σX = 0`, so `Y`
    ///   rounds toward zero;
    /// - `Z_i`: a row whose `Z >= 2^Es − 256^(i+1)` takes `Y − 1` with `Z − 2^Es` held
    ///   from byte `i` up;
    /// - `R_i` (`gap_i`): a row whose `R >= D − 256^(i+1)` (`R < 256^(i+1)`) takes
    ///   `M + 1` (`M − 1`) with the negative remainder (gap) held from byte `i` up, and
    ///   `J`, `Y` following.
    fn near_edges(&self, c: Constraint, found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        let Constraint::Range(k) = c else {
            return false;
        };
        let name = r.ranges[k]
            .name
            .strip_prefix(&format!("{SCOPE}/"))
            .unwrap_or("");
        let name = name.strip_suffix("/range").unwrap_or(name);
        let (prefix, i) = match name.find(|ch: char| ch.is_ascii_digit()) {
            Some(at) => (&name[..at], name[at..].parse::<u32>().unwrap_or(u32::MAX)),
            None => return false,
        };
        let column = r.ranges[k].column;
        match prefix {
            "X" if i == 0 => {
                let mut inputs = self.inputs.to_vec();
                inputs[0][0] = -1;
                let mut v = self.fresh(&inputs);
                let base = self.y(&v);
                set(r, &mut v, self.col("X0"), 0, -1);
                set(r, &mut v, self.col("X1"), 0, 0);
                set(r, &mut v, self.col("sigmaX"), 0, 0);
                recompute_matmuls(r, &mut v, c);
                self.solver.solve(&mut v, c).is_some()
                    && self.emit(
                        "tie at X = -1: X0 = -1, X1 = 0, sigmaX = 0, solved".into(),
                        v,
                        &base,
                        found,
                    )
            }
            "Z" => {
                let es = 8
                    * (0..)
                        .take_while(|j| self.try_col(&format!("Z{j}")).is_some())
                        .count() as u32;
                for (t, x) in self.edge_rows() {
                    let mut inputs = self.inputs.to_vec();
                    inputs[t] = x.clone();
                    let v = self.fresh(&inputs);
                    let base = self.y(&v);
                    for e in 0..4 {
                        let at = 4 * t + e;
                        let z: i128 = (0..es / 8)
                            .map(|j| get(r, &v, self.col(&format!("Z{j}")), at) << (8 * j))
                            .sum();
                        let target = z - (1i128 << es);
                        if target < -(1i128 << (8 * (i + 1))) {
                            continue;
                        }
                        let mut w = v.clone();
                        set(r, &mut w, column, at, target.div_euclid(1 << (8 * i)));
                        self.solver.keep.set(Some(column));
                        let ok = self.solver.solve(&mut w, c);
                        self.solver.keep.set(None);
                        if ok.is_some()
                            && self.emit(
                                format!(
                                    "row {x:?}: Z near 2^Es, Y - 1, Z{i} = {}",
                                    target.div_euclid(1 << (8 * i))
                                ),
                                w,
                                &base,
                                found,
                            )
                        {
                            return true;
                        }
                    }
                }
                false
            }
            "R" | "gap" => {
                let up = prefix == "R";
                let window = 1i128 << (8 * (i + 1));
                // Screen rows with the executor first; build assignments only near the edge.
                let rows = self.edge_rows_n(1 << 18).filter(|(_, x)| {
                    let (row, exact) = evaluate(x, &self.norm.gains);
                    let honest = exact.iter().all(|&y| i16::try_from(y).is_ok());
                    let near = if up {
                        row.remainder >= row.divisor - window
                    } else {
                        row.remainder < window
                    };
                    // J must move for Y to move: M ± 1 off the reciprocal's plateau, on a
                    // row with a gain-carrying feature.
                    let m = i64::from(row.mantissa) + if up { 1 } else { -1 };
                    let moves = (16384..65536).contains(&m)
                        && self.rsqrt[(m - 16384) as usize] != i64::from(row.reciprocal)
                        && (x[0] != 0 || x[1] != 0);
                    near && moves && honest
                });
                for (t, x) in rows.take(64) {
                    let mut inputs = self.inputs.to_vec();
                    inputs[t] = x.clone();
                    let mut v = self.fresh(&inputs);
                    let base = self.y(&v);
                    let (rem, d) = (self.sum_bytes(&v, "R", t), self.sum_bytes(&v, "gamma", t));
                    let near = if up { rem >= d - window } else { rem < window };
                    let m = get(r, &v, self.col("M"), t) + if up { 1 } else { -1 };
                    if !near || !(16384..65536).contains(&m) {
                        continue;
                    }
                    let j = i128::from(self.rsqrt[(m - 16384) as usize]);
                    for (n, value) in [
                        ("M", m),
                        ("M0", m & 255),
                        ("M1", m >> 8),
                        ("J", j),
                        ("J0", j & 255),
                        ("J1", j >> 8),
                    ] {
                        set(r, &mut v, self.col(n), t, value);
                    }
                    // The other byte column follows; this one holds the edge from byte i up.
                    let edge = if up { rem - d } else { d - 1 - (rem + d) };
                    set(r, &mut v, column, t, edge.div_euclid(1 << (8 * i)));
                    self.solver.keep.set(Some(column));
                    let ok = self.solver.solve(&mut v, c);
                    self.solver.keep.set(None);
                    if ok.is_some()
                        && self.emit(
                            format!(
                                "row {x:?}: R near {}, M {}1, J and Y follow",
                                if up { "D" } else { "0" },
                                if up { "+" } else { "-" }
                            ),
                            v,
                            &base,
                            found,
                        )
                    {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Attacker rows `[x0, x1, x2, x3]` (row 3, or row 0 for large `X0`), deterministic:
    /// small and large statistics, with gain-carrying features so `Y` can move.
    fn edge_rows(&self) -> impl Iterator<Item = (usize, Vec<i32>)> + '_ {
        self.edge_rows_n(4096)
    }

    fn edge_rows_n(&self, count: usize) -> impl Iterator<Item = (usize, Vec<i32>)> + '_ {
        let mut rng = Rng(0x0e16_0004);
        (0..count).map(move |n| {
            let big = n % 2 == 0;
            let wide = if big { 32767 } else { 300 };
            let x = vec![
                rng.range(-3, 3) as i32,
                rng.range(-3, 3) as i32,
                rng.range(-wide, wide) as i32,
                rng.range(-wide, wide) as i32,
            ];
            (3, x)
        })
    }

    /// Overflowing rows `X = [1, 0, x2, 0]`, `Y_0 = R(X·H·J/2^e) ∈ [2^15, 2^27)`: the int16
    /// range of `Y` alone rejects the true output, and an output position above `Y`
    /// alone rejects the output wrapped modulo `256^(i − top)`.
    fn overflow(&self, c: Constraint, found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        let y = self.col("Y");
        let range = matches!(c, Constraint::Range(i) if r.ranges[i].column == y);
        let position = match c {
            Constraint::Identity(id) => r.identities[id]
                .name
                .strip_prefix(&format!("{SCOPE}/output/"))
                .and_then(|n| n.parse::<u32>().ok()),
            _ => None,
        };
        let top = (0u32..)
            .find(|i| {
                r.identities.iter().any(|d| {
                    d.name == format!("{SCOPE}/output/{i}")
                        && d.terms
                            .iter()
                            .any(|t| t.factors.iter().any(|f| f.column == y))
                })
            })
            .expect("Y position");
        if !range && position.is_none_or(|i| i <= top) {
            return false;
        }
        let mut tries = 0;
        for (x0, x2) in (1..=16).flat_map(|x0| (1..=32767).rev().step_by(3).map(move |x2| (x0, x2)))
        {
            let mut inputs = self.inputs.to_vec();
            inputs[0] = vec![x0, 0, x2, 0];
            let truth = evaluate(&inputs[0], &self.norm.gains).1[0];
            if i16::try_from(truth).is_ok() {
                continue;
            }
            let wrapped = match position {
                Some(i) => {
                    let modulus = 1i128 << (8 * (i - top));
                    let w = (truth + modulus / 2).rem_euclid(modulus) - modulus / 2;
                    if i16::try_from(w).is_err() {
                        continue;
                    }
                    Some(w)
                }
                None => None,
            };
            tries += 1;
            if tries > 32 {
                return false;
            }
            let mut v = self.fresh(&inputs);
            if let Some(w) = wrapped {
                set(r, &mut v, y, 0, w);
                self.solver.keep.set(Some(y));
            }
            let ok = self.solver.solve(&mut v, c);
            self.solver.keep.set(None);
            let how = match wrapped {
                Some(w) => {
                    format!("overflow X = [{x0}, 0, {x2}, 0]: true Y = {truth}, wrapped to {w}")
                }
                None => format!("overflow X = [{x0}, 0, {x2}, 0]: true Y = {truth} outside int16"),
            };
            if ok.is_some()
                && found(Attack {
                    how,
                    values: v,
                    output: true,
                })
            {
                return true;
            }
        }
        false
    }

    /// Move row `t`'s one-hot to `k`, subtract `offset` from `A`, rebase and solve.
    #[allow(clippy::too_many_arguments)]
    fn offset_at(
        &self,
        v: &Values,
        c: Constraint,
        t: usize,
        k: usize,
        offset: i128,
        base: &[i64],
        found: &mut dyn FnMut(Attack) -> bool,
    ) -> bool {
        let r = self.r;
        let h = self.col("h");
        let mut v = v.clone();
        for j in 0..64 {
            set(r, &mut v, h, (t << 6) + j, i128::from(j == k));
        }
        self.offset.set(Some((t, offset)));
        let ok = self.rebased(&mut v, c);
        self.offset.set(None);
        ok.is_some()
            && self.emit(
                format!("row {t}: exponent K = {k}, A - {offset}, rebased"),
                v,
                base,
                found,
            )
    }

    /// A removed quotient position `i`: `A − M·D − R = k·256^i` at some exponent, first
    /// on the honest rows, then on a row `[0, 1, x2, x3]` whose `S = 1 + x2² + x3²` reaches it.
    fn quotient(&self, c: Constraint, base: &[i64], found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        let Constraint::Identity(id) = c else {
            return false;
        };
        let Some(i) = r.identities[id]
            .name
            .strip_prefix(&format!("{SCOPE}/quotient/"))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            return false;
        };
        let unit = 1i128 << (8 * i);
        for t in 0..self.inputs.len() {
            for k in 0..64 {
                for times in [-2i128, -1, 1, 2] {
                    if self.offset_at(self.honest, c, t, k, times * unit, base, found) {
                        return true;
                    }
                }
            }
        }
        let constant = |prefix: &str, k: usize| -> i128 {
            (0..64)
                .filter_map(|j| column(r, &format!("{SCOPE}/{prefix}{j}/K")).map(|c| (j, c)))
                .map(|(j, col)| match &r.columns[col.0 as usize].kind {
                    Kind::Public(values) => i128::from(values[k]) << (8 * j),
                    _ => 0,
                })
                .sum()
        };
        let mut tries = 0;
        for k in 0..64 {
            let (alpha, beta, d) = (
                constant("alpha", k),
                constant("beta", k),
                constant("gamma", k),
            );
            if alpha == 0 || d == 0 {
                continue;
            }
            for times in [1i128, 2, 3] {
                let low = (times * unit - beta + 16384 * d + alpha - 1)
                    .div_euclid(alpha)
                    .max(1);
                let high = (times * unit - beta + 65536 * d - 1)
                    .div_euclid(alpha)
                    .min(2 * 32767 * 32767);
                for s in low..=high.min(low + 4096) {
                    let Some((x2, x3)) = two_squares(s - 1) else {
                        continue;
                    };
                    tries += 1;
                    if tries > 512 {
                        return false;
                    }
                    let mut inputs = self.inputs.to_vec();
                    inputs[3] = vec![0, 1, x2, x3];
                    let v = self.fresh(&inputs);
                    let fresh_base = self.y(&v);
                    if self.offset_at(&v, c, 3, k, times * unit, &fresh_base, found) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Attacks charged to whichever single constraint they violate: `M ± k` with `J`
    /// following (or kept), and moves between adjacent limbs of every Compose.
    fn pool(&self) -> Vec<Attack> {
        let r = self.r;
        let base = self.y(self.honest);
        let mut out = Vec::new();
        let none = Constraint::Matmul(usize::MAX);
        for t in 0..self.inputs.len() {
            for k in (-8i128..=8).filter(|&k| k != 0) {
                for follow in [true, false] {
                    let mut v = self.honest.clone();
                    let m = get(r, &v, self.col("M"), t) + k;
                    let j = match self.rsqrt.get((m - 16384).max(0) as usize) {
                        Some(&j) if follow && (16384..65536).contains(&m) => i128::from(j),
                        _ => get(r, &v, self.col("J"), t),
                    };
                    for (name, value) in [
                        ("M", m),
                        ("M0", m & 255),
                        ("M1", m >> 8),
                        ("J", j),
                        ("J0", j & 255),
                        ("J1", j >> 8),
                    ] {
                        set(r, &mut v, self.col(name), t, value);
                    }
                    if self.solver.solve(&mut v, none).is_some() {
                        let output = self.y(&v) != base;
                        out.push(Attack {
                            how: format!(
                                "row {t}: M {k:+}{}, solved",
                                if follow { ", J = rsqrt(M)" } else { ", J kept" }
                            ),
                            values: v,
                            output,
                        });
                    }
                }
            }
        }
        for (n, comp) in r.composes.iter().enumerate() {
            for pair in comp.limbs.windows(2) {
                let ((low, _), (high, _)) = (pair[0], pair[1]);
                for i in 0..(1usize << r.columns[low.0 as usize].log_len).min(16) {
                    for s in [1i128, -1] {
                        let mut v = self.honest.clone();
                        let (a, b) = (get(r, &v, low, i), get(r, &v, high, i));
                        set(r, &mut v, low, i, a + 256 * s);
                        set(r, &mut v, high, i, b - s);
                        recompute_matmuls(r, &mut v, Constraint::Compose(n));
                        if self.solver.solve(&mut v, none).is_some() {
                            let name = &r.columns[low.0 as usize].name;
                            let output = self.y(&v) != base;
                            out.push(Attack {
                                how: format!(
                                    "{name}[{i}] {:+} with the next limb {:+}, solved",
                                    256 * s,
                                    -s
                                ),
                                values: v,
                                output,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    /// A removed position `i` of the `S` chain frees byte `S_i`: `S' = S ± 256^i` at
    /// another exponent, with `M`, `J` and the output following.
    fn statistic(
        &self,
        c: Constraint,
        base: &[i64],
        found: &mut dyn FnMut(Attack) -> bool,
    ) -> bool {
        let r = self.r;
        let Constraint::Identity(id) = c else {
            return false;
        };
        let Some(i) = r.identities[id]
            .name
            .strip_prefix(&format!("{SCOPE}/S/"))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            return false;
        };
        let byte = self.col(&format!("S_{i}"));
        let h = self.col("h");
        for t in 0..self.inputs.len() {
            for delta in [1i128, -1, 2] {
                for k in 0..64 {
                    let mut v = self.honest.clone();
                    let old = get(r, &v, byte, t);
                    set(r, &mut v, byte, t, old + delta);
                    for j in 0..64 {
                        set(r, &mut v, h, (t << 6) + j, i128::from(j == k));
                    }
                    recompute_matmuls(r, &mut v, c);
                    self.solver.keep.set(Some(byte));
                    let ok = self
                        .rebase(&mut v)
                        .and_then(|_| self.solver.solve(&mut v, c));
                    self.solver.keep.set(None);
                    if ok.is_some()
                        && self.emit(
                            format!("row {t}: S_{i} {delta:+}, exponent K = {k}, rebased"),
                            v,
                            base,
                            found,
                        )
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Move (or add, or set to 2 against a −1 elsewhere) the one-hot entry of row 0; for a
    /// removed selection matmul, also choose its free byte.
    fn exponent(&self, c: Constraint, base: &[i64], found: &mut dyn FnMut(Attack) -> bool) -> bool {
        let r = self.r;
        let h = self.col("h");
        let k0 = (0..64)
            .find(|&k| get(r, self.honest, h, k) == 1)
            .expect("one-hot");
        let free = match c {
            Constraint::Matmul(j)
                if matches!(
                    r.columns[r.matmuls[j].out.column.0 as usize].kind,
                    Kind::Witness(_)
                ) =>
            {
                Some(r.matmuls[j].out.column)
            }
            Constraint::Matmul(_) => None,
            _ => return false,
        };
        for other in 0..64 {
            for (pattern, (at_k0, at_other)) in [(0, (0, 1)), (1, (1, 1)), (2, (2, -1))] {
                let two = pattern > 0;
                let mut v = self.honest.clone();
                set(r, &mut v, h, k0, at_k0);
                set(r, &mut v, h, other, at_other);
                recompute_matmuls(r, &mut v, c);
                for value in if free.is_some() { 0..256 } else { 0..1 } {
                    let mut v = v.clone();
                    if let Some(f) = free {
                        set(r, &mut v, f, 0, value);
                    }
                    let how = format!(
                        "h[{k0}] = {at_k0}, h[{other}] = {at_other}{}, rebased",
                        if free.is_some() {
                            format!(", byte {value}")
                        } else {
                            String::new()
                        }
                    );
                    let _ = two;
                    if self.rebased(&mut v, c).is_some() && self.emit(how, v, base, found) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// The survey checked against its golden table; `none` rows are not searched.
#[test]
fn rejects_every_rmsnorm_constraint_alone() {
    rmsnorm_survey(false);
}

/// The exhaustive survey that produced the golden table (slow; run with `--ignored`).
#[test]
#[ignore]
fn surveys_every_rmsnorm_constraint_exhaustively() {
    rmsnorm_survey(true);
}

fn rmsnorm_survey(exhaustive: bool) {
    let (norm, inputs) = instance();
    let rows = norm.rows(&inputs);
    let (r, module, x) = norm.relation(rows.len());
    let (_, honest) = norm.assigned(&rows).expect("assign");
    let attack = NormAttack {
        norm: &norm,
        module: &module,
        x,
        r: &r,
        honest: &honest,
        inputs: &inputs,
        solver: Solver {
            r: &r,
            scope: SCOPE,
            specs: CHAINS,
            keep: Cell::new(None),
        },
        rsqrt: {
            let table = stele_cqis::tables::Table::rsqrt().expect("table");
            table
                .entries()
                .chunks_exact(2)
                .filter(|e| e[0] >= 16384)
                .map(|e| i64::from(e[1]))
                .collect()
        },
        offset: Cell::new(None),
    };
    let pool = attack.pool();
    let expected = include_str!("rmsnorm-mutation.txt");
    let golden_hint = (!exhaustive).then_some(expected);
    let survey = survey(
        &r,
        &honest,
        &pool,
        &|c, found| attack.search(c, found),
        golden_hint,
    );
    golden("rmsnorm_q", &survey, expected);
}
