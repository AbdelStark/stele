//! RFC-0026 §5 row 2: `rmsnorm_q` (RFC-0021 §2.3 and A4) as relations over committed
//! integer columns, reproducing `stele_cqis::functions::Descriptor::evaluate_rmsnorm`.
//!
//! Integer definition, per row of `d` inputs `X` with public gains `H` and public
//! `d, F, G, E, en, ed`: `S = Σ X²`, `unit = d·4^F`, `N = ed·S + en·unit`,
//! `P = ed·unit`; the unique `a` with `M = floor(N·fa / (P·fd)) ∈ [2^14, 2^16)`, where
//! `fa = 4^max(−a,0)`, `fd = 4^max(a,0)`; `J = rsqrt_q[M]`; `e = F+G+21+a−E`; and
//! `Y = R(X·H·J / 2^e)` (half away from zero) when `e >= 1`, `Y = X·H·J·2^(−e)` when
//! `e <= 0`. The executor rejects `a` outside `[−23, 9]` (`[−23, 16]` for version 2),
//! `e` outside `[−16, 90]` (`97`), and any `Y` outside int16.
//!
//! Committed witness advice columns (RFC-0028 §1.2):
//! - Element domain `(t, k)`: high input bytes `X_{1..n-1}`, top-limb sign `sigmaX`,
//!   pre-multiplied product carries `P_q0` (and `P_q1` for int24) and top limb `P2`/`P3`
//!   (radix `2^12` product `P = X·H`), rounded output `Y` (`s16`), and unsplit radix-`2^12`
//!   `output/carry*`.
//! - Row domain `t`: `S_pq` byte-composed limbs (`S00_0..`), `S/carry*`, `M`, `M1`, `J`,
//!   `J1`, `quotient/carry*`, `remainder/carry*`, and radix-`2^12` `Jg/carry*`.
//! - Selector domain `(t, K)`: one-hot exponent selector `h` (`u1`).
//! - Virtual: `X0`, `S_pq` contractions, `S_*`, `alpha*`/`beta*`/`gamma*`/`g*`/`gp*`/`pos`
//!   selection contractions, `M0`, `J0`, `R*`, `gap*`, `Jg0..`, `P0..`, and `Z*`.
//! - Public: gain bytes `H0`, `H1`, `sigmaH`, `flipH` (committed as weights under dev-zk),
//!   `valid`, and `K`-indexed constant tables.
//!
//! `e' = min(e, Es_cap)` with `Es_cap = bits(X) + 30`; `Es` is the least multiple of
//! `OUT_RADIX = 12` at least `max(1, max e')`.
//!
//! **Output uniqueness (RFC-0026 §5.2).** Fix `X` within its width.
//! 1. The byte limbs of `X` are unique (low bytes in `[0, 256)`, top limb fixed), and
//!    `σX = [X < 0]`. So each `S_pq` is unique and `S = Σ c_pq·256^(p+q)·S_pq = Σ X²`;
//!    the chain gives `S = Σ 256^i S_i` with bytes in `[0, 256)`, so the bytes are unique.
//! 2. `h` is 0/1, one entry is set among the valid `K`, and none outside, so each
//!    selected byte is the byte of the constant at the chosen `K`.
//! 3. The chains give, over Z, `N·fa = M·D + R` and `D = R + gap + 1` with
//!    `D = P·fd` and `R, gap >= 0`: `M = floor(N·fa / D)`. The lookup forces
//!    `M ∈ [2^14, 2^16)`, and the intervals `[2^14·4^a, 2^16·4^a)` are disjoint for
//!    distinct `a`, so `K`, `M`, and `J = rsqrt_q[M]` are the executor's.
//! 4. The output chain gives `Z = Y·2^Es − g·Q + pos·(σ − 1)·g + pos·2^(Es−1)` with
//!    `Q = X·H·J` and `g = 2^(Es − e')`. If `e' >= 1`, `Z/g = Y·2^e' − Q + σ − 1 + 2^(e'−1)`
//!    lies in `[0, 2^e')`, which is `Y·2^e' − Q ∈ (−2^(e'−1), 2^(e'−1)]` for `σ = 0` and
//!    `[−2^(e'−1), 2^(e'−1))` for `σ = 1`: `Y = R(Q/2^e')`. `σ = [Q < 0]` whenever
//!    `Q != 0` (`J > 0`); at `Q = 0` both `σ` give `Y = 0`. If `e' <= 0`,
//!    `Z = 2^Es·(Y − Q·2^(−e'))` in `[0, 2^Es)` forces `Y = Q·2^(−e')` exactly. So `Y` is
//!    unique. When `e > e'`, `|Q| <= 2^(bits(X)+28) < 2^(bits(X)+29) = 2^(e'−1)`, so both
//!    `R(Q/2^e)` and `R(Q/2^e')` are 0. Padded features have `H = 0`, so `Q = 0` and `Y = 0`.
//!
//! Upstream obligation: the padded entries of `X` (features `k >= d`) are 0, as every
//! producer pins its padding (RFC-0026 §2.1). Step 1 counts exactly the `d` real
//! features only under that obligation.

use super::limbs::{at, bytes, log2_ceil, sign_table, term, Scope};
use super::{bit_length, Builder, Chain, Unsupported};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::functions::{Descriptor, NormEvaluation};
use stele_cqis::tables::Table as CqisTable;
use stele_ir::relation::{
    ColumnId, Def, Kind, Lookup, Matmul, Module, Range, Relation, Table, Term, Values, Violation,
    Width,
};

/// Bits of the exponent selector domain: `K = a + 23 < 64`.
const KBITS: u8 = 6;

/// Plan data of one rmsnorm_q instance.
#[derive(Clone, Debug)]
pub struct RmsNormPlan {
    /// The checked `rmsnorm_q` descriptor, version 1 or 2.
    pub descriptor: Descriptor,
    /// The `d` signed int16 gain codes.
    pub gains: Vec<i16>,
    /// Rows `T`, a power of two.
    pub rows: usize,
    /// dev-zk (E12-27): the gain-derived columns take their format's full widths
    /// (`H0` unsigned 8, `H1` signed 8, `σH` unsigned 1, `flipH` signed 2) instead
    /// of the widths of these gains, so the relation does not depend on them.
    pub fixed_widths: bool,
}

/// The executor's intermediates of one row (RFC-0026 §3.8), from [`NormEvaluation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RmsNormRow {
    pub input: Vec<i32>,
    /// `a`.
    pub exponent: i8,
    /// `M`.
    pub mantissa: u16,
    /// `J = rsqrt_q[M]`.
    pub reciprocal: u16,
    /// `D = P·fd`.
    pub divisor: i128,
    /// `R = N·fa − M·D`; signed so that a capture can hold any candidate value.
    pub remainder: i128,
    pub output: Vec<i16>,
}

impl RmsNormRow {
    pub fn new(input: &[i32], evaluation: &NormEvaluation) -> Self {
        let (_, divisor, remainder) = evaluation.normalized_ratio();
        // The executor keeps D < 2^124 and R < D (RFC-0021 §2.3), so both fit i128.
        let (divisor, remainder) = (divisor as i128, remainder as i128);
        Self {
            input: input.to_vec(),
            exponent: evaluation.exponent(),
            mantissa: evaluation.mantissa(),
            reciprocal: evaluation.reciprocal(),
            divisor,
            remainder,
            output: evaluation.outputs().to_vec(),
        }
    }
}

/// Radix in bits for the per-element output chain (`P = X*H`, `Jg`, `gp`, `Z`, RFC-0028 §1.2).
const OUT_RADIX: u8 = 12;

/// `base · 2^shift`, kept factored because some constants exceed 128 bits.
#[derive(Clone, Copy)]
struct Shifted(u128, u32);

impl Shifted {
    fn limb(self, j: usize, r: u32) -> i64 {
        let s = i64::from(self.1) - i64::from(r) * j as i64;
        let v = if s >= 0 {
            if s >= i64::from(r) {
                0
            } else {
                self.0 << s
            }
        } else if -s >= 128 {
            0
        } else {
            self.0 >> -s
        };
        (v & ((1u128 << r) - 1)) as i64
    }

    fn limbs(self, r: u32) -> usize {
        if self.0 == 0 {
            0
        } else {
            (u32::from(bit_length(self.0)) + self.1).div_ceil(r) as usize
        }
    }

    fn bytes(self) -> usize {
        self.limbs(8)
    }
}

/// One `K`-indexed constant family of [`Exponent`].
type Constant = fn(&Exponent) -> Shifted;

#[derive(Clone, Copy)]
struct Exponent {
    valid: bool,
    alpha: Shifted,
    beta: Shifted,
    gamma: Shifted,
    g: Shifted,
    pos: bool,
}

struct Columns {
    limbs: Vec<ColumnId>,
    sign: ColumnId,
    sums: Vec<(usize, usize, ColumnId, Vec<ColumnId>)>,
    statistic: Vec<ColumnId>,
    onehot: ColumnId,
    selected: Vec<(ColumnId, Vec<i64>)>,
    mantissa: (ColumnId, Vec<ColumnId>),
    reciprocal: (ColumnId, Vec<ColumnId>),
    remainder: Vec<ColumnId>,
    gap: Vec<ColumnId>,
    scaled: Vec<ColumnId>,
    /// Committed advice columns for `P = X * H` in radix `2^12` (`[qp0, p2]` or `[qp0, qp1, p3]`).
    p_advice: Vec<ColumnId>,
    output: ColumnId,
    z: Vec<ColumnId>,
    chains: Vec<Chain>,
}

/// RFC-0026 §5 row 2 module; `input` is the upstream residual column (T×d).
pub struct RmsNorm {
    plan: RmsNormPlan,
    input: ColumnId,
    scope: Scope,
    d: usize,
    xbits: u32,
    exponents: Vec<Exponent>,
    es: u32,
    columns: Option<Columns>,
}

impl RmsNorm {
    pub fn new(plan: RmsNormPlan, input: ColumnId, scope: &str) -> Result<Self, Unsupported> {
        let p = plan.descriptor.parameters();
        if plan.descriptor.name() != "rmsnorm_q" || p.len() != 13 {
            return Err(Unsupported::Shape);
        }
        let d = usize::from(u16::from_le_bytes([p[0], p[1]]));
        let (f, g, e) = (i32::from(p[2]), i32::from(p[3]), i32::from(p[4]));
        let en = u128::from(u32::from_le_bytes([p[5], p[6], p[7], p[8]]));
        let ed = u128::from(u32::from_le_bytes([p[9], p[10], p[11], p[12]]));
        let version = plan.descriptor.version();
        let (xbits, highest_a, highest_e) = if version == 2 {
            (24, 16, 97)
        } else {
            (16, 9, 90)
        };
        // Signed S_pq widths need 2^log(d)·255² < 2^29 (RFC-0026 §3.6 matmul discipline).
        if d > 8192 || plan.gains.len() != d || !plan.rows.is_power_of_two() {
            return Err(Unsupported::Shape);
        }
        let cap = xbits as i32 + 30;
        let mut exponents = Vec::new();
        let mut top = 1;
        for k in 0..1i32 << KBITS {
            let a = k - 23;
            let shift = f + g + 21 + a - e;
            let valid = a <= highest_a && (-16..=highest_e).contains(&shift);
            let clamped = shift.min(cap);
            if valid {
                top = top.max(clamped);
            }
            let (fa, fd) = (2 * (-a).max(0) as u32, 2 * a.max(0) as u32);
            exponents.push((valid, clamped, fa, fd));
        }
        let r = i32::from(OUT_RADIX);
        let es = ((top + r - 1) / r * r) as u32;
        let unit = 2 * f as u32;
        let exponents = exponents
            .into_iter()
            .map(|(valid, e, fa, fd)| {
                let zero = Shifted(0, 0);
                let pick = |s: Shifted| if valid { s } else { zero };
                Exponent {
                    valid,
                    alpha: pick(Shifted(ed, fa)),
                    beta: pick(Shifted(en * d as u128, unit + fa)),
                    gamma: pick(Shifted(ed * d as u128, unit + fd)),
                    g: pick(Shifted(1, (es as i32 - e) as u32)),
                    pos: valid && e >= 1,
                }
            })
            .collect::<Vec<_>>();
        if !exponents.iter().any(|x| x.valid) {
            return Err(Unsupported::Shape);
        }
        Ok(Self {
            plan,
            input,
            scope: Scope { name: scope.into() },
            d,
            xbits,
            exponents,
            es,
            columns: None,
        })
    }

    /// The norm output `Y` (T×d, int16) consumed by row conversion (RFC-0026 §5.1).
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }

    fn logs(&self) -> (u8, u8) {
        (log2_ceil(self.plan.rows), log2_ceil(self.d))
    }

    fn limb_count(&self) -> usize {
        self.xbits.div_ceil(8) as usize
    }

    fn width(&self, f: impl Fn(&Exponent) -> usize) -> usize {
        self.exponents.iter().map(f).max().unwrap_or(0)
    }

    fn gain_bytes(&self, ld: u8) -> [Vec<i64>; 4] {
        let mut out = [(); 4].map(|_| vec![0; 1 << ld]);
        out[3] = vec![1; 1 << ld];
        for (k, &h) in self.plan.gains.iter().enumerate() {
            let h = i64::from(h);
            out[0][k] = h & 255;
            out[1][k] = h >> 8;
            out[2][k] = i64::from(h < 0);
            out[3][k] = 1 - 2 * i64::from(h < 0);
        }
        out
    }
}

impl Module for RmsNorm {
    type Capture = [RmsNormRow];

    fn declare(&mut self, relation: &mut Relation) {
        let (lt, ld) = self.logs();
        let ev = ld + lt;
        let s = &self.scope;
        let n = self.limb_count();
        let x = self.input;
        let row = |c| at(c, ld..ev);
        let elem = |c| at(c, 0..ev);
        let feature = |c| at(c, 0..ld);

        // 1. Byte limbs of X (X0 virtual Linear under RFC-0028 §1.2, A1; X1.. committed)
        // and the input sign.
        let mut hi_limbs = Vec::new();
        for a in 1..n {
            hi_limbs.push(if a + 1 < n {
                s.ranged(relation, &format!("X{a}"), Width::unsigned(8), ev)
            } else {
                s.witness(relation, &format!("X{a}"), Width::signed(8), ev)
            });
        }
        let mut x0_terms = vec![(1, elem(x))];
        for (idx, &col) in hi_limbs.iter().enumerate() {
            x0_terms.push((-(1i64 << (8 * (idx + 1))), elem(col)));
        }
        let x0 = if n == 1 {
            s.witness(relation, "X0", Width::signed(8), ev)
        } else {
            let id = relation.add_virtual(
                &format!("{}/X0", s.name),
                Def::Linear {
                    constant: 0,
                    terms: x0_terms,
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/X0/range", s.name),
                column: id,
                width: Width::unsigned(8),
            });
            id
        };
        let mut limbs = Vec::with_capacity(n);
        limbs.push(x0);
        limbs.extend(hi_limbs);
        let sign = s.witness(relation, "sigmaX", Width::unsigned(1), ev);
        let table = sign_table(relation, 8);
        relation.lookups.push(Lookup {
            name: format!("{}/sigmaX", s.name),
            vars: ev,
            selector: None,
            tuple: vec![elem(limbs[n - 1]), elem(sign)],
            table,
        });

        // 2. Row sums of limb products (virtual Contractions, RFC-0028 §1.2) and their bytes,
        // then virtual bytes of S via `chain_virtual`.
        let magnitude = |a: usize| if a + 1 < n { 255i128 } else { 128 };
        let mut sums = Vec::new();
        let mut positions: Vec<Vec<Term>> = Vec::new();
        let push = |positions: &mut Vec<Vec<Term>>, i: usize, t: Term| {
            if positions.len() <= i {
                positions.resize(i + 1, Vec::new());
            }
            positions[i].push(t);
        };
        for p in 0..n {
            for q in p..n {
                let bound = (magnitude(p) * magnitude(q)) << ld;
                let out = relation.add_virtual(
                    &format!("{}/S{p}{q}", s.name),
                    Def::Contraction {
                        free: lt,
                        summed: ld,
                        lhs: at(limbs[p], (lt..lt + ld).chain(0..lt)),
                        rhs: at(limbs[q], (lt..lt + ld).chain(0..lt)),
                    },
                    lt,
                );
                let low = if p == q { 0 } else { -bound };
                let parts = s.byte_limbs(relation, &format!("S{p}{q}_"), low, bound, lt);
                s.compose(relation, out, &parts);
                let c = if p == q { 1 } else { 2 };
                for (l, &part) in parts.iter().enumerate() {
                    push(&mut positions, p + q + l, term(c, vec![at(part, 0..lt)]));
                }
                sums.push((p, q, out, parts));
            }
        }
        let largest = (self.d as u128) << (2 * (self.xbits - 1));
        let ns = bit_length(largest).div_ceil(8) as usize;
        let s_targets: Vec<_> = (0..ns)
            .map(|i| (i, format!("S_{i}"), Width::unsigned(8)))
            .collect();
        let (s_chain, statistic) = s.chain_virtual(relation, "S", lt, positions, &s_targets);
        let mut chains = vec![s_chain];

        // 3. The exponent one-hot and the selected constant bytes (virtual Contractions).
        let onehot = s.ranged(relation, "h", Width::unsigned(1), lt + KBITS);
        let valid: Vec<i64> = self.exponents.iter().map(|x| i64::from(x.valid)).collect();
        let invalid = valid.iter().map(|v| 1 - v).collect();
        let valid_col = s.public(relation, "valid", valid, KBITS);
        let invalid = s.public(relation, "invalid", invalid, KBITS);
        let ones = s.public(relation, "ones", vec![1; 1 << lt], lt);
        let h_sel = || at(onehot, (lt..lt + KBITS).chain(0..lt));
        relation.matmuls.push(Matmul {
            name: format!("{}/onehot", s.name),
            free: lt,
            summed: KBITS,
            out: at(ones, 0..lt),
            lhs: h_sel(),
            rhs: at(valid_col, lt..lt + KBITS),
        });
        s.identity(
            relation,
            "invalid",
            lt + KBITS,
            vec![term(
                1,
                vec![at(onehot, 0..lt + KBITS), at(invalid, 0..KBITS)],
            )],
        );
        let mut selected = Vec::new();
        let mut select = |relation: &mut Relation, name: &str, column: Vec<i64>| {
            if column.iter().all(|&v| v == 0) {
                return None;
            }
            let constant = s.public(relation, &format!("{name}/K"), column.clone(), KBITS);
            let width = relation.columns[constant.0 as usize].width;
            let out = relation.add_virtual(
                &format!("{}/{name}", s.name),
                Def::Contraction {
                    free: lt,
                    summed: KBITS,
                    lhs: h_sel(),
                    rhs: at(constant, lt..lt + KBITS),
                },
                lt,
            );
            relation.ranges.push(Range {
                name: format!("{}/{name}/range", s.name),
                column: out,
                width,
            });
            selected.push((out, column));
            Some(out)
        };
        let na = self.width(|x| x.alpha.bytes());
        let nb = self.width(|x| x.beta.bytes());
        let nc = self.width(|x| x.gamma.bytes());
        let ng = self.width(|x| x.g.limbs(u32::from(OUT_RADIX)));
        let positive = |x: &Exponent| if x.pos { x.g } else { Shifted(0, 0) };
        let families: [(&str, Constant, usize, u32); 5] = [
            ("alpha", |x| x.alpha, na, 8),
            ("beta", |x| x.beta, nb, 8),
            ("gamma", |x| x.gamma, nc, 8),
            ("g", |x| x.g, ng, u32::from(OUT_RADIX)),
            ("gp", positive, ng, u32::from(OUT_RADIX)),
        ];
        let [alpha, beta, gamma, g, gp] = families.map(|(name, f, count, rbits)| {
            (0..count)
                .map(|j| {
                    let vals = self.exponents.iter().map(|x| f(x).limb(j, rbits)).collect();
                    select(relation, &format!("{name}{j}"), vals)
                })
                .collect::<Vec<_>>()
        });
        let pos = select(
            relation,
            "pos",
            self.exponents.iter().map(|x| i64::from(x.pos)).collect(),
        );

        // 4. Mantissa, reciprocal, quotient and remainder (virtual M0/J0 and virtual R/gap).
        let mantissa = s.witness(relation, "M", Width::unsigned(16), lt);
        let reciprocal = s.witness(relation, "J", Width::unsigned(15), lt);
        let rsqrt = CqisTable::rsqrt().expect("rsqrt_q generation is total");
        let rows = rsqrt
            .entries()
            .chunks_exact(2)
            .filter(|r| r[0] >= 16384)
            .map(|r| vec![i64::from(r[0]), i64::from(r[1])])
            .collect();
        let table = relation.add_table(Table {
            name: "rsqrt_q".into(),
            widths: vec![Width::unsigned(16), Width::unsigned(15)],
            rows,
        });
        relation.lookups.push(Lookup {
            name: format!("{}/rsqrt", s.name),
            vars: lt,
            selector: None,
            tuple: vec![at(mantissa, 0..lt), at(reciprocal, 0..lt)],
            table,
        });
        let m1 = s.ranged(relation, "M1", Width::unsigned(8), lt);
        let m0 = relation.add_virtual(
            &format!("{}/M0", s.name),
            Def::Linear {
                constant: 0,
                terms: vec![(1, at(mantissa, 0..lt)), (-256, at(m1, 0..lt))],
            },
            lt,
        );
        relation.ranges.push(Range {
            name: format!("{}/M0/range", s.name),
            column: m0,
            width: Width::unsigned(8),
        });
        let m = vec![m0, m1];
        let j1 = s.ranged(relation, "J1", Width::unsigned(15 - OUT_RADIX), lt);
        let j0 = relation.add_virtual(
            &format!("{}/J0", s.name),
            Def::Linear {
                constant: 0,
                terms: vec![
                    (1, at(reciprocal, 0..lt)),
                    (-(1i64 << OUT_RADIX), at(j1, 0..lt)),
                ],
            },
            lt,
        );
        relation.ranges.push(Range {
            name: format!("{}/J0/range", s.name),
            column: j0,
            width: Width::unsigned(OUT_RADIX),
        });
        let j = vec![j0, j1];
        let r1 = |c| at(c, 0..lt);
        let mut quotient = Vec::new();
        for (mi, &sm) in statistic.iter().enumerate() {
            for (ai, a) in alpha.iter().enumerate() {
                if let Some(a) = a {
                    push(&mut quotient, mi + ai, term(1, vec![r1(sm), r1(*a)]));
                }
            }
        }
        for (i, b) in beta.iter().enumerate() {
            if let Some(b) = b {
                push(&mut quotient, i, term(1, vec![r1(*b)]));
            }
        }
        for (ci, &mc) in m.iter().enumerate() {
            for (gi, c) in gamma.iter().enumerate() {
                if let Some(c) = c {
                    push(&mut quotient, ci + gi, term(-1, vec![r1(mc), r1(*c)]));
                }
            }
        }
        let r_targets: Vec<_> = (0..nc)
            .map(|i| (i, format!("R{i}"), Width::unsigned(8)))
            .collect();
        let (q_chain, remainder) = s.chain_virtual(relation, "quotient", lt, quotient, &r_targets);
        chains.push(q_chain);
        let mut rest = vec![vec![term(-1, vec![])]];
        for (i, c) in gamma.iter().enumerate() {
            if let Some(c) = c {
                push(&mut rest, i, term(1, vec![r1(*c)]));
            }
        }
        for (i, &rem_col) in remainder.iter().enumerate().take(nc) {
            push(&mut rest, i, term(-1, vec![r1(rem_col)]));
        }
        let gap_targets: Vec<_> = (0..nc)
            .map(|i| (i, format!("gap{i}"), Width::unsigned(8)))
            .collect();
        let (rem_chain, gap) = s.chain_virtual(relation, "remainder", lt, rest, &gap_targets);
        chains.push(rem_chain);

        // 5. Jg = J·g in radix 2^12 (virtual limbs), P = X·H in radix 2^12 (degree-2),
        // then the per-element output chain in radix 2^12 (unsplit carries, virtual Z0..Z_{top-1}).
        let rbits = u32::from(OUT_RADIX);
        let njg = (15 + self.width(|x| x.g.1 as usize) as u32).div_ceil(rbits) as usize;
        let mut jg = Vec::new();
        for (ci, &jc) in j.iter().enumerate() {
            for (gi, gc) in g.iter().enumerate() {
                if let Some(gc) = gc {
                    push(&mut jg, ci + gi, term(1, vec![r1(jc), r1(*gc)]));
                }
            }
        }
        let jg_targets: Vec<_> = (0..njg)
            .map(|i| (i, format!("Jg{i}"), Width::unsigned(OUT_RADIX)))
            .collect();
        let (jg_chain, scaled) = Chain::declare_virtual(
            &mut Builder::new(relation, &s.name),
            "Jg",
            lt,
            OUT_RADIX,
            jg,
            &jg_targets,
        );
        chains.push(jg_chain);

        let [h0, h1, sh, s1] = self.gain_bytes(ld);
        let fixed = self.plan.fixed_widths;
        let mut public = |name: &str, values: Vec<i64>, width: Width| match fixed {
            true => s.public_width(relation, name, values, width, ld),
            false => s.public(relation, name, values, ld),
        };
        let gains = [
            public("H0", h0, Width::unsigned(8)),
            public("H1", h1, Width::signed(8)),
        ];
        let sigma_h = public("sigmaH", sh, Width::unsigned(1));
        let flip = public("flipH", s1, Width::signed(2));

        // P = X * H in radix 2^12 (`p0, p1` virtual u12 + committed carries/top).
        let (p_limbs, p_advice): (Vec<ColumnId>, Vec<ColumnId>) = if n == 2 {
            let qp0 = s.ranged(relation, "P_q0", Width::signed(13), ev);
            let p0 = relation.add_virtual(
                &format!("{}/P0", s.name),
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![elem(limbs[0]), feature(gains[0])]),
                        term(256, vec![elem(limbs[0]), feature(gains[1])]),
                        term(256, vec![elem(limbs[1]), feature(gains[0])]),
                        term(-4096, vec![elem(qp0)]),
                    ],
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/P0/range", s.name),
                column: p0,
                width: Width::unsigned(OUT_RADIX),
            });
            let p2 = s.ranged(relation, "P2", Width::signed(8), ev);
            let p1 = relation.add_virtual(
                &format!("{}/P1", s.name),
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![elem(qp0)]),
                        term(16, vec![elem(limbs[1]), feature(gains[1])]),
                        term(-4096, vec![elem(p2)]),
                    ],
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/P1/range", s.name),
                column: p1,
                width: Width::unsigned(OUT_RADIX),
            });
            (vec![p0, p1, p2], vec![qp0, p2])
        } else {
            let qp0 = s.ranged(relation, "P_q0", Width::signed(14), ev);
            let p0 = relation.add_virtual(
                &format!("{}/P0", s.name),
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![elem(limbs[0]), feature(gains[0])]),
                        term(256, vec![elem(limbs[0]), feature(gains[1])]),
                        term(256, vec![elem(limbs[1]), feature(gains[0])]),
                        term(-4096, vec![elem(qp0)]),
                    ],
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/P0/range", s.name),
                column: p0,
                width: Width::unsigned(OUT_RADIX),
            });
            let qp1 = s.ranged(relation, "P_q1", Width::signed(10), ev);
            let p1 = relation.add_virtual(
                &format!("{}/P1", s.name),
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![elem(qp0)]),
                        term(16, vec![elem(limbs[1]), feature(gains[1])]),
                        term(16, vec![elem(limbs[2]), feature(gains[0])]),
                        term(-4096, vec![elem(qp1)]),
                    ],
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/P1/range", s.name),
                column: p1,
                width: Width::unsigned(OUT_RADIX),
            });
            let p3 = s.ranged(relation, "P3", Width::signed(4), ev);
            let p2 = relation.add_virtual(
                &format!("{}/P2", s.name),
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![elem(qp1)]),
                        term(1, vec![elem(limbs[2]), feature(gains[1])]),
                        term(-4096, vec![elem(p3)]),
                    ],
                },
                ev,
            );
            relation.ranges.push(Range {
                name: format!("{}/P2/range", s.name),
                column: p2,
                width: Width::unsigned(OUT_RADIX),
            });
            (vec![p0, p1, p2, p3], vec![qp0, qp1, p3])
        };

        let output = s.ranged(relation, "Y", Width::signed(16), ev);
        let top = (self.es / rbits) as usize;
        let mut out = Vec::new();
        for (a, &pa) in p_limbs.iter().enumerate() {
            for (m, &jm) in scaled.iter().enumerate() {
                push(&mut out, a + m, term(-1, vec![elem(pa), row(jm)]));
            }
        }
        for (i, c) in gp.iter().enumerate() {
            if let Some(c) = c {
                push(
                    &mut out,
                    i,
                    term(1, vec![elem(sign), feature(flip), row(*c)]),
                );
                push(&mut out, i, term(1, vec![feature(sigma_h), row(*c)]));
                push(&mut out, i, term(-1, vec![row(*c)]));
            }
        }
        if let Some(pos) = pos {
            push(
                &mut out,
                top - 1,
                term(1i64 << (OUT_RADIX - 1), vec![row(pos)]),
            );
        }
        push(&mut out, top, term(1, vec![elem(output)]));
        let z_targets: Vec<_> = (0..top)
            .map(|i| (i, format!("Z{i}"), Width::unsigned(OUT_RADIX)))
            .collect();
        let (out_chain, z) = Chain::declare_virtual(
            &mut Builder::new(relation, &s.name),
            "output",
            ev,
            OUT_RADIX,
            out,
            &z_targets,
        );
        chains.push(out_chain);

        self.columns = Some(Columns {
            limbs,
            sign,
            sums,
            statistic,
            onehot,
            selected,
            mantissa: (mantissa, m),
            reciprocal: (reciprocal, j),
            remainder,
            gap,
            scaled,
            p_advice,
            output,
            z,
            chains,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &[RmsNormRow],
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(self.input))?;
        let (lt, ld) = self.logs();
        let (rows, size) = (self.plan.rows, 1usize << (ld + lt));
        let shape = capture.len() == rows
            && capture
                .iter()
                .all(|r| r.input.len() == self.d && r.output.len() == self.d);
        if !shape {
            return Err(Violation::Missing(c.output));
        }
        let n = self.limb_count();
        let mut x = vec![0i128; size];
        let mut y = vec![0i64; size];
        for (t, r) in capture.iter().enumerate() {
            for k in 0..self.d {
                x[(t << ld) + k] = i128::from(r.input[k]);
                y[(t << ld) + k] = i64::from(r.output[k]);
            }
        }
        let limbs: Vec<Vec<i64>> = {
            let split: Vec<Vec<i64>> = x.iter().map(|&v| bytes(v, n)).collect();
            (0..n)
                .map(|a| split.iter().map(|b| b[a]).collect())
                .collect()
        };
        for (a, &col) in c.limbs.iter().enumerate() {
            if !matches!(relation.columns[col.0 as usize].kind, Kind::Virtual(_)) {
                values.set(relation, col, limbs[a].clone())?;
            }
        }
        let sign: Vec<i64> = x.iter().map(|&v| i64::from(v < 0)).collect();
        values.set(relation, c.sign, sign.clone())?;
        for (p, q, out, parts) in &c.sums {
            let sum: Vec<i128> = (0..rows)
                .map(|t| {
                    (0..1usize << ld)
                        .map(|k| i128::from(limbs[*p][(t << ld) + k] * limbs[*q][(t << ld) + k]))
                        .sum()
                })
                .collect();
            if !matches!(relation.columns[out.0 as usize].kind, Kind::Virtual(_)) {
                values.set(relation, *out, sum.iter().map(|&v| v as i64).collect())?;
            }
            set_bytes(relation, values, parts, &sum)?;
        }
        let statistic: Vec<i128> = (0..rows)
            .map(|t| {
                (0..self.d)
                    .map(|k| x[(t << ld) + k] * x[(t << ld) + k])
                    .sum()
            })
            .collect();
        set_bytes(relation, values, &c.statistic, &statistic)?;

        let mut onehot = vec![0i64; rows << KBITS];
        let mut chosen = Vec::new();
        for (t, r) in capture.iter().enumerate() {
            let k = (i32::from(r.exponent) + 23).clamp(0, (1 << KBITS) - 1) as usize;
            onehot[(t << KBITS) + k] = 1;
            chosen.push(k);
        }
        values.set(relation, c.onehot, onehot)?;
        for (out, column) in &c.selected {
            if !matches!(relation.columns[out.0 as usize].kind, Kind::Virtual(_)) {
                values.set(relation, *out, chosen.iter().map(|&k| column[k]).collect())?;
            }
        }
        let field = |f: fn(&RmsNormRow) -> i128| capture.iter().map(f).collect::<Vec<i128>>();
        let mantissa = field(|r| i128::from(r.mantissa));
        let reciprocal = field(|r| i128::from(r.reciprocal));
        values.set(
            relation,
            c.mantissa.0,
            mantissa.iter().map(|&v| v as i64).collect(),
        )?;
        set_bytes(relation, values, &c.mantissa.1, &mantissa)?;
        values.set(
            relation,
            c.reciprocal.0,
            reciprocal.iter().map(|&v| v as i64).collect(),
        )?;
        set_limbs(relation, values, &c.reciprocal.1, &reciprocal, OUT_RADIX)?;
        let remainder: Vec<i128> = capture.iter().map(|r| r.remainder).collect();
        let gap: Vec<i128> = capture
            .iter()
            .map(|r| r.divisor - 1 - r.remainder)
            .collect();
        set_bytes(relation, values, &c.remainder, &remainder)?;
        set_bytes(relation, values, &c.gap, &gap)?;
        let ex = |t: usize| self.exponents[chosen[t]];
        let scaled: Vec<i128> = (0..rows).map(|t| reciprocal[t] << ex(t).g.1).collect();
        set_limbs(relation, values, &c.scaled, &scaled, OUT_RADIX)?;

        let gains = &self.plan.gains;
        let [gh0, gh1, _, _] = self.gain_bytes(ld);
        let mask_d = (1usize << ld) - 1;
        if n == 2 {
            let mut qp0_col = Vec::with_capacity(size);
            let mut p2_col = Vec::with_capacity(size);
            for i in 0..size {
                let k = i & mask_d;
                let (x0, x1) = (i128::from(limbs[0][i]), i128::from(limbs[1][i]));
                let (h0, h1) = (i128::from(gh0[k]), i128::from(gh1[k]));
                let raw0 = x0 * h0 + 256 * (x0 * h1 + x1 * h0);
                let qp0 = raw0.div_euclid(4096);
                let raw1 = qp0 + 16 * x1 * h1;
                let p2 = raw1.div_euclid(4096);
                qp0_col.push(qp0 as i64);
                p2_col.push(p2 as i64);
            }
            values.set(relation, c.p_advice[0], qp0_col)?;
            values.set(relation, c.p_advice[1], p2_col)?;
        } else {
            let mut qp0_col = Vec::with_capacity(size);
            let mut qp1_col = Vec::with_capacity(size);
            let mut p3_col = Vec::with_capacity(size);
            for i in 0..size {
                let k = i & mask_d;
                let (x0, x1, x2) = (
                    i128::from(limbs[0][i]),
                    i128::from(limbs[1][i]),
                    i128::from(limbs[2][i]),
                );
                let (h0, h1) = (i128::from(gh0[k]), i128::from(gh1[k]));
                let raw0 = x0 * h0 + 256 * (x0 * h1 + x1 * h0);
                let qp0 = raw0.div_euclid(4096);
                let raw1 = qp0 + 16 * (x1 * h1 + x2 * h0);
                let qp1 = raw1.div_euclid(4096);
                let raw2 = qp1 + x2 * h1;
                let p3 = raw2.div_euclid(4096);
                qp0_col.push(qp0 as i64);
                qp1_col.push(qp1 as i64);
                p3_col.push(p3 as i64);
            }
            values.set(relation, c.p_advice[0], qp0_col)?;
            values.set(relation, c.p_advice[1], qp1_col)?;
            values.set(relation, c.p_advice[2], p3_col)?;
        }

        let es = self.es;
        let z: Vec<i128> = (0..size)
            .map(|i| {
                let (t, k) = (i >> ld, i & ((1 << ld) - 1));
                let e = ex(t);
                let h = if k < self.d { i128::from(gains[k]) } else { 0 };
                let q = x[i] * h * reciprocal[t];
                let sigma = i128::from(sign[i]) * (1 - 2 * i128::from(h < 0)) + i128::from(h < 0);
                let g = if e.valid { 1i128 << e.g.1 } else { 0 };
                let pos = i128::from(e.pos);
                (i128::from(y[i]) << es) - g * q + pos * (sigma - 1) * g + pos * (1 << (es - 1))
            })
            .collect();
        values.set(relation, c.output, y)?;
        set_limbs(relation, values, &c.z, &z, OUT_RADIX)?;
        // The chains read the input from the capture and not through `values`: the input is
        // a virtual column of the modules before this one, and reading it there would tie
        // this module's assignment to theirs (the layers are assigned beside each other).
        let input: Vec<i64> = x.iter().map(|&v| v as i64).collect();
        for chain in &c.chains {
            chain.assign_given(relation, values, None, &[(self.input, &input)])?;
        }
        Ok(())
    }
}

/// Set radix-`2^radix` limb columns of `v` (one value per index); the top limb keeps any excess.
fn set_limbs(
    relation: &Relation,
    values: &mut Values,
    columns: &[ColumnId],
    v: &[i128],
    radix: u8,
) -> Result<(), Violation> {
    let base = 1i128 << radix;
    let count = columns.len();
    for (i, &col) in columns.iter().enumerate() {
        if !matches!(relation.columns[col.0 as usize].kind, Kind::Virtual(_)) {
            let col_vals: Vec<i64> = v
                .iter()
                .map(|&x| {
                    let mut rem = x;
                    for _ in 0..i {
                        rem = rem.div_euclid(base);
                    }
                    if i + 1 == count {
                        rem as i64
                    } else {
                        rem.rem_euclid(base) as i64
                    }
                })
                .collect();
            values.set(relation, col, col_vals)?;
        }
    }
    Ok(())
}

/// Set byte-limb columns of `v` (one value per index); the top limb keeps any excess.
fn set_bytes(
    relation: &Relation,
    values: &mut Values,
    columns: &[ColumnId],
    v: &[i128],
) -> Result<(), Violation> {
    let split: Vec<Vec<i64>> = v.iter().map(|&x| bytes(x, columns.len())).collect();
    for (i, &col) in columns.iter().enumerate() {
        if !matches!(relation.columns[col.0 as usize].kind, Kind::Virtual(_)) {
            values.set(relation, col, split.iter().map(|b| b[i]).collect())?;
        }
    }
    Ok(())
}
