//! Causal attention of one layer (RFC-0026 §5 rows 6-9; RFC-0025 §2.4, RFC-0009 A4,
//! RFC-0004 A6, RFC-0021 §2.1).
//!
//! Inputs are the Q/K/V row conversions (E16-05 [`RowOutput`]: int8 codes, one scale
//! per row). Index layouts, low bits first: codes `(c, head, i)`, the score domain
//! `S = (j, head, i)`, the output domain `O = (c, head, i)` (the O-input row layout,
//! so head assembly is the identity), and `Ob = (c, head, i, b)` with `b` the
//! absolute 1024-key block in block mode. GQA reads K/V through the high
//! `log(g)` bits of `head` (`group = head / (h/g)`, `h/g` a power of two).
//!
//! - Row 6, scores: `dot = sum_c q*k` (matmul, shared group bits);
//!   `dot = (1-2sigma)*A` with byte limbs `A`; `W = sq*sk` in bytes on `(j,i)`; one
//!   chain `sum A_a*W_b*m_c*256^(a+b+c) + 2^(k-1) = Q*2^k + rho` (`e = -k < 0`, `rho`
//!   in `[0,2^k)` as bytes) or `= Q` (`e >= 0`); `score = (1-2sigma)*2^max(e,0)*Q`.
//! - Row 7, causal max over the public scope `causal(j,i) = [j <= i < n]`:
//!   `u = causal*(Mx - score) >= 0` (by the exp lookups), one-hot `h` with
//!   `sum_j h*causal = real(i)` (matmul onto the public `real`) and `h*u = 0`;
//!   `Mx*(1-real) = 0` pins padded rows.
//! - Row 8, exp (RFC-0021 §2.1): mode 0 looks up `(t, P)` with `t = -u`; modes 1/2
//!   split `u = 2^k*hi + lo`, look up `(hi, H)`, `(lo, L)`, and
//!   `H*L = (P - C)*2^E + rr` with `C = 0` (mode 1) or `(t, C)` looked up (mode 2).
//!   Mode 1 adds `slack = 2^B*causal - u >= 0` when the score bound admits `u > 2^B`.
//! - Row 9: the committed masked `Pm = causal*P` (a matmul has two factors);
//!   `Z = sum_j Pm` (matmul); `Pm*sv` in byte rows `p_b` (chain); `T_b = sum_j p_b*v`
//!   (one matmul per byte row, per key block); sign chain `sum 256^b T_b =
//!   (1-2sigma)*n` with byte limbs `n`. Block mode: `B = (1-2sigma)*R(n/2^c)`
//!   (int16) and `T = sum_b B` (matmul). Output `o = (1-2tau)*q`,
//!   `q = R(|T|*2^E2/Z)`, `E2 = fa - fv + c`, by the division chains
//!   `2^(E2'+1)*nh + bit + Z = 2*Z*q + r` and `real*(2Z-1) = r + s`, `r, s >= 0`
//!   (so `Z >= 1` on real rows); for `E2 < 0`, `|T| = nh*2^j + bit*2^(j-1) + nl`.
//!   `q*(1-real) = 0` pins padded rows.
//!
//! Output-uniqueness lemma A: `agents/reviews/e16-07-attention.md`.

use super::{bit_length, log2_ceil, r, signed_for, term, Builder, Chain, RowOutput, Unsupported};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_cqis::functions::Representation;
use stele_cqis::tables::Table as CqisTable;
use stele_ir::relation::{
    ColumnId, Compose, Invalid, Kind, Lookup, Matmul, Module, Relation, Table, Term, Values,
    Violation, Width, MAX_VARS, MAX_WIDTH_BITS,
};

/// Absolute key block of RFC-0025 §2.4 block mode.
const BLOCK_BITS: u8 = 10;

/// Plan data of one layer's attention (RFC-0025 §2.4, `Model` block parameters).
#[derive(Clone, Debug)]
pub struct AttentionPlan {
    /// Real tokens `n` (padded to `2^t`).
    pub rows: usize,
    pub heads: usize,
    pub groups: usize,
    pub head_width: usize,
    /// Row conversions of Q', K' and V (E16-05), per-row policies.
    pub query: RowOutput,
    pub key: RowOutput,
    pub value: RowOutput,
    /// `(m_score, e_score)`.
    pub score_multiplier: (u16, i8),
    /// `fq, fk, fv` (projection fractions) and `fa` (attention output fraction).
    pub fractions: [u8; 4],
    pub accumulation: u8,
    pub drop: u8,
    pub exponential: Representation,
}

/// Executor intermediates of one query position (E16-03 `witness::Attention`): the
/// score, block and output quotients and the exp output, layouts as there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PositionCapture {
    /// `[head][key]` int8 code dot, every key.
    pub dot: Vec<i64>,
    /// `[head][key]` score.
    pub score: Vec<i64>,
    /// `[head]` maximum over keys `<= i`.
    pub maximum: Vec<i64>,
    /// `[head][key <= i]` exp outputs `P`.
    pub exp: Vec<i64>,
    /// `[head]` `Z`.
    pub normaliser: Vec<u128>,
    /// `[head][lane][block]` rounded block sums (block mode only).
    pub block: Vec<i64>,
    /// `[head][lane]` `T`.
    pub total: Vec<i128>,
    /// `[head][lane]` int16 output.
    pub output: Vec<i64>,
}

impl From<&stele_cqis::execution::capture::Attention> for PositionCapture {
    /// The 1:1 map from witness capture (task E16-03).
    fn from(a: &stele_cqis::execution::capture::Attention) -> Self {
        Self {
            dot: a.dot.clone(),
            score: a.score.quotient.clone(),
            maximum: a.maximum.clone(),
            exp: a.exp.output.clone(),
            normaliser: a.normaliser.clone(),
            block: a.block.quotient.clone(),
            total: a.total.clone(),
            output: a.output.quotient.clone(),
        }
    }
}

/// What [`Attention::assign`] reads/// What [`Attention::assign`] reads: the Q/K/V codes and scales (the row
/// conversions' captures) and every position's attention intermediates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttentionCapture {
    /// `[row][lane]` codes and `[row]` scales of Q, K, V.
    pub codes: [Vec<Vec<i64>>; 3],
    pub scales: [Vec<u32>; 3],
    /// `[position]`.
    pub positions: Vec<PositionCapture>,
}

/// One looked-up exp component converted row for row (real rows only).
#[derive(Clone, Debug)]
struct ExpTable {
    table: Table,
    /// Input value of row 0 and the outputs in row order.
    first: i64,
    outputs: Vec<i64>,
}

impl ExpTable {
    fn new(component: stele_cqis::tables::Descriptor) -> Result<Self, Unsupported> {
        let generated = CqisTable::generate(component).map_err(|_| Unsupported::Policy)?;
        let n = component.shape().rows() as usize;
        let rows: Vec<Vec<i64>> = generated
            .entries()
            .chunks_exact(2)
            .take(n)
            .map(|row| vec![i64::from(row[0]), i64::from(row[1])])
            .collect();
        let width = |c: usize| {
            let (lo, hi) = rows.iter().fold((0i64, 0i64), |(lo, hi), row| {
                (lo.min(row[c]), hi.max(row[c]))
            });
            if lo < 0 {
                signed_for(u128::from(lo.unsigned_abs().max(hi.unsigned_abs())))
            } else {
                Width::unsigned(bit_length(hi as u128).max(1))
            }
        };
        let widths = vec![width(0), width(1)];
        // Inputs are consecutive (ascending for hi/lo, descending for direct/correction).
        let first = rows[0][0];
        let outputs = rows.iter().map(|row| row[1]).collect();
        Ok(Self {
            table: Table {
                name: format!("{}/{:?}", component.name(), component.parameters()),
                widths,
                rows,
            },
            first,
            outputs,
        })
    }

    fn at(&self, input: i64) -> i64 {
        self.outputs
            .get((input - self.first).unsigned_abs() as usize)
            .copied()
            .unwrap_or(0)
    }
}

/// Exp parameters (RFC-0021 §2.1) and the component tables in role order.
#[derive(Clone, Debug)]
struct Exp {
    mode: u8,
    domain: u8,
    output: u8,
    split: u8,
    fraction: u8,
    tables: Vec<ExpTable>,
}

impl Exp {
    fn new(r: &Representation) -> Result<Self, Unsupported> {
        let p = r.function().parameters();
        let components = r.components();
        let split = if r.mode() == 0 {
            0
        } else {
            components[0].parameters()[3]
        };
        let tables = components
            .iter()
            .map(|c| ExpTable::new(*c))
            .collect::<Result<Vec<_>, _>>()?;
        if r.mode() > 2 || tables.len() != [1, 2, 3][usize::from(r.mode())] {
            return Err(Unsupported::Policy);
        }
        Ok(Self {
            mode: r.mode(),
            domain: p[0],
            fraction: p[1],
            output: p[2],
            split,
            tables,
        })
    }

    /// `(hi, lo, H, L, C, rr, P)` of `t` (`C = 0` outside mode 2), as the executor.
    fn parts(&self, t: i64) -> [i64; 7] {
        if self.mode == 0 {
            return [0, 0, 0, 0, 0, 0, self.tables[0].at(t)];
        }
        let u = -t;
        let (hi, lo) = (u >> self.split, u & ((1 << self.split) - 1));
        let (h, l) = (self.tables[0].at(hi), self.tables[1].at(lo));
        let c = if self.mode == 2 {
            self.tables[2].at(t)
        } else {
            0
        };
        let product = (h * l) >> self.output;
        [
            hi,
            lo,
            h,
            l,
            c,
            h * l - (product << self.output),
            product + c,
        ]
    }
}

/// Bytes covering `bits` bits, the top one narrower.
fn byte_widths(bits: u8) -> Vec<Width> {
    let n = usize::from(bits.max(1)).div_ceil(8);
    (0..n)
        .map(|i| {
            Width::unsigned(if i + 1 == n {
                bits.max(1) - 8 * i as u8
            } else {
                8
            })
        })
        .collect()
}

/// A wide identity's positions, filled at bit offsets (radix 256 per [`Chain`]).
struct Positions(Vec<Vec<Term>>);

impl Positions {
    fn at(&mut self, bit: usize, coeff: i64, factors: Vec<stele_ir::relation::Ref>) {
        let k = bit / 8;
        if self.0.len() <= k {
            self.0.resize(k + 1, Vec::new());
        }
        self.0[k].push(term(coeff << (bit % 8), factors));
    }
}

/// A column wider than 16 bits: unsigned 16-bit low limb plus a high limb, composed.
#[derive(Clone, Copy, Debug)]
struct Wide {
    column: ColumnId,
    limbs: Option<(ColumnId, ColumnId)>,
}

fn wide(b: &mut Builder<'_>, name: &str, width: Width, log_len: u8) -> Wide {
    if width.bits <= 16 {
        return Wide {
            column: b.witness(name, width, log_len),
            limbs: None,
        };
    }
    let column = b.column(name, width, log_len);
    let high = Width {
        signed: width.signed,
        bits: width.bits - 16,
    };
    let lo = b.witness(&format!("{name}/lo"), Width::unsigned(16), log_len);
    let hi = b.witness(&format!("{name}/hi"), high, log_len);
    let compose_name = format!("{}/{name}", b.prefix());
    b.relation.composes.push(Compose {
        name: compose_name,
        column,
        limbs: vec![(lo, 0), (hi, 16)],
    });
    Wide {
        column,
        limbs: Some((lo, hi)),
    }
}

/// Fresh unsigned byte limbs of `bits` bits.
fn bytes(b: &mut Builder<'_>, name: &str, bits: u8, log_len: u8) -> Vec<ColumnId> {
    byte_widths(bits)
        .into_iter()
        .enumerate()
        .map(|(i, w)| b.witness(&format!("{name}/{i}"), w, log_len))
        .collect()
}

/// Composed byte limbs: a column (at most 30 bits) and its bytes.
fn composed(b: &mut Builder<'_>, name: &str, bits: u8, log_len: u8) -> (ColumnId, Vec<ColumnId>) {
    let column = b.column(name, Width::unsigned(bits), log_len);
    let limbs = bytes(b, &format!("{name}/byte"), bits, log_len);
    split_bytes(b, name, column, &limbs);
    (column, limbs)
}

/// `column = sum 256^i limbs[i]`.
fn split_bytes(b: &mut Builder<'_>, name: &str, column: ColumnId, limbs: &[ColumnId]) {
    let compose_name = format!("{}/{name}/bytes", b.prefix());
    b.relation.composes.push(Compose {
        name: compose_name,
        column,
        limbs: limbs
            .iter()
            .enumerate()
            .map(|(i, l)| (*l, 8 * i as u8))
            .collect(),
    });
}

/// A scale as product terms: `(bit offset, coefficient, column)`.
type Scale = Vec<(usize, i64, Option<ColumnId>)>;

/// Block mode: `(qB, rhoB bytes, B, T when kb > 0, tau, |T|)`.
type BlockColumns = (
    ColumnId,
    Vec<ColumnId>,
    ColumnId,
    Option<ColumnId>,
    ColumnId,
    Wide,
);

#[derive(Clone, Debug)]
struct Columns {
    dot: ColumnId,
    sign: ColumnId,
    magnitude: Vec<ColumnId>,
    weight: Vec<ColumnId>,
    quotient: (ColumnId, Vec<ColumnId>),
    remainder: Vec<ColumnId>,
    maximum: Wide,
    /// Mode 0/2: `t`; modes 1/2: `hi, lo, H, L, rr` (rr absent when `E = 0`);
    /// mode 2: `C`; mode 1: optional slack.
    t: Option<ColumnId>,
    split: Option<[ColumnId; 4]>,
    rr: Option<ColumnId>,
    correction: Option<ColumnId>,
    slack: Option<Wide>,
    exp: ColumnId,
    masked: ColumnId,
    hit: ColumnId,
    normaliser: ColumnId,
    value: Vec<ColumnId>,
    sums: Vec<ColumnId>,
    total_sign: ColumnId,
    total: Vec<ColumnId>,
    block: Option<BlockColumns>,
    /// `E2 < 0`: `(nh bytes, bit, nl bytes)`.
    shifted: Option<(Vec<ColumnId>, Option<ColumnId>, Vec<ColumnId>)>,
    z: Vec<ColumnId>,
    q: (ColumnId, Vec<ColumnId>),
    r: Vec<ColumnId>,
    s: Vec<ColumnId>,
    output: ColumnId,
    /// Wide identities by name.
    chains: Vec<(&'static str, Chain)>,
}

/// Attention of one layer (RFC-0026 §5 rows 6-9).
#[derive(Clone, Debug)]
pub struct Attention {
    prefix: String,
    plan: AttentionPlan,
    exp: Exp,
    columns: Option<Columns>,
}

/// Index bits of one layer: `(t, d, hb, rb, kb)`.
#[derive(Clone, Copy, Debug)]
struct Bits {
    t: u8,
    d: u8,
    hb: u8,
    rb: u8,
    kb: u8,
}

impl Bits {
    fn s(self) -> u8 {
        2 * self.t + self.hb
    }
    fn o(self) -> u8 {
        self.d + self.hb + self.t
    }
}

impl Attention {
    /// Rejects plans outside RFC-0026 §1.3 or the relation API: non-power-of-two head
    /// width or GQA ratio, grouped Q/K/V rows, exp domains past 30 bits, and identity
    /// domains past `MAX_VARS` (matmuls are split into row blocks, RFC-0026 A6).
    pub fn new(layer: usize, plan: AttentionPlan) -> Result<Self, Unsupported> {
        let (h, g, dh) = (plan.heads, plan.groups, plan.head_width);
        let shape = plan.rows > 0
            && h > 0
            && g > 0
            && h % g == 0
            && (h / g).is_power_of_two()
            && dh.is_power_of_two()
            && plan.accumulation <= 1
            && (plan.accumulation == 1 || plan.drop == 0);
        if !shape {
            return Err(Unsupported::Shape);
        }
        let t = log2_ceil(plan.rows);
        let d = dh.trailing_zeros() as u8;
        let rb = (h / g).trailing_zeros() as u8;
        let gb = log2_ceil(g);
        let rows_ok = |row: &RowOutput, lanes: u8| {
            row.log_rows == t
                && row.log_dimension == d + lanes
                && row.log_group == row.log_dimension
        };
        if !(rows_ok(&plan.query, gb + rb) && rows_ok(&plan.key, gb) && rows_ok(&plan.value, gb)) {
            return Err(Unsupported::Shape);
        }
        let exp = Exp::new(&plan.exponential)?;
        let this = Self {
            prefix: format!("L{layer}/attention"),
            plan,
            exp,
            columns: None,
        };
        let bits = this.bits();
        // Matmuls past MAX_VARS are split into row blocks (RFC-0026 A6); the identity
        // domains (scores and the block-mode values) must fit as they are.
        let identities = bits.s().max(bits.o() + bits.kb);
        if identities > MAX_VARS || this.score_bound().1 >= 1 << 28 {
            return Err(Unsupported::Domain);
        }
        if this.exp.mode == 1 && this.exp.domain + 1 > MAX_WIDTH_BITS {
            return Err(Unsupported::Domain);
        }
        Ok(this)
    }

    fn bits(&self) -> Bits {
        let p = &self.plan;
        let t = log2_ceil(p.rows);
        let rb = (p.heads / p.groups).trailing_zeros() as u8;
        Bits {
            t,
            d: p.head_width.trailing_zeros() as u8,
            hb: log2_ceil(p.groups) + rb,
            rb,
            kb: if p.accumulation == 1 {
                t.saturating_sub(BLOCK_BITS)
            } else {
                0
            },
        }
    }

    /// The score exponent `e = e_score - fq - fk + F`.
    fn exponent(&self) -> i32 {
        let p = &self.plan;
        i32::from(p.score_multiplier.1) - i32::from(p.fractions[0]) - i32::from(p.fractions[1])
            + i32::from(self.exp.fraction)
    }

    /// Largest scale of a row (`2^bits - 1` for a dynamic scale, as its bytes admit).
    fn scale_max(row: &RowOutput, relation: Option<&Relation>) -> u128 {
        match relation
            .and_then(|rel| rel.column(row.scale))
            .map(|c| &c.kind)
        {
            Some(Kind::Public(_)) => u128::from(row.scale_bound),
            _ => (1u128 << bit_length(u128::from(row.scale_bound))) - 1,
        }
    }

    /// `(|A| bound, Q bound)` from the dot width and scale bounds.
    fn score_bound(&self) -> (u128, u128) {
        let a = (128u128 * 128) << self.bits().d;
        let w = Self::scale_max(&self.plan.query, None) * Self::scale_max(&self.plan.key, None);
        let n = a * w * u128::from(self.plan.score_multiplier.0);
        let e = self.exponent();
        let q = if e >= 0 {
            n
        } else {
            (n + (1u128 << (-e - 1).min(126))) >> (-e).min(127)
        };
        (a, q << e.clamp(0, 60))
    }

    /// Output column (`T x h*dh`, int16), the O-input row conversion's input.
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }
}

/// `columns[i]` as a scale product term list.
fn scale_terms(row: &RowOutput, relation: &Relation) -> Scale {
    match relation.column(row.scale).map(|c| &c.kind) {
        Some(Kind::Public(_)) => (0..3)
            .map(|i| (8 * i, i64::from(row.scale_bound >> (8 * i)) & 255, None))
            .filter(|t| t.1 != 0)
            .collect(),
        _ => vec![(0, 1, Some(row.scale))],
    }
}

impl Module for Attention {
    type Capture = AttentionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let bits = self.bits();
        let Bits { t, d, hb, rb, kb } = bits;
        let (sd, od) = (bits.s(), bits.o());
        let obd = od + kb;
        let n = self.plan.rows;
        let sq = scale_terms(&self.plan.query, relation);
        let sk = scale_terms(&self.plan.key, relation);
        let sv = scale_terms(&self.plan.value, relation);
        let (amax, _) = self.score_bound();
        let smax_q = Self::scale_max(&self.plan.query, Some(relation));
        let smax_k = Self::scale_max(&self.plan.key, Some(relation));
        let smax_v = Self::scale_max(&self.plan.value, Some(relation));
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mut chains = Vec::new();

        // Domain reads.
        let s_all = |c: ColumnId| r(c, 0..sd);
        let s_ji = |c: ColumnId| r(c, (0..t).chain(t + hb..sd));
        let s_j = |c: ColumnId| r(c, 0..t);
        let s_hi = |c: ColumnId| r(c, t..sd);
        let causal: Vec<i64> = (0..1usize << (2 * t))
            .map(|x| {
                let (j, i) = (x & ((1 << t) - 1), x >> t);
                i64::from(j <= i && i < n)
            })
            .collect();
        let causal = b.public("causal", causal, Width::unsigned(1), 2 * t);
        let real = b.public(
            "real",
            (0..1usize << t).map(|i| i64::from(i < n)).collect(),
            Width::unsigned(1),
            t,
        );

        // Row 6: dot = sum_c q*k, with K read through the group bits of head.
        let worst = (128u128 * 128) << d;
        let dot = b.column("dot", signed_for(worst), sd);
        b.relation.add_matmul(Matmul {
            name: format!("{prefix}/dot"),
            free: sd,
            summed: d,
            out: s_all(dot),
            lhs: r(self.plan.query.codes, (sd..sd + d).chain(t..sd)),
            rhs: r(
                self.plan.key.codes,
                (sd..sd + d).chain(t + rb..t + hb).chain(0..t),
            ),
        });
        // dot = A - 2*sigma*A with A in bytes.
        let sign = b.witness("score/sign", Width::unsigned(1), sd);
        let magnitude = bytes(&mut b, "score/magnitude", bit_length(amax), sd);
        let mut terms = vec![term(1, vec![s_all(dot)])];
        for (i, a) in magnitude.iter().enumerate() {
            terms.push(term(-(1 << (8 * i)), vec![s_all(*a)]));
            terms.push(term(2 << (8 * i), vec![s_all(sign), s_all(*a)]));
        }
        b.identity("score/sign", sd, terms);

        // W = sq*sk in bytes on (j, i).
        let wbits = bit_length(smax_q * smax_k);
        let weight = bytes(&mut b, "score/scales", wbits, 2 * t);
        let mut positions = Positions(Vec::new());
        for &(oq, cq, fq) in &sq {
            for &(ok, ck, fk) in &sk {
                let factors = fq
                    .map(|c| r(c, t..2 * t))
                    .into_iter()
                    .chain(fk.map(|c| r(c, 0..t)))
                    .collect();
                positions.at(oq + ok, cq * ck, factors);
            }
        }
        for (i, w) in weight.iter().enumerate() {
            positions.at(8 * i, -1, vec![r(*w, 0..2 * t)]);
        }
        chains.push((
            "score/scales",
            Chain::declare(&mut b, "score/scales", 2 * t, 8, positions.0),
        ));

        // A*W*m + 2^(k-1) = Q*2^k + rho, or A*W*m = Q.
        let e = self.exponent();
        let m = self.plan.score_multiplier.0;
        let nmax = amax * ((1u128 << wbits) - 1) * u128::from(m);
        let qmax = if e >= 0 {
            nmax
        } else {
            (nmax + (1u128 << (-e - 1))) >> (-e)
        };
        let quotient = composed(&mut b, "score/quotient", bit_length(qmax).max(1), sd);
        let mut positions = Positions(Vec::new());
        for (ia, a) in magnitude.iter().enumerate() {
            for (iw, w) in weight.iter().enumerate() {
                for c in 0..2 {
                    let mc = i64::from(m >> (8 * c)) & 255;
                    if mc != 0 {
                        positions.at(8 * (ia + iw + c), mc, vec![s_all(*a), s_ji(*w)]);
                    }
                }
            }
        }
        let k = if e < 0 { (-e) as usize } else { 0 };
        let mut remainder = Vec::new();
        if k > 0 {
            positions.at(k - 1, 1, vec![]);
            remainder = bytes(&mut b, "score/remainder", k as u8, sd);
            for (i, rho) in remainder.iter().enumerate() {
                positions.at(8 * i, -1, vec![s_all(*rho)]);
            }
        }
        for (i, q) in quotient.1.iter().enumerate() {
            positions.at(k + 8 * i, -1, vec![s_all(*q)]);
        }
        chains.push((
            "score/round",
            Chain::declare(&mut b, "score/round", sd, 8, positions.0),
        ));
        let up = 1i64 << e.max(0);
        let smax = qmax << e.max(0);
        let quotient_ref = s_all(quotient.0);
        // causal*score as terms with the given coefficient.
        let score_terms = |coeff: i64| {
            vec![
                term(coeff * up, vec![s_ji(causal), quotient_ref.clone()]),
                term(
                    -2 * coeff * up,
                    vec![s_ji(causal), s_all(sign), quotient_ref.clone()],
                ),
            ]
        };

        // Row 7: Mx, pinned to 0 on padded rows.
        let maximum = wide(&mut b, "maximum", signed_for(smax), t + hb);
        b.identity(
            "maximum/padding",
            t + hb,
            vec![
                term(1, vec![r(maximum.column, 0..t + hb)]),
                term(-1, vec![r(maximum.column, 0..t + hb), r(real, hb..t + hb)]),
            ],
        );

        // Row 8: exp lookups.
        let exp = self.exp.clone();
        let table_ids: Vec<_> = exp
            .tables
            .iter()
            .map(|e| b.relation.add_table(e.table.clone()))
            .collect();
        let widths = |i: usize| (exp.tables[i].table.widths[0], exp.tables[i].table.widths[1]);
        let lookup = |b: &mut Builder<'_>, name: &str, tuple: Vec<ColumnId>, table| {
            b.relation.lookups.push(Lookup {
                name: format!("{prefix}/{name}"),
                vars: sd,
                selector: None,
                tuple: tuple.into_iter().map(s_all).collect(),
                table,
            });
        };
        let pwidth = Width::unsigned(exp.output + 1);
        let (mut t_col, mut split, mut rr, mut correction, mut slack) =
            (None, None, None, None, None);
        let pexp;
        let mut u_terms: Vec<Term> = Vec::new();
        if exp.mode != 1 {
            let index = if exp.mode == 0 { 0 } else { 2 };
            let (wi, wo) = widths(index);
            let tc = b.column("exp/t", wi, sd);
            let out = b.column(if exp.mode == 0 { "exp/p" } else { "exp/c" }, wo, sd);
            lookup(
                &mut b,
                if exp.mode == 0 {
                    "exp/direct"
                } else {
                    "exp/correction"
                },
                vec![tc, out],
                table_ids[index],
            );
            // t = causal*(score - Mx).
            let mut terms = vec![
                term(-1, vec![s_all(tc)]),
                term(-1, vec![s_ji(causal), s_hi(maximum.column)]),
            ];
            terms.extend(score_terms(1));
            b.identity("exp/difference", sd, terms);
            u_terms.push(term(-1, vec![s_all(tc)]));
            t_col = Some(tc);
            if exp.mode == 0 {
                pexp = out;
            } else {
                correction = Some(out);
                pexp = b.witness("exp/p", pwidth, sd);
            }
        } else {
            pexp = b.witness("exp/p", pwidth, sd);
        }
        if exp.mode != 0 {
            let (whi, wh) = widths(0);
            let (wlo, wl) = widths(1);
            let hi = b.column("exp/hi", whi, sd);
            let high = b.column("exp/high", wh, sd);
            let lo = b.column("exp/lo", wlo, sd);
            let low = b.column("exp/low", wl, sd);
            lookup(&mut b, "exp/hi", vec![hi, high], table_ids[0]);
            lookup(&mut b, "exp/lo", vec![lo, low], table_ids[1]);
            let k = 1i64 << exp.split;
            let u = vec![term(k, vec![s_all(hi)]), term(1, vec![s_all(lo)])];
            if let Some(tc) = t_col {
                // t + 2^k*hi + lo = 0.
                let mut terms = u.clone();
                terms.push(term(1, vec![s_all(tc)]));
                b.identity("exp/split", sd, terms);
            } else {
                // 2^k*hi + lo = causal*(Mx - score).
                let mut terms = u.clone();
                terms.push(term(-1, vec![s_ji(causal), s_hi(maximum.column)]));
                terms.extend(score_terms(1));
                b.identity("exp/difference", sd, terms);
                u_terms = u.clone();
                // slack = 2^B*causal - u >= 0 when u could exceed 2^B.
                if 2 * smax > 1u128 << exp.domain {
                    let sl = wide(&mut b, "exp/slack", Width::unsigned(exp.domain + 1), sd);
                    let mut terms = vec![
                        term(1, vec![s_all(sl.column)]),
                        term(-(1 << exp.domain), vec![s_ji(causal)]),
                    ];
                    terms.extend(u.clone());
                    b.identity("exp/slack", sd, terms);
                    slack = Some(sl);
                }
            }
            // H*L = (P - C)*2^E + rr.
            let mut terms = vec![
                term(1, vec![s_all(high), s_all(low)]),
                term(-(1 << exp.output), vec![s_all(pexp)]),
            ];
            if let Some(c) = correction {
                terms.push(term(1 << exp.output, vec![s_all(c)]));
            }
            if exp.output > 0 {
                let rem = b.witness("exp/rr", Width::unsigned(exp.output), sd);
                terms.push(term(-1, vec![s_all(rem)]));
                rr = Some(rem);
            }
            b.identity("exp/product", sd, terms);
            split = Some([hi, lo, high, low]);
        }

        // Attained maximum: sum_j h*causal = real, h*u = 0.
        let hit = b.witness("maximum/hit", Width::unsigned(1), sd);
        let hb_t = hb + t;
        b.relation.add_matmul(Matmul {
            name: format!("{prefix}/maximum/one-hot"),
            free: hb_t,
            summed: t,
            out: r(real, hb..hb_t),
            lhs: r(hit, (hb_t..hb_t + t).chain(0..hb_t)),
            rhs: r(causal, (hb_t..hb_t + t).chain(hb..hb_t)),
        });
        b.identity(
            "maximum/attained",
            sd,
            u_terms
                .iter()
                .map(|u| {
                    let mut f = u.factors.clone();
                    f.push(s_all(hit));
                    term(u.coeff, f)
                })
                .collect(),
        );

        // Row 9: Pm = causal*P; Z = sum_j Pm.
        let masked = b.witness("exp/masked", pwidth, sd);
        b.identity(
            "exp/masked",
            sd,
            vec![
                term(1, vec![s_all(masked)]),
                term(-1, vec![s_ji(causal), s_all(pexp)]),
            ],
        );
        let pmax = (1u128 << pwidth.bits) - 1;
        let normaliser = b.column("normaliser", signed_for(pmax << t), hb_t);
        b.relation.add_matmul(Matmul {
            name: format!("{prefix}/normaliser"),
            free: hb_t,
            summed: t,
            out: r(normaliser, 0..hb_t),
            lhs: r(masked, (hb_t..hb_t + t).chain(0..hb_t)),
            rhs: r(causal, (hb_t..hb_t + t).chain(hb..hb_t)),
        });
        // Pm*sv in byte rows.
        let value = bytes(&mut b, "value/weight", bit_length(pmax * smax_v), sd);
        let mut positions = Positions(Vec::new());
        for &(o, c, f) in &sv {
            let mut factors = vec![s_all(masked)];
            factors.extend(f.map(s_j));
            positions.at(o, c, factors);
        }
        for (i, p) in value.iter().enumerate() {
            positions.at(8 * i, -1, vec![s_all(*p)]);
        }
        chains.push((
            "value/weight",
            Chain::declare(&mut b, "value/weight", sd, 8, positions.0),
        ));
        // T_b = sum_o p_b(i, head, (o, blk)) * v((o, blk), group, c) on Ob.
        let summed = t - kb;
        let key: Vec<u8> = (obd..obd + summed).chain(od..obd).collect();
        let mut sums = Vec::new();
        let mut xmax = 0u128;
        for (i, p) in value.iter().enumerate() {
            let pw = b.relation.columns[p.0 as usize].width.magnitude();
            let worst = (pw * 128) << summed;
            xmax += worst << (8 * i);
            let sum = b.column(&format!("value/sum/{i}"), signed_for(worst), obd);
            b.relation.add_matmul(Matmul {
                name: format!("{prefix}/value/sum/{i}"),
                free: obd,
                summed,
                out: r(sum, 0..obd),
                lhs: r(*p, key.iter().copied().chain(d..od)),
                rhs: r(
                    self.plan.value.codes,
                    (0..d).chain(d + rb..d + hb).chain(key.iter().copied()),
                ),
            });
            sums.push(sum);
        }
        // sum 256^b T_b = (1 - 2 sigma) * n.
        let total_sign = b.witness("total/sign", Width::unsigned(1), obd);
        let total = bytes(&mut b, "total/magnitude", bit_length(xmax), obd);
        let mut positions = Positions(Vec::new());
        for (i, s) in sums.iter().enumerate() {
            positions.at(8 * i, 1, vec![r(*s, 0..obd)]);
        }
        for (i, nb) in total.iter().enumerate() {
            positions.at(8 * i, -1, vec![r(*nb, 0..obd)]);
            positions.at(8 * i, 2, vec![r(total_sign, 0..obd), r(*nb, 0..obd)]);
        }
        chains.push((
            "total/sign",
            Chain::declare(&mut b, "total/sign", obd, 8, positions.0),
        ));

        // Numerator |T| for the output division: atoms at bit 0 and its bound.
        let o_all = |c: ColumnId| r(c, 0..od);
        let (numerator, nmax, tau, block): (Vec<(usize, ColumnId)>, u128, ColumnId, _) =
            if self.plan.accumulation == 1 {
                let c = usize::from(self.plan.drop);
                let qb = b.witness("block/quotient", Width::unsigned(16), obd);
                let mut positions = Positions(Vec::new());
                for (i, nb) in total.iter().enumerate() {
                    positions.at(8 * i, 1, vec![r(*nb, 0..obd)]);
                }
                let rho = if c > 0 {
                    positions.at(c - 1, 1, vec![]);
                    bytes(&mut b, "block/remainder", c as u8, obd)
                } else {
                    Vec::new()
                };
                for (i, rb) in rho.iter().enumerate() {
                    positions.at(8 * i, -1, vec![r(*rb, 0..obd)]);
                }
                positions.at(c, -1, vec![r(qb, 0..obd)]);
                chains.push((
                    "block/round",
                    Chain::declare(&mut b, "block/round", obd, 8, positions.0),
                ));
                let blk = b.witness("block", Width::signed(16), obd);
                b.identity(
                    "block",
                    obd,
                    vec![
                        term(1, vec![r(blk, 0..obd)]),
                        term(-1, vec![r(qb, 0..obd)]),
                        term(2, vec![r(total_sign, 0..obd), r(qb, 0..obd)]),
                    ],
                );
                let tmax = 32768u128 << kb;
                let tsum = (kb > 0).then(|| {
                    let ones = b.public("block/ones", vec![1; 1 << kb], Width::unsigned(1), kb);
                    let ts = b.column("block/total", signed_for(tmax), od);
                    b.relation.add_matmul(Matmul {
                        name: format!("{prefix}/block/total"),
                        free: od,
                        summed: kb,
                        out: o_all(ts),
                        lhs: r(blk, 0..obd),
                        rhs: r(ones, od..obd),
                    });
                    ts
                });
                let tcol = tsum.unwrap_or(blk);
                let tau = b.witness("block/sign", Width::unsigned(1), od);
                let nt = wide(
                    &mut b,
                    "block/magnitude",
                    Width::unsigned(bit_length(tmax)),
                    od,
                );
                b.identity(
                    "block/sign",
                    od,
                    vec![
                        term(1, vec![o_all(tcol)]),
                        term(-1, vec![o_all(nt.column)]),
                        term(2, vec![o_all(tau), o_all(nt.column)]),
                    ],
                );
                (
                    vec![(0, nt.column)],
                    tmax,
                    tau,
                    Some((qb, rho, blk, tsum, tau, nt)),
                )
            } else {
                (
                    total.iter().enumerate().map(|(i, c)| (8 * i, *c)).collect(),
                    xmax,
                    total_sign,
                    None,
                )
            };

        // Output division on O.
        let e2 = i32::from(self.plan.fractions[3]) - i32::from(self.plan.fractions[2])
            + i32::from(self.plan.drop);
        let nbits = usize::from(bit_length(nmax));
        let (num, shifted): (Vec<(usize, ColumnId)>, _) = if e2 < 0 {
            let j = (-e2) as usize;
            let mut positions = Positions(Vec::new());
            for &(o, c) in &numerator {
                positions.at(o, 1, vec![o_all(c)]);
            }
            let nh = if nbits > j {
                bytes(&mut b, "output/high", (nbits - j) as u8, od)
            } else {
                Vec::new()
            };
            let bit = (nbits >= j).then(|| b.witness("output/bit", Width::unsigned(1), od));
            let nl = if j >= 2 {
                bytes(&mut b, "output/low", (j - 1).min(nbits).max(1) as u8, od)
            } else {
                Vec::new()
            };
            for (i, c) in nh.iter().enumerate() {
                positions.at(j + 8 * i, -1, vec![o_all(*c)]);
            }
            if let Some(bit) = bit {
                positions.at(j - 1, -1, vec![o_all(bit)]);
            }
            for (i, c) in nl.iter().enumerate() {
                positions.at(8 * i, -1, vec![o_all(*c)]);
            }
            chains.push((
                "output/split",
                Chain::declare(&mut b, "output/split", od, 8, positions.0),
            ));
            (
                nh.iter().enumerate().map(|(i, c)| (8 * i, *c)).collect(),
                Some((nh, bit, nl)),
            )
        } else {
            (numerator, None)
        };
        let up2 = e2.max(0) as usize + 1;
        let zmax = pmax << t;
        let z = bytes(&mut b, "normaliser/byte", bit_length(zmax), hb_t);
        split_bytes(&mut b, "normaliser", normaliser, &z);
        let q = composed(&mut b, "output/quotient", 16, od);
        let rbits = bit_length(2 * zmax);
        let rem = bytes(&mut b, "output/remainder", rbits, od);
        let spare = bytes(&mut b, "output/spare", rbits, od);
        let o_z = |c: ColumnId| r(c, d..od);
        let o_real = r(real, d + hb..od);
        let mut positions = Positions(Vec::new());
        for &(o, c) in &num {
            positions.at(o + up2, 1, vec![o_all(c)]);
        }
        if let Some((_, Some(bit), _)) = &shifted {
            positions.at(0, 1, vec![o_all(*bit)]);
        }
        for (i, zb) in z.iter().enumerate() {
            positions.at(8 * i, 1, vec![o_z(*zb)]);
            for (l, qb) in q.1.iter().enumerate() {
                positions.at(8 * (i + l), -2, vec![o_z(*zb), o_all(*qb)]);
            }
        }
        for (i, c) in rem.iter().enumerate() {
            positions.at(8 * i, -1, vec![o_all(*c)]);
        }
        chains.push((
            "output/division",
            Chain::declare(&mut b, "output/division", od, 8, positions.0),
        ));
        // real*(2Z - 1) = r + s.
        let mut positions = Positions(Vec::new());
        for (i, zb) in z.iter().enumerate() {
            positions.at(8 * i + 1, 1, vec![o_real.clone(), o_z(*zb)]);
        }
        positions.at(0, -1, vec![o_real.clone()]);
        for (i, c) in rem.iter().enumerate() {
            positions.at(8 * i, -1, vec![o_all(*c)]);
        }
        for (i, c) in spare.iter().enumerate() {
            positions.at(8 * i, -1, vec![o_all(*c)]);
        }
        chains.push((
            "output/spare",
            Chain::declare(&mut b, "output/spare", od, 8, positions.0),
        ));
        b.identity(
            "output/padding",
            od,
            vec![
                term(1, vec![o_all(q.0)]),
                term(-1, vec![o_all(q.0), o_real.clone()]),
            ],
        );
        let output = b.witness("output", Width::signed(16), od);
        b.identity(
            "output",
            od,
            vec![
                term(1, vec![o_all(output)]),
                term(-1, vec![o_all(q.0)]),
                term(2, vec![o_all(tau), o_all(q.0)]),
            ],
        );
        self.columns = Some(Columns {
            dot,
            sign,
            magnitude,
            weight,
            quotient,
            remainder,
            maximum,
            t: t_col,
            split,
            rr,
            correction,
            slack,
            exp: pexp,
            masked,
            hit,
            normaliser,
            value,
            sums,
            total_sign,
            total,
            block,
            shifted,
            z,
            q,
            r: rem,
            s: spare,
            output,
            chains,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &AttentionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(self.plan.query.codes))?;
        let p = &self.plan;
        let bits = self.bits();
        let Bits { t, d, hb, rb, kb } = bits;
        let (n, h, dh) = (p.rows, p.heads, p.head_width);
        let rows = |k: usize, width: usize| {
            capture.codes[k].len() == n
                && capture.scales[k].len() == n
                && capture.codes[k].iter().all(|row| row.len() == width)
        };
        let ok = rows(0, h * dh)
            && rows(1, p.groups * dh)
            && rows(2, p.groups * dh)
            && capture.positions.len() == n;
        if !ok {
            return Err(Invalid::Column(c.output).into());
        }
        let scale = |k: usize, row: &RowOutput, i: usize| -> i128 {
            match relation.column(row.scale).map(|col| &col.kind) {
                Some(Kind::Public(v)) => i128::from(v[i]),
                _ if i < n => i128::from(capture.scales[k][i]),
                _ => 0,
            }
        };
        let code = |k: usize, i: usize, lane: usize| -> i64 {
            capture.codes[k]
                .get(i)
                .and_then(|row| row.get(lane))
                .copied()
                .unwrap_or(0)
        };
        let (sd, od) = (bits.s(), bits.o());
        let obd = od + kb;
        let mask = |bits: u8| (1usize << bits) - 1;
        let e = self.exponent();
        let k = (-e).max(0) as u32;
        let m = i128::from(p.score_multiplier.0);
        let exp = &self.exp;
        let mut set = |id: ColumnId, v: Vec<i64>| -> Result<(), Violation> {
            values.set(relation, id, v).map_err(Violation::from)
        };
        let set_bytes = |v: &[i128], ids: &[ColumnId]| -> Vec<Vec<i64>> {
            let last = ids.len() - 1;
            (0..ids.len())
                .map(|i| {
                    v.iter()
                        .map(|x| {
                            let y = x >> (8 * i);
                            (if i == last { y } else { y & 255 }) as i64
                        })
                        .collect()
                })
                .collect()
        };
        let put_bytes = |set: &mut dyn FnMut(ColumnId, Vec<i64>) -> Result<(), Violation>,
                         v: &[i128],
                         ids: &[ColumnId]|
         -> Result<(), Violation> {
            for (id, column) in ids.iter().zip(set_bytes(v, ids)) {
                set(*id, column)?;
            }
            Ok(())
        };
        let put_wide = |set: &mut dyn FnMut(ColumnId, Vec<i64>) -> Result<(), Violation>,
                        w: Wide,
                        v: Vec<i64>|
         -> Result<(), Violation> {
            if let Some((lo, hi)) = w.limbs {
                set(lo, v.iter().map(|x| x.rem_euclid(1 << 16)).collect())?;
                set(hi, v.iter().map(|x| x.div_euclid(1 << 16)).collect())?;
            }
            set(w.column, v)
        };

        // Score domain S = (j, head, i).
        let size = 1usize << sd;
        let decode = |x: usize| (x & mask(t), (x >> t) & mask(hb), x >> (t + hb));
        let causal = |j: usize, i: usize| j <= i && i < n;
        let mut dot = vec![0i64; size];
        let mut score = vec![0i64; size];
        for (x, (dv, sv)) in dot.iter_mut().zip(score.iter_mut()).enumerate() {
            let (j, head, i) = decode(x);
            if i < n && j < n && head < h {
                *dv = capture.positions[i].dot[head * n + j];
                *sv = capture.positions[i].score[head * n + j];
            }
        }
        let wv: Vec<i128> = (0..1usize << (2 * t))
            .map(|x| scale(0, &p.query, x >> t) * scale(1, &p.key, x & mask(t)))
            .collect();
        let up = 1i64 << e.max(0);
        let quotient: Vec<i128> = score.iter().map(|s| i128::from(s.abs() / up)).collect();
        let magnitude: Vec<i128> = dot.iter().map(|v| i128::from(v.abs())).collect();
        let remainder: Vec<i128> = (0..size)
            .map(|x| {
                let (j, _, i) = decode(x);
                let product = magnitude[x] * wv[(i << t) | j] * m;
                product + (1i128 << k) / 2 - (quotient[x] << k)
            })
            .collect();
        set(c.dot, dot.clone())?;
        set(c.sign, dot.iter().map(|v| i64::from(*v < 0)).collect())?;
        put_bytes(&mut set, &magnitude, &c.magnitude)?;
        put_bytes(&mut set, &wv, &c.weight)?;
        set(c.quotient.0, quotient.iter().map(|v| *v as i64).collect())?;
        put_bytes(&mut set, &quotient, &c.quotient.1)?;
        if !c.remainder.is_empty() {
            put_bytes(&mut set, &remainder, &c.remainder)?;
        }

        // Maximum per (head, i); padded heads see zero scores.
        let hsize = 1usize << (t + hb);
        let maximum: Vec<i64> = (0..hsize)
            .map(|y| {
                let (head, i) = (y & mask(hb), y >> hb);
                if i >= n {
                    0
                } else if head < h {
                    capture.positions[i].maximum[head]
                } else {
                    (0..=i).map(|j| score[(y << t) | j]).max().unwrap_or(0)
                }
            })
            .collect();
        put_wide(&mut set, c.maximum, maximum.clone())?;
        // Exp parts and the captured P on scope.
        let mut parts = vec![[0i64; 7]; size];
        let mut tv = vec![0i64; size];
        let mut hit = vec![0i64; size];
        let mut pm = vec![0i64; size];
        for x in 0..size {
            let (j, head, i) = decode(x);
            let tx = if causal(j, i) {
                score[x] - maximum[x >> t]
            } else {
                0
            };
            tv[x] = tx;
            let mut part = exp.parts(tx);
            if causal(j, i) && head < h {
                let captured = capture.positions[i].exp[head * (i + 1) + j];
                // rr follows the captured P, so a wrong P fails a range or lookup.
                part[5] += (part[6] - captured) << exp.output;
                part[6] = captured;
            }
            parts[x] = part;
            if causal(j, i) {
                pm[x] = part[6];
            }
        }
        for y in 0..hsize {
            if (y >> hb) < n {
                if let Some(j) =
                    (0..1usize << t).find(|&j| causal(j, y >> hb) && tv[(y << t) | j] == 0)
                {
                    hit[(y << t) | j] = 1;
                }
            }
        }
        let column = |i: usize| parts.iter().map(|p| p[i]).collect::<Vec<_>>();
        if let Some(tc) = c.t {
            set(tc, tv.clone())?;
        }
        if let Some([hi, lo, high, low]) = c.split {
            set(hi, column(0))?;
            set(lo, column(1))?;
            set(high, column(2))?;
            set(low, column(3))?;
        }
        if let Some(cc) = c.correction {
            set(cc, column(4))?;
        }
        if let Some(rr) = c.rr {
            set(rr, column(5))?;
        }
        set(c.exp, column(6))?;
        if let Some(sl) = c.slack {
            let v = (0..size)
                .map(|x| {
                    let (j, _, i) = decode(x);
                    if causal(j, i) {
                        (1i64 << exp.domain) + tv[x]
                    } else {
                        0
                    }
                })
                .collect();
            put_wide(&mut set, sl, v)?;
        }
        set(c.hit, hit)?;
        set(c.masked, pm.clone())?;

        // Z per (head, i): captured on real heads.
        let normaliser: Vec<i64> = (0..hsize)
            .map(|y| {
                let (head, i) = (y & mask(hb), y >> hb);
                if i < n && head < h {
                    capture.positions[i].normaliser[head] as i64
                } else {
                    (0..1usize << t).map(|j| pm[(y << t) | j]).sum()
                }
            })
            .collect();
        set(c.normaliser, normaliser.clone())?;
        put_bytes(
            &mut set,
            &normaliser
                .iter()
                .map(|v| i128::from(*v))
                .collect::<Vec<_>>(),
            &c.z,
        )?;
        // Pm*sv bytes and the per-byte, per-block sums.
        let weighted: Vec<i128> = (0..size)
            .map(|x| i128::from(pm[x]) * scale(2, &p.value, x & mask(t)))
            .collect();
        put_bytes(&mut set, &weighted, &c.value)?;
        let byte_rows = set_bytes(&weighted, &c.value);
        let osize = 1usize << obd;
        let summed = t - kb;
        let mut x_total = vec![0i128; osize];
        for (bi, (id, row)) in c.sums.iter().zip(&byte_rows).enumerate() {
            let column: Vec<i64> = (0..osize)
                .map(|x| {
                    let (lane, head, i, blk) = (
                        x & mask(d),
                        (x >> d) & mask(hb),
                        (x >> (d + hb)) & mask(t),
                        x >> od,
                    );
                    let group = head >> rb;
                    (0..1usize << summed)
                        .map(|o| {
                            let j = (blk << summed) | o;
                            row[(i << (t + hb)) | (head << t) | j] * code(2, j, (group << d) | lane)
                        })
                        .sum()
                })
                .collect();
            for (xt, v) in x_total.iter_mut().zip(&column) {
                *xt += i128::from(*v) << (8 * bi);
            }
            set(*id, column)?;
        }
        set(
            c.total_sign,
            x_total.iter().map(|v| i64::from(*v < 0)).collect(),
        )?;
        put_bytes(
            &mut set,
            &x_total.iter().map(|v| v.abs()).collect::<Vec<_>>(),
            &c.total,
        )?;
        let real_o = |x: usize| (x >> (d + hb)) & mask(t) < n;
        let lane_real = |x: usize| (x & mask(d)) < dh && ((x >> d) & mask(hb)) < h;
        let osize0 = 1usize << od;
        let numerator: Vec<i128> = if let Some((qb, rho, blk, tsum, tau, nt)) = &c.block {
            let (qb, blk, tsum, tau, nt) = (*qb, *blk, *tsum, *tau, *nt);
            let cdrop = u32::from(p.drop);
            let blocks: Vec<i64> = (0..osize)
                .map(|x| {
                    let (i, bk) = ((x >> (d + hb)) & mask(t), x >> od);
                    let (lane, head) = (x & mask(d), (x >> d) & mask(hb));
                    let nblocks = n.div_ceil(1 << BLOCK_BITS);
                    if real_o(x) && lane_real(x) && bk < nblocks {
                        capture.positions[i].block[(head * dh + lane) * nblocks + bk]
                    } else {
                        let v = x_total[x];
                        let q = (v.abs() + ((1i128 << cdrop) >> 1)) >> cdrop;
                        (v.signum() * q) as i64
                    }
                })
                .collect();
            let qv: Vec<i128> = blocks.iter().map(|v| i128::from(v.abs())).collect();
            set(qb, qv.iter().map(|v| *v as i64).collect())?;
            if !rho.is_empty() {
                let rv: Vec<i128> = (0..osize)
                    .map(|x| x_total[x].abs() + ((1i128 << cdrop) >> 1) - (qv[x] << cdrop))
                    .collect();
                put_bytes(&mut set, &rv, rho)?;
            }
            set(blk, blocks.clone())?;
            let totals: Vec<i64> = (0..osize0)
                .map(|x| (0..1usize << kb).map(|bk| blocks[(bk << od) | x]).sum())
                .collect();
            if let Some(ts) = tsum {
                set(ts, totals.clone())?;
            }
            set(tau, totals.iter().map(|v| i64::from(*v < 0)).collect())?;
            put_wide(&mut set, nt, totals.iter().map(|v| v.abs()).collect())?;
            totals.iter().map(|v| i128::from(v.abs())).collect()
        } else {
            x_total.iter().map(|v| v.abs()).collect()
        };
        // Output division.
        let e2 = i32::from(p.fractions[3]) - i32::from(p.fractions[2]) + i32::from(p.drop);
        let output: Vec<i64> = (0..osize0)
            .map(|x| {
                let (lane, head, i) = (x & mask(d), (x >> d) & mask(hb), x >> (d + hb));
                if i < n && lane_real(x) {
                    capture.positions[i].output[head * dh + lane]
                } else {
                    0
                }
            })
            .collect();
        let qv: Vec<i128> = output.iter().map(|v| i128::from(v.abs())).collect();
        let zf = |x: usize| i128::from(normaliser[x >> d]);
        let nh: Vec<i128> = if let Some((nh_ids, bit, nl)) = &c.shifted {
            let j = (-e2) as u32;
            let nh: Vec<i128> = numerator.iter().map(|v| v >> j).collect();
            if !nh_ids.is_empty() {
                put_bytes(&mut set, &nh, nh_ids)?;
            }
            if let Some(bit) = bit {
                set(
                    *bit,
                    numerator
                        .iter()
                        .map(|v| ((v >> (j - 1)) & 1) as i64)
                        .collect(),
                )?;
            }
            if !nl.is_empty() {
                let low: Vec<i128> = numerator
                    .iter()
                    .map(|v| v & ((1i128 << (j - 1)) - 1))
                    .collect();
                put_bytes(&mut set, &low, nl)?;
            }
            nh.iter()
                .zip(&numerator)
                .map(|(h, v)| 2 * h + ((v >> (j - 1)) & 1))
                .collect()
        } else {
            numerator.iter().map(|v| v << (e2 + 1)).collect()
        };
        let rv: Vec<i128> = (0..osize0)
            .map(|x| nh[x] + zf(x) - 2 * zf(x) * qv[x])
            .collect();
        let spare: Vec<i128> = (0..osize0)
            .map(|x| if real_o(x) { 2 * zf(x) - 1 } else { 0 } - rv[x])
            .collect();
        set(c.q.0, qv.iter().map(|v| *v as i64).collect())?;
        put_bytes(&mut set, &qv, &c.q.1)?;
        put_bytes(&mut set, &rv, &c.r)?;
        put_bytes(&mut set, &spare, &c.s)?;
        set(c.output, output)?;
        for (_, chain) in &c.chains {
            chain.assign_around(relation, values, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
