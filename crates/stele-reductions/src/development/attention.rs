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
//!
//! Committed witness advice columns (RFC-0028 §1.2):
//! - Score: mixed-radix score advice (`score/w1`, optional `score/mc0`, `score/wm2` on `(j,i)`;
//!   `score/d1`, `score/sign`, `score/c0`, optional `score/c1` on `S`), or general fallback
//!   carries/bytes when mixed-radix does not apply. Contraction `dot` and `score` are virtual.
//! - Max / exp: `maximum`, `maximum/lo`, `maximum/hi` (row `(h,i)`), `maximum/hit`, `exp/p`
//!   (plus `exp/hi`, `exp/lo`, `exp/h`, `exp/l`, `exp/c` in modes 1/2). `u`, `Pm`, and `Z`
//!   are virtual.
//! - Value / division: `value/sv_v/1..`, `value/sum_hi/*` (radix-16 `total/sign` path),
//!   `total/sign`, `total/magnitude/*`, `total/sign/carry*`, `normaliser/byte/1..` (radix-12
//!   when `zmax >= 2^16` and `0 <= E2 <= 3`), `output/quotient/byte/*`,
//!   `output/division/carry*`, `output/spare/carry*` (plus block advice in block mode).
//!   Contractions `value/sum/*`, low bytes, remainders, spares, and final `output` are virtual.
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
    ColumnId, Compose, Def, Invalid, Kind, Lookup, Matmul, Module, Relation, Table, Term, Values,
    Violation, Width, HALF_MODULUS, MAX_VARS, MAX_WIDTH_BITS,
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
        self.at_radix(bit, 8, coeff, factors);
    }

    fn at_radix(
        &mut self,
        bit: usize,
        radix: u8,
        coeff: i64,
        factors: Vec<stele_ir::relation::Ref>,
    ) {
        let r = usize::from(radix);
        let k = bit / r;
        if self.0.len() <= k {
            self.0.resize(k + 1, Vec::new());
        }
        self.0[k].push(term(coeff << (bit % r), factors));
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

/// Mixed-radix plan for Row 6 signed score rounding on `S` (RFC-0028 §1.2).
#[derive(Clone, Copy, Debug)]
struct MixedScorePlan {
    /// Number of remainder limbs (`2` or `3`); `r*(limbs - 1) + rlast == K`.
    limbs: usize,
    r: u8,
    rlast: u8,
    w1_width: Option<Width>,
    mc0_width: Option<Width>,
    mc1_width: Option<Width>,
    wm_last_width: Option<Width>,
    d1_width: Width,
    carry_widths: [Option<Width>; 3],
}

#[derive(Clone, Debug)]
struct MixedScoreCols {
    plan: MixedScorePlan,
    /// `(j, i)` domain (`2*t`) committed columns: `w1`, `mc0`, `mc1`, `wm_last`.
    w1: Option<ColumnId>,
    mc0: Option<ColumnId>,
    mc1: Option<ColumnId>,
    wm_last: Option<ColumnId>,
    /// `S` domain committed columns: `d1`, `c0..c_{L-1}`.
    d1: ColumnId,
    carries: Vec<ColumnId>,
}

#[derive(Clone, Debug)]
struct Columns {
    dot: ColumnId,
    sign: ColumnId,
    magnitude: Vec<ColumnId>,
    weight: Vec<ColumnId>,
    quotient: (ColumnId, Vec<ColumnId>),
    remainder: Vec<ColumnId>,
    mixed_score: Option<MixedScoreCols>,
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
    /// Limb bit width of `sv * v` on `(c, group, j)` (`8`, `4`, `2`, or `1`).
    sv_v_bits: u8,
    /// `sv * v` limbs on `(c, group, j)` (`d + gb + t`): limb 0 virtual, limbs 1.. committed.
    sv_v: Vec<ColumnId>,
    /// Radix of `total/magnitude` and the `total/sign` chain (`16` when `sum_hi` split is used, else `sv_v_bits`).
    total_radix: u8,
    /// Optional high-limb split `sums[i] = s_lo (u16 virtual) + 65536 * sum_hi[i]` on `Ob`.
    sum_hi: Vec<ColumnId>,
    total_sign: ColumnId,
    total: Vec<ColumnId>,
    block: Option<BlockColumns>,
    /// `E2 < 0`: `(nh bytes, bit, nl bytes)`.
    shifted: Option<(Vec<ColumnId>, Option<ColumnId>, Vec<ColumnId>)>,
    /// Radix of `normaliser/byte`, `output/quotient/byte`, `output/division`, and `output/spare` (`12` when `zmax >= 65536`, else `8`).
    div_radix: u8,
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

    /// Shifted score magnitude bound `S_max = Q_max * 2^max(e, 0)` for `W <= 2^wbits - 1`.
    fn score_qmax(&self, wbits: u8) -> u128 {
        let a = (128u128 * 128) << self.bits().d;
        let w = (1u128 << wbits) - 1;
        let n = a * w * u128::from(self.plan.score_multiplier.0);
        let e = self.exponent();
        let q = if e >= 0 {
            n
        } else {
            (n + (1u128 << (-e - 1).min(126))) >> (-e).min(127)
        };
        q.checked_shl(e.clamp(0, 60) as u32).unwrap_or(u128::MAX)
    }

    /// Bit width of the scale product `W = sq * sk` (RFC-0026 A25).
    fn score_wbits(&self, relation: Option<&Relation>) -> u8 {
        let smax_q = Self::scale_max(&self.plan.query, relation);
        let smax_k = Self::scale_max(&self.plan.key, relation);
        let loose = bit_length(smax_q * smax_k);
        if self.score_qmax(loose) < 1 << 28 {
            loose
        } else {
            bit_length(
                u128::from(self.plan.query.scale_bound) * u128::from(self.plan.key.scale_bound),
            )
        }
    }

    /// `(|A| bound, Q bound)` from the dot width and scale bounds.
    fn score_bound(&self) -> (u128, u128) {
        let a = (128u128 * 128) << self.bits().d;
        let wbits = self.score_wbits(None);
        (a, self.score_qmax(wbits))
    }

    /// Select the 2- or 3-limb mixed-radix signed score plan when all static bounds fit
    /// `HALF_MODULUS` (RFC-0028 §1.2, §2.2).
    fn mixed_score_plan(&self, relation: &Relation, wbits: u8) -> Option<MixedScorePlan> {
        let e = self.exponent();
        if e >= 0 {
            return None;
        }
        let k = (-e) as u8;
        if !(2..=38).contains(&k) {
            return None;
        }
        let m = u128::from(self.plan.score_multiplier.0);
        if m == 0 {
            return None;
        }
        let smax_q = Self::scale_max(&self.plan.query, Some(relation));
        let smax_k = Self::scale_max(&self.plan.key, Some(relation));
        let sq_mag = match relation.column(self.plan.query.scale).map(|c| &c.kind) {
            Some(Kind::Public(_)) => {
                (1u128 << bit_length(u128::from(self.plan.query.scale_bound)).max(1)) - 1
            }
            _ => smax_q,
        };
        let sk_mag = match relation.column(self.plan.key.scale).map(|c| &c.kind) {
            Some(Kind::Public(_)) => {
                (1u128 << bit_length(u128::from(self.plan.key.scale_bound)).max(1)) - 1
            }
            _ => smax_k,
        };
        let w_prod_mag = sq_mag.saturating_mul(sk_mag);
        if w_prod_mag > (1u128 << 24) {
            return None;
        }
        let amax = (128u128 * 128) << self.bits().d;
        if amax > HALF_MODULUS {
            return None;
        }
        let smax = self.score_qmax(wbits);
        let mx_mag = signed_for(smax).magnitude();

        for limbs in [1usize, 2usize, 3usize] {
            for r in 4..=13u8 {
                let rlast = if limbs == 1 {
                    if r != k {
                        continue;
                    }
                    k
                } else {
                    let prefix_bits = r * (limbs as u8 - 1);
                    if k <= prefix_bits {
                        continue;
                    }
                    let rl = k - prefix_bits;
                    if rl == 0 || rl > r {
                        continue;
                    }
                    rl
                };
                let (rad, rad_last) = (1u128 << r, 1u128 << rlast);
                let ratio = rad / rad_last;

                // (j, i) split: W = sq*sk = w0 + rad*w1.
                let w1_max = w_prod_mag >> r;
                let w1_width = if w1_max == 0 {
                    None
                } else {
                    let bits = bit_length(w1_max).max(1);
                    if bits > 16 {
                        continue;
                    }
                    Some(Width::unsigned(bits))
                };
                let w1_mag = w1_width.map_or(0, Width::magnitude);
                if w_prod_mag.saturating_add(rad.saturating_mul(w1_mag)) > HALF_MODULUS {
                    continue;
                }
                // Wm = W * m: pos 0 -> Wm0 = w0*m - rad*mc0.
                let mc0_max = ((rad - 1).saturating_mul(m)) >> r;
                let mc0_width = if mc0_max == 0 {
                    None
                } else {
                    let mc0_bits = bit_length(mc0_max).max(1);
                    if mc0_bits > 16 {
                        continue;
                    }
                    Some(Width::unsigned(mc0_bits))
                };
                let mc0_mag = mc0_width.map_or(0, Width::magnitude);
                if (rad - 1)
                    .saturating_mul(m)
                    .saturating_add(rad.saturating_mul(mc0_mag))
                    > HALF_MODULUS
                {
                    continue;
                }
                let wm1_raw = w1_mag.saturating_mul(m).saturating_add(mc0_mag);
                let (mc1_width, wm_last_width) = if limbs == 1 {
                    let wm1_width = if wm1_raw == 0 {
                        None
                    } else {
                        let bits = bit_length(wm1_raw).max(1);
                        if bits > 16 {
                            continue;
                        }
                        Some(Width::unsigned(bits))
                    };
                    (None, wm1_width)
                } else if limbs == 2 {
                    let wm2_max = wm1_raw >> rlast;
                    let wm2_width = if wm2_max == 0 {
                        None
                    } else {
                        let bits = bit_length(wm2_max).max(1);
                        if bits > 16 {
                            continue;
                        }
                        Some(Width::unsigned(bits))
                    };
                    let wm2_mag = wm2_width.map_or(0, Width::magnitude);
                    if wm1_raw.saturating_add(rad_last.saturating_mul(wm2_mag)) > HALF_MODULUS {
                        continue;
                    }
                    (None, wm2_width)
                } else {
                    let mc1_max = wm1_raw >> r;
                    let mc1_bits = bit_length(mc1_max).max(1);
                    if mc1_bits > 16 {
                        continue;
                    }
                    let mc1_w = Width::unsigned(mc1_bits);
                    let mc1_mag = mc1_w.magnitude();
                    if wm1_raw.saturating_add(rad.saturating_mul(mc1_mag)) > HALF_MODULUS {
                        continue;
                    }
                    let wm3_max = mc1_mag >> rlast;
                    let wm3_width = if wm3_max == 0 {
                        None
                    } else {
                        let bits = bit_length(wm3_max).max(1);
                        if bits > 16 {
                            continue;
                        }
                        Some(Width::unsigned(bits))
                    };
                    let wm3_mag = wm3_width.map_or(0, Width::magnitude);
                    if mc1_mag.saturating_add(rad_last.saturating_mul(wm3_mag)) > HALF_MODULUS {
                        continue;
                    }
                    (Some(mc1_w), wm3_width)
                };
                let wm_last_mag = wm_last_width.map_or(0, Width::magnitude);

                // S domain: dot = d0 + rad*d1.
                let d1_max = amax.div_ceil(rad);
                let d1_width = signed_for(d1_max);
                if d1_width.bits > 16 {
                    continue;
                }
                let d1_mag = d1_width.magnitude();
                if amax.saturating_add(rad.saturating_mul(d1_mag)) > HALF_MODULUS {
                    continue;
                }
                // Carries c_0..c_{limbs-1}.
                let half0 = if limbs == 1 { rad >> 1 } else { 0 };
                let c0_max = ((rad - 1).saturating_mul(rad - 1).saturating_add(rad)) >> r;
                let c0_bits = bit_length(c0_max).max(1);
                if c0_bits > 16 {
                    continue;
                }
                let c0_width = Width::unsigned(c0_bits);
                let c0_mag = c0_width.magnitude();
                if (rad - 1)
                    .saturating_mul(rad - 1)
                    .saturating_add(2)
                    .saturating_add(half0)
                    .saturating_add(rad.saturating_mul(c0_mag))
                    > HALF_MODULUS
                {
                    continue;
                }
                let mut carry_widths = [Some(c0_width), None, None];
                let mut prev_mag = c0_mag;
                let mut carries_ok = true;
                for (j, slot) in carry_widths.iter_mut().enumerate().take(limbs).skip(1) {
                    let rad_j = if j + 1 == limbs { rad_last } else { rad };
                    let wmj_mag = rad_j - 1;
                    let half_term = if j + 1 == limbs { rad_j >> 1 } else { 0 };
                    let raw = (rad - 1)
                        .saturating_mul(wmj_mag)
                        .saturating_add(d1_mag.saturating_mul(rad - 1))
                        .saturating_add(prev_mag)
                        .saturating_add(half_term);
                    let cj_max = raw.div_ceil(rad_j);
                    let cj_width = signed_for(cj_max);
                    if cj_width.bits > 16 {
                        carries_ok = false;
                        break;
                    }
                    let cj_mag = cj_width.magnitude();
                    if raw.saturating_add(rad_j.saturating_mul(cj_mag)) > HALF_MODULUS {
                        carries_ok = false;
                        break;
                    }
                    *slot = Some(cj_width);
                    prev_mag = cj_mag;
                }
                if !carries_ok {
                    continue;
                }
                // Virtual score = dot*Wm_L + ratio*d1*Wm_{L-1} + c_{L-1} (dot = d0 + rad*d1).
                let score_mag = amax
                    .saturating_mul(wm_last_mag)
                    .saturating_add(ratio.saturating_mul(d1_mag).saturating_mul(rad_last - 1))
                    .saturating_add(prev_mag);
                if score_mag > HALF_MODULUS || score_mag.saturating_add(mx_mag) > HALF_MODULUS {
                    continue;
                }
                return Some(MixedScorePlan {
                    limbs,
                    r,
                    rlast,
                    w1_width,
                    mc0_width,
                    mc1_width,
                    wm_last_width,
                    d1_width,
                    carry_widths,
                });
            }
        }
        None
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

/// Limbs of `radix` bits covering `bits` bits, the top one narrower.
fn radix_widths(bits: u8, radix: u8) -> Vec<Width> {
    let r = usize::from(radix);
    let total = usize::from(bits.max(1));
    let n = total.div_ceil(r);
    (0..n)
        .map(|i| Width::unsigned((total - r * i).min(r) as u8))
        .collect()
}

/// Tighten a `Kind::Public` scale column to `scale_bound` bits; witness scales pass through.
fn tight_scale(b: &mut Builder<'_>, label: &str, row: &RowOutput, t: u8) -> (ColumnId, u128) {
    match b.relation.column(row.scale).map(|c| c.kind.clone()) {
        Some(Kind::Public(vals)) => {
            let bits = bit_length(u128::from(row.scale_bound)).max(1);
            let w = Width::unsigned(bits);
            (b.public(label, vals, w, t), w.magnitude())
        }
        _ => (
            row.scale,
            b.relation.columns[row.scale.0 as usize].width.magnitude(),
        ),
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
        let (amax, _) = self.score_bound();
        let wbits = self.score_wbits(Some(relation));
        let mixed_plan = self.mixed_score_plan(relation, wbits);
        let prefix = self.prefix.clone();
        let mut b = Builder::new(relation, &prefix);
        let mut chains = Vec::new();

        // Domain reads.
        let s_all = |c: ColumnId| r(c, 0..sd);
        let s_ji = |c: ColumnId| r(c, (0..t).chain(t + hb..sd));
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

        // Row 6: dot = sum_c q*k (virtual Contraction, RFC-0028 §1.2).
        let dot = b.virtual_col(
            "dot",
            Def::Contraction {
                free: sd,
                summed: d,
                lhs: r(self.plan.query.codes, (sd..sd + d).chain(t..sd)),
                rhs: r(
                    self.plan.key.codes,
                    (sd..sd + d).chain(t + rb..t + hb).chain(0..t),
                ),
            },
            sd,
        );

        let e = self.exponent();
        let m = self.plan.score_multiplier.0;
        let nmax = amax * ((1u128 << wbits) - 1) * u128::from(m);
        let qmax = if e >= 0 {
            nmax
        } else {
            (nmax + (1u128 << (-e - 1))) >> (-e)
        };
        let up = 1i64 << e.max(0);
        let smax = qmax << e.max(0);

        type ScoreDeclaration = (
            ColumnId,
            Vec<ColumnId>,
            Vec<ColumnId>,
            (ColumnId, Vec<ColumnId>),
            Vec<ColumnId>,
            Option<MixedScoreCols>,
            Option<ColumnId>,
        );
        let (sign, magnitude, weight, quotient, remainder, mixed_score, score_terms_col): ScoreDeclaration =
            if let Some(mp) = mixed_plan {
            let (rad, rad_last) = (1i64 << mp.r, 1i64 << mp.rlast);
            let ratio = rad / rad_last;
            // (j, i) domain (2*t, 32x smaller than S): W = sq*sk, Wm = W*m in mixed radix.
            let (sq_col, _) = tight_scale(&mut b, "score/sq", &self.plan.query, t);
            let (sk_col, _) = tight_scale(&mut b, "score/sk", &self.plan.key, t);
            let w1 = mp.w1_width.map(|w| b.witness("score/w1", w, 2 * t));
            let mut w0_terms = vec![term(1, vec![r(sq_col, t..2 * t), r(sk_col, 0..t)])];
            if let Some(w1_id) = w1 {
                w0_terms.push(term(-rad, vec![r(w1_id, 0..2 * t)]));
            }
            let w0 = b.virtual_ranged(
                "score/w0",
                Def::Pointwise { terms: w0_terms },
                Width::unsigned(mp.r),
                2 * t,
            );
            let mc0 = mp.mc0_width.map(|w| b.witness("score/mc0", w, 2 * t));
            let mut wm0_terms = vec![(i64::from(m), r(w0, 0..2 * t))];
            if let Some(mc0_id) = mc0 {
                wm0_terms.push((-rad, r(mc0_id, 0..2 * t)));
            }
            let wm0 = b.virtual_ranged(
                "score/wm0",
                Def::Linear {
                    constant: 0,
                    terms: wm0_terms,
                },
                Width::unsigned(mp.r),
                2 * t,
            );
            let (mc1, wm_last, wm_limbs) = if mp.limbs == 1 {
                let mut wm1_terms = Vec::new();
                if let Some(mc0_id) = mc0 {
                    wm1_terms.push((1, r(mc0_id, 0..2 * t)));
                }
                if let Some(w1_id) = w1 {
                    wm1_terms.push((i64::from(m), r(w1_id, 0..2 * t)));
                }
                let wm1 = (!wm1_terms.is_empty()).then(|| {
                    b.virtual_col(
                        "score/wm1",
                        Def::Linear {
                            constant: 0,
                            terms: wm1_terms,
                        },
                        2 * t,
                    )
                });
                (None, wm1, vec![wm0])
            } else if mp.limbs == 2 {
                let wm2 = mp.wm_last_width.map(|w| b.witness("score/wm2", w, 2 * t));
                let mut wm1_terms = Vec::new();
                if let Some(mc0_id) = mc0 {
                    wm1_terms.push((1, r(mc0_id, 0..2 * t)));
                }
                if let Some(w1_id) = w1 {
                    wm1_terms.push((i64::from(m), r(w1_id, 0..2 * t)));
                }
                if let Some(wm2_id) = wm2 {
                    wm1_terms.push((-rad_last, r(wm2_id, 0..2 * t)));
                }
                let wm1 = b.virtual_ranged(
                    "score/wm1",
                    Def::Linear {
                        constant: 0,
                        terms: wm1_terms,
                    },
                    Width::unsigned(mp.rlast),
                    2 * t,
                );
                (None, wm2, vec![wm0, wm1])
            } else {
                let mc1_id = b.witness("score/mc1", mp.mc1_width.expect("mc1"), 2 * t);
                let mut wm1_terms = vec![(-rad, r(mc1_id, 0..2 * t))];
                if let Some(mc0_id) = mc0 {
                    wm1_terms.push((1, r(mc0_id, 0..2 * t)));
                }
                if let Some(w1_id) = w1 {
                    wm1_terms.push((i64::from(m), r(w1_id, 0..2 * t)));
                }
                let wm1 = b.virtual_ranged(
                    "score/wm1",
                    Def::Linear {
                        constant: 0,
                        terms: wm1_terms,
                    },
                    Width::unsigned(mp.r),
                    2 * t,
                );
                let wm3 = mp.wm_last_width.map(|w| b.witness("score/wm3", w, 2 * t));
                let mut wm2_terms = vec![(1, r(mc1_id, 0..2 * t))];
                if let Some(wm3_id) = wm3 {
                    wm2_terms.push((-rad_last, r(wm3_id, 0..2 * t)));
                }
                let wm2 = b.virtual_ranged(
                    "score/wm2",
                    Def::Linear {
                        constant: 0,
                        terms: wm2_terms,
                    },
                    Width::unsigned(mp.rlast),
                    2 * t,
                );
                (Some(mc1_id), wm3, vec![wm0, wm1, wm2])
            };

            // S domain: d1, sigma, c0..c_{L-1} committed (4 or 5 cols); d0, twos, rho_j, score virtual.
            let d1 = b.witness("score/d1", mp.d1_width, sd);
            let d0 = b.virtual_ranged(
                "score/d0",
                Def::Linear {
                    constant: 0,
                    terms: vec![(1, s_all(dot)), (-rad, s_all(d1))],
                },
                Width::unsigned(mp.r),
                sd,
            );
            let sign = b.witness("score/sign", Width::unsigned(1), sd);
            let _twos = b.virtual_ranged(
                "score/twos",
                Def::Linear {
                    constant: 0,
                    terms: vec![(1, s_all(d1)), (1i64 << mp.d1_width.bits, s_all(sign))],
                },
                Width::unsigned(mp.d1_width.bits),
                sd,
            );
            let c0 = b.witness("score/c0", mp.carry_widths[0].expect("c0"), sd);
            let mut rho0_terms = vec![
                term(-1, vec![s_all(d0), s_ji(wm_limbs[0])]),
                term(1, vec![s_all(sign)]),
                term(-1, vec![]),
                term(rad, vec![s_all(c0)]),
            ];
            if mp.limbs == 1 {
                rho0_terms.push(term(rad >> 1, vec![]));
            }
            let rho0 = b.virtual_ranged(
                "score/remainder/0",
                Def::Pointwise { terms: rho0_terms },
                Width::unsigned(mp.r),
                sd,
            );
            let mut carries = vec![c0];
            let mut rem = vec![rho0];
            for j in 1..mp.limbs {
                let is_last = j + 1 == mp.limbs;
                let rj = if is_last { mp.rlast } else { mp.r };
                let rad_j = 1i64 << rj;
                let cj = b.witness(&format!("score/c{j}"), mp.carry_widths[j].expect("cj"), sd);
                let mut rho_terms = vec![
                    term(-1, vec![s_all(d0), s_ji(wm_limbs[j])]),
                    term(-1, vec![s_all(d1), s_ji(wm_limbs[j - 1])]),
                    term(-1, vec![s_all(carries[j - 1])]),
                    term(rad_j, vec![s_all(cj)]),
                ];
                if is_last {
                    rho_terms.push(term(rad_j >> 1, vec![]));
                }
                let rho_j = b.virtual_ranged(
                    &format!("score/remainder/{j}"),
                    Def::Pointwise { terms: rho_terms },
                    Width::unsigned(rj),
                    sd,
                );
                carries.push(cj);
                rem.push(rho_j);
            }
            let mut score_def = vec![
                term(ratio, vec![s_all(d1), s_ji(wm_limbs[mp.limbs - 1])]),
                term(1, vec![s_all(carries[mp.limbs - 1])]),
            ];
            if let Some(wm_top) = wm_last {
                score_def.push(term(1, vec![s_all(dot), s_ji(wm_top)]));
            }
            let score_col = b.virtual_col("score/value", Def::Pointwise { terms: score_def }, sd);
            (
                sign,
                Vec::new(),
                Vec::new(),
                (score_col, Vec::new()),
                rem,
                Some(MixedScoreCols {
                    plan: mp,
                    w1,
                    mc0,
                    mc1,
                    wm_last,
                    d1,
                    carries,
                }),
                Some(score_col),
            )
        } else {
            // General Row 6 fallback (e >= 0, k == 1, or wide static scales): virtual remainder & quotient.
            let sign = b.witness("score/sign", Width::unsigned(1), sd);
            let magnitude = bytes(&mut b, "score/magnitude", bit_length(amax), sd);
            let mut terms = vec![term(1, vec![s_all(dot)])];
            for (i, a) in magnitude.iter().enumerate() {
                terms.push(term(-(1 << (8 * i)), vec![s_all(*a)]));
                terms.push(term(2 << (8 * i), vec![s_all(sign), s_all(*a)]));
            }
            b.identity("score/sign", sd, terms);

            // W = sq*sk on (j, i) with virtual bytes via Chain::declare_virtual.
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
            let w_targets: Vec<(usize, String, Width)> = byte_widths(wbits)
                .into_iter()
                .enumerate()
                .map(|(i, w)| (i, format!("score/scales/{i}"), w))
                .collect();
            let (sc_chain, weight) =
                Chain::declare_virtual(&mut b, "score/scales", 2 * t, 8, positions.0, &w_targets);
            chains.push(("score/scales", sc_chain));

            // A*W*m + 2^(k-1) = Q*2^k + rho (virtual quotient parent & virtual remainder bytes).
            let q_limbs = bytes(&mut b, "score/quotient/byte", bit_length(qmax).max(1), sd);
            let q_col = b.virtual_col(
                "score/quotient",
                Def::Linear {
                    constant: 0,
                    terms: q_limbs
                        .iter()
                        .enumerate()
                        .map(|(i, &l)| (1i64 << (8 * i), s_all(l)))
                        .collect(),
                },
                sd,
            );
            let quotient = (q_col, q_limbs);
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
            for (i, q) in quotient.1.iter().enumerate() {
                positions.at(k + 8 * i, -1, vec![s_all(*q)]);
            }
            let remainder = if k > 0 {
                positions.at(k - 1, 1, vec![]);
                let r_targets: Vec<(usize, String, Width)> = byte_widths(k as u8)
                    .into_iter()
                    .enumerate()
                    .map(|(i, w)| (i, format!("score/remainder/{i}"), w))
                    .collect();
                let (r_chain, rem) =
                    Chain::declare_virtual(&mut b, "score/round", sd, 8, positions.0, &r_targets);
                chains.push(("score/round", r_chain));
                rem
            } else {
                chains.push((
                    "score/round",
                    Chain::declare(&mut b, "score/round", sd, 8, positions.0),
                ));
                Vec::new()
            };
            (sign, magnitude, weight, quotient, remainder, None, None)
        };

        let quotient_ref = s_all(quotient.0);
        // causal*score as terms with the given coefficient.
        let score_terms = |coeff: i64| match score_terms_col {
            Some(sc) => vec![term(coeff, vec![s_ji(causal), s_all(sc)])],
            None => vec![
                term(coeff * up, vec![s_ji(causal), quotient_ref.clone()]),
                term(
                    -2 * coeff * up,
                    vec![s_ji(causal), s_all(sign), quotient_ref.clone()],
                ),
            ],
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

        // Row 8: exp lookups (virtual exp/t when under HALF_MODULUS, virtual exp/rr & exp/slack).
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
            let mut t_def = score_terms(1);
            t_def.push(term(-1, vec![s_ji(causal), s_hi(maximum.column)]));
            let t_bound: u128 = t_def
                .iter()
                .map(|tm| {
                    tm.factors
                        .iter()
                        .fold(u128::from(tm.coeff.unsigned_abs()), |acc, f| {
                            let m = b.relation.column_magnitude(f.column).unwrap_or_else(|| {
                                b.relation.columns[f.column.0 as usize].width.magnitude()
                            });
                            acc.saturating_mul(m)
                        })
                })
                .fold(0u128, u128::saturating_add);
            let tc = if t_bound <= HALF_MODULUS {
                b.virtual_col("exp/t", Def::Pointwise { terms: t_def }, sd)
            } else {
                let tc = b.column("exp/t", wi, sd);
                let mut id_terms = vec![term(-1, vec![s_all(tc)])];
                id_terms.extend(t_def);
                b.identity("exp/difference", sd, id_terms);
                tc
            };
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
                let mut terms = u.clone();
                terms.push(term(1, vec![s_all(tc)]));
                b.identity("exp/split", sd, terms);
            } else {
                let mut terms = u.clone();
                terms.push(term(-1, vec![s_ji(causal), s_hi(maximum.column)]));
                terms.extend(score_terms(1));
                b.identity("exp/difference", sd, terms);
                u_terms = u.clone();
                if 2 * smax > 1u128 << exp.domain {
                    if exp.domain < 16 {
                        let sl_col = b.virtual_ranged(
                            "exp/slack",
                            Def::Linear {
                                constant: 0,
                                terms: vec![
                                    (1 << exp.domain, s_ji(causal)),
                                    (-k, s_all(hi)),
                                    (-1, s_all(lo)),
                                ],
                            },
                            Width::unsigned(exp.domain + 1),
                            sd,
                        );
                        slack = Some(Wide {
                            column: sl_col,
                            limbs: None,
                        });
                    } else {
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
            }
            // H*L = (P - C)*2^E + rr: virtual rr when H*L + 2^E*(P + C) <= HALF_MODULUS.
            let mut rr_terms = vec![
                term(1, vec![s_all(high), s_all(low)]),
                term(-(1 << exp.output), vec![s_all(pexp)]),
            ];
            let mut rr_bound = wh
                .magnitude()
                .saturating_mul(wl.magnitude())
                .saturating_add((1u128 << exp.output).saturating_mul(pwidth.magnitude()));
            if let Some(c) = correction {
                rr_terms.push(term(1 << exp.output, vec![s_all(c)]));
                rr_bound = rr_bound.saturating_add(
                    (1u128 << exp.output)
                        .saturating_mul(b.relation.columns[c.0 as usize].width.magnitude()),
                );
            }
            if exp.output > 0 {
                if rr_bound <= HALF_MODULUS {
                    let rem = b.virtual_ranged(
                        "exp/rr",
                        Def::Pointwise { terms: rr_terms },
                        Width::unsigned(exp.output),
                        sd,
                    );
                    rr = Some(rem);
                } else {
                    let rem = b.witness("exp/rr", Width::unsigned(exp.output), sd);
                    rr_terms.push(term(-1, vec![s_all(rem)]));
                    b.identity("exp/product", sd, rr_terms);
                    rr = Some(rem);
                }
            } else {
                b.identity("exp/product", sd, rr_terms);
            }
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

        // Row 9: virtual Pm = causal*P (range implied by causal ∈ {0,1} and P ∈ pwidth);
        // virtual Z = sum_j Pm*causal; sv*v off S onto (c, group, j)!
        let masked = b.virtual_col(
            "exp/masked",
            Def::Pointwise {
                terms: vec![term(1, vec![s_ji(causal), s_all(pexp)])],
            },
            sd,
        );
        let pmax = pwidth.magnitude();
        let normaliser = b.virtual_col(
            "normaliser",
            Def::Contraction {
                free: hb_t,
                summed: t,
                lhs: r(masked, (hb_t..hb_t + t).chain(0..hb_t)),
                rhs: r(causal, (hb_t..hb_t + t).chain(hb..hb_t)),
            },
            hb_t,
        );

        // Move sv * v off S onto (c, group, j) (d + gb + t, up to 1024x smaller than S!).
        let summed = t - kb;
        let gb = hb - rb;
        let vd = d + gb + t;
        let (sv_col, smax_v_tight) = tight_scale(&mut b, "value/sv", &self.plan.value, t);
        // Each `sums[i]` must stay below `HALF_MODULUS / 2` so `total/sign/i` (which adds
        // `sums[i]` plus `radix * carry[i]` with composed carry magnitude up to ~`2 * sums[i] / radix`)
        // stays strictly below `M31 - 1` (RFC-0026 §3.2).
        let sv_v_bits: u8 = [8u8, 4, 2, 1]
            .into_iter()
            .find(|&bits| {
                (1u128 << summed)
                    .saturating_mul(pmax)
                    .saturating_mul((1u128 << bits) - 1)
                    <= HALF_MODULUS / 2
            })
            .unwrap_or(1);
        let rad_v = 1u128 << sv_v_bits;
        let max_sv_v = 128u128.saturating_mul(smax_v_tight);
        let mut n_v = 1usize;
        let mut pow_v = 1u128;
        while max_sv_v.div_ceil(pow_v) > (1u128 << (sv_v_bits - 1)) {
            n_v += 1;
            pow_v *= rad_v;
        }
        let sv_v: Vec<ColumnId> = if n_v == 1 {
            let top_w = signed_for(max_sv_v);
            vec![b.virtual_ranged(
                "value/sv_v/0",
                Def::Pointwise {
                    terms: vec![term(
                        1,
                        vec![r(self.plan.value.codes, 0..vd), r(sv_col, d + gb..vd)],
                    )],
                },
                top_w,
                vd,
            )]
        } else {
            let mut hi = Vec::with_capacity(n_v - 1);
            for k in 1..n_v {
                let w = if k + 1 == n_v {
                    let top_mag = max_sv_v.div_ceil(rad_v.pow(k as u32));
                    let sw = signed_for(top_mag);
                    Width::signed(sw.bits.min(sv_v_bits))
                } else {
                    Width::unsigned(sv_v_bits)
                };
                hi.push(b.witness(&format!("value/sv_v/{k}"), w, vd));
            }
            let mut terms = vec![term(
                1,
                vec![r(self.plan.value.codes, 0..vd), r(sv_col, d + gb..vd)],
            )];
            for (i, &col) in hi.iter().enumerate() {
                terms.push(term(
                    -(1i64 << (sv_v_bits * (i as u8 + 1))),
                    vec![r(col, 0..vd)],
                ));
            }
            let lo = b.virtual_ranged(
                "value/sv_v/0",
                Def::Pointwise { terms },
                Width::unsigned(sv_v_bits),
                vd,
            );
            core::iter::once(lo).chain(hi).collect()
        };

        // Virtual contractions T_b = sum_o Pm(i, head, (o, blk)) * sv_v_b(c, group, (o, blk)) on Ob.
        let key: Vec<u8> = (obd..obd + summed).chain(od..obd).collect();
        let mut sums = Vec::new();
        // Exact bound over Z: sum_b rad^b * T_b = sum_o Pm_o * (sv_o * v_o), so |T| <= 2^summed * pmax * max_sv_v.
        let xmax = (pmax.saturating_mul(max_sv_v)) << summed;
        for (i, &sv_b) in sv_v.iter().enumerate() {
            let sum = b.virtual_col(
                &format!("value/sum/{i}"),
                Def::Contraction {
                    free: obd,
                    summed,
                    lhs: r(masked, key.iter().copied().chain(d..od)),
                    rhs: r(
                        sv_b,
                        (0..d).chain(d + rb..d + hb).chain(key.iter().copied()),
                    ),
                },
                obd,
            );
            sums.push(sum);
        }

        // sum (2^sv_v_bits)^b T_b = (1 - 2 sigma) * n.
        // When `sv_v_bits` divides 16 and every `sums[i]` fits `s_lo (u16 virtual) + 65536 * s_hi`,
        // fold into a radix-2^16 chain so `total/magnitude` uses 16-bit limbs and carries stay unsplit.
        let total_sign = b.witness("total/sign", Width::unsigned(1), obd);
        let sum_mags: Vec<u128> = sums
            .iter()
            .map(|&s| b.relation.column_magnitude(s).unwrap_or(HALF_MODULUS))
            .collect();
        let total_len = usize::from(bit_length(xmax).max(1)).div_ceil(16);
        let max_hi_pos = if sums.is_empty() {
            0
        } else {
            (usize::from(sv_v_bits) * (sums.len() - 1)) / 16 + 1
        };
        let hi_widths: Option<Vec<Width>> =
            if (sv_v_bits == 4 || sv_v_bits == 8) && sums.len() >= 3 && max_hi_pos < total_len {
                let mut ws = Vec::with_capacity(sums.len());
                let mut ok = true;
                for &sm in &sum_mags {
                    let w = signed_for(sm.div_ceil(1 << 16));
                    if w.bits > 16 || sm.saturating_add(w.magnitude() << 16) > HALF_MODULUS {
                        ok = false;
                        break;
                    }
                    ws.push(w);
                }
                if ok {
                    // Verify every radix-2^16 chain position stays below M31 - 1.
                    let mut pos_mags = vec![0u128; total_len];
                    for (i, w) in ws.iter().enumerate() {
                        let bit = usize::from(sv_v_bits) * i;
                        let (pos, rem) = (bit / 16, bit % 16);
                        let coeff = 1u128 << rem;
                        pos_mags[pos] = pos_mags[pos].saturating_add(coeff.saturating_mul(65535));
                        pos_mags[pos + 1] =
                            pos_mags[pos + 1].saturating_add(coeff.saturating_mul(w.magnitude()));
                    }
                    let total_ws = radix_widths(bit_length(xmax), 16);
                    let mut prev_c = 0u128;
                    for (pos, (pm, tw)) in pos_mags.iter().zip(&total_ws).enumerate() {
                        let raw = pm
                            .saturating_add(3u128.saturating_mul(tw.magnitude()))
                            .saturating_add(prev_c);
                        if pos + 1 < total_len {
                            let cw = signed_for(raw >> 16);
                            if cw.bits > 16
                                || raw.saturating_add(cw.magnitude() << 16) >= (1u128 << 31) - 1
                            {
                                ok = false;
                                break;
                            }
                            prev_c = cw.magnitude();
                        } else if raw >= (1u128 << 31) - 1 {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        Some(ws)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
        let (total_radix, sum_hi, total) = if let Some(ws) = hi_widths {
            let mut s_hi = Vec::with_capacity(sums.len());
            let mut s_lo = Vec::with_capacity(sums.len());
            for (i, (&sum_col, &w)) in sums.iter().zip(&ws).enumerate() {
                let hi = b.witness(&format!("value/sum_hi/{i}"), w, obd);
                let lo = b.virtual_ranged(
                    &format!("value/sum_lo/{i}"),
                    Def::Linear {
                        constant: 0,
                        terms: vec![(1, r(sum_col, 0..obd)), (-(1i64 << 16), r(hi, 0..obd))],
                    },
                    Width::unsigned(16),
                    obd,
                );
                s_hi.push(hi);
                s_lo.push(lo);
            }
            let total: Vec<ColumnId> = radix_widths(bit_length(xmax), 16)
                .into_iter()
                .enumerate()
                .map(|(i, w)| b.witness(&format!("total/magnitude/{i}"), w, obd))
                .collect();
            let mut tpos: Vec<Vec<Term>> = Vec::new();
            let mut push_t = |pos: usize, t: Term| {
                if tpos.len() <= pos {
                    tpos.resize(pos + 1, Vec::new());
                }
                tpos[pos].push(t);
            };
            for i in 0..sums.len() {
                let bit = usize::from(sv_v_bits) * i;
                let (pos, rem) = (bit / 16, bit % 16);
                let coeff = 1i64 << rem;
                push_t(pos, term(coeff, vec![r(s_lo[i], 0..obd)]));
                push_t(pos + 1, term(coeff, vec![r(s_hi[i], 0..obd)]));
            }
            for (i, &nb) in total.iter().enumerate() {
                push_t(i, term(-1, vec![r(nb, 0..obd)]));
                push_t(i, term(2, vec![r(total_sign, 0..obd), r(nb, 0..obd)]));
            }
            chains.push((
                "total/sign",
                Chain::declare(&mut b, "total/sign", obd, 16, tpos),
            ));
            (16u8, s_hi, total)
        } else {
            let total: Vec<ColumnId> = radix_widths(bit_length(xmax), sv_v_bits)
                .into_iter()
                .enumerate()
                .map(|(i, w)| b.witness(&format!("total/magnitude/{i}"), w, obd))
                .collect();
            let mut tpos: Vec<Vec<Term>> = Vec::new();
            let mut push_t = |pos: usize, t: Term| {
                if tpos.len() <= pos {
                    tpos.resize(pos + 1, Vec::new());
                }
                tpos[pos].push(t);
            };
            for (i, &s) in sums.iter().enumerate() {
                push_t(i, term(1, vec![r(s, 0..obd)]));
            }
            for (i, &nb) in total.iter().enumerate() {
                push_t(i, term(-1, vec![r(nb, 0..obd)]));
                push_t(i, term(2, vec![r(total_sign, 0..obd), r(nb, 0..obd)]));
            }
            chains.push((
                "total/sign",
                Chain::declare(&mut b, "total/sign", obd, sv_v_bits, tpos),
            ));
            (sv_v_bits, Vec::new(), total)
        };

        // Numerator |T| for the output division: atoms at bit offsets and its bound.
        let o_all = |c: ColumnId| r(c, 0..od);
        let (numerator, nmax, tau, block): (Vec<(usize, ColumnId)>, u128, ColumnId, _) = if self
            .plan
            .accumulation
            == 1
        {
            let c = usize::from(self.plan.drop);
            let qb = b.witness("block/quotient", Width::unsigned(16), obd);
            let mut positions = Positions(Vec::new());
            for (i, nb) in total.iter().enumerate() {
                positions.at(usize::from(total_radix) * i, 1, vec![r(*nb, 0..obd)]);
            }
            positions.at(c, -1, vec![r(qb, 0..obd)]);
            let rho = if c > 0 {
                positions.at(c - 1, 1, vec![]);
                let r_targets: Vec<(usize, String, Width)> = byte_widths(c as u8)
                    .into_iter()
                    .enumerate()
                    .map(|(i, w)| (i, format!("block/remainder/{i}"), w))
                    .collect();
                let (b_chain, rho) =
                    Chain::declare_virtual(&mut b, "block/round", obd, 8, positions.0, &r_targets);
                chains.push(("block/round", b_chain));
                rho
            } else {
                chains.push((
                    "block/round",
                    Chain::declare(&mut b, "block/round", obd, 8, positions.0),
                ));
                Vec::new()
            };
            // Virtual block = (1 - 2*total_sign) * qb (signed 16).
            let blk = b.virtual_ranged(
                "block",
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![r(qb, 0..obd)]),
                        term(-2, vec![r(total_sign, 0..obd), r(qb, 0..obd)]),
                    ],
                },
                Width::signed(16),
                obd,
            );
            let tmax = 32768u128 << kb;
            let tsum = (kb > 0).then(|| {
                let ones = b.public("block/ones", vec![1; 1 << kb], Width::unsigned(1), kb);
                b.virtual_col(
                    "block/total",
                    Def::Contraction {
                        free: od,
                        summed: kb,
                        lhs: r(blk, 0..obd),
                        rhs: r(ones, od..obd),
                    },
                    od,
                )
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
                total
                    .iter()
                    .enumerate()
                    .map(|(i, c)| (usize::from(total_radix) * i, *c))
                    .collect(),
                xmax,
                total_sign,
                None,
            )
        };

        // Output division on O (virtual normaliser/byte/0, virtual q.0, virtual r & s, virtual output).
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
        let div_radix: u8 = if zmax >= (1 << 16) && (0..=3).contains(&e2) {
            12
        } else {
            8
        };
        let dr = usize::from(div_radix);
        let z_widths = radix_widths(bit_length(zmax), div_radix);
        let z: Vec<ColumnId> = if z_widths.len() == 1 {
            vec![b.virtual_ranged(
                "normaliser/byte/0",
                Def::Linear {
                    constant: 0,
                    terms: vec![(1, r(normaliser, 0..hb_t))],
                },
                z_widths[0],
                hb_t,
            )]
        } else {
            let mut z_hi = Vec::with_capacity(z_widths.len() - 1);
            for (i, &w) in z_widths.iter().enumerate().skip(1) {
                z_hi.push(b.witness(&format!("normaliser/byte/{i}"), w, hb_t));
            }
            let mut lin = vec![(1, r(normaliser, 0..hb_t))];
            for (i, &col) in z_hi.iter().enumerate() {
                lin.push((-(1i64 << (dr * (i + 1))), r(col, 0..hb_t)));
            }
            let z0 = b.virtual_ranged(
                "normaliser/byte/0",
                Def::Linear {
                    constant: 0,
                    terms: lin,
                },
                z_widths[0],
                hb_t,
            );
            core::iter::once(z0).chain(z_hi).collect()
        };
        let q_limbs: Vec<ColumnId> = radix_widths(16, div_radix)
            .into_iter()
            .enumerate()
            .map(|(i, w)| b.witness(&format!("output/quotient/byte/{i}"), w, od))
            .collect();
        let q_col = b.virtual_col(
            "output/quotient",
            Def::Linear {
                constant: 0,
                terms: vec![
                    (1, o_all(q_limbs[0])),
                    (1i64 << div_radix, o_all(q_limbs[1])),
                ],
            },
            od,
        );
        let q = (q_col, q_limbs);
        let rbits = bit_length(2 * zmax);
        let o_z = |c: ColumnId| r(c, d..od);
        let o_real = r(real, d + hb..od);
        let mut positions = Positions(Vec::new());
        for &(o, c) in &num {
            positions.at_radix(o + up2, div_radix, 1, vec![o_all(c)]);
        }
        if let Some((_, Some(bit), _)) = &shifted {
            positions.at_radix(0, div_radix, 1, vec![o_all(*bit)]);
        }
        for (i, zb) in z.iter().enumerate() {
            positions.at_radix(dr * i, div_radix, 1, vec![o_z(*zb)]);
            for (l, qb) in q.1.iter().enumerate() {
                positions.at_radix(dr * (i + l), div_radix, -2, vec![o_z(*zb), o_all(*qb)]);
            }
        }
        let rem_targets: Vec<(usize, String, Width)> = radix_widths(rbits, div_radix)
            .into_iter()
            .enumerate()
            .map(|(i, w)| (i, format!("output/remainder/{i}"), w))
            .collect();
        let (div_chain, rem) = Chain::declare_virtual(
            &mut b,
            "output/division",
            od,
            div_radix,
            positions.0,
            &rem_targets,
        );
        chains.push(("output/division", div_chain));

        // real*(2Z - 1) - r = s (virtual spare limbs via Chain::declare_virtual).
        let mut positions = Positions(Vec::new());
        for (i, zb) in z.iter().enumerate() {
            positions.at_radix(dr * i + 1, div_radix, 1, vec![o_real.clone(), o_z(*zb)]);
        }
        positions.at_radix(0, div_radix, -1, vec![o_real.clone()]);
        for (i, c) in rem.iter().enumerate() {
            positions.at_radix(dr * i, div_radix, -1, vec![o_all(*c)]);
        }
        let spare_targets: Vec<(usize, String, Width)> = radix_widths(rbits, div_radix)
            .into_iter()
            .enumerate()
            .map(|(i, w)| (i, format!("output/spare/{i}"), w))
            .collect();
        let (sp_chain, spare) = Chain::declare_virtual(
            &mut b,
            "output/spare",
            od,
            div_radix,
            positions.0,
            &spare_targets,
        );
        chains.push(("output/spare", sp_chain));

        b.identity(
            "output/padding",
            od,
            vec![
                term(1, vec![o_all(q.0)]),
                term(-1, vec![o_all(q.0), o_real.clone()]),
            ],
        );
        // Virtual output = (1 - 2*tau) * q.0 (signed 16).
        let output = b.virtual_ranged(
            "output",
            Def::Pointwise {
                terms: vec![
                    term(1, vec![o_all(q.0)]),
                    term(-2, vec![o_all(tau), o_all(q.0)]),
                ],
            },
            Width::signed(16),
            od,
        );
        self.columns = Some(Columns {
            dot,
            sign,
            magnitude,
            weight,
            quotient,
            remainder,
            mixed_score,
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
            sv_v_bits,
            sv_v,
            total_radix,
            sum_hi,
            total_sign,
            total,
            block,
            shifted,
            div_radix,
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
            if !matches!(relation.columns[id.0 as usize].kind, Kind::Witness(_)) {
                return Ok(());
            }
            values.set(relation, id, v).map_err(Violation::from)
        };
        let set_radix = |v: &[i128], ids: &[ColumnId], rbits: u8| -> Vec<Vec<i64>> {
            let last = ids.len() - 1;
            let rmask = (1i128 << rbits) - 1;
            (0..ids.len())
                .map(|i| {
                    v.iter()
                        .map(|x| {
                            let y = x >> (usize::from(rbits) * i);
                            (if i == last { y } else { y & rmask }) as i64
                        })
                        .collect()
                })
                .collect()
        };
        let put_bytes = |set: &mut dyn FnMut(ColumnId, Vec<i64>) -> Result<(), Violation>,
                         v: &[i128],
                         ids: &[ColumnId]|
         -> Result<(), Violation> {
            if ids.is_empty() {
                return Ok(());
            }
            for (id, column) in ids.iter().zip(set_radix(v, ids, 8)) {
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
        if let Some(ms) = &c.mixed_score {
            let mp = ms.plan;
            let (rad, rad_last) = (1i128 << mp.r, 1i128 << mp.rlast);
            let ratio = rad / rad_last;
            let ji_size = 1usize << (2 * t);
            let mut w1_col = vec![0i64; ji_size];
            let mut mc0_col = vec![0i64; ji_size];
            let mut mc1_col = vec![0i64; ji_size];
            let mut wm_last_col = vec![0i64; ji_size];
            let mut wm_limbs: Vec<Vec<i128>> = vec![vec![0; ji_size]; mp.limbs];
            for (ji, &w_val) in wv.iter().enumerate() {
                let w1 = if ms.w1.is_some() {
                    w_val.div_euclid(rad)
                } else {
                    0
                };
                let w0 = w_val - rad * w1;
                let mc0 = (w0 * m).div_euclid(rad);
                let wm0 = w0 * m - rad * mc0;
                wm_limbs[0][ji] = wm0;
                w1_col[ji] = w1 as i64;
                mc0_col[ji] = mc0 as i64;
                if mp.limbs == 1 {
                    wm_last_col[ji] = (w1 * m + mc0) as i64;
                } else if mp.limbs == 2 {
                    let wm1_full = w1 * m + mc0;
                    let wm2 = if ms.wm_last.is_some() {
                        wm1_full.div_euclid(rad_last)
                    } else {
                        0
                    };
                    wm_limbs[1][ji] = wm1_full - rad_last * wm2;
                    wm_last_col[ji] = wm2 as i64;
                } else {
                    let wm1_full = w1 * m + mc0;
                    let mc1 = wm1_full.div_euclid(rad);
                    wm_limbs[1][ji] = wm1_full - rad * mc1;
                    let wm3 = if ms.wm_last.is_some() {
                        mc1.div_euclid(rad_last)
                    } else {
                        0
                    };
                    wm_limbs[2][ji] = mc1 - rad_last * wm3;
                    mc1_col[ji] = mc1 as i64;
                    wm_last_col[ji] = wm3 as i64;
                }
            }
            if let Some(id) = ms.w1 {
                set(id, w1_col)?;
            }
            if let Some(id) = ms.mc0 {
                set(id, mc0_col)?;
            }
            if let Some(id) = ms.mc1 {
                set(id, mc1_col)?;
            }
            if let Some(id) = ms.wm_last {
                set(id, wm_last_col.clone())?;
            }
            let mut d1_col = vec![0i64; size];
            let mut sign_col = vec![0i64; size];
            let mut c_cols = vec![vec![0i64; size]; mp.limbs];
            for x in 0..size {
                let (j, _, i) = decode(x);
                let ji = (i << t) | j;
                let dv = i128::from(dot[x]);
                let d1 = dv.div_euclid(rad);
                let d0 = dv - rad * d1;
                let sigma = i128::from(d1 < 0);
                let c0 = (d0 * wm_limbs[0][ji] - sigma + rad).div_euclid(rad);
                d1_col[x] = d1 as i64;
                sign_col[x] = sigma as i64;
                c_cols[0][x] = c0 as i64;
                let mut prev = c0;
                for limb in 1..mp.limbs - 1 {
                    let cj = (d0 * wm_limbs[limb][ji] + d1 * wm_limbs[limb - 1][ji] + prev + rad
                        - 1)
                    .div_euclid(rad);
                    c_cols[limb][x] = cj as i64;
                    prev = cj;
                }
                // Solve top carry from captured `score[x]` so tampered scores propagate to `rho_{L-1}`.
                let wm_top = i128::from(wm_last_col[ji]);
                let c_last = i128::from(score[x])
                    - d0 * wm_top
                    - ratio * d1 * wm_limbs[mp.limbs - 1][ji]
                    - rad * d1 * wm_top;
                c_cols[mp.limbs - 1][x] = c_last as i64;
                let _ = prev;
            }
            set(ms.d1, d1_col)?;
            set(c.sign, sign_col)?;
            for (&cid, col) in ms.carries.iter().zip(c_cols) {
                set(cid, col)?;
            }
        } else {
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
        let norm_i128: Vec<i128> = normaliser.iter().map(|v| i128::from(*v)).collect();
        for (id, column) in c.z.iter().zip(set_radix(&norm_i128, &c.z, c.div_radix)) {
            set(*id, column)?;
        }
        // sv * v limbs on (c, group, j) (d + gb + t) and per-block totals on Ob.
        let gb = hb - rb;
        let vd = d + gb + t;
        let vsize = 1usize << vd;
        let n_v = c.sv_v.len();
        let rad_v = 1i128 << c.sv_v_bits;
        let mut sv_v_cols = vec![vec![0i64; vsize]; n_v];
        for x in 0..vsize {
            let lane = x & mask(d);
            let group = (x >> d) & mask(gb);
            let j = x >> (d + gb);
            let mut val = scale(2, &p.value, j) * i128::from(code(2, j, (group << d) | lane));
            for col in sv_v_cols.iter_mut().take(n_v - 1) {
                let d_val = val.rem_euclid(rad_v);
                col[x] = d_val as i64;
                val = val.div_euclid(rad_v);
            }
            sv_v_cols[n_v - 1][x] = val as i64;
        }
        for (&id, col) in c.sv_v.iter().zip(&sv_v_cols) {
            set(id, col.clone())?;
        }
        let osize = 1usize << obd;
        let summed = t - kb;
        if !c.sum_hi.is_empty() {
            for (limb_idx, &hi_id) in c.sum_hi.iter().enumerate() {
                let sv_col = &sv_v_cols[limb_idx];
                let hi_vals: Vec<i64> = (0..osize)
                    .map(|x| {
                        let (lane, head, i, blk) = (
                            x & mask(d),
                            (x >> d) & mask(hb),
                            (x >> (d + hb)) & mask(t),
                            x >> od,
                        );
                        let group = head >> rb;
                        let s: i128 = (0..1usize << summed)
                            .map(|o| {
                                let j = (blk << summed) | o;
                                i128::from(pm[(i << (t + hb)) | (head << t) | j])
                                    * i128::from(sv_col[(j << (d + gb)) | (group << d) | lane])
                            })
                            .sum();
                        s.div_euclid(1 << 16) as i64
                    })
                    .collect();
                set(hi_id, hi_vals)?;
            }
        }
        let x_total: Vec<i128> = (0..osize)
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
                        i128::from(pm[(i << (t + hb)) | (head << t) | j])
                            * scale(2, &p.value, j)
                            * i128::from(code(2, j, (group << d) | lane))
                    })
                    .sum()
            })
            .collect();
        set(
            c.total_sign,
            x_total.iter().map(|v| i64::from(*v < 0)).collect(),
        )?;
        let abs_total: Vec<i128> = x_total.iter().map(|v| v.abs()).collect();
        for (id, column) in c
            .total
            .iter()
            .zip(set_radix(&abs_total, &c.total, c.total_radix))
        {
            set(*id, column)?;
        }
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
        for (id, column) in c.q.1.iter().zip(set_radix(&qv, &c.q.1, c.div_radix)) {
            set(*id, column)?;
        }
        for (id, column) in c.r.iter().zip(set_radix(&rv, &c.r, c.div_radix)) {
            set(*id, column)?;
        }
        for (id, column) in c.s.iter().zip(set_radix(&spare, &c.s, c.div_radix)) {
            set(*id, column)?;
        }
        set(c.output, output)?;
        for (_, chain) in &c.chains {
            chain.assign_around(relation, values, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
