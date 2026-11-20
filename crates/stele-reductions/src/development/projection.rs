//! Affine projection of converted int8 rows (RFC-0026 §5 row 4 and A25; RFC-0025 §2.2/2.5,
//! wide int24 outputs RFC-0004 A14, grouped rows RFC-0004 A15, gated scales RFC-0004 A8;
//! `SCALED-LINEAR.md`).
//!
//! Family 1, no bias: `Y_j = R(V_j * m_j * u * 2^l)` with one round-half-away and
//! int16 (or int24 for wide O/down under RFC-0004 A14) rejection, where `l = e - f + fo` and
//! - per-row input: `V = A = sum_i q_i*w_ji` (one matmul) and `u = s`;
//! - grouped int16 input: `V = A' = sum_i s_k(i)*q_i*w_ji` and `u = 1`. The folded value
//!   `q_i*s_k(i) = b0_i + 256*b1_i` is split into digit rows, `C_t = sum_i b_t,i*w_ji`
//!   is one matmul per digit and `V = C_0 + 256*C_1` (RFC-0004 A15 digit rows);
//! - grouped gated input (`scale_bound > 259`): `s_k` is split into unsigned bytes `s_c`
//!   on the group domain, `q_i*s_k(i) = sum_t 256^t b_t,i` is proven by a radix-256 byte
//!   chain with balanced signed-8 digits `b_t`, and `V = sum_t 256^t C_t`.
//!
//! Wide values never appear in one relation (limb rule, RFC-0026 §3.5):
//! - sign chain: `sum_t 256^t C_t = (1-2*tau) * sum_k 256^k v_k` with byte limbs `v_k`;
//! - scale bytes: `s = sum_c 256^c s_c`;
//! - rounding chain, for `l < 0` with `K = -l`:
//!   `sum v_a*m_b*s_c*256^(a+b+c) + 2^(K-1) = Ymag*2^K + rho`, `rho` in `[0, 2^K)` as
//!   byte limbs; for `l >= 0`: `sum v_a*m_b*s_c*256^(a+b+c+l/8) = Ymag'` and
//!   `Ymag = 2^(l mod 8) * Ymag'`. When `K > bits(Pmax) + 1` the rounding is
//!   identically zero and `Ymag = 0` replaces the chain;
//! - output: for int16, `Y = mask * (1 - 2*tau) * Ymag`, signed 16, zero on padding;
//!   for int24 (RFC-0004 A14), `Ymag` and `Y` are each composed from three byte limbs
//!   (`u8, u8, u8` and `u8, u8, i8`) and linked by a 3-limb radix-256 output chain.
//!
//! Committed columns (RFC-0028 §1.2):
//! - Weight: `weight` (`O × d`, int8 or int4, unless shared/tied).
//! - Witness advice (mixed-radix fast path, covering 100% of L2a/L3b layers):
//!   - Fold (grouped): `digit/1` (`Grouped2`), or `fold_scale/1..2`, `fold/carry0..1`,
//!     `digit/3` (`Grouped4`); low fold digits are virtual.
//!   - Scale split (wide dynamic per-row): `scale/hi`; `scale/lo` is virtual.
//!   - Output `(t, O)`: product/carry advice (`v1`/`c0` or `b1`/`q0` or `b01..b31, q0..q2`),
//!     top quotient (`w2` or `w_t0..w_t2`), `sign`, rounding carries (`rc0..rc_{L-1}`), and
//!     `output/c*` (under `TopSplit::Two`/`Three`). All contractions, remainders `rho*`,
//!     `twos`, and final `output` (`Y`) are virtual.
//! - Witness advice (general fallback path, e.g. `l >= 0` or `K = 1` or `K > 45`):
//!   `digit/hi`, `scale/hi`, `sign`, `byte/*`, `sign/carry*`, `magnitude` (or bytes),
//!   `round/carry*`, and `output/carry*` (int24); `sums`, `remainder`, and `output` are virtual.
//! - Vanishing rounding (`K > bits(Pmax) + 1`): **0** committed witness columns.
//!
//! `m_j` is split into two public bytes per channel; padded channels have `m = 0`.
//! Output-uniqueness lemma P and the mutation table:
//! `agents/reviews/e16-05-projections.md`.

use super::{bit_length, log2_ceil, r, signed_for, term, Builder, Chain, RowOutput, Unsupported};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use stele_ir::relation::{
    ColumnId, Def, Invalid, Kind, Module, Range, Relation, Term, Values, Violation, Width,
    HALF_MODULUS, MAX_VARS, MAX_WIDTH_BITS,
};

/// Largest gated dynamic scale, `ceil(2^30/127)` (RFC-0004 A8).
const GATED_SCALE: u32 = 8454661;
/// Largest grouped (int16) scale, `ceil(32768/127)`.
const GROUPED_SCALE: u32 = 259;

/// Plan data of one projection (RFC-0025 §2.5), for one layer and role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionPlan {
    /// Real rows `T` and dimensions `d` (inner) and `o` (outputs).
    pub rows: usize,
    pub inner: usize,
    pub outputs: usize,
    /// Weight code bits, 4 or 8.
    pub weight_bits: u8,
    /// Public channel mantissas `m_j`, one per output channel.
    pub mantissas: Vec<u16>,
    /// `l = e - f + fo`: weight exponent minus row fraction plus output fraction.
    pub shift: i32,
    /// Signed output width in bits: `16` (default) or `24` (wide O/down, RFC-0004 A14).
    pub output_bits: u8,
}

/// Executor intermediates of one projection over every real row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectionCapture {
    /// `[row][lane]` input codes and `[row][group]` input scales (the row conversion's).
    pub codes: Vec<Vec<i64>>,
    pub scales: Vec<Vec<u32>>,
    /// `[output][lane]` weight codes; padded weight entries are zero.
    pub weights: Vec<Vec<i64>>,
    /// `[row][output]` projection outputs (int16, or int24 when `output_bits == 24`).
    pub outputs: Vec<Vec<i64>>,
}

/// How `Y = W_top * m + rc_last` is reconstructed at the top of a mixed-radix plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TopSplit {
    /// Single signed `w_top`: `Y = w_top*m + rc_last` (or `y0 (u16) + 65536*y1 (s8)` for int24).
    One,
    /// Two-limb `W_top = w_t0 (u8) + 256*w_t1 (s_*)`:
    /// `y_lo (u8) = w_t0*m + rc_last - 256*y_c`, `y_hi (s8 or s16) = w_t1*m + y_c`.
    Two { y_c_width: Width },
    /// Three-limb `W_top = w_t0 (u8) + 256*w_t1 (u8 virtual) + 65536*w_t2 (s_*)` (int24):
    /// `y0 = w_t0*m + rc_last - 256*yc0`, `y1 = w_t1*m + yc0 - 256*yc1`, `y2 = w_t2*m + yc1`.
    Three { yc0_width: Width, yc1_width: Width },
}

/// Mode of the mixed-radix signed rounding fast path (RFC-0028 §1.2, §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MixedKind {
    /// Per-row `!grouped` with unsplit scale `s` (`L in {2, 3}`).
    PerRow {
        v1_width: Width,
        c0_width: Option<Width>,
        q1_width: Option<Width>,
    },
    /// Per-row `!grouped` with split dynamic scale `s = s0 + R0*s1` on `t` (`L in {3, 4}`).
    PerRowSplit {
        s1_width: Width,
        v1_width: Width,
        c0_width: Width,
        c1_width: Width,
        q2_width: Option<Width>,
    },
    /// 2-digit grouped (`V = C0 + 256*C1`, `u = 1`, `L in {2, 3}`).
    Grouped2 {
        b1_width: Option<Width>,
        q0_width: Width,
        q1_width: Option<Width>,
    },
    /// 4-digit wide_grouped (`V = C0 + 256*C1 + 65536*C2 + 2^24*C3`, `u = 1`, `L in {3, 4}`).
    Grouped4 {
        b_widths: [Width; 4],
        q0_width: Width,
        q1_width: Width,
        q2_width: Width,
    },
}

/// Static mixed-radix plan for signed projection rounding (RFC-0028 §1.2).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MixedPlan {
    pub(crate) kind: MixedKind,
    pub(crate) limbs: usize,
    pub(crate) radices: [u8; 4],
    pub(crate) w_top_width: Width,
    pub(crate) top_split: TopSplit,
    pub(crate) rc_widths: [Option<Width>; 4],
    pub(crate) m_width: Width,
}

#[derive(Clone, Debug)]
pub(crate) struct MixedCols {
    pub(crate) plan: MixedPlan,
    /// Row-domain split scale `s1` (`PerRowSplit` only).
    pub(crate) s1: Option<ColumnId>,
    /// Pre-tail witness columns on `out` in plan order (ending with `w_t0` when split top).
    pub(crate) head: Vec<ColumnId>,
    /// Top signed limb `w_L` (or `w_t1`/`w_t2` when split top) on `out`.
    pub(crate) w_top: ColumnId,
    /// Rounding carries `rc_0..rc_{L-1}` on `out`.
    pub(crate) rcs: Vec<ColumnId>,
    /// Output carry / high-byte columns on `out` (`[y1]` for int24 `One`, `[y_c]` for `Two`, `[yc0, yc1]` for `Three`).
    pub(crate) out_cols: Vec<ColumnId>,
}

#[derive(Clone, Debug)]
pub(crate) struct Columns {
    pub(crate) weight: ColumnId,
    /// Grouped gated only: group-domain scale bytes feeding the fold chain.
    pub(crate) fold_scale_bytes: Vec<ColumnId>,
    /// Grouped gated only: fold carries `c_0..c_{n_digits-3}` on `lanes`.
    pub(crate) fold_carries: Vec<ColumnId>,
    /// Grouped only: digit columns `b0..b_{T-1}`.
    pub(crate) digits: Vec<ColumnId>,
    /// One virtual contraction output per digit row.
    pub(crate) sums: Vec<ColumnId>,
    pub(crate) bytes: Vec<ColumnId>,
    pub(crate) sign: ColumnId,
    /// Per-row only: scale bytes.
    pub(crate) scale_bytes: Vec<ColumnId>,
    pub(crate) magnitude: ColumnId,
    /// Wide output only: 3 unsigned byte limbs composing `magnitude`.
    pub(crate) magnitude_bytes: Vec<ColumnId>,
    pub(crate) remainder: Vec<ColumnId>,
    pub(crate) output: ColumnId,
    /// Wide output only: 3 byte limbs (`u8, u8, i8`) composing `output`.
    pub(crate) output_bytes: Vec<ColumnId>,
    pub(crate) chains: Vec<(String, Chain)>,
    /// Present when rounding uses the mixed-radix fast path.
    pub(crate) mixed: Option<MixedCols>,
}

/// Steps of the witness dataflow, in order (see `row::Step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    Digits,
    Sums,
    Sign,
    Bytes,
    ScaleBytes,
    Magnitude,
    Remainder,
    Output,
}

/// Values of every witness column; `inputs` are the read-only module inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectionWitness {
    /// `[lane]` input codes and `[group]` input scales, padded.
    pub(crate) codes: Vec<i64>,
    pub(crate) scales: Vec<i64>,
    /// `[output][lane]` weights, padded.
    pub(crate) weights: Vec<Vec<i64>>,
    /// `[byte][group]` (grouped gated only).
    pub(crate) fold_scale_bytes: Vec<Vec<i64>>,
    /// `[carry][lane]` (grouped gated only).
    pub(crate) fold_carries: Vec<Vec<i64>>,
    /// `[digit][lane]`.
    pub(crate) digits: Vec<Vec<i64>>,
    /// `[digit][out]`.
    pub(crate) sums: Vec<Vec<i64>>,
    pub(crate) sign: Vec<i64>,
    /// `[byte][out]`.
    pub(crate) bytes: Vec<Vec<i64>>,
    /// `[byte][row]`.
    pub(crate) scale_bytes: Vec<Vec<i64>>,
    pub(crate) magnitude: Vec<i64>,
    /// `[byte][out]` (wide output only).
    pub(crate) magnitude_bytes: Vec<Vec<i64>>,
    /// `[limb][out]`.
    pub(crate) remainder: Vec<Vec<i64>>,
    pub(crate) output: Vec<i64>,
    /// `[byte][out]` (wide output only).
    pub(crate) output_bytes: Vec<Vec<i64>>,
    /// Mixed-radix fast-path advice columns.
    pub(crate) mixed_s1: Vec<i64>,
    pub(crate) mixed_head: Vec<Vec<i64>>,
    pub(crate) mixed_w_top: Vec<i64>,
    pub(crate) mixed_rcs: Vec<Vec<i64>>,
    pub(crate) mixed_out: Vec<Vec<i64>>,
}

/// One projection reading a converted row (RFC-0026 §5 row 4).
pub struct Projection {
    prefix: String,
    input: RowOutput,
    weight: Option<ColumnId>,
    plan: ProjectionPlan,
    pub(crate) columns: Option<Columns>,
    /// Matmul domain cap; tests lower it to force row blocks (RFC-0026 A6).
    #[allow(dead_code)]
    pub(crate) limit: u8,
}

/// Bytes needed for `n`.
fn bytes(n: u128) -> usize {
    usize::from(bit_length(n)).div_ceil(8).max(1)
}

fn relation_col_kind(relation: &Relation, id: ColumnId) -> Option<Kind> {
    relation.columns.get(id.0 as usize).map(|c| c.kind.clone())
}

/// Positions of a wide identity, filled term by term.
struct Positions(Vec<Vec<Term>>);

impl Positions {
    fn push(&mut self, position: usize, t: Term) {
        if self.0.len() <= position {
            self.0.resize(position + 1, Vec::new());
        }
        self.0[position].push(t);
    }
}

impl Projection {
    /// `weight`: an already-declared weight column to read (a tied head), or `None`
    /// to declare this role's own weight source here, in plan order (RFC-0026 §2.2).
    pub fn new(
        prefix: &str,
        input: RowOutput,
        weight: Option<ColumnId>,
        plan: ProjectionPlan,
    ) -> Result<Self, Unsupported> {
        let shape = plan.rows > 0
            && (1..=16384).contains(&plan.inner)
            && plan.outputs > 0
            && plan.mantissas.len() == plan.outputs
            && matches!(plan.weight_bits, 4 | 8)
            && matches!(plan.output_bits, 16 | 24)
            && log2_ceil(plan.rows) == input.log_rows
            && log2_ceil(plan.inner) == input.log_dimension;
        if !shape {
            return Err(Unsupported::Shape);
        }
        if input.scale_bound == 0 || input.scale_bound > GATED_SCALE {
            return Err(Unsupported::Policy);
        }
        // The sum matmuls are split into row blocks past MAX_VARS (RFC-0026 A6); every
        // other relation lives on the output domain (rows, outputs).
        if input.log_rows + log2_ceil(plan.outputs) > MAX_VARS {
            return Err(Unsupported::Domain);
        }
        let this = Self {
            prefix: prefix.into(),
            input,
            weight,
            plan,
            columns: None,
            limit: MAX_VARS,
        };
        if this.sum_widths().iter().any(|w| w.bits > MAX_WIDTH_BITS) {
            return Err(Unsupported::Domain);
        }
        Ok(this)
    }

    fn grouped(&self) -> bool {
        self.input.log_group < self.input.log_dimension
    }

    /// Grouped input with a scale past the int16 dynamic limit (gated FFN, RFC-0004 A15):
    /// uses byte-decomposed scales and balanced signed-8 digit rows via a fold chain.
    fn wide_grouped(&self) -> bool {
        self.grouped() && self.input.scale_bound > GROUPED_SCALE
    }

    fn wide_output(&self) -> bool {
        self.plan.output_bits == 24
    }

    fn weight_width(&self) -> Width {
        Width::signed(self.plan.weight_bits)
    }

    /// Digit widths of the matmul left operand.
    fn digit_widths(&self) -> Vec<Width> {
        if self.wide_grouped() {
            let n = bytes(u128::from(self.input.scale_bound));
            let mut w = vec![Width::unsigned(8); n];
            w.push(Width::signed(8));
            w
        } else if self.grouped() {
            vec![Width::unsigned(8), Width::signed(9)]
        } else {
            vec![Width::signed(8)]
        }
    }

    /// Verify the common mixed-radix rounding carries `rc_0..rc_{L-1}`.
    fn check_rcs(
        &self,
        radices: [u8; 4],
        limbs: usize,
        m_mag: u128,
    ) -> Option<([Option<Width>; 4], u128)> {
        let mut rc_widths = [None; 4];
        let mut prev_mag = 0u128;
        for j in 0..limbs {
            let rj = radices[j];
            if !(1..=14).contains(&rj) {
                return None;
            }
            let rad = 1u128 << rj;
            let (rc_max, bound_extra) = if j == 0 {
                // rho0 = -w0*m + tau - 1 + R0*rc0; rc0 = floor((w0*m - tau + R0) / R0).
                (
                    ((rad - 1).saturating_mul(m_mag).saturating_add(rad)) >> rj,
                    2u128,
                )
            } else if j + 1 < limbs {
                // rho_j = -w_j*m - rc_{j-1} + R_j*rc_j.
                (
                    ((rad - 1)
                        .saturating_mul(m_mag)
                        .saturating_add(prev_mag)
                        .saturating_add(rad - 1))
                        >> rj,
                    prev_mag,
                )
            } else {
                // rho_{L-1} = -w_{L-1}*m + R_{L-1}/2 - rc_{L-2} + R_{L-1}*rc_{L-1}.
                let half = rad >> 1;
                (
                    ((rad - 1)
                        .saturating_mul(m_mag)
                        .saturating_add(prev_mag)
                        .saturating_add(half)
                        .saturating_sub(1))
                        >> rj,
                    half.saturating_add(prev_mag),
                )
            };
            let bits = bit_length(rc_max).max(1);
            if bits > 16 {
                return None;
            }
            let w = Width::unsigned(bits);
            let mag = w.magnitude();
            if (rad - 1)
                .saturating_mul(m_mag)
                .saturating_add(bound_extra)
                .saturating_add(rad.saturating_mul(mag))
                > HALF_MODULUS
            {
                return None;
            }
            rc_widths[j] = Some(w);
            prev_mag = mag;
        }
        Some((rc_widths, prev_mag))
    }

    /// Verify the rounding tail and top limb(s) from `top_raw` (bound on the pre-division
    /// value entering `w_{L-1}`), preferring single `w_top` (`TopSplit::One`) over
    /// two-limb `w_t0 (u8) + 256*w_t1` (`TopSplit::Two`).
    fn check_tail(
        &self,
        radices: [u8; 4],
        limbs: usize,
        top_raw: u128,
        m_mag: u128,
    ) -> Option<(Width, TopSplit, [Option<Width>; 4])> {
        let (rc_widths, rc_last_mag) = self.check_rcs(radices, limbs, m_mag)?;
        let rad_last = 1u128 << radices[limbs - 1];

        // Try TopSplit::One first (fewest committed columns).
        let w_top_width = signed_for(top_raw.div_ceil(rad_last));
        if w_top_width.bits <= 16
            && top_raw.saturating_add(rad_last.saturating_mul(w_top_width.magnitude()))
                <= HALF_MODULUS
        {
            let y_bound = w_top_width
                .magnitude()
                .saturating_mul(m_mag)
                .saturating_add(rc_last_mag);
            let y_ok = if self.wide_output() {
                y_bound.saturating_add(65536 * 128) <= HALF_MODULUS
            } else {
                y_bound <= HALF_MODULUS
            };
            if y_ok {
                return Some((w_top_width, TopSplit::One, rc_widths));
            }
        }

        // Fall back to TopSplit::Two: W_top = w_t0 (u8) + 256*w_t1 (s_*).
        let div2 = rad_last << 8;
        let w_t1_width = signed_for(top_raw.div_ceil(div2));
        if w_t1_width.bits > 16
            || top_raw
                .saturating_add(rad_last.saturating_mul(255))
                .saturating_add(div2.saturating_mul(w_t1_width.magnitude()))
                > HALF_MODULUS
        {
            return None;
        }
        let y_c_max = (255u128.saturating_mul(m_mag).saturating_add(rc_last_mag)) >> 8;
        let y_c_bits = bit_length(y_c_max).max(1);
        if y_c_bits > 16 {
            return None;
        }
        let y_c_width = Width::unsigned(y_c_bits);
        let y_c_mag = y_c_width.magnitude();
        if 255u128
            .saturating_mul(m_mag)
            .saturating_add(rc_last_mag)
            .saturating_add(256 * y_c_mag)
            > HALF_MODULUS
        {
            return None;
        }
        if w_t1_width
            .magnitude()
            .saturating_mul(m_mag)
            .saturating_add(y_c_mag)
            > HALF_MODULUS
        {
            return None;
        }
        Some((w_t1_width, TopSplit::Two { y_c_width }, rc_widths))
    }

    /// Select a mixed-radix signed rounding plan (per-row, split-scale per-row,
    /// 2-digit grouped, or 4-digit wide-grouped) when all static bounds fit
    /// `HALF_MODULUS` (RFC-0028 §1.2, §2.2).
    fn mixed_plan(&self, relation: &Relation) -> Option<MixedPlan> {
        if self.vanishing() || self.shift() >= 0 {
            return None;
        }
        let k = (-self.shift()) as u8;
        if !(2..=48).contains(&k) {
            return None;
        }
        let mmax_val = u128::from(self.plan.mantissas.iter().copied().max().unwrap_or(0));
        let m_bits = bit_length(mmax_val).max(1);
        let m_width = Width::unsigned(m_bits);
        let m_mag = m_width.magnitude();

        if self.wide_grouped() {
            let bounds = self.sum_bounds();
            if bounds.len() != 4 {
                return None;
            }
            let mut b_widths = [Width::signed(1); 4];
            for (i, &sb) in bounds.iter().enumerate() {
                if sb > HALF_MODULUS {
                    return None;
                }
                let bw = signed_for(sb.div_ceil(65536));
                if bw.bits > 16 || sb.saturating_add(65536 * bw.magnitude()) > HALF_MODULUS {
                    return None;
                }
                b_widths[i] = bw;
            }
            let w0_raw = 65535u128 + 256 * 65535;
            let q0_width = Width::unsigned(bit_length(w0_raw.div_ceil(4096)).max(1));
            if q0_width.bits > 16 || w0_raw + 4096 * q0_width.magnitude() > HALF_MODULUS {
                return None;
            }
            let w1_raw = q0_width.magnitude() + 16 * b_widths[0].magnitude() + 16 * 65535;
            let q1_width = signed_for(w1_raw.div_ceil(4096));
            if q1_width.bits > 16 || w1_raw + 4096 * q1_width.magnitude() > HALF_MODULUS {
                return None;
            }
            if (25..=32).contains(&k) && self.wide_output() {
                let r2 = k - 24;
                let rad2 = 1u128 << r2;
                let q2_div = rad2 << 8;
                let w2_raw = q1_width.magnitude()
                    + b_widths[1].magnitude()
                    + 65535
                    + 256 * b_widths[2].magnitude();
                let q2_width = signed_for(w2_raw.div_ceil(q2_div));
                if q2_width.bits > 16
                    || w2_raw
                        .saturating_add(rad2 * 255)
                        .saturating_add(q2_div.saturating_mul(q2_width.magnitude()))
                        > HALF_MODULUS
                {
                    return None;
                }
                let shift_b3 = 32 - k;
                let w_top_hi_raw = q2_width
                    .magnitude()
                    .saturating_add((1u128 << shift_b3).saturating_mul(b_widths[3].magnitude()));
                let w_t2_width = signed_for(w_top_hi_raw.div_ceil(256));
                if w_t2_width.bits > 16
                    || w_top_hi_raw.saturating_add(256 * w_t2_width.magnitude()) > HALF_MODULUS
                {
                    return None;
                }
                let radices = [12, 12, r2, 0];
                let (rc_widths, rc_last_mag) = self.check_rcs(radices, 3, m_mag)?;
                let yc0_bits =
                    bit_length((255u128.saturating_mul(m_mag).saturating_add(rc_last_mag)) >> 8)
                        .max(1);
                if yc0_bits > 16 {
                    return None;
                }
                let yc0_width = Width::unsigned(yc0_bits);
                if 255u128
                    .saturating_mul(m_mag)
                    .saturating_add(rc_last_mag)
                    .saturating_add(256 * yc0_width.magnitude())
                    > HALF_MODULUS
                {
                    return None;
                }
                let yc1_bits = bit_length(
                    (255u128
                        .saturating_mul(m_mag)
                        .saturating_add(yc0_width.magnitude()))
                        >> 8,
                )
                .max(1);
                if yc1_bits > 16 {
                    return None;
                }
                let yc1_width = Width::unsigned(yc1_bits);
                if 255u128
                    .saturating_mul(m_mag)
                    .saturating_add(yc0_width.magnitude())
                    .saturating_add(256 * yc1_width.magnitude())
                    > HALF_MODULUS
                {
                    return None;
                }
                if w_t2_width
                    .magnitude()
                    .saturating_mul(m_mag)
                    .saturating_add(yc1_width.magnitude())
                    > HALF_MODULUS
                {
                    return None;
                }
                return Some(MixedPlan {
                    kind: MixedKind::Grouped4 {
                        b_widths,
                        q0_width,
                        q1_width,
                        q2_width,
                    },
                    limbs: 3,
                    radices,
                    w_top_width: w_t2_width,
                    top_split: TopSplit::Three {
                        yc0_width,
                        yc1_width,
                    },
                    rc_widths,
                    m_width,
                });
            }
            if !(33..=45).contains(&k) {
                return None;
            }
            let r3 = k - 32;
            let w2_raw = q1_width.magnitude() + b_widths[1].magnitude() + 65535;
            let q2_width = signed_for(w2_raw.div_ceil(256));
            if q2_width.bits > 16 || w2_raw + 256 * q2_width.magnitude() > HALF_MODULUS {
                return None;
            }
            let w3_raw =
                q2_width.magnitude() + b_widths[2].magnitude() + 256 * b_widths[3].magnitude();
            let radices = [12, 12, 8, r3];
            let (w_top_width, top_split, rc_widths) = self.check_tail(radices, 4, w3_raw, m_mag)?;
            return Some(MixedPlan {
                kind: MixedKind::Grouped4 {
                    b_widths,
                    q0_width,
                    q1_width,
                    q2_width,
                },
                limbs: 4,
                radices,
                w_top_width,
                top_split,
                rc_widths,
                m_width,
            });
        }

        if self.grouped() {
            let bounds = self.sum_bounds();
            if bounds.len() != 2 || bounds[0] > HALF_MODULUS || bounds[1] > HALF_MODULUS {
                return None;
            }
            let (c0_max, c1_max) = (bounds[0], bounds[1]);
            for limbs in [2usize, 3usize] {
                for use_b1 in [false, true] {
                    let mut best: Option<(u16, MixedPlan)> = None;
                    for r0 in 1..=13u8 {
                        if r0 >= k {
                            break;
                        }
                        let rad0 = 1u128 << r0;
                        let (b1_width, q0_width, w1_raw) = if !use_b1 {
                            let w0_raw = c0_max.saturating_add(256 * c1_max);
                            let q0_w = signed_for(w0_raw.div_ceil(rad0));
                            if q0_w.bits > 16
                                || w0_raw.saturating_add(rad0.saturating_mul(q0_w.magnitude()))
                                    > HALF_MODULUS
                            {
                                continue;
                            }
                            (None, q0_w, q0_w.magnitude())
                        } else {
                            let b1_w = signed_for(c1_max.div_ceil(rad0));
                            if b1_w.bits > 16
                                || c1_max.saturating_add(rad0.saturating_mul(b1_w.magnitude()))
                                    > HALF_MODULUS
                            {
                                continue;
                            }
                            let w0_raw = c0_max.saturating_add(256 * (rad0 - 1));
                            let q0_w = signed_for(w0_raw.div_ceil(rad0));
                            if q0_w.bits > 16
                                || w0_raw.saturating_add(rad0.saturating_mul(q0_w.magnitude()))
                                    > HALF_MODULUS
                            {
                                continue;
                            }
                            (
                                Some(b1_w),
                                q0_w,
                                q0_w.magnitude().saturating_add(256 * b1_w.magnitude()),
                            )
                        };
                        if limbs == 2 {
                            let r1 = k - r0;
                            if r1 > 13 {
                                continue;
                            }
                            let radices = [r0, r1, 0, 0];
                            let Some((w_top_width, top_split, rc_widths)) =
                                self.check_tail(radices, 2, w1_raw, m_mag)
                            else {
                                continue;
                            };
                            let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                            let score = split_pen
                                + u16::from(b1_width.map_or(0, |w| w.bits))
                                + u16::from(q0_width.bits)
                                + u16::from(w_top_width.bits);
                            let plan = MixedPlan {
                                kind: MixedKind::Grouped2 {
                                    b1_width,
                                    q0_width,
                                    q1_width: None,
                                },
                                limbs: 2,
                                radices,
                                w_top_width,
                                top_split,
                                rc_widths,
                                m_width,
                            };
                            if best.is_none_or(|(s, _)| score < s) {
                                best = Some((score, plan));
                            }
                        } else {
                            for r1 in 1..=13u8 {
                                if r0 + r1 >= k {
                                    break;
                                }
                                let r2 = k - r0 - r1;
                                if r2 > 13 {
                                    continue;
                                }
                                let rad1 = 1u128 << r1;
                                let q1_w = signed_for(w1_raw.div_ceil(rad1));
                                if q1_w.bits > 16
                                    || w1_raw.saturating_add(rad1.saturating_mul(q1_w.magnitude()))
                                        > HALF_MODULUS
                                {
                                    continue;
                                }
                                let radices = [r0, r1, r2, 0];
                                let Some((w_top_width, top_split, rc_widths)) =
                                    self.check_tail(radices, 3, q1_w.magnitude(), m_mag)
                                else {
                                    continue;
                                };
                                let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                                let score = split_pen
                                    + u16::from(b1_width.map_or(0, |w| w.bits))
                                    + u16::from(q0_width.bits)
                                    + u16::from(q1_w.bits)
                                    + u16::from(w_top_width.bits);
                                let plan = MixedPlan {
                                    kind: MixedKind::Grouped2 {
                                        b1_width,
                                        q0_width,
                                        q1_width: Some(q1_w),
                                    },
                                    limbs: 3,
                                    radices,
                                    w_top_width,
                                    top_split,
                                    rc_widths,
                                    m_width,
                                };
                                if best.is_none_or(|(s, _)| score < s) {
                                    best = Some((score, plan));
                                }
                            }
                        }
                    }
                    if let Some((_, plan)) = best {
                        return Some(plan);
                    }
                }
            }
            return None;
        }

        // Per-row (!grouped): try unsplit scale (L = 2, then L = 3), then split scale (L = 3, 4).
        let col_mag =
            |id: ColumnId, fallback: u128| relation.column_magnitude(id).unwrap_or(fallback);
        let codes_mag = col_mag(self.input.codes, 128);
        let vmax = (codes_mag * self.weight_width().magnitude()) << self.input.log_dimension;
        if vmax > HALF_MODULUS {
            return None;
        }
        let smax = match relation_col_kind(relation, self.input.scale) {
            Some(Kind::Public(_)) => {
                (1u128 << bit_length(u128::from(self.input.scale_bound)).max(1)) - 1
            }
            _ => col_mag(
                self.input.scale,
                (1u128 << bit_length(u128::from(self.input.scale_bound))) - 1,
            ),
        };

        for limbs in [2usize, 3usize] {
            let mut best: Option<(u16, MixedPlan)> = None;
            for r0 in 1..=14u8 {
                if r0 >= k {
                    break;
                }
                let rad0 = 1u128 << r0;
                let v1_width = signed_for(vmax.div_ceil(rad0));
                if v1_width.bits > 16
                    || vmax.saturating_add(rad0.saturating_mul(v1_width.magnitude())) > HALF_MODULUS
                {
                    continue;
                }
                let c0_max = ((rad0 - 1).saturating_mul(smax)) >> r0;
                let c0_width = if c0_max == 0 {
                    None
                } else {
                    let bits = bit_length(c0_max).max(1);
                    if bits > 16 {
                        continue;
                    }
                    Some(Width::unsigned(bits))
                };
                let c0_mag = c0_width.map_or(0, Width::magnitude);
                if (rad0 - 1)
                    .saturating_mul(smax)
                    .saturating_add(rad0.saturating_mul(c0_mag))
                    > HALF_MODULUS
                {
                    continue;
                }
                let w1_raw = v1_width
                    .magnitude()
                    .saturating_mul(smax)
                    .saturating_add(c0_mag);
                if limbs == 2 {
                    let r1 = k - r0;
                    if r1 > 14 {
                        continue;
                    }
                    let radices = [r0, r1, 0, 0];
                    let Some((w_top_width, top_split, rc_widths)) =
                        self.check_tail(radices, 2, w1_raw, m_mag)
                    else {
                        continue;
                    };
                    let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                    let score = split_pen
                        + u16::from(v1_width.bits)
                        + u16::from(w_top_width.bits)
                        + u16::from(rc_widths[0].map_or(0, |w| w.bits))
                        + u16::from(rc_widths[1].map_or(0, |w| w.bits));
                    let plan = MixedPlan {
                        kind: MixedKind::PerRow {
                            v1_width,
                            c0_width,
                            q1_width: None,
                        },
                        limbs: 2,
                        radices,
                        w_top_width,
                        top_split,
                        rc_widths,
                        m_width,
                    };
                    if best.is_none_or(|(s, _)| score < s) {
                        best = Some((score, plan));
                    }
                } else {
                    for r1 in 1..=14u8 {
                        if r0 + r1 >= k {
                            break;
                        }
                        let r2 = k - r0 - r1;
                        if r2 > 14 {
                            continue;
                        }
                        let rad1 = 1u128 << r1;
                        let q1_w = signed_for(w1_raw.div_ceil(rad1));
                        if q1_w.bits > 16
                            || w1_raw.saturating_add(rad1.saturating_mul(q1_w.magnitude()))
                                > HALF_MODULUS
                        {
                            continue;
                        }
                        let radices = [r0, r1, r2, 0];
                        let Some((w_top_width, top_split, rc_widths)) =
                            self.check_tail(radices, 3, q1_w.magnitude(), m_mag)
                        else {
                            continue;
                        };
                        let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                        let score = split_pen
                            + u16::from(v1_width.bits)
                            + u16::from(q1_w.bits)
                            + u16::from(w_top_width.bits);
                        let plan = MixedPlan {
                            kind: MixedKind::PerRow {
                                v1_width,
                                c0_width,
                                q1_width: Some(q1_w),
                            },
                            limbs: 3,
                            radices,
                            w_top_width,
                            top_split,
                            rc_widths,
                            m_width,
                        };
                        if best.is_none_or(|(s, _)| score < s) {
                            best = Some((score, plan));
                        }
                    }
                }
            }
            if let Some((_, plan)) = best {
                return Some(plan);
            }
        }

        // Split-scale per-row (large dynamic gated scales, L = 3 or L = 4).
        for limbs in [3usize, 4usize] {
            let mut best: Option<(u16, MixedPlan)> = None;
            for r0 in 8..=13u8 {
                let rad0 = 1u128 << r0;
                let s1_max = smax >> r0;
                if s1_max == 0 {
                    continue;
                }
                let s1_bits = bit_length(s1_max).max(1);
                if s1_bits > 16 {
                    continue;
                }
                let s1_width = Width::unsigned(s1_bits);
                if smax.saturating_add(rad0.saturating_mul(s1_width.magnitude())) > HALF_MODULUS {
                    continue;
                }
                let v1_width = signed_for(vmax.div_ceil(rad0));
                if v1_width.bits > 16
                    || vmax.saturating_add(rad0.saturating_mul(v1_width.magnitude())) > HALF_MODULUS
                {
                    continue;
                }
                let c0_max = ((rad0 - 1).saturating_mul(rad0 - 1)) >> r0;
                let c0_bits = bit_length(c0_max).max(1);
                if c0_bits > 16 {
                    continue;
                }
                let c0_width = Width::unsigned(c0_bits);
                if (rad0 - 1)
                    .saturating_mul(rad0 - 1)
                    .saturating_add(rad0.saturating_mul(c0_width.magnitude()))
                    > HALF_MODULUS
                {
                    continue;
                }
                let w1_raw = (rad0 - 1)
                    .saturating_mul(s1_width.magnitude())
                    .saturating_add(v1_width.magnitude().saturating_mul(rad0 - 1))
                    .saturating_add(c0_width.magnitude());
                for r1 in 8..=r0 {
                    if r0 + r1 >= k {
                        break;
                    }
                    let rad1 = 1u128 << r1;
                    let ratio = 1u128 << (r0 - r1);
                    let c1_width = signed_for(w1_raw.div_ceil(rad1));
                    if c1_width.bits > 16
                        || w1_raw.saturating_add(rad1.saturating_mul(c1_width.magnitude()))
                            > HALF_MODULUS
                    {
                        continue;
                    }
                    let w2_raw = ratio
                        .saturating_mul(v1_width.magnitude())
                        .saturating_mul(s1_width.magnitude())
                        .saturating_add(c1_width.magnitude());
                    if limbs == 3 {
                        let r2 = k - r0 - r1;
                        if r2 > 13 {
                            continue;
                        }
                        let radices = [r0, r1, r2, 0];
                        let Some((w_top_width, top_split, rc_widths)) =
                            self.check_tail(radices, 3, w2_raw, m_mag)
                        else {
                            continue;
                        };
                        let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                        let score = split_pen
                            + u16::from(v1_width.bits)
                            + u16::from(c0_width.bits)
                            + u16::from(c1_width.bits)
                            + u16::from(w_top_width.bits);
                        let plan = MixedPlan {
                            kind: MixedKind::PerRowSplit {
                                s1_width,
                                v1_width,
                                c0_width,
                                c1_width,
                                q2_width: None,
                            },
                            limbs: 3,
                            radices,
                            w_top_width,
                            top_split,
                            rc_widths,
                            m_width,
                        };
                        if best.is_none_or(|(s, _)| score < s) {
                            best = Some((score, plan));
                        }
                    } else {
                        for r2 in 4..=13u8 {
                            if r0 + r1 + r2 >= k {
                                break;
                            }
                            let r3 = k - r0 - r1 - r2;
                            if r3 > 13 {
                                continue;
                            }
                            let rad2 = 1u128 << r2;
                            let q2_w = signed_for(w2_raw.div_ceil(rad2));
                            if q2_w.bits > 16
                                || w2_raw.saturating_add(rad2.saturating_mul(q2_w.magnitude()))
                                    > HALF_MODULUS
                            {
                                continue;
                            }
                            let radices = [r0, r1, r2, r3];
                            let Some((w_top_width, top_split, rc_widths)) =
                                self.check_tail(radices, 4, q2_w.magnitude(), m_mag)
                            else {
                                continue;
                            };
                            let split_pen = if top_split == TopSplit::One { 0 } else { 200 };
                            let score = split_pen
                                + u16::from(v1_width.bits)
                                + u16::from(c0_width.bits)
                                + u16::from(c1_width.bits)
                                + u16::from(q2_w.bits)
                                + u16::from(w_top_width.bits);
                            let plan = MixedPlan {
                                kind: MixedKind::PerRowSplit {
                                    s1_width,
                                    v1_width,
                                    c0_width,
                                    c1_width,
                                    q2_width: Some(q2_w),
                                },
                                limbs: 4,
                                radices,
                                w_top_width,
                                top_split,
                                rc_widths,
                                m_width,
                            };
                            if best.is_none_or(|(s, _)| score < s) {
                                best = Some((score, plan));
                            }
                        }
                    }
                }
            }
            if let Some((_, plan)) = best {
                return Some(plan);
            }
        }
        None
    }

    fn sum_bounds(&self) -> Vec<u128> {
        let w = self.weight_width().magnitude();
        self.digit_widths()
            .iter()
            .map(|d| (d.magnitude() * w) << self.input.log_dimension)
            .collect()
    }

    fn sum_widths(&self) -> Vec<Width> {
        self.sum_bounds().into_iter().map(signed_for).collect()
    }

    /// `|V| <= vmax` for every input within its declared widths.
    fn vmax(&self) -> u128 {
        self.sum_bounds()
            .iter()
            .enumerate()
            .map(|(k, c)| c << (8 * k))
            .sum()
    }

    /// The rounding is identically zero: `K > bits(Pmax) + 1`.
    pub(crate) fn vanishing(&self) -> bool {
        // The scale bytes bound s below 2^bits(scale_bound).
        let u_max = if self.grouped() {
            1
        } else {
            (1u128 << bit_length(u128::from(self.input.scale_bound))) - 1
        };
        let pmax = self.vmax() * 65535 * u_max;
        self.shift() < 0 && (-self.shift()) as u32 > u32::from(bit_length(pmax)) + 1
    }

    /// `l`, with a left shift clamped to `output_bits`: for `l >= output_bits` every
    /// `P >= 1` leaves the signed output range and `P = 0` stays 0, so
    /// `min(l, output_bits)` has the same accepted set.
    fn shift(&self) -> i32 {
        self.plan.shift.min(i32::from(self.plan.output_bits))
    }

    /// `(offset bytes, output factor)` of a left shift.
    fn left(&self) -> (usize, i64) {
        let l = self.shift();
        if l >= 0 {
            ((l / 8) as usize, 1i64 << (l % 8))
        } else {
            (0, 1)
        }
    }

    /// Output column (`T x o`, signed 16 or signed 24); `None` before `declare`.
    pub fn output(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.output)
    }

    /// The weight column read (declared here unless one was supplied).
    pub fn weight(&self) -> Option<ColumnId> {
        self.columns.as_ref().map(|c| c.weight)
    }

    pub(crate) fn logs(&self) -> (u8, u8, u8, u8) {
        let i = self.input;
        (
            i.log_rows,
            i.log_dimension,
            i.log_group,
            log2_ceil(self.plan.outputs),
        )
    }

    pub(crate) fn real(&self, x: usize) -> bool {
        let (_, _, _, lo) = self.logs();
        (x >> lo) < self.plan.rows && (x & ((1 << lo) - 1)) < self.plan.outputs
    }

    fn output_id(&self) -> ColumnId {
        self.columns.as_ref().map_or(ColumnId(0), |c| c.output)
    }

    /// The capture's inputs over the padded layout; a public (static) scale column
    /// is read as declared.
    pub(crate) fn source(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
    ) -> Result<ProjectionWitness, Violation> {
        let (t, ld, lg, lo) = self.logs();
        let plan = &self.plan;
        let real_groups = plan.inner.div_ceil(1 << lg);
        let ok = capture.codes.len() == plan.rows
            && capture.codes.iter().all(|row| row.len() == plan.inner)
            && capture.scales.len() == plan.rows
            && capture.scales.iter().all(|row| row.len() == real_groups)
            && capture.weights.len() == plan.outputs
            && capture.weights.iter().all(|row| row.len() == plan.inner)
            && capture.outputs.len() == plan.rows
            && capture.outputs.iter().all(|row| row.len() == plan.outputs);
        if !ok {
            return Err(Invalid::Column(self.output_id()).into());
        }
        let per_row = 1usize << (ld - lg);
        let scales = match relation.column(self.input.scale).map(|c| &c.kind) {
            Some(Kind::Public(v)) => v.clone(),
            _ => (0..1usize << (t + ld - lg))
                .map(|k| {
                    let (row, group) = (k / per_row, k % per_row);
                    if row < plan.rows && group < real_groups {
                        i64::from(capture.scales[row][group])
                    } else {
                        0
                    }
                })
                .collect(),
        };
        let codes = (0..1usize << (t + ld))
            .map(|x| {
                let (row, i) = (x >> ld, x & ((1 << ld) - 1));
                if row < plan.rows && i < plan.inner {
                    capture.codes[row][i]
                } else {
                    0
                }
            })
            .collect();
        let weights = (0..1usize << lo)
            .map(|j| {
                let mut row = capture.weights.get(j).cloned().unwrap_or_default();
                row.resize(1 << ld, 0);
                row
            })
            .collect();
        Ok(ProjectionWitness {
            codes,
            scales,
            weights,
            ..ProjectionWitness::default()
        })
    }

    /// Recompute every step from `from` on (see `row::RowConversion::complete`).
    pub(crate) fn complete(&self, w: &mut ProjectionWitness, from: Step, frozen: Option<Step>) {
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (1usize << (t + ld), 1usize << (t + lo));
        let at = |step: Step| from <= step && frozen != Some(step);
        let c = self.columns.as_ref();
        let (n_fold_scale, n_bytes, n_scale, n_rem) = c.map_or((0, 0, 0, 0), |c| {
            (
                c.fold_scale_bytes.len(),
                c.bytes.len(),
                c.scale_bytes.len(),
                c.remainder.len(),
            )
        });
        let grouped = self.grouped();
        let wide_grouped = self.wide_grouped();
        let wide_output = self.wide_output();
        if at(Step::Digits) && grouped {
            if wide_grouped {
                let groups = 1usize << (t + ld - lg);
                w.fold_scale_bytes = (0..n_fold_scale)
                    .map(|k| {
                        (0..groups)
                            .map(|g| {
                                let s = w.scales[g];
                                if k + 1 == n_fold_scale {
                                    s >> (8 * k)
                                } else {
                                    (s >> (8 * k)) & 255
                                }
                            })
                            .collect()
                    })
                    .collect();
                let n_digits = self.digit_widths().len();
                let mut digits = vec![Vec::with_capacity(lanes); n_digits];
                let mut fcarries = vec![Vec::with_capacity(lanes); n_digits.saturating_sub(2)];
                for x in 0..lanes {
                    let code = i128::from(w.codes[x]);
                    let g = x >> lg;
                    let mut prev = 0i128;
                    for k in 0..n_digits - 1 {
                        let sk = i128::from(w.fold_scale_bytes[k][g]);
                        let raw = code * sk + prev;
                        let d = raw.rem_euclid(256);
                        let q = raw.div_euclid(256);
                        digits[k].push(d as i64);
                        if k + 2 < n_digits {
                            fcarries[k].push(q as i64);
                        } else {
                            digits[n_digits - 1].push(q as i64);
                        }
                        prev = q;
                    }
                }
                w.fold_carries = fcarries;
                w.digits = digits;
            } else {
                let folded: Vec<i64> = (0..lanes).map(|x| w.codes[x] * w.scales[x >> lg]).collect();
                w.digits = vec![
                    folded.iter().map(|f| f.rem_euclid(256)).collect(),
                    folded.iter().map(|f| f.div_euclid(256)).collect(),
                ];
            }
        }
        if at(Step::Sums) {
            let operands: Vec<&Vec<i64>> = if grouped {
                w.digits.iter().collect()
            } else {
                vec![&w.codes]
            };
            // Every output is an independent integer dot product.
            w.sums = operands
                .iter()
                .map(|operand| {
                    let mut sums = vec![0i64; out];
                    stele_sumcheck::parallel::for_each_chunk(&mut sums, |start, chunk| {
                        for (k, sum) in chunk.iter_mut().enumerate() {
                            let x = start + k;
                            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
                            *sum = (0..1usize << ld)
                                .map(|i| operand[(row << ld) | i] * w.weights[j][i])
                                .sum();
                        }
                    });
                    sums
                })
                .collect();
        }
        if let Some(mc) = c.and_then(|c| c.mixed.as_ref()) {
            let mp = mc.plan;
            let n_head = mc.head.len();
            let n_out = mc.out_cols.len();
            let mut head_cols = vec![Vec::with_capacity(out); n_head];
            let mut w_top_col = Vec::with_capacity(out);
            let mut tau_col = Vec::with_capacity(out);
            let mut rc_cols = vec![Vec::with_capacity(out); mp.limbs];
            let mut out_aux = vec![Vec::with_capacity(out); n_out];
            let mut out_col = Vec::with_capacity(out);
            let rads: [i128; 4] = mp.radices.map(|rb| 1i128 << rb);
            let s1_col: Vec<i64> = if matches!(mp.kind, MixedKind::PerRowSplit { .. }) {
                (0..1usize << t)
                    .map(|row| {
                        let s = i128::from(w.scales[row << (ld - lg)]);
                        s.div_euclid(rads[0]) as i64
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let k_shift = (-self.shift()) as u8;
            for x in 0..out {
                let (row, j) = (x >> lo, x & ((1 << lo) - 1));
                let m = self.plan.mantissas.get(j).map_or(0, |&m| i128::from(m));
                let mut ws = [0i128; 4];
                // `top_full`: the integer at bit `2^K` (`W_top = w_t0 + 256*w_t1 + ...`).
                let w_top_full: i128;
                let w_sign_limb: i128;
                let mut w_t0_val = 0i128;
                let mut w_t1_val = 0i128;
                if matches!(mp.top_split, TopSplit::Three { .. }) {
                    // Grouped4 with limbs == 3, k in 25..=32.
                    let mut b0 = [0i128; 4];
                    let mut b1 = [0i128; 4];
                    for k in 0..4 {
                        let ck = i128::from(w.sums[k][x]);
                        b1[k] = ck.div_euclid(65536);
                        b0[k] = ck - 65536 * b1[k];
                        head_cols[k].push(b1[k] as i64);
                    }
                    let w0_full = b0[0] + 256 * b0[1];
                    let q0 = w0_full.div_euclid(4096);
                    ws[0] = w0_full - 4096 * q0;
                    let w1_full = q0 + 16 * b1[0] + 16 * b0[2];
                    let q1 = w1_full.div_euclid(4096);
                    ws[1] = w1_full - 4096 * q1;
                    let w2_full = q1 + b1[1] + b0[3] + 256 * b1[2];
                    let q2_div = rads[2] << 8;
                    let q2 = w2_full.div_euclid(q2_div);
                    let rem2 = w2_full - q2_div * q2;
                    w_t0_val = rem2.div_euclid(rads[2]);
                    ws[2] = rem2 - rads[2] * w_t0_val;
                    let w_top_hi = q2 + (1i128 << (32 - k_shift)) * b1[3];
                    let w_t2 = w_top_hi.div_euclid(256);
                    w_t1_val = w_top_hi - 256 * w_t2;
                    w_top_full = w_t0_val + 256 * w_t1_val + 65536 * w_t2;
                    w_sign_limb = w_t2;
                    head_cols[4].push(q0 as i64);
                    head_cols[5].push(q1 as i64);
                    head_cols[6].push(q2 as i64);
                    head_cols[7].push(w_t0_val as i64);
                } else {
                    let top_pre: i128;
                    let mut h = 0usize;
                    match mp.kind {
                        MixedKind::PerRow {
                            c0_width, q1_width, ..
                        } => {
                            let v = i128::from(w.sums[0][x]);
                            let s = i128::from(w.scales[row << (ld - lg)]);
                            let v1 = v.div_euclid(rads[0]);
                            let v0 = v - rads[0] * v1;
                            let c0 = if c0_width.is_some() {
                                (v0 * s).div_euclid(rads[0])
                            } else {
                                0
                            };
                            ws[0] = v0 * s - rads[0] * c0;
                            let w1_full = v1 * s + c0;
                            head_cols[h].push(v1 as i64);
                            h += 1;
                            if c0_width.is_some() {
                                head_cols[h].push(c0 as i64);
                                h += 1;
                            }
                            if q1_width.is_some() {
                                let q1 = w1_full.div_euclid(rads[1]);
                                ws[1] = w1_full - rads[1] * q1;
                                head_cols[h].push(q1 as i64);
                                h += 1;
                                top_pre = q1;
                            } else {
                                top_pre = w1_full;
                            }
                        }
                        MixedKind::PerRowSplit { q2_width, .. } => {
                            let v = i128::from(w.sums[0][x]);
                            let s = i128::from(w.scales[row << (ld - lg)]);
                            let s1 = i128::from(s1_col[row]);
                            let s0 = s - rads[0] * s1;
                            let v1 = v.div_euclid(rads[0]);
                            let v0 = v - rads[0] * v1;
                            let c0 = (v0 * s0).div_euclid(rads[0]);
                            ws[0] = v0 * s0 - rads[0] * c0;
                            let w1_full = v0 * s1 + v1 * s0 + c0;
                            let c1 = w1_full.div_euclid(rads[1]);
                            ws[1] = w1_full - rads[1] * c1;
                            let ratio = 1i128 << (mp.radices[0] - mp.radices[1]);
                            let w2_full = ratio * v1 * s1 + c1;
                            head_cols[0].push(v1 as i64);
                            head_cols[1].push(c0 as i64);
                            head_cols[2].push(c1 as i64);
                            h = 3;
                            if q2_width.is_some() {
                                let q2 = w2_full.div_euclid(rads[2]);
                                ws[2] = w2_full - rads[2] * q2;
                                head_cols[3].push(q2 as i64);
                                h = 4;
                                top_pre = q2;
                            } else {
                                top_pre = w2_full;
                            }
                        }
                        MixedKind::Grouped2 {
                            b1_width, q1_width, ..
                        } => {
                            let c0 = i128::from(w.sums[0][x]);
                            let c1 = i128::from(w.sums[1][x]);
                            let w1_full = if b1_width.is_some() {
                                let b1 = c1.div_euclid(rads[0]);
                                let b0 = c1 - rads[0] * b1;
                                let w0_full = c0 + 256 * b0;
                                let q0 = w0_full.div_euclid(rads[0]);
                                ws[0] = w0_full - rads[0] * q0;
                                head_cols[h].push(b1 as i64);
                                h += 1;
                                head_cols[h].push(q0 as i64);
                                h += 1;
                                q0 + 256 * b1
                            } else {
                                let w0_full = c0 + 256 * c1;
                                let q0 = w0_full.div_euclid(rads[0]);
                                ws[0] = w0_full - rads[0] * q0;
                                head_cols[h].push(q0 as i64);
                                h += 1;
                                q0
                            };
                            if q1_width.is_some() {
                                let q1 = w1_full.div_euclid(rads[1]);
                                ws[1] = w1_full - rads[1] * q1;
                                head_cols[h].push(q1 as i64);
                                h += 1;
                                top_pre = q1;
                            } else {
                                top_pre = w1_full;
                            }
                        }
                        MixedKind::Grouped4 { .. } => {
                            let mut b0 = [0i128; 4];
                            let mut b1 = [0i128; 4];
                            for k in 0..4 {
                                let ck = i128::from(w.sums[k][x]);
                                b1[k] = ck.div_euclid(65536);
                                b0[k] = ck - 65536 * b1[k];
                                head_cols[k].push(b1[k] as i64);
                            }
                            let w0_full = b0[0] + 256 * b0[1];
                            let q0 = w0_full.div_euclid(4096);
                            ws[0] = w0_full - 4096 * q0;
                            let w1_full = q0 + 16 * b1[0] + 16 * b0[2];
                            let q1 = w1_full.div_euclid(4096);
                            ws[1] = w1_full - 4096 * q1;
                            let w2_full = q1 + b1[1] + b0[3];
                            let q2 = w2_full.div_euclid(256);
                            ws[2] = w2_full - 256 * q2;
                            head_cols[4].push(q0 as i64);
                            head_cols[5].push(q1 as i64);
                            head_cols[6].push(q2 as i64);
                            h = 7;
                            top_pre = q2 + b1[2] + 256 * b1[3];
                        }
                    }
                    let rad_last = rads[mp.limbs - 1];
                    w_top_full = top_pre.div_euclid(rad_last);
                    ws[mp.limbs - 1] = top_pre - rad_last * w_top_full;
                    match mp.top_split {
                        TopSplit::One => {
                            w_sign_limb = w_top_full;
                        }
                        TopSplit::Two { .. } => {
                            w_sign_limb = w_top_full.div_euclid(256);
                            w_t0_val = w_top_full - 256 * w_sign_limb;
                            head_cols[h].push(w_t0_val as i64);
                        }
                        TopSplit::Three { .. } => unreachable!(),
                    }
                }
                let tau = i128::from(w_sign_limb < 0);
                let mut prev_rc = 0i128;
                for limb in 0..mp.limbs {
                    let rad = rads[limb];
                    let rc = if limb == 0 {
                        (ws[0] * m - tau + rad).div_euclid(rad)
                    } else if limb + 1 < mp.limbs {
                        (ws[limb] * m + prev_rc + rad - 1).div_euclid(rad)
                    } else {
                        (ws[limb] * m + prev_rc + (rad >> 1) - 1).div_euclid(rad)
                    };
                    rc_cols[limb].push(rc as i64);
                    prev_rc = rc;
                }
                let y = w_top_full * m + prev_rc;
                w_top_col.push(w_sign_limb as i64);
                tau_col.push(tau as i64);
                match mp.top_split {
                    TopSplit::One => {
                        if wide_output {
                            out_aux[0].push(y.div_euclid(1 << 16) as i64);
                        }
                    }
                    TopSplit::Two { .. } => {
                        let yc = (w_t0_val * m + prev_rc).div_euclid(256);
                        out_aux[0].push(yc as i64);
                    }
                    TopSplit::Three { .. } => {
                        let yc0 = (w_t0_val * m + prev_rc).div_euclid(256);
                        let yc1 = (w_t1_val * m + yc0).div_euclid(256);
                        out_aux[0].push(yc0 as i64);
                        out_aux[1].push(yc1 as i64);
                    }
                }
                out_col.push(y as i64);
            }
            if at(Step::Sign) {
                w.sign = tau_col;
            }
            if at(Step::Output) {
                w.output = out_col;
            }
            w.mixed_s1 = s1_col;
            w.mixed_head = head_cols;
            w.mixed_w_top = w_top_col;
            w.mixed_rcs = rc_cols;
            w.mixed_out = out_aux;
            return;
        }
        let wide = |w: &ProjectionWitness, x: usize| -> i128 {
            w.sums
                .iter()
                .enumerate()
                .map(|(k, s)| i128::from(s[x]) << (8 * k))
                .sum()
        };
        if at(Step::Sign) {
            w.sign = (0..out).map(|x| i64::from(wide(w, x) < 0)).collect();
        }
        if at(Step::Bytes) {
            // sum 256^t C_t = (1 - 2 tau) |V|: the bytes of V / (1 - 2 tau) where that
            // is exact (always, for a Boolean tau).
            let values: Vec<i128> = (0..out)
                .map(|x| {
                    let (odd, v) = (1 - 2 * i128::from(w.sign[x]), wide(w, x));
                    if v % odd == 0 {
                        v / odd
                    } else {
                        odd * v
                    }
                })
                .collect();
            w.bytes = (0..n_bytes)
                .map(|k| {
                    values
                        .iter()
                        .map(|v| {
                            if k + 1 == n_bytes {
                                (v >> (8 * k)) as i64
                            } else {
                                ((v >> (8 * k)) & 255) as i64
                            }
                        })
                        .collect()
                })
                .collect();
        }
        if at(Step::ScaleBytes) {
            w.scale_bytes = (0..n_scale)
                .map(|k| {
                    (0..1usize << t)
                        .map(|row| {
                            let s = w.scales[row << (ld - lg)];
                            if k + 1 == n_scale {
                                s >> (8 * k)
                            } else {
                                (s >> (8 * k)) & 255
                            }
                        })
                        .collect()
                })
                .collect();
        }
        // P = |V| * m_j * u from the byte limbs actually assigned.
        let product = |w: &ProjectionWitness, x: usize| -> i128 {
            let (row, j) = (x >> lo, x & ((1 << lo) - 1));
            let v: i128 = w
                .bytes
                .iter()
                .enumerate()
                .map(|(k, b)| i128::from(b[x]) << (8 * k))
                .sum();
            let u: i128 = if grouped {
                1
            } else {
                w.scale_bytes
                    .iter()
                    .enumerate()
                    .map(|(k, b)| i128::from(b[row]) << (8 * k))
                    .sum()
            };
            v * self.plan.mantissas.get(j).map_or(0, |m| i128::from(*m)) * u
        };
        let shift = self.shift();
        let vanishing = self.vanishing();
        if at(Step::Magnitude) {
            w.magnitude = (0..out)
                .map(|x| {
                    let p = product(w, x);
                    if vanishing {
                        0
                    } else if shift >= 0 {
                        (p << (8 * (shift / 8))) as i64
                    } else {
                        let k = -shift;
                        ((p + (1i128 << (k - 1))) >> k) as i64
                    }
                })
                .collect();
            if wide_output {
                w.magnitude_bytes = (0..3)
                    .map(|k| {
                        w.magnitude
                            .iter()
                            .map(|&m| {
                                if k == 2 {
                                    m.div_euclid(1 << 16)
                                } else {
                                    m.div_euclid(1 << (8 * k)).rem_euclid(256)
                                }
                            })
                            .collect()
                    })
                    .collect();
            }
        }
        if at(Step::Remainder) && n_rem > 0 {
            let k = (-shift).max(1) as u32;
            let rho: Vec<i128> = (0..out)
                .map(|x| product(w, x) + (1i128 << (k - 1)) - (i128::from(w.magnitude[x]) << k))
                .collect();
            w.remainder = (0..n_rem)
                .map(|i| {
                    rho.iter()
                        .map(|v| {
                            if i + 1 == n_rem {
                                (v >> (8 * i)) as i64
                            } else {
                                ((v >> (8 * i)) & 255) as i64
                            }
                        })
                        .collect()
                })
                .collect();
        }
        if at(Step::Output) {
            let (_, factor) = self.left();
            w.output = (0..out)
                .map(|x| {
                    if self.real(x) {
                        factor * (1 - 2 * w.sign[x]) * w.magnitude[x]
                    } else {
                        0
                    }
                })
                .collect();
            if wide_output {
                w.output_bytes = (0..3)
                    .map(|k| {
                        w.output
                            .iter()
                            .map(|&y| {
                                if k == 2 {
                                    y.div_euclid(1 << 16)
                                } else {
                                    y.div_euclid(1 << (8 * k)).rem_euclid(256)
                                }
                            })
                            .collect()
                    })
                    .collect();
            }
        }
    }

    /// Write a (possibly forged) witness. `skip` names one chain position whose
    /// carries are assigned around it (mutation tests).
    pub(crate) fn write(
        &self,
        relation: &Relation,
        w: &ProjectionWitness,
        values: &mut Values,
        skip: Option<(&str, usize)>,
    ) -> Result<(), Violation> {
        let c = self
            .columns
            .as_ref()
            .ok_or(Violation::Missing(self.output_id()))?;
        let is_writable =
            |id: ColumnId| matches!(relation.columns[id.0 as usize].kind, Kind::Witness(_));
        if let Some(mc) = &c.mixed {
            for (ids, columns) in [
                (&c.fold_scale_bytes, &w.fold_scale_bytes),
                (&c.fold_carries, &w.fold_carries),
                (&c.digits, &w.digits),
            ] {
                for (id, column) in ids.iter().zip(columns) {
                    if is_writable(*id) {
                        values.set(relation, *id, column.clone())?;
                    }
                }
            }
            if let Some(s1) = mc.s1 {
                values.set(relation, s1, w.mixed_s1.clone())?;
            }
            for (&id, col) in mc.head.iter().zip(&w.mixed_head) {
                values.set(relation, id, col.clone())?;
            }
            values.set(relation, mc.w_top, w.mixed_w_top.clone())?;
            values.set(relation, c.sign, w.sign.clone())?;
            for (&id, col) in mc.rcs.iter().zip(&w.mixed_rcs) {
                values.set(relation, id, col.clone())?;
            }
            for (&id, col) in mc.out_cols.iter().zip(&w.mixed_out) {
                values.set(relation, id, col.clone())?;
            }
            return Ok(());
        }
        for (ids, columns) in [
            (&c.fold_scale_bytes, &w.fold_scale_bytes),
            (&c.fold_carries, &w.fold_carries),
            (&c.digits, &w.digits),
            (&c.sums, &w.sums),
            (&c.bytes, &w.bytes),
            (&c.scale_bytes, &w.scale_bytes),
            (&c.magnitude_bytes, &w.magnitude_bytes),
            (&c.remainder, &w.remainder),
            (&c.output_bytes, &w.output_bytes),
        ] {
            for (id, column) in ids.iter().zip(columns) {
                if is_writable(*id) {
                    values.set(relation, *id, column.clone())?;
                }
            }
        }
        if is_writable(c.sign) {
            values.set(relation, c.sign, w.sign.clone())?;
        }
        if is_writable(c.magnitude) {
            values.set(relation, c.magnitude, w.magnitude.clone())?;
        }
        if is_writable(c.output) {
            values.set(relation, c.output, w.output.clone())?;
        }
        for (name, chain) in &c.chains {
            let around = skip.filter(|(n, _)| n == name).map(|(_, k)| k);
            chain.assign_around(relation, values, around)?;
        }
        Ok(())
    }
}

impl Module for Projection {
    type Capture = ProjectionCapture;

    fn declare(&mut self, relation: &mut Relation) {
        let (t, ld, lg, lo) = self.logs();
        let (lanes, out) = (t + ld, t + lo);
        let grouped = self.grouped();
        let wide_grouped = self.wide_grouped();
        let wide_output = self.wide_output();
        let prefix = self.prefix.clone();
        let plan = &self.plan;
        let mixed_plan = self.mixed_plan(relation);
        let mut b = Builder::new(relation, &prefix);

        let weight = self.weight.unwrap_or_else(|| {
            let name = alloc::format!("{prefix}/weight");
            let id = b
                .relation
                .add_column(&name, Kind::Weight, self.weight_width(), lo + ld);
            b.relation.ranges.push(Range {
                name: alloc::format!("{name}/range"),
                column: id,
                width: self.weight_width(),
            });
            id
        });
        let at = |c: ColumnId| r(c, 0..out);
        let summed = (out..out + ld).collect::<Vec<u8>>();

        // Vanishing rounding (K > bits(Pmax) + 1): output is identically zero (0 committed cols).
        if self.vanishing() {
            let output = b.virtual_col(
                "output",
                Def::Linear {
                    constant: 0,
                    terms: Vec::new(),
                },
                out,
            );
            self.columns = Some(Columns {
                weight,
                fold_scale_bytes: Vec::new(),
                fold_carries: Vec::new(),
                digits: Vec::new(),
                sums: Vec::new(),
                bytes: Vec::new(),
                sign: output,
                scale_bytes: Vec::new(),
                magnitude: output,
                magnitude_bytes: Vec::new(),
                remainder: Vec::new(),
                output,
                output_bytes: Vec::new(),
                chains: Vec::new(),
                mixed: None,
            });
            return;
        }

        // Matmul operands: codes directly, or A15 digit rows (low digits virtual, no redundant top carry).
        let codes = r(self.input.codes, 0..lanes);
        let (fold_scale_bytes, fold_carries, digits): (
            Vec<ColumnId>,
            Vec<ColumnId>,
            Vec<ColumnId>,
        ) = if wide_grouped {
            let groups = t + ld - lg;
            let bound = u128::from(self.input.scale_bound);
            let n = bytes(bound);
            let top = bit_length(bound) as usize - 8 * (n - 1);
            let mut s_hi = Vec::with_capacity(n.saturating_sub(1));
            for c in 1..n {
                let bits = if c + 1 == n { top } else { 8 } as u8;
                s_hi.push(b.witness(
                    &alloc::format!("fold_scale/{c}"),
                    Width::unsigned(bits),
                    groups,
                ));
            }
            let s: Vec<ColumnId> = if n == 1 {
                vec![self.input.scale]
            } else {
                let mut lin = vec![(1, r(self.input.scale, 0..groups))];
                for (i, &id) in s_hi.iter().enumerate() {
                    lin.push((-(1 << (8 * (i + 1))), r(id, 0..groups)));
                }
                let s0 = b.virtual_ranged(
                    "fold_scale/0",
                    Def::Linear {
                        constant: 0,
                        terms: lin,
                    },
                    Width::unsigned(8),
                    groups,
                );
                core::iter::once(s0).chain(s_hi).collect()
            };
            let n_digits = self.digit_widths().len();
            let mut fcarries = Vec::with_capacity(n_digits.saturating_sub(2));
            let mut d = Vec::with_capacity(n_digits);
            let mut prev_c: Option<ColumnId> = None;
            for (k, &sc) in s.iter().enumerate() {
                let next_c = if k + 1 < s.len() {
                    let c = b.witness(&alloc::format!("fold/carry{k}"), Width::signed(8), lanes);
                    fcarries.push(c);
                    c
                } else {
                    b.witness(
                        &alloc::format!("digit/{}", n_digits - 1),
                        Width::signed(8),
                        lanes,
                    )
                };
                let mut terms = vec![
                    term(1, vec![codes.clone(), r(sc, lg..lanes)]),
                    term(-256, vec![r(next_c, 0..lanes)]),
                ];
                if let Some(pc) = prev_c {
                    terms.push(term(1, vec![r(pc, 0..lanes)]));
                }
                let dk = b.virtual_ranged(
                    &alloc::format!("digit/{k}"),
                    Def::Pointwise { terms },
                    Width::unsigned(8),
                    lanes,
                );
                d.push(dk);
                prev_c = Some(next_c);
            }
            d.push(prev_c.expect("top digit"));
            (s, fcarries, d)
        } else if grouped {
            let d1 = b.witness("digit/1", Width::signed(9), lanes);
            let d0 = b.virtual_ranged(
                "digit/0",
                Def::Pointwise {
                    terms: vec![
                        term(1, vec![codes.clone(), r(self.input.scale, lg..lanes)]),
                        term(-256, vec![r(d1, 0..lanes)]),
                    ],
                },
                Width::unsigned(8),
                lanes,
            );
            (Vec::new(), Vec::new(), vec![d0, d1])
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };
        let lhs: Vec<ColumnId> = if grouped {
            digits.clone()
        } else {
            vec![self.input.codes]
        };
        let mut sums = Vec::new();
        for (k, column) in lhs.iter().enumerate() {
            let sum = b.virtual_col(
                &alloc::format!("sum/{k}"),
                Def::Contraction {
                    free: out,
                    summed: ld,
                    lhs: r(*column, summed.iter().copied().chain(lo..out)),
                    rhs: r(weight, summed.iter().copied().chain(0..lo)),
                },
                out,
            );
            sums.push(sum);
        }

        // Fast path: mixed-radix signed rounding (per-row, split-scale, grouped2, grouped4).
        if let Some(mp) = mixed_plan {
            let rads: [i64; 4] = mp.radices.map(|rb| 1i64 << rb);
            let mut s1_col = None;
            let mut head = Vec::new();
            let mut w_limbs = Vec::with_capacity(mp.limbs);
            let mut w_t0_col: Option<ColumnId> = None;
            let mut w_t1_virt: Option<ColumnId> = None;
            let w_top: ColumnId;
            let k_shift = (-self.shift()) as u8;
            match mp.kind {
                MixedKind::PerRow {
                    v1_width,
                    c0_width,
                    q1_width,
                } => {
                    let scale_col = match relation_col_kind(b.relation, self.input.scale) {
                        Some(Kind::Public(vals)) => {
                            let s_bits = bit_length(u128::from(self.input.scale_bound)).max(1);
                            b.public("scale", vals, Width::unsigned(s_bits), t)
                        }
                        _ => self.input.scale,
                    };
                    let scale = r(scale_col, lo..out);
                    let v1 = b.witness("v1", v1_width, out);
                    head.push(v1);
                    let v0 = b.virtual_ranged(
                        "v0",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, at(sums[0])), (-rads[0], at(v1))],
                        },
                        Width::unsigned(mp.radices[0]),
                        out,
                    );
                    let (c0, w0_terms) = match c0_width {
                        Some(cw) => {
                            let c0 = b.witness("c0", cw, out);
                            head.push(c0);
                            (
                                Some(c0),
                                vec![
                                    term(1, vec![at(v0), scale.clone()]),
                                    term(-rads[0], vec![at(c0)]),
                                ],
                            )
                        }
                        None => (None, vec![term(1, vec![at(v0), scale.clone()])]),
                    };
                    let w0 = b.virtual_ranged(
                        "w0",
                        Def::Pointwise { terms: w0_terms },
                        Width::unsigned(mp.radices[0]),
                        out,
                    );
                    w_limbs.push(w0);
                    let mut w1_terms = vec![term(1, vec![at(v1), scale])];
                    if let Some(c0) = c0 {
                        w1_terms.push(term(1, vec![at(c0)]));
                    }
                    if let Some(q1_w) = q1_width {
                        let q1 = b.witness("q1", q1_w, out);
                        head.push(q1);
                        w1_terms.push(term(-rads[1], vec![at(q1)]));
                        w_limbs.push(b.virtual_ranged(
                            "w1",
                            Def::Pointwise { terms: w1_terms },
                            Width::unsigned(mp.radices[1]),
                            out,
                        ));
                        let mut last_lin = vec![(1, at(q1))];
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            last_lin.push((-rads[2], at(wt0)));
                            last_lin.push((-(rads[2] << 8), at(w_top)));
                        } else {
                            w_top = b.witness("w3", mp.w_top_width, out);
                            last_lin.push((-rads[2], at(w_top)));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w2",
                            Def::Linear {
                                constant: 0,
                                terms: last_lin,
                            },
                            Width::unsigned(mp.radices[2]),
                            out,
                        ));
                    } else {
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            w1_terms.push(term(-rads[1], vec![at(wt0)]));
                            w1_terms.push(term(-(rads[1] << 8), vec![at(w_top)]));
                        } else {
                            w_top = b.witness("w2", mp.w_top_width, out);
                            w1_terms.push(term(-rads[1], vec![at(w_top)]));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w1",
                            Def::Pointwise { terms: w1_terms },
                            Width::unsigned(mp.radices[1]),
                            out,
                        ));
                    }
                }
                MixedKind::PerRowSplit {
                    s1_width,
                    v1_width,
                    c0_width,
                    c1_width,
                    q2_width,
                } => {
                    let s1 = b.witness("scale/hi", s1_width, t);
                    s1_col = Some(s1);
                    let s0 = b.virtual_ranged(
                        "scale/lo",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, r(self.input.scale, 0..t)), (-rads[0], r(s1, 0..t))],
                        },
                        Width::unsigned(mp.radices[0]),
                        t,
                    );
                    let (s0_r, s1_r) = (r(s0, lo..out), r(s1, lo..out));
                    let v1 = b.witness("v1", v1_width, out);
                    let v0 = b.virtual_ranged(
                        "v0",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, at(sums[0])), (-rads[0], at(v1))],
                        },
                        Width::unsigned(mp.radices[0]),
                        out,
                    );
                    let c0 = b.witness("c0", c0_width, out);
                    let w0 = b.virtual_ranged(
                        "w0",
                        Def::Pointwise {
                            terms: vec![
                                term(1, vec![at(v0), s0_r.clone()]),
                                term(-rads[0], vec![at(c0)]),
                            ],
                        },
                        Width::unsigned(mp.radices[0]),
                        out,
                    );
                    let c1 = b.witness("c1", c1_width, out);
                    let w1 = b.virtual_ranged(
                        "w1",
                        Def::Pointwise {
                            terms: vec![
                                term(1, vec![at(v0), s1_r.clone()]),
                                term(1, vec![at(v1), s0_r]),
                                term(1, vec![at(c0)]),
                                term(-rads[1], vec![at(c1)]),
                            ],
                        },
                        Width::unsigned(mp.radices[1]),
                        out,
                    );
                    head.extend([v1, c0, c1]);
                    w_limbs.extend([w0, w1]);
                    let ratio = 1i64 << (mp.radices[0] - mp.radices[1]);
                    if let Some(q2_w) = q2_width {
                        let q2 = b.witness("q2", q2_w, out);
                        head.push(q2);
                        w_limbs.push(b.virtual_ranged(
                            "w2",
                            Def::Pointwise {
                                terms: vec![
                                    term(ratio, vec![at(v1), s1_r]),
                                    term(1, vec![at(c1)]),
                                    term(-rads[2], vec![at(q2)]),
                                ],
                            },
                            Width::unsigned(mp.radices[2]),
                            out,
                        ));
                        let mut last_lin = vec![(1, at(q2))];
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            last_lin.push((-rads[3], at(wt0)));
                            last_lin.push((-(rads[3] << 8), at(w_top)));
                        } else {
                            w_top = b.witness("w4", mp.w_top_width, out);
                            last_lin.push((-rads[3], at(w_top)));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w3",
                            Def::Linear {
                                constant: 0,
                                terms: last_lin,
                            },
                            Width::unsigned(mp.radices[3]),
                            out,
                        ));
                    } else {
                        let mut w2_terms =
                            vec![term(ratio, vec![at(v1), s1_r]), term(1, vec![at(c1)])];
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            w2_terms.push(term(-rads[2], vec![at(wt0)]));
                            w2_terms.push(term(-(rads[2] << 8), vec![at(w_top)]));
                        } else {
                            w_top = b.witness("w3", mp.w_top_width, out);
                            w2_terms.push(term(-rads[2], vec![at(w_top)]));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w2",
                            Def::Pointwise { terms: w2_terms },
                            Width::unsigned(mp.radices[2]),
                            out,
                        ));
                    }
                }
                MixedKind::Grouped2 {
                    b1_width,
                    q0_width,
                    q1_width,
                } => {
                    let (b1_opt, w0_terms) = if let Some(b1_w) = b1_width {
                        let b1 = b.witness("b1", b1_w, out);
                        head.push(b1);
                        let b0 = b.virtual_ranged(
                            "b0",
                            Def::Linear {
                                constant: 0,
                                terms: vec![(1, at(sums[1])), (-rads[0], at(b1))],
                            },
                            Width::unsigned(mp.radices[0]),
                            out,
                        );
                        (Some(b1), vec![(1, at(sums[0])), (256, at(b0))])
                    } else {
                        (None, vec![(1, at(sums[0])), (256, at(sums[1]))])
                    };
                    let q0 = b.witness("q0", q0_width, out);
                    head.push(q0);
                    let mut w0_lin = w0_terms;
                    w0_lin.push((-rads[0], at(q0)));
                    w_limbs.push(b.virtual_ranged(
                        "w0",
                        Def::Linear {
                            constant: 0,
                            terms: w0_lin,
                        },
                        Width::unsigned(mp.radices[0]),
                        out,
                    ));
                    let mut w1_lin = vec![(1, at(q0))];
                    if let Some(b1) = b1_opt {
                        w1_lin.push((256, at(b1)));
                    }
                    if let Some(q1_w) = q1_width {
                        let q1 = b.witness("q1", q1_w, out);
                        head.push(q1);
                        w1_lin.push((-rads[1], at(q1)));
                        w_limbs.push(b.virtual_ranged(
                            "w1",
                            Def::Linear {
                                constant: 0,
                                terms: w1_lin,
                            },
                            Width::unsigned(mp.radices[1]),
                            out,
                        ));
                        let mut last_lin = vec![(1, at(q1))];
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            last_lin.push((-rads[2], at(wt0)));
                            last_lin.push((-(rads[2] << 8), at(w_top)));
                        } else {
                            w_top = b.witness("w3", mp.w_top_width, out);
                            last_lin.push((-rads[2], at(w_top)));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w2",
                            Def::Linear {
                                constant: 0,
                                terms: last_lin,
                            },
                            Width::unsigned(mp.radices[2]),
                            out,
                        ));
                    } else {
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            w1_lin.push((-rads[1], at(wt0)));
                            w1_lin.push((-(rads[1] << 8), at(w_top)));
                        } else {
                            w_top = b.witness("w2", mp.w_top_width, out);
                            w1_lin.push((-rads[1], at(w_top)));
                        }
                        w_limbs.push(b.virtual_ranged(
                            "w1",
                            Def::Linear {
                                constant: 0,
                                terms: w1_lin,
                            },
                            Width::unsigned(mp.radices[1]),
                            out,
                        ));
                    }
                }
                MixedKind::Grouped4 {
                    b_widths,
                    q0_width,
                    q1_width,
                    q2_width,
                } => {
                    let mut b0 = Vec::with_capacity(4);
                    let mut b1 = Vec::with_capacity(4);
                    for (k, &bw) in b_widths.iter().enumerate() {
                        let bk1 = b.witness(&alloc::format!("b{k}1"), bw, out);
                        let bk0 = b.virtual_ranged(
                            &alloc::format!("b{k}0"),
                            Def::Linear {
                                constant: 0,
                                terms: vec![(1, at(sums[k])), (-65536, at(bk1))],
                            },
                            Width::unsigned(16),
                            out,
                        );
                        head.push(bk1);
                        b0.push(bk0);
                        b1.push(bk1);
                    }
                    let q0 = b.witness("q0", q0_width, out);
                    let w0 = b.virtual_ranged(
                        "w0",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, at(b0[0])), (256, at(b0[1])), (-4096, at(q0))],
                        },
                        Width::unsigned(12),
                        out,
                    );
                    let q1 = b.witness("q1", q1_width, out);
                    let w1 = b.virtual_ranged(
                        "w1",
                        Def::Linear {
                            constant: 0,
                            terms: vec![
                                (1, at(q0)),
                                (16, at(b1[0])),
                                (16, at(b0[2])),
                                (-4096, at(q1)),
                            ],
                        },
                        Width::unsigned(12),
                        out,
                    );
                    let q2 = b.witness("q2", q2_width, out);
                    if matches!(mp.top_split, TopSplit::Three { .. }) {
                        let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                        w_t0_col = Some(wt0);
                        let w2 = b.virtual_ranged(
                            "w2",
                            Def::Linear {
                                constant: 0,
                                terms: vec![
                                    (1, at(q1)),
                                    (1, at(b1[1])),
                                    (1, at(b0[3])),
                                    (256, at(b1[2])),
                                    (-rads[2], at(wt0)),
                                    (-(rads[2] << 8), at(q2)),
                                ],
                            },
                            Width::unsigned(mp.radices[2]),
                            out,
                        );
                        w_top = b.witness("w_t2", mp.w_top_width, out);
                        let wt1 = b.virtual_ranged(
                            "w_t1",
                            Def::Linear {
                                constant: 0,
                                terms: vec![
                                    (1, at(q2)),
                                    (1i64 << (32 - k_shift), at(b1[3])),
                                    (-256, at(w_top)),
                                ],
                            },
                            Width::unsigned(8),
                            out,
                        );
                        w_t1_virt = Some(wt1);
                        head.extend([q0, q1, q2, wt0]);
                        w_limbs.extend([w0, w1, w2]);
                    } else {
                        let w2 = b.virtual_ranged(
                            "w2",
                            Def::Linear {
                                constant: 0,
                                terms: vec![
                                    (1, at(q1)),
                                    (1, at(b1[1])),
                                    (1, at(b0[3])),
                                    (-256, at(q2)),
                                ],
                            },
                            Width::unsigned(8),
                            out,
                        );
                        head.extend([q0, q1, q2]);
                        let mut w3_lin = vec![(1, at(q2)), (1, at(b1[2])), (256, at(b1[3]))];
                        if matches!(mp.top_split, TopSplit::Two { .. }) {
                            let wt0 = b.witness("w_t0", Width::unsigned(8), out);
                            head.push(wt0);
                            w_t0_col = Some(wt0);
                            w_top = b.witness("w_t1", mp.w_top_width, out);
                            w3_lin.push((-rads[3], at(wt0)));
                            w3_lin.push((-(rads[3] << 8), at(w_top)));
                        } else {
                            w_top = b.witness("w4", mp.w_top_width, out);
                            w3_lin.push((-rads[3], at(w_top)));
                        }
                        let w3 = b.virtual_ranged(
                            "w3",
                            Def::Linear {
                                constant: 0,
                                terms: w3_lin,
                            },
                            Width::unsigned(mp.radices[3]),
                            out,
                        );
                        w_limbs.extend([w0, w1, w2, w3]);
                    }
                }
            }

            // Common signed rounding tail: twos, rc_0..rc_{L-1}, rho_0..rho_{L-1}, output.
            let sign = b.witness("sign", Width::unsigned(1), out);
            let _twos = b.virtual_ranged(
                "twos",
                Def::Linear {
                    constant: 0,
                    terms: vec![(1, at(w_top)), (1i64 << mp.w_top_width.bits, at(sign))],
                },
                Width::unsigned(mp.w_top_width.bits),
                out,
            );
            let m_vals: Vec<i64> = (0..1usize << lo)
                .map(|j| plan.mantissas.get(j).map_or(0, |&m| i64::from(m)))
                .collect();
            let m = b.public("mantissa", m_vals, mp.m_width, lo);
            let m_ref = r(m, 0..lo);
            let mut rcs = Vec::with_capacity(mp.limbs);
            let mut rhos = Vec::with_capacity(mp.limbs);
            for j in 0..mp.limbs {
                let rad = rads[j];
                let rc = b.witness(
                    &alloc::format!("rc{j}"),
                    mp.rc_widths[j].expect("rc width"),
                    out,
                );
                let terms = if j == 0 {
                    vec![
                        term(-1, vec![at(w_limbs[0]), m_ref.clone()]),
                        term(1, vec![at(sign)]),
                        term(-1, vec![]),
                        term(rad, vec![at(rc)]),
                    ]
                } else if j + 1 < mp.limbs {
                    vec![
                        term(-1, vec![at(w_limbs[j]), m_ref.clone()]),
                        term(-1, vec![at(rcs[j - 1])]),
                        term(rad, vec![at(rc)]),
                    ]
                } else {
                    vec![
                        term(-1, vec![at(w_limbs[j]), m_ref.clone()]),
                        term(rad >> 1, vec![]),
                        term(-1, vec![at(rcs[j - 1])]),
                        term(rad, vec![at(rc)]),
                    ]
                };
                let rho = b.virtual_ranged(
                    &alloc::format!("rho{j}"),
                    Def::Pointwise { terms },
                    Width::unsigned(mp.radices[j]),
                    out,
                );
                rcs.push(rc);
                rhos.push(rho);
            }
            let rc_last = *rcs.last().expect("rc_last");
            let (output, out_cols) = match mp.top_split {
                TopSplit::One => {
                    if wide_output {
                        let y1 = b.witness("output/hi", Width::signed(8), out);
                        let y0 = b.virtual_ranged(
                            "output/lo",
                            Def::Pointwise {
                                terms: vec![
                                    term(1, vec![at(w_top), m_ref]),
                                    term(1, vec![at(rc_last)]),
                                    term(-(1 << 16), vec![at(y1)]),
                                ],
                            },
                            Width::unsigned(16),
                            out,
                        );
                        let y = b.virtual_col(
                            "output",
                            Def::Linear {
                                constant: 0,
                                terms: vec![(1, at(y0)), (1 << 16, at(y1))],
                            },
                            out,
                        );
                        (y, vec![y1])
                    } else {
                        let y = b.virtual_ranged(
                            "output",
                            Def::Pointwise {
                                terms: vec![
                                    term(1, vec![at(w_top), m_ref]),
                                    term(1, vec![at(rc_last)]),
                                ],
                            },
                            Width::signed(16),
                            out,
                        );
                        (y, Vec::new())
                    }
                }
                TopSplit::Two { y_c_width } => {
                    let wt0 = w_t0_col.expect("w_t0");
                    let yc = b.witness("output/c", y_c_width, out);
                    let y_lo = b.virtual_ranged(
                        "output/lo",
                        Def::Pointwise {
                            terms: vec![
                                term(1, vec![at(wt0), m_ref.clone()]),
                                term(1, vec![at(rc_last)]),
                                term(-256, vec![at(yc)]),
                            ],
                        },
                        Width::unsigned(8),
                        out,
                    );
                    let y_hi = b.virtual_ranged(
                        "output/hi",
                        Def::Pointwise {
                            terms: vec![term(1, vec![at(w_top), m_ref]), term(1, vec![at(yc)])],
                        },
                        if wide_output {
                            Width::signed(16)
                        } else {
                            Width::signed(8)
                        },
                        out,
                    );
                    let y = b.virtual_col(
                        "output",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, at(y_lo)), (256, at(y_hi))],
                        },
                        out,
                    );
                    (y, vec![yc])
                }
                TopSplit::Three {
                    yc0_width,
                    yc1_width,
                } => {
                    let wt0 = w_t0_col.expect("w_t0");
                    let wt1 = w_t1_virt.expect("w_t1");
                    let yc0 = b.witness("output/c0", yc0_width, out);
                    let y0 = b.virtual_ranged(
                        "output/0",
                        Def::Pointwise {
                            terms: vec![
                                term(1, vec![at(wt0), m_ref.clone()]),
                                term(1, vec![at(rc_last)]),
                                term(-256, vec![at(yc0)]),
                            ],
                        },
                        Width::unsigned(8),
                        out,
                    );
                    let yc1 = b.witness("output/c1", yc1_width, out);
                    let y1 = b.virtual_ranged(
                        "output/1",
                        Def::Pointwise {
                            terms: vec![
                                term(1, vec![at(wt1), m_ref.clone()]),
                                term(1, vec![at(yc0)]),
                                term(-256, vec![at(yc1)]),
                            ],
                        },
                        Width::unsigned(8),
                        out,
                    );
                    let y2 = b.virtual_ranged(
                        "output/2",
                        Def::Pointwise {
                            terms: vec![term(1, vec![at(w_top), m_ref]), term(1, vec![at(yc1)])],
                        },
                        Width::signed(8),
                        out,
                    );
                    let y = b.virtual_col(
                        "output",
                        Def::Linear {
                            constant: 0,
                            terms: vec![(1, at(y0)), (256, at(y1)), (65536, at(y2))],
                        },
                        out,
                    );
                    (y, vec![yc0, yc1])
                }
            };
            self.columns = Some(Columns {
                weight,
                fold_scale_bytes,
                fold_carries,
                digits,
                sums,
                bytes: Vec::new(),
                sign,
                scale_bytes: Vec::new(),
                magnitude: output,
                magnitude_bytes: Vec::new(),
                remainder: rhos,
                output,
                output_bytes: Vec::new(),
                chains: Vec::new(),
                mixed: Some(MixedCols {
                    plan: mp,
                    s1: s1_col,
                    head,
                    w_top,
                    rcs,
                    out_cols,
                }),
            });
            return;
        }

        // General path: shift >= 0, or large/small K outside mixed-radix bounds.
        let mask = (0..1usize << out)
            .map(|x| i64::from(self.real(x)))
            .collect();
        let mask = b.public("mask", mask, Width::unsigned(1), out);
        let mantissa = |shift: u32| {
            (0..1usize << lo)
                .map(|j| {
                    plan.mantissas
                        .get(j)
                        .map_or(0, |m| i64::from(m >> shift) & 255)
                })
                .collect::<Vec<_>>()
        };
        let m = [
            b.public("mantissa/0", mantissa(0), Width::unsigned(8), lo),
            b.public("mantissa/1", mantissa(8), Width::unsigned(8), lo),
        ];
        let mut chains = Vec::new();

        // Sign chain: sum_t 256^t C_t - (1 - 2 tau) sum_k 256^k v_k = 0.
        let sign = b.witness("sign", Width::unsigned(1), out);
        let v: Vec<ColumnId> = (0..bytes(self.vmax()))
            .map(|k| b.witness(&alloc::format!("byte/{k}"), Width::unsigned(8), out))
            .collect();
        let mut positions = Positions(Vec::new());
        for (k, sum) in sums.iter().enumerate() {
            positions.push(k, term(1, vec![at(*sum)]));
        }
        for (k, byte) in v.iter().enumerate() {
            positions.push(k, term(-1, vec![at(*byte)]));
            positions.push(k, term(2, vec![at(sign), at(*byte)]));
        }
        chains.push((
            alloc::format!("{prefix}/sign"),
            Chain::declare(&mut b, "sign", out, 8, positions.0),
        ));

        // Scale bytes (per-row input): s = sum_c 256^c s_c on the row domain.
        // Public (static) scales split into public bytes; dynamic scales virtualize scale/0.
        let scale_bytes: Vec<ColumnId> = if grouped {
            Vec::new()
        } else if let Some(Kind::Public(vals)) = relation_col_kind(b.relation, self.input.scale) {
            let bound = u128::from(self.input.scale_bound);
            let n = bytes(bound);
            let top = bit_length(bound) as usize - 8 * (n - 1);
            (0..n)
                .map(|c| {
                    let bits = if c + 1 == n { top } else { 8 } as u8;
                    let col: Vec<i64> = vals
                        .iter()
                        .map(|&s| {
                            if c + 1 == n {
                                s >> (8 * c)
                            } else {
                                (s >> (8 * c)) & 255
                            }
                        })
                        .collect();
                    b.public(&alloc::format!("scale/{c}"), col, Width::unsigned(bits), t)
                })
                .collect()
        } else {
            let bound = u128::from(self.input.scale_bound);
            let n = bytes(bound);
            let top = bit_length(bound) as usize - 8 * (n - 1);
            if n == 1 && b.relation.columns[self.input.scale.0 as usize].width.bits <= 8 {
                vec![self.input.scale]
            } else {
                let mut s_hi = Vec::with_capacity(n.saturating_sub(1));
                for c in 1..n {
                    let bits = if c + 1 == n { top } else { 8 } as u8;
                    s_hi.push(b.witness(&alloc::format!("scale/{c}"), Width::unsigned(bits), t));
                }
                let mut lin = vec![(1, r(self.input.scale, 0..t))];
                for (i, &id) in s_hi.iter().enumerate() {
                    lin.push((-(1 << (8 * (i + 1))), r(id, 0..t)));
                }
                let bits0 = if n == 1 { top as u8 } else { 8 };
                let s0 = b.virtual_ranged(
                    "scale/0",
                    Def::Linear {
                        constant: 0,
                        terms: lin,
                    },
                    Width::unsigned(bits0),
                    t,
                );
                core::iter::once(s0).chain(s_hi).collect()
            }
        };

        // Rounding chain (remainder bytes virtual via Chain::declare_virtual).
        let (magnitude, magnitude_bytes) = if wide_output {
            let limbs: Vec<ColumnId> = (0..3)
                .map(|k| b.witness(&alloc::format!("magnitude/{k}"), Width::unsigned(8), out))
                .collect();
            let mag = b.virtual_col(
                "magnitude",
                Def::Linear {
                    constant: 0,
                    terms: limbs
                        .iter()
                        .enumerate()
                        .map(|(k, &id)| (1 << (8 * k), at(id)))
                        .collect(),
                },
                out,
            );
            (mag, limbs)
        } else {
            (b.witness("magnitude", Width::unsigned(16), out), Vec::new())
        };
        let shift = self.shift();
        let (offset, factor) = self.left();
        let mut positions = Positions(Vec::new());
        for (a, va) in v.iter().enumerate() {
            for (bi, mb) in m.iter().enumerate() {
                if scale_bytes.is_empty() {
                    positions.push(a + bi + offset, term(1, vec![at(*va), r(*mb, 0..lo)]));
                }
                for (c, sc) in scale_bytes.iter().enumerate() {
                    positions.push(
                        a + bi + c + offset,
                        term(1, vec![at(*va), r(*mb, 0..lo), r(*sc, lo..out)]),
                    );
                }
            }
        }
        let remainder = if shift >= 0 {
            if wide_output {
                for (j, &limb) in magnitude_bytes.iter().enumerate() {
                    positions.push(j, term(-1, vec![at(limb)]));
                }
            } else {
                positions.push(0, term(-1, vec![at(magnitude)]));
            }
            chains.push((
                alloc::format!("{prefix}/round"),
                Chain::declare(&mut b, "round", out, 8, positions.0),
            ));
            Vec::new()
        } else {
            let k = (-shift) as usize;
            positions.push((k - 1) / 8, term(1 << ((k - 1) % 8), vec![]));
            if wide_output {
                for (j, &limb) in magnitude_bytes.iter().enumerate() {
                    positions.push(k / 8 + j, term(-(1 << (k % 8)), vec![at(limb)]));
                }
            } else {
                positions.push(k / 8, term(-(1 << (k % 8)), vec![at(magnitude)]));
            }
            let n = k.div_ceil(8);
            let targets: Vec<(usize, String, Width)> = (0..n)
                .map(|i| {
                    let bits = if i + 1 == n { k - 8 * (n - 1) } else { 8 } as u8;
                    (i, alloc::format!("remainder/{i}"), Width::unsigned(bits))
                })
                .collect();
            let (round_chain, rem) =
                Chain::declare_virtual(&mut b, "round", out, 8, positions.0, &targets);
            chains.push((alloc::format!("{prefix}/round"), round_chain));
            rem
        };

        // Y = mask*factor*(1 - 2*tau)*Ymag (virtual for int16; virtual low bytes + virtual Y for int24).
        let (output, output_bytes) = if wide_output {
            let out2 = b.witness("output/2", Width::signed(8), out);
            let mut positions = Positions(Vec::new());
            for (j, &mag_j) in magnitude_bytes.iter().enumerate() {
                positions.push(j, term(factor, vec![at(mask), at(mag_j)]));
                positions.push(j, term(-2 * factor, vec![at(mask), at(sign), at(mag_j)]));
            }
            positions.push(2, term(-1, vec![at(out2)]));
            let targets = vec![
                (
                    0,
                    alloc::string::String::from("output/0"),
                    Width::unsigned(8),
                ),
                (
                    1,
                    alloc::string::String::from("output/1"),
                    Width::unsigned(8),
                ),
            ];
            let (out_chain, mut limbs) =
                Chain::declare_virtual(&mut b, "output", out, 8, positions.0, &targets);
            limbs.push(out2);
            chains.push((alloc::format!("{prefix}/output"), out_chain));
            let y = b.virtual_col(
                "output",
                Def::Linear {
                    constant: 0,
                    terms: limbs
                        .iter()
                        .enumerate()
                        .map(|(k, &id)| (1 << (8 * k), at(id)))
                        .collect(),
                },
                out,
            );
            (y, limbs)
        } else {
            let y = b.virtual_ranged(
                "output",
                Def::Pointwise {
                    terms: vec![
                        term(factor, vec![at(mask), at(magnitude)]),
                        term(-2 * factor, vec![at(mask), at(sign), at(magnitude)]),
                    ],
                },
                Width::signed(16),
                out,
            );
            (y, Vec::new())
        };
        self.columns = Some(Columns {
            weight,
            fold_scale_bytes,
            fold_carries,
            digits,
            sums,
            bytes: v,
            sign,
            scale_bytes,
            magnitude,
            magnitude_bytes,
            remainder,
            output,
            output_bytes,
            chains,
            mixed: None,
        });
    }

    fn assign(
        &self,
        relation: &Relation,
        capture: &ProjectionCapture,
        values: &mut Values,
    ) -> Result<(), Violation> {
        let mut w = self.source(relation, capture)?;
        self.complete(&mut w, Step::Digits, None);
        // The executor's outputs must be the ones the relations force.
        let (_, _, _, lo) = self.logs();
        let ok = (0..w.output.len())
            .all(|x| !self.real(x) || w.output[x] == capture.outputs[x >> lo][x & ((1 << lo) - 1)]);
        if !ok {
            return Err(Invalid::Column(self.output_id()).into());
        }
        self.write(relation, &w, values, None)
    }
}
