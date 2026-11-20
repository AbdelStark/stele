//! RFC-0029 & RFC-0010 A17 — coefficient-form interleaved Circle RS recursive PCS (version 4, Policy 3).
//!
//! Fresh-mode recursive opening (`RFC-0029 §2`, `RFC-0010 A17`, `RFC-0012 A20`):
//! - Level 0 commits an `R_0 × C_0` M31 matrix (`R_0 = 2^ell_0`, `C_0 = 2^m_0`) encoded row-by-row
//!   with [`CircleCoeff`] (`stele/circle-coeff-m31/v1 || u8(m) || u8(b)`, `b in 1..=4`, `m + b <= 30`)
//!   into an RFC-0012 A3 BLAKE3 Merkle tree.
//! - Each level `i >= 1` runs `ell_i` degree-2 row-round sumcheck rounds, commits the row
//!   combination `u_{i+1} = eq(·, r_i)^T M_i` (or sends `u_L` in the clear at `i = L - 1`),
//!   absorbs the root / clear vector under `AbsorbLabel::PcsLevelRoot` before drawing `q_i`
//!   column indices (`ChallengeLabel::OpeningColumn`), verifies and absorbs the queried columns
//!   (`AbsorbLabel::OpeningColumns`), and (for `i < L - 1`) batches the `q_i` consistency
//!   claims with `ChallengeLabel::PcsLevelBeta`.
//! - Every parameter (`L`, `(ell_i, m_i, b_i)`, `q_i`) is verifier-owned; no proof byte selects
//!   a parameter (`RFC-0029 §3`). Query counts are derived by exact `#![no_std]` integer
//!   arithmetic with zero floating-point operations.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use rayon::prelude::*;
use stele_code::CircleCoeff;
use stele_field::{Field, Serialize, M31};
use stele_hash::{
    certificate_id, merkle, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript,
};

/// RFC-0010 A17 source version for coefficient-form recursive Circle RS sources.
pub const RECURSIVE_VERSION: u8 = 4;
/// RFC-0010 A17 Policy 3 byte (admitted only for version-4 sources).
pub const POLICY_THREE: u8 = 3;
/// Default Policy 3 target security bits (RFC-0029 §5).
pub const DEFAULT_TARGET_BITS: u16 = 100;

const PURPOSE: &[u8; 23] = b"stele/v0.1/field-source";
const MAX_DOMAIN_BITS: u8 = 30;
const MAX_LEVELS: usize = 30;
const MAX_TARGET_BITS: u16 = 256;
const M31_MODULUS: u64 = (1u64 << 31) - 1;

/// Rejected recursive PCS context, wire bytes, binding check or capacity bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecursiveError {
    /// Unsupported dimensions, blow-up, domain ceiling, version, policy or nonzero ZK reservation.
    UnsupportedSource,
    /// Proof header, level count, `(ell, m, b)` plan, or byte length disagrees with expected plan.
    ProofShape,
    /// A decoded M31 limb is at least `2^31 - 1`.
    NoncanonicalField,
    /// Producer message length disagrees with `R_0 * C_0` or claim point length disagrees with `ell_0 + m_0`.
    MessageShape,
    /// Circle encoder rejected parameters or capacity.
    Encoder(stele_code::Error),
    /// Merkle tree construction or path authentication failed (`RootMismatch`, etc.).
    Merkle(merkle::Error),
    /// Transcript validation, sampling or local accounting failed.
    Transcript(stele_hash::Error),
    /// A queried column disagrees with the re-encoded final row combination `u_L` (`NC-0630` / `NC-0632`).
    ColumnMismatch,
    /// Final scalar inner product `⟨w_L, u_L⟩` disagrees with the running claim (`NC-0632`).
    ValueMismatch,
    /// A row-round or fresh-mode batching sumcheck round/final equation failed (`NC-0634`).
    RoundSumMismatch,
    /// Registration certificate belongs to a different source or certified radius (`NC-0635`).
    CertificateContext,
    /// Allocation or platform size limit exceeded.
    Capacity,
}

impl From<stele_code::Error> for RecursiveError {
    fn from(e: stele_code::Error) -> Self {
        Self::Encoder(e)
    }
}

impl From<merkle::Error> for RecursiveError {
    fn from(e: merkle::Error) -> Self {
        Self::Merkle(e)
    }
}

impl From<stele_hash::Error> for RecursiveError {
    fn from(e: stele_hash::Error) -> Self {
        Self::Transcript(e)
    }
}

fn reserve_vec<T>(len: usize) -> Result<Vec<T>, RecursiveError> {
    let mut v = Vec::new();
    v.try_reserve_exact(len)
        .map_err(|_| RecursiveError::Capacity)?;
    Ok(v)
}

fn add_usize(a: usize, b: usize) -> Result<usize, RecursiveError> {
    a.checked_add(b).ok_or(RecursiveError::Capacity)
}

fn mul_usize(a: usize, b: usize) -> Result<usize, RecursiveError> {
    a.checked_mul(b).ok_or(RecursiveError::Capacity)
}

/// Exact unsigned big integer in little-endian base-`2^64` limbs (`#![no_std]`, zero floats).
#[derive(Clone, Debug, Eq, PartialEq)]
struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    fn from_u64(v: u64) -> Result<Self, RecursiveError> {
        let mut limbs = reserve_vec(1)?;
        if v != 0 {
            limbs.push(v);
        }
        Ok(Self { limbs })
    }

    fn from_pow2(bits: u16) -> Result<Self, RecursiveError> {
        let word = (bits / 64) as usize;
        let bit = bits % 64;
        let mut limbs = reserve_vec(word + 1)?;
        limbs.resize(word + 1, 0);
        limbs[word] = 1u64 << bit;
        Ok(Self { limbs })
    }

    fn mul_u64(&mut self, factor: u64) -> Result<(), RecursiveError> {
        if factor == 0 || self.limbs.is_empty() {
            self.limbs.clear();
            return Ok(());
        }
        let mut carry = 0u128;
        let f = u128::from(factor);
        for limb in &mut self.limbs {
            let prod = u128::from(*limb) * f + carry;
            *limb = prod as u64;
            carry = prod >> 64;
        }
        if carry != 0 {
            self.limbs
                .try_reserve(1)
                .map_err(|_| RecursiveError::Capacity)?;
            self.limbs.push(carry as u64);
        }
        Ok(())
    }

    fn shr_bits(&self, bits: u16) -> Result<Self, RecursiveError> {
        let word_shift = (bits / 64) as usize;
        let bit_shift = (bits % 64) as u32;
        if word_shift >= self.limbs.len() {
            return Ok(Self { limbs: Vec::new() });
        }
        let out_len = self.limbs.len() - word_shift;
        let mut out = reserve_vec(out_len)?;
        for i in 0..out_len {
            let lo = self.limbs[i + word_shift] >> bit_shift;
            let hi = if bit_shift != 0 && i + word_shift + 1 < self.limbs.len() {
                self.limbs[i + word_shift + 1] << (64 - bit_shift)
            } else {
                0
            };
            out.push(lo | hi);
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        Ok(Self { limbs: out })
    }

    fn cmp_val(&self, other: &Self) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }

    fn fits_cap(val: u64, cap: &Self) -> bool {
        if cap.limbs.len() > 1 {
            return true;
        }
        let cap_u64 = cap.limbs.first().copied().unwrap_or(0);
        val <= cap_u64
    }

    fn mul_big(&self, other: &Self) -> Result<Self, RecursiveError> {
        if self.limbs.is_empty() || other.limbs.is_empty() {
            return Ok(Self { limbs: Vec::new() });
        }
        let len = add_usize(self.limbs.len(), other.limbs.len())?;
        let mut out = reserve_vec(len)?;
        out.resize(len, 0u64);
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            let a128 = u128::from(a);
            for (j, &b) in other.limbs.iter().enumerate() {
                let prod = a128 * u128::from(b) + u128::from(out[i + j]) + carry;
                out[i + j] = prod as u64;
                carry = prod >> 64;
            }
            out[i + other.limbs.len()] = carry as u64;
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        Ok(Self { limbs: out })
    }

    fn pow_u32(base: u64, mut exp: u32) -> Result<Self, RecursiveError> {
        let mut result = Self::from_u64(1)?;
        let mut cur = Self::from_u64(base)?;
        while exp != 0 {
            if exp & 1 != 0 {
                result = result.mul_big(&cur)?;
            }
            exp >>= 1;
            if exp != 0 {
                cur = cur.mul_big(&cur)?;
            }
        }
        Ok(result)
    }

    /// True iff `self <= 2^shift` (exact, zero allocation).
    fn le_pow2(&self, shift: u64) -> bool {
        if self.limbs.is_empty() {
            return true;
        }
        let top_idx = self.limbs.len() - 1;
        let top = self.limbs[top_idx];
        let bit_len = (top_idx as u64) * 64 + u64::from(64 - top.leading_zeros());
        if bit_len <= shift {
            return true;
        }
        if bit_len == shift + 1 {
            // Exact equality `self == 2^shift` iff top limb is a power of 2 and all lower limbs are 0.
            return top.is_power_of_two() && self.limbs[..top_idx].iter().all(|&w| w == 0);
        }
        false
    }
}

/// Exact least positive `q <= cap` satisfying `2^target_bits * miss^q <= (2^log_n)^q`
/// via exponential + binary search using exact `#![no_std]` `BigUint` exponentiation.
fn least_q_pow2_denom(
    log_n: u8,
    miss: u64,
    target_bits: u16,
    cap: u32,
) -> Result<u32, RecursiveError> {
    let n = 1u64 << log_n;
    if miss == 0 || miss >= n || target_bits == 0 || target_bits > MAX_TARGET_BITS || cap == 0 {
        return Err(RecursiveError::UnsupportedSource);
    }
    let passes = |q: u32| -> Result<bool, RecursiveError> {
        let total_bits = u64::from(q) * u64::from(log_n);
        if total_bits < u64::from(target_bits) {
            return Ok(false);
        }
        let shift = total_bits - u64::from(target_bits);
        let lhs = BigUint::pow_u32(miss, q)?;
        Ok(lhs.le_pow2(shift))
    };
    let mut hi = 1u32;
    while !passes(hi)? {
        if hi == cap {
            return Err(RecursiveError::UnsupportedSource);
        }
        hi = hi.saturating_mul(2).min(cap);
    }
    let mut lo = hi / 2 + 1;
    if hi == 1 {
        return Ok(1);
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if passes(mid)? {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

/// Exact field cap `floor((2^31 - 1)^ext_degree / 2^target_bits)` (RFC-0029 §3, §5).
fn field_cap(ext_degree: u8, target_bits: u16) -> Result<BigUint, RecursiveError> {
    let mut p_pow = BigUint::from_u64(1)?;
    for _ in 0..ext_degree {
        p_pow.mul_u64(M31_MODULUS)?;
    }
    p_pow.shr_bits(target_bits)
}

/// Exact circle code parameters `(C, N, D, e)` for RFC-0029 §5 and RFC-0010 A17.
pub fn circle_coeff_params(m: u8, b: u8) -> Result<(u64, u64, u64, u64), RecursiveError> {
    if !(1..=4).contains(&b) || m.saturating_add(b) > MAX_DOMAIN_BITS {
        return Err(RecursiveError::UnsupportedSource);
    }
    let c = 1u64 << m;
    let n = 1u64 << (m + b);
    let d = if c == 1 { n } else { n - c };
    let e = (d - 1) / 3;
    Ok((c, n, d, e))
}

/// Exact least positive `q` with `2^target_bits * (N - e - 1)^q <= N^q` (RFC-0029 §5, Policy 3).
/// Returns `(q, N, D, e)`.
pub fn policy3_fresh_queries(
    m: u8,
    b: u8,
    target_bits: u16,
) -> Result<(u16, u64, u64, u64), RecursiveError> {
    if target_bits == 0 || target_bits > MAX_TARGET_BITS {
        return Err(RecursiveError::UnsupportedSource);
    }
    let (_, n, d, e) = circle_coeff_params(m, b)?;
    let far_miss = n - e - 1;
    let near_miss = n - d + e;
    if far_miss == 0 || far_miss >= n || near_miss > far_miss {
        return Err(RecursiveError::UnsupportedSource);
    }
    let mut lhs = BigUint::from_pow2(target_bits)?;
    let mut rhs = BigUint::from_u64(1)?;
    let mut q = 0u16;
    while lhs.cmp_val(&rhs) == Ordering::Greater {
        q = q.checked_add(1).ok_or(RecursiveError::UnsupportedSource)?;
        lhs.mul_u64(far_miss)?;
        rhs.mul_u64(n)?;
    }
    Ok((q, n, d, e))
}

/// One level of a recursive commitment plan (RFC-0029 §§1.2, 2, 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LevelSpec {
    /// Row exponent `ell_i >= 1` (`R_i = 2^ell_i`).
    pub ell: u8,
    /// Column exponent `m_i` (`C_i = 2^m_i`).
    pub m: u8,
    /// Blow-up exponent `b_i in 1..=4` (`N_i = 2^(m_i + b_i) <= 2^30`).
    pub b: u8,
    /// RFC-0029 §7 reserved per-row randomiser count; must be 0 until RFC-0013 A3 (E19-06).
    pub randomisers: u16,
    /// RFC-0029 §7 reserved mask-row count; must be 0 until RFC-0013 A3 (E19-06).
    pub mask_rows: u16,
}

impl LevelSpec {
    /// Non-hiding development/Policy-3 level specification (ZK reservation fixed to 0).
    pub const fn new(ell: u8, m: u8, b: u8) -> Self {
        Self {
            ell,
            m,
            b,
            randomisers: 0,
            mask_rows: 0,
        }
    }

    /// Number of rows `R_i = 2^ell_i`.
    pub fn rows(self) -> Result<usize, RecursiveError> {
        1usize
            .checked_shl(u32::from(self.ell))
            .ok_or(RecursiveError::Capacity)
    }

    /// Number of message columns `C_i = 2^m_i`.
    pub fn columns(self) -> Result<usize, RecursiveError> {
        1usize
            .checked_shl(u32::from(self.m))
            .ok_or(RecursiveError::Capacity)
    }

    /// Codeword length `N_i = 2^(m_i + b_i)`.
    pub fn codeword_len(self) -> Result<usize, RecursiveError> {
        let log = self
            .m
            .checked_add(self.b)
            .ok_or(RecursiveError::UnsupportedSource)?;
        1usize
            .checked_shl(u32::from(log))
            .ok_or(RecursiveError::Capacity)
    }

    /// Merkle path height `m_i + b_i`.
    pub fn path_height(self) -> usize {
        usize::from(self.m) + usize::from(self.b)
    }
}

/// Complete verifier-owned recursion plan (RFC-0029 §§2–5, RFC-0010 A17).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursivePlan {
    target_bits: u16,
    ext_degree: u8,
    levels: Vec<LevelSpec>,
    queries: Vec<u16>,
}

impl RecursivePlan {
    /// Validate a level chain and derive exact Policy 3 query counts (no floats).
    pub fn new(
        levels: Vec<LevelSpec>,
        ext_degree: u8,
        target_bits: u16,
    ) -> Result<Self, RecursiveError> {
        if levels.is_empty()
            || levels.len() > MAX_LEVELS
            || (ext_degree != 4 && ext_degree != 8)
            || target_bits == 0
            || target_bits > MAX_TARGET_BITS
        {
            return Err(RecursiveError::UnsupportedSource);
        }
        let mut queries = reserve_vec(levels.len())?;
        for (i, &spec) in levels.iter().enumerate() {
            if spec.ell == 0
                || spec.ell > MAX_DOMAIN_BITS
                || spec.randomisers != 0
                || spec.mask_rows != 0
            {
                return Err(RecursiveError::UnsupportedSource);
            }
            if i + 1 < levels.len() && spec.m == 0 {
                return Err(RecursiveError::UnsupportedSource);
            }
            // Validate CircleCoeff parameters and capacity.
            let _ =
                CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).map_err(|e| match e {
                    stele_code::Error::Capacity => RecursiveError::Capacity,
                    _ => RecursiveError::UnsupportedSource,
                })?;
            let _ = spec.rows()?;
            if i + 1 < levels.len() {
                let next = levels[i + 1];
                if next.ell.checked_add(next.m) != Some(spec.m) {
                    return Err(RecursiveError::UnsupportedSource);
                }
            }
            let (q, _, _, _) = policy3_fresh_queries(spec.m, spec.b, target_bits)?;
            queries.push(q);
        }
        Ok(Self {
            target_bits,
            ext_degree,
            levels,
            queries,
        })
    }

    /// Exact DP minimiser matching `research/rfc0029-pcs/check_policy3.py` (RFC-0029 §3).
    /// Minimises `body_bytes` over `ell_i >= 1`, `m_i >= 1`, `b_i in blowups`, `m_i + b_i <= 30`,
    /// optionally enforcing the `2 * ell_i * (e_i + 1) <= floor(|K| / 2^T)` proximity bound (RFC-0029 §5).
    pub fn fresh_for_size(
        total_bits: u8,
        ext_degree: u8,
        target_bits: u16,
        capped: bool,
        blowups: &[u8],
    ) -> Result<Self, RecursiveError> {
        if !(2..=40).contains(&total_bits)
            || (ext_degree != 4 && ext_degree != 8)
            || target_bits == 0
            || target_bits > MAX_TARGET_BITS
            || blowups.is_empty()
            || blowups.iter().any(|&b| !(1..=4).contains(&b))
        {
            return Err(RecursiveError::UnsupportedSource);
        }
        let cap = field_cap(ext_degree, target_bits)?;
        let elem_ext = 4usize * usize::from(ext_degree);

        // Precompute (q, e) table for m in 1..=29, b in 1..=4 with m + b <= 30.
        let mut qe_table = [[None; 5]; 31];
        for (m_usize, row) in qe_table.iter_mut().enumerate().take(30).skip(1) {
            let m = m_usize as u8;
            for &b in blowups {
                if m + b <= MAX_DOMAIN_BITS && row[usize::from(b)].is_none() {
                    let (q, _, _, e) = policy3_fresh_queries(m, b, target_bits)?;
                    row[usize::from(b)] = Some((q, e));
                }
            }
        }

        // Memoised DP indexed by (n_bits, lvl), where lvl=0 is M31 and lvl>=1 is extension K.
        // At lvl>=1, `n_bits <= 29`; lvl <= 30.
        type DpBest = Option<(u64, Vec<LevelSpec>)>;
        type DpMemo = [Vec<Option<DpBest>>];
        let max_n = usize::from(total_bits);
        let mut memo: Vec<Vec<Option<DpBest>>> = vec![vec![None; MAX_LEVELS + 1]; max_n + 1];

        #[allow(clippy::too_many_arguments)]
        fn solve(
            n_bits: u8,
            lvl: usize,
            elem_ext: usize,
            capped: bool,
            cap: &BigUint,
            blowups: &[u8],
            qe_table: &[[Option<(u16, u64)>; 5]; 31],
            memo: &mut DpMemo,
        ) -> DpBest {
            if lvl >= MAX_LEVELS {
                return None;
            }
            if let Some(cached) = &memo[usize::from(n_bits)][lvl] {
                return cached.clone();
            }
            let mut best: Option<(u64, Vec<LevelSpec>)> = None;
            if lvl >= 1 && n_bits <= 30 {
                let final_bytes = (elem_ext as u64).checked_mul(1u64 << n_bits)?;
                best = Some((final_bytes, Vec::new()));
            }
            let elem = if lvl == 0 { 4u64 } else { elem_ext as u64 };
            for &b in blowups {
                for ell in 1..n_bits {
                    let m = n_bits - ell;
                    if ell > MAX_DOMAIN_BITS || m < 1 || m + b > MAX_DOMAIN_BITS {
                        continue;
                    }
                    let Some((q, e)) = qe_table[usize::from(m)][usize::from(b)] else {
                        continue;
                    };
                    if capped {
                        let prox_num = 2u64
                            .saturating_mul(u64::from(ell))
                            .saturating_mul(e.saturating_add(1));
                        if !BigUint::fits_cap(prox_num, cap)
                            || !BigUint::fits_cap(u64::from(q), cap)
                        {
                            continue;
                        }
                    }
                    let Some((sub_bytes, sub_levels)) =
                        solve(m, lvl + 1, elem_ext, capped, cap, blowups, qe_table, memo)
                    else {
                        continue;
                    };
                    let is_final_transition = sub_levels.is_empty();
                    let root_bytes = if is_final_transition { 0u64 } else { 32u64 };
                    let sc_bytes = if lvl >= 1 {
                        u64::from(ell) * 3 * (elem_ext as u64)
                    } else {
                        0u64
                    };
                    let Some(rows) = 1u64.checked_shl(u32::from(ell)) else {
                        continue;
                    };
                    let Some(col_bytes) = elem
                        .checked_mul(rows)
                        .and_then(|v| v.checked_add(32u64 * u64::from(m + b)))
                        .and_then(|v| u64::from(q).checked_mul(v))
                    else {
                        continue;
                    };
                    let Some(total) = root_bytes
                        .checked_add(sc_bytes)
                        .and_then(|v| v.checked_add(col_bytes))
                        .and_then(|v| v.checked_add(sub_bytes))
                    else {
                        continue;
                    };
                    let better = match &best {
                        None => true,
                        Some((best_total, _)) => total < *best_total,
                    };
                    if better {
                        let mut chain = Vec::with_capacity(1 + sub_levels.len());
                        chain.push(LevelSpec::new(ell, m, b));
                        chain.extend_from_slice(&sub_levels);
                        best = Some((total, chain));
                    }
                }
            }
            memo[usize::from(n_bits)][lvl] = Some(best.clone());
            best
        }

        let (_, chain) = solve(
            total_bits, 0, elem_ext, capped, &cap, blowups, &qe_table, &mut memo,
        )
        .ok_or(RecursiveError::UnsupportedSource)?;
        Self::new(chain, ext_degree, target_bits)
    }

    /// Target security parameter `T` in bits.
    pub fn target_bits(&self) -> u16 {
        self.target_bits
    }

    /// Extension field degree (`4` for QM31, `8` for OM31).
    pub fn ext_degree(&self) -> u8 {
        self.ext_degree
    }

    /// Ordered level specifications `0..L`.
    pub fn levels(&self) -> &[LevelSpec] {
        &self.levels
    }

    /// Derived Policy 3 query counts `q_0..q_{L-1}`.
    pub fn queries(&self) -> &[u16] {
        &self.queries
    }

    /// Total level-0 message elements `R_0 * C_0 = 2^(ell_0 + m_0)`.
    pub fn level0_elements(&self) -> Result<usize, RecursiveError> {
        let l0 = self.levels[0];
        mul_usize(l0.rows()?, l0.columns()?)
    }

    /// Total level-0 boolean variables `ell_0 + m_0`.
    pub fn level0_vars(&self) -> usize {
        usize::from(self.levels[0].ell) + usize::from(self.levels[0].m)
    }

    /// Fixed proof header length: `version (1 B) + L (1 B) + 3 * L` bytes of `(ell_i, m_i, b_i)`.
    pub fn header_bytes(&self) -> usize {
        2 + 3 * self.levels.len()
    }

    /// Exact RFC-0029 §3 body bytes (matches `research/rfc0029-pcs/check_policy3.py` to the byte).
    pub fn body_bytes(&self) -> Result<usize, RecursiveError> {
        let elem_ext = 4usize * usize::from(self.ext_degree);
        let l = self.levels.len();
        let mut total = 0usize;
        for (i, (&spec, &q)) in self.levels.iter().zip(&self.queries).enumerate() {
            let elem = if i == 0 { 4usize } else { elem_ext };
            let rows = spec.rows()?;
            if i >= 1 {
                let sc = mul_usize(usize::from(spec.ell), mul_usize(3, elem_ext)?)?;
                total = add_usize(total, sc)?;
            }
            if i + 1 < l {
                total = add_usize(total, 32)?;
            } else {
                let final_vec = mul_usize(spec.columns()?, elem_ext)?;
                total = add_usize(total, final_vec)?;
            }
            let per_query = add_usize(mul_usize(elem, rows)?, mul_usize(32, spec.path_height())?)?;
            total = add_usize(total, mul_usize(usize::from(q), per_query)?)?;
        }
        Ok(total)
    }

    /// Exact complete wire proof size (`header_bytes() + body_bytes()`).
    pub fn proof_size(&self) -> Result<usize, RecursiveError> {
        add_usize(self.header_bytes(), self.body_bytes()?)
    }

    fn write_header(&self, out: &mut Vec<u8>) {
        out.push(RECURSIVE_VERSION);
        out.push(self.levels.len() as u8);
        for spec in &self.levels {
            out.push(spec.ell);
            out.push(spec.m);
            out.push(spec.b);
        }
    }

    fn check_header(&self, proof: &[u8]) -> Result<usize, RecursiveError> {
        let expected_len = self.proof_size()?;
        let header_len = self.header_bytes();
        if proof.len() != expected_len || proof.len() < header_len {
            return Err(RecursiveError::ProofShape);
        }
        if proof[0] != RECURSIVE_VERSION || usize::from(proof[1]) != self.levels.len() {
            return Err(RecursiveError::ProofShape);
        }
        for (i, spec) in self.levels.iter().enumerate() {
            let off = 2 + 3 * i;
            if proof[off] != spec.ell || proof[off + 1] != spec.m || proof[off + 2] != spec.b {
                return Err(RecursiveError::ProofShape);
            }
        }
        Ok(header_len)
    }
}

/// Verifier-owned version-4 recursive Circle RS source context (RFC-0010 A17, RFC-0029 §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveSource<K: ChallengeField> {
    id: u64,
    plan: RecursivePlan,
    root: merkle::Digest,
    field: PhantomData<K>,
}

impl<K: ChallengeField> RecursiveSource<K> {
    /// Construct a validated version-4 source context for field `K`.
    pub fn new(id: u64, plan: RecursivePlan, root: merkle::Digest) -> Result<Self, RecursiveError> {
        if plan.ext_degree() != K::DEGREE as u8 {
            return Err(RecursiveError::UnsupportedSource);
        }
        Ok(Self {
            id,
            plan,
            root,
            field: PhantomData,
        })
    }

    /// Source identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Verifier-owned recursion plan.
    pub fn plan(&self) -> &RecursivePlan {
        &self.plan
    }

    /// Expected level-0 Merkle root.
    pub fn root(&self) -> merkle::Digest {
        self.root
    }

    /// Canonical version-4 source context bytes (RFC-0010 A17, RFC-0029 §7):
    /// `PURPOSE (23) || u8(4) || deg(K) || id (8) || ell_0 || code_id_0 (27) || R_0 (8) || C_0 (8)
    ///  || layout(0) || policy(3) || root_0 (32) || target_bits (2) || L (1)
    ///  || L * (ell_i, m_i, b_i, randomisers_i: u16, mask_rows_i: u16)`.
    pub fn bytes(&self) -> Result<Vec<u8>, RecursiveError> {
        let l0 = self.plan.levels[0];
        let code0 = CircleCoeff::new(u32::from(l0.m), u32::from(l0.b))?;
        let len = 114 + 7 * self.plan.levels.len();
        let mut out = reserve_vec(len)?;
        out.extend_from_slice(PURPOSE);
        out.push(RECURSIVE_VERSION);
        out.push(K::DEGREE as u8);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(l0.ell);
        out.extend_from_slice(&code0.code_id());
        out.extend_from_slice(&(1u64 << l0.ell).to_le_bytes());
        out.extend_from_slice(&(1u64 << l0.m).to_le_bytes());
        out.push(0); // layout
        out.push(POLICY_THREE);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.plan.target_bits.to_le_bytes());
        out.push(self.plan.levels.len() as u8);
        for spec in &self.plan.levels {
            out.push(spec.ell);
            out.push(spec.m);
            out.push(spec.b);
            out.extend_from_slice(&spec.randomisers.to_le_bytes());
            out.extend_from_slice(&spec.mask_rows.to_le_bytes());
        }
        Ok(out)
    }

    /// Parse exact canonical version-4 source context bytes; rejects any deviation with
    /// `UnsupportedSource` (including nonzero ZK reservations, wrong version/policy, or broken chain).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecursiveError> {
        if bytes.len() < 114 || bytes[..23] != PURPOSE[..] {
            return Err(RecursiveError::UnsupportedSource);
        }
        if bytes[23] != RECURSIVE_VERSION
            || bytes[24] != K::DEGREE as u8
            || bytes[77] != 0
            || bytes[78] != POLICY_THREE
        {
            return Err(RecursiveError::UnsupportedSource);
        }
        let id = u64::from_le_bytes(
            bytes[25..33]
                .try_into()
                .map_err(|_| RecursiveError::UnsupportedSource)?,
        );
        let root: merkle::Digest = bytes[79..111]
            .try_into()
            .map_err(|_| RecursiveError::UnsupportedSource)?;
        let target_bits = u16::from_le_bytes([bytes[111], bytes[112]]);
        let level_count = usize::from(bytes[113]);
        if level_count == 0 || level_count > MAX_LEVELS || bytes.len() != 114 + 7 * level_count {
            return Err(RecursiveError::UnsupportedSource);
        }
        let mut levels = reserve_vec(level_count)?;
        for i in 0..level_count {
            let off = 114 + 7 * i;
            let spec = LevelSpec {
                ell: bytes[off],
                m: bytes[off + 1],
                b: bytes[off + 2],
                randomisers: u16::from_le_bytes([bytes[off + 3], bytes[off + 4]]),
                mask_rows: u16::from_le_bytes([bytes[off + 5], bytes[off + 6]]),
            };
            levels.push(spec);
        }
        let plan = RecursivePlan::new(levels, K::DEGREE as u8, target_bits)?;
        let source = Self::new(id, plan, root)?;
        // Canonical re-serialization checks ell_0, code_id_0, R_0, C_0, layout, policy, etc.
        if source.bytes()? != bytes {
            return Err(RecursiveError::UnsupportedSource);
        }
        Ok(source)
    }
}

/// Exact per-level soundness accounting record (RFC-0029 §5, RFC-0012 A20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LevelLedger {
    /// Recursion level index `0..L`.
    pub level: u8,
    /// Row exponent `ell_i`.
    pub ell: u8,
    /// Column exponent `m_i`.
    pub m: u8,
    /// Blow-up exponent `b_i`.
    pub b: u8,
    /// Codeword length `N_i = 2^(m_i + b_i)`.
    pub length: u64,
    /// Distance lower bound `D_i = N_i - C_i` (`N_i` for `C_i = 1`).
    pub distance: u64,
    /// Proximity radius `e_i = floor((D_i - 1) / 3)`.
    pub radius: u64,
    /// Policy 3 query count `q_i`.
    pub queries: u16,
    /// Number of logical source blocks at this level (`1` for single-source fresh mode).
    pub blocks: u32,
    /// Tensor proximity test numerator over `|K|`: `2 * ell_i * (e_i + 1)`.
    pub proximity_numerator: u64,
    /// Row-round sumcheck numerator over `|K|`: `2 * ell_i` for `i >= 1`, `0` for `i = 0`.
    pub sumcheck_numerator: u64,
    /// Per-source consistency RLC (`pcs/level-beta`) numerator over `|K|`: `q_i` for `i < L - 1`, `0` for `i = L - 1`.
    pub beta_numerator: u64,
    /// Multi-source block combination RLC (`pcs/level-gamma`) numerator over `|K|`: `blocks - 1`.
    pub gamma_numerator: u64,
    /// Extension field degree (`4` or `8`).
    pub field_degree: u8,
    /// Policy 3 target bits `T`.
    pub target_bits: u16,
}

/// Complete soundness ledger for one verified recursive opening (RFC-0029 §5, RFC-0012 A20).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveLedger {
    /// Opening identifier bound into the transcript.
    pub opening_id: u64,
    /// Fresh-mode batching RLC numerator `(k - 1)` when invoked via `verify_fresh_claims`, else `0`.
    pub batch_rlc_numerator: u64,
    /// Fresh-mode batching sumcheck numerator `2 * (ell_0 + m_0)` when invoked via `verify_fresh_claims`, else `0`.
    pub batch_sc_numerator: u64,
    /// Per-level PCS / RLC / SC accounting records.
    pub levels: Vec<LevelLedger>,
    /// Local Merkle hash usage observed during verification (not an adversarial bound).
    pub merkle_usage: HashUsage,
}

/// Verified recursive opening receipt; constructed only after every level and final check passes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecursiveOpening<K: ChallengeField> {
    source_id: u64,
    opening_id: u64,
    point: Vec<K>,
    value: K,
    ledger: RecursiveLedger,
}

impl<K: ChallengeField> VerifiedRecursiveOpening<K> {
    /// Verified source id.
    pub fn source_id(&self) -> u64 {
        self.source_id
    }
    /// Verified opening id.
    pub fn opening_id(&self) -> u64 {
        self.opening_id
    }
    /// Fresh opening point `r*` (`len == ell_0 + m_0`).
    pub fn point(&self) -> &[K] {
        &self.point
    }
    /// Verified evaluation `M_0(r*)`.
    pub fn value(&self) -> K {
        self.value
    }
    /// Exact per-level soundness accounting ledger (RFC-0029 §5, RFC-0012 A20).
    pub fn ledger(&self) -> &RecursiveLedger {
        &self.ledger
    }
}

/// Canonical RFC-0012 A3 Merkle tree descriptor for recursion `level` of `source_id`.
/// Level 0 uses `id = source_id`; higher levels domain-separate with `source_id ^ (level << 56)`.
pub fn level_descriptor(
    source_id: u64,
    level: u8,
    spec: LevelSpec,
    elem_bytes: usize,
) -> Result<merkle::Descriptor, RecursiveError> {
    let rows = spec.rows()?;
    let n = spec.codeword_len()?;
    let width = mul_usize(rows, elem_bytes)?;
    Ok(merkle::Descriptor {
        kind: merkle::Kind::Columns,
        id: source_id ^ (u64::from(level) << 56),
        count: n as u64,
        width: width as u64,
    })
}

fn build_merkle_tree(
    spec: merkle::Descriptor,
    column_bytes: &[u8],
    usage: &mut HashUsage,
) -> Result<merkle::Tree, RecursiveError> {
    let n = usize::try_from(spec.count).map_err(|_| RecursiveError::Capacity)?;
    let width = usize::try_from(spec.width).map_err(|_| RecursiveError::Capacity)?;
    let mut leaves = reserve_vec(n)?;
    for j in 0..n {
        let start = mul_usize(j, width)?;
        leaves.push(&column_bytes[start..start + width]);
    }
    #[cfg(feature = "std")]
    let tree = merkle::Tree::new_with_usage_filled(spec, &leaves, usage, &|out, digest| {
        out.par_iter_mut()
            .enumerate()
            .for_each(|(idx, slot)| *slot = digest(idx));
    })?;
    #[cfg(not(feature = "std"))]
    let tree = merkle::Tree::new_with_usage(spec, &leaves, usage)?;
    Ok(tree)
}

/// Committed level-`i` matrix (encoded column bytes + Merkle tree).
struct CommittedLevel {
    descriptor: merkle::Descriptor,
    column_bytes: Vec<u8>,
    tree: merkle::Tree,
}

impl CommittedLevel {
    fn commit_m31(
        source_id: u64,
        spec: LevelSpec,
        message: &[M31],
        usage: &mut HashUsage,
    ) -> Result<Self, RecursiveError> {
        let rows = spec.rows()?;
        let cols = spec.columns()?;
        let n = spec.codeword_len()?;
        let expected_elems = mul_usize(rows, cols)?;
        if message.len() != expected_elems {
            return Err(RecursiveError::MessageShape);
        }
        let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;
        let col_bytes = mul_usize(rows, 4)?;
        let total_bytes = mul_usize(n, col_bytes)?;
        let mut column_bytes = reserve_vec(total_bytes)?;
        column_bytes.resize(total_bytes, 0u8);

        // Encode all R rows independently with CircleCoeff (one forward circle transform per row).
        #[cfg(feature = "std")]
        let encoded_rows: Vec<Vec<M31>> = message
            .par_chunks_exact(cols)
            .map(|row| code.encode(row))
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(not(feature = "std"))]
        let encoded_rows: Vec<Vec<M31>> = {
            let mut v = reserve_vec(rows)?;
            for row in message.chunks_exact(cols) {
                v.push(code.encode(row)?);
            }
            v
        };

        // Transpose into column-major canonical little-endian leaf payloads (`N` leaves of `4 * R` bytes).
        #[cfg(feature = "std")]
        column_bytes
            .par_chunks_exact_mut(col_bytes)
            .enumerate()
            .for_each(|(j, leaf)| {
                for (r, enc_row) in encoded_rows.iter().enumerate() {
                    let off = r * 4;
                    leaf[off..off + 4].copy_from_slice(&enc_row[j].to_le_bytes());
                }
            });
        #[cfg(not(feature = "std"))]
        for (j, leaf) in column_bytes.chunks_exact_mut(col_bytes).enumerate() {
            for (r, enc_row) in encoded_rows.iter().enumerate() {
                let off = r * 4;
                leaf[off..off + 4].copy_from_slice(&enc_row[j].to_le_bytes());
            }
        }
        drop(encoded_rows);

        let descriptor = level_descriptor(source_id, 0, spec, 4)?;
        let tree = build_merkle_tree(descriptor, &column_bytes, usage)?;
        Ok(Self {
            descriptor,
            column_bytes,
            tree,
        })
    }

    fn commit_ext<K: ChallengeField>(
        source_id: u64,
        level: u8,
        spec: LevelSpec,
        message: &[K],
        usage: &mut HashUsage,
    ) -> Result<Self, RecursiveError> {
        let rows = spec.rows()?;
        let cols = spec.columns()?;
        let n = spec.codeword_len()?;
        let expected_elems = mul_usize(rows, cols)?;
        if message.len() != expected_elems {
            return Err(RecursiveError::MessageShape);
        }
        let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;
        let elem_bytes = 4 * K::DEGREE;
        let col_bytes = mul_usize(rows, elem_bytes)?;
        let total_bytes = mul_usize(n, col_bytes)?;
        let mut column_bytes = reserve_vec(total_bytes)?;
        column_bytes.resize(total_bytes, 0u8);

        #[cfg(feature = "std")]
        let encoded_rows: Vec<Vec<K>> = message
            .par_chunks_exact(cols)
            .map(|row| code.encode(row))
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(not(feature = "std"))]
        let encoded_rows: Vec<Vec<K>> = {
            let mut v = reserve_vec(rows)?;
            for row in message.chunks_exact(cols) {
                v.push(code.encode(row)?);
            }
            v
        };

        #[cfg(feature = "std")]
        column_bytes
            .par_chunks_exact_mut(col_bytes)
            .enumerate()
            .for_each(|(j, leaf)| {
                for (r, enc_row) in encoded_rows.iter().enumerate() {
                    let off = r * elem_bytes;
                    leaf[off..off + elem_bytes].copy_from_slice(enc_row[j].to_le_bytes().as_ref());
                }
            });
        #[cfg(not(feature = "std"))]
        for (j, leaf) in column_bytes.chunks_exact_mut(col_bytes).enumerate() {
            for (r, enc_row) in encoded_rows.iter().enumerate() {
                let off = r * elem_bytes;
                leaf[off..off + elem_bytes].copy_from_slice(enc_row[j].to_le_bytes().as_ref());
            }
        }
        drop(encoded_rows);

        let descriptor = level_descriptor(source_id, level, spec, elem_bytes)?;
        let tree = build_merkle_tree(descriptor, &column_bytes, usage)?;
        Ok(Self {
            descriptor,
            column_bytes,
            tree,
        })
    }

    fn root(&self) -> merkle::Digest {
        self.tree.root()
    }

    fn append_response(&self, index: u64, out: &mut Vec<u8>) -> Result<(), RecursiveError> {
        let j = usize::try_from(index).map_err(|_| RecursiveError::Capacity)?;
        let width = usize::try_from(self.descriptor.width).map_err(|_| RecursiveError::Capacity)?;
        let start = mul_usize(j, width)?;
        out.extend_from_slice(&self.column_bytes[start..start + width]);
        let siblings = self.tree.path(index)?;
        for sibling in siblings {
            out.extend_from_slice(&sibling);
        }
        Ok(())
    }

    fn payload(&self, index: u64) -> Result<&[u8], RecursiveError> {
        let j = usize::try_from(index).map_err(|_| RecursiveError::Capacity)?;
        let width = usize::try_from(self.descriptor.width).map_err(|_| RecursiveError::Capacity)?;
        let start = mul_usize(j, width)?;
        Ok(&self.column_bytes[start..start + width])
    }
}

/// Prepared level-0 M31 source ready for fresh-mode recursive openings (RFC-0029 §2).
pub struct PreparedRecursive<K: ChallengeField> {
    source: RecursiveSource<K>,
    message: Vec<M31>,
    level0: CommittedLevel,
}

impl<K: ChallengeField> PreparedRecursive<K> {
    /// Commit a row-major `R_0 × C_0` M31 matrix under `plan` (version 4, Policy 3).
    pub fn commit(id: u64, plan: RecursivePlan, message: Vec<M31>) -> Result<Self, RecursiveError> {
        if plan.ext_degree() != K::DEGREE as u8 {
            return Err(RecursiveError::UnsupportedSource);
        }
        let mut usage = HashUsage::default();
        let level0 = CommittedLevel::commit_m31(id, plan.levels[0], &message, &mut usage)?;
        let root = level0.root();
        let source = RecursiveSource::new(id, plan, root)?;
        Ok(Self {
            source,
            message,
            level0,
        })
    }

    /// The verifier-facing version-4 source context (including level-0 root).
    pub fn source(&self) -> &RecursiveSource<K> {
        &self.source
    }

    /// Borrow the underlying row-major M31 message.
    pub fn message(&self) -> &[M31] {
        &self.message
    }

    /// Evaluate the multilinear extension `M̃_0(point)` at an MSB-first point of length `ell_0 + m_0`.
    pub fn evaluate(&self, point: &[K]) -> Result<K, RecursiveError> {
        let l0 = self.source.plan.levels[0];
        let ell0 = usize::from(l0.ell);
        let m0 = usize::from(l0.m);
        if point.len() != ell0 + m0 {
            return Err(RecursiveError::MessageShape);
        }
        let eq_row = stele_poly::eq_table(&point[..ell0]).map_err(|_| RecursiveError::Capacity)?;
        let eq_col = stele_poly::eq_table(&point[ell0..]).map_err(|_| RecursiveError::Capacity)?;
        let cols = l0.columns()?;
        let mut total = K::from_i64(0);
        for (row, &a) in self.message.chunks_exact(cols).zip(&eq_row) {
            let mut row_dot = K::from_i64(0);
            for (&val, &b) in row.iter().zip(&eq_col) {
                row_dot = row_dot + b.mul_m31(val);
            }
            total = total + a * row_dot;
        }
        Ok(total)
    }

    /// Produce a fresh-mode recursive opening proof at an already-derived fresh point `point`
    /// (`len == ell_0 + m_0`) with claimed evaluation `value` (RFC-0029 §2).
    ///
    /// Caller invariant (RFC-0029 §1.3): `self.source().root()` MUST already be absorbed into
    /// `t` before `point` was drawn. Use [`Self::open_fresh_claims`] to run the full fresh-mode
    /// batching sumcheck + recursive opening together.
    pub fn open_fresh_at_point(
        &self,
        t: &mut Transcript<K>,
        opening_id: u64,
        point: &[K],
        value: K,
    ) -> Result<Vec<u8>, RecursiveError>
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let plan = &self.source.plan;
        let l = plan.levels.len();
        let l0 = plan.levels[0];
        let ell0 = usize::from(l0.ell);
        let m0 = usize::from(l0.m);
        if point.len() != ell0 + m0 {
            return Err(RecursiveError::MessageShape);
        }

        let r_row0 = &point[..ell0];
        let r_col0 = &point[ell0..];
        let eq_row0 = stele_poly::eq_table(r_row0).map_err(|_| RecursiveError::Capacity)?;
        let mut cur_w = stele_poly::eq_table(r_col0).map_err(|_| RecursiveError::Capacity)?;

        // Level-0 row combination u_1 = eq(r_row0)^T M_0.
        let cols0 = l0.columns()?;
        let mut cur_u = reserve_vec(cols0)?;
        cur_u.resize(cols0, K::from_i64(0));
        for (row, &a) in self.message.chunks_exact(cols0).zip(&eq_row0) {
            for (dst, &val) in cur_u.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(val);
            }
        }
        let actual_v0 = dot_ext(&cur_w, &cur_u);
        if actual_v0.to_le_bytes().as_ref() != value.to_le_bytes().as_ref() {
            return Err(RecursiveError::ValueMismatch);
        }

        // Absorb opening statement.
        absorb_opening_statement(t, opening_id, &self.source, point, value)?;

        let mut proof = reserve_vec(plan.proof_size()?)?;
        plan.write_header(&mut proof);

        let mut cur_committed: Option<CommittedLevel> = None;
        let mut cur_eq_row = eq_row0;
        let mut cur_claim = value;
        let mut commit_usage = HashUsage::default();

        for i in 0..l {
            let spec = plan.levels[i];
            let q_i = usize::from(plan.queries[i]);
            let code_i = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;

            // Step 1 (i >= 1): ell_i degree-2 row-round sumcheck on (cur_w, M_i).
            if i >= 1 {
                let res = run_row_sumcheck_prover(
                    t,
                    opening_id,
                    i as u8,
                    spec.ell,
                    spec.columns()?,
                    cur_w,
                    cur_u,
                    cur_claim,
                    &mut proof,
                )?;
                cur_w = res.next_w;
                cur_u = res.next_u;
                cur_eq_row =
                    stele_poly::eq_table(&res.challenges).map_err(|_| RecursiveError::Capacity)?;
                cur_claim = res.running;
            }

            // Step 2: commit u_{i+1} (or send u_L in the clear at final level i == L - 1).
            let next_committed = if i + 1 < l {
                let next_spec = plan.levels[i + 1];
                let committed = CommittedLevel::commit_ext(
                    self.source.id,
                    (i + 1) as u8,
                    next_spec,
                    &cur_u,
                    &mut commit_usage,
                )?;
                let root = committed.root();
                proof.extend_from_slice(&root);
                t.absorb(AbsorbLabel::PcsLevelRoot, &root)?;
                Some(committed)
            } else {
                let start = proof.len();
                for elem in &cur_u {
                    proof.extend_from_slice(elem.to_le_bytes().as_ref());
                }
                t.absorb(AbsorbLabel::PcsLevelRoot, &proof[start..])?;
                None
            };

            // Step 3: draw q_i column indices, append payloads + Merkle paths, absorb OpeningColumns.
            let active = match &cur_committed {
                None => &self.level0,
                Some(lvl) => lvl,
            };
            let n_i = active.descriptor.count;
            let mut queried = reserve_vec(q_i)?;
            let resp_start = proof.len();
            for _ in 0..q_i {
                let idx = t.opening_column(n_i)?;
                active.append_response(idx, &mut proof)?;
                queried.push(idx);
            }
            t.absorb(AbsorbLabel::OpeningColumns, &proof[resp_start..])?;

            // Step 4 (i < L - 1): compute y_t, draw beta_i, fold into w_{i+1} and v_{i+1}.
            if i + 1 < l {
                let mut ys = reserve_vec(q_i)?;
                for &idx in &queried {
                    let payload = active.payload(idx)?;
                    let y = if i == 0 {
                        column_dot_m31(&cur_eq_row, payload)?
                    } else {
                        column_dot_ext(&cur_eq_row, payload)?
                    };
                    ys.push(y);
                }
                let beta = t.challenge(ChallengeLabel::PcsLevelBeta)?;
                let mut beta_pow = beta;
                let mut basis_buf = reserve_vec(cur_w.len())?;
                basis_buf.resize(cur_w.len(), M31::ZERO);
                for (&idx, &y) in queried.iter().zip(&ys) {
                    cur_claim = cur_claim + beta_pow * y;
                    let mut factors = code_i.basis_factors(idx as usize)?;
                    factors.reverse(); // MSB-first
                    fill_basis_table(&factors, &mut basis_buf);
                    for (dst, &b_val) in cur_w.iter_mut().zip(&basis_buf) {
                        *dst = *dst + beta_pow.mul_m31(b_val);
                    }
                    beta_pow = beta_pow * beta;
                }
                cur_committed = next_committed;
            }
        }

        debug_assert_eq!(proof.len(), plan.proof_size()?);
        Ok(proof)
    }

    /// Complete fresh-mode opening for one or more point claims `(point_c, value_c)` on `M_0`
    /// (RFC-0029 §1.3): absorbs `self.source().bytes()`, runs the `ell_0 + m_0`-round degree-2
    /// batching sumcheck to derive a genuinely fresh transcript-random point `r*`, and opens
    /// `M_0` recursively at `r*`.
    pub fn open_fresh_claims(
        &self,
        t: &mut Transcript<K>,
        opening_id: u64,
        claims: &[(&[K], K)],
    ) -> Result<Vec<u8>, RecursiveError>
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let vars = self.source.plan.level0_vars();
        if claims.is_empty() || claims.iter().any(|(p, _)| p.len() != vars) {
            return Err(RecursiveError::MessageShape);
        }
        let source_bytes = self.source.bytes()?;
        t.absorb(AbsorbLabel::FieldSources, &source_bytes)?;
        absorb_claims_header(t, opening_id, claims)?;

        let lambda = if claims.len() > 1 {
            t.challenge(ChallengeLabel::BatchCoefficient)?
        } else {
            K::from_i64(1)
        };

        let n_elems = self.message.len();
        let mut w_batch = reserve_vec(n_elems)?;
        w_batch.resize(n_elems, K::from_i64(0));
        let mut batch_claim = K::from_i64(0);
        let mut lam_pow = K::from_i64(1);
        for &(point, val) in claims {
            let eq = stele_poly::eq_table(point).map_err(|_| RecursiveError::Capacity)?;
            for (dst, &e) in w_batch.iter_mut().zip(&eq) {
                *dst = *dst + lam_pow * e;
            }
            batch_claim = batch_claim + lam_pow * val;
            lam_pow = lam_pow * lambda;
        }

        let elem_bytes = 4 * K::DEGREE;
        let batch_prefix_len = add_usize(mul_usize(vars, mul_usize(3, elem_bytes)?)?, elem_bytes)?;
        let total_len = add_usize(batch_prefix_len, self.source.plan.proof_size()?)?;
        let mut out = reserve_vec(total_len)?;

        // Absorb batch sumcheck instance header.
        absorb_sumcheck_instance(t, opening_id, 0xff, vars as u8, batch_claim)?;

        // Run `vars` degree-2 sumcheck rounds over `w_batch` and `self.message` (base field on round 0).
        let (r_star, v_star) = run_batch_sumcheck_prover(
            t,
            opening_id,
            vars,
            w_batch,
            &self.message,
            batch_claim,
            &mut out,
        )?;
        out.extend_from_slice(v_star.to_le_bytes().as_ref());
        t.absorb(AbsorbLabel::Final, v_star.to_le_bytes().as_ref())?;

        // Append recursive opening at the fresh point `r_star`.
        let rec_bytes = self.open_fresh_at_point(t, opening_id, &r_star, v_star)?;
        out.extend_from_slice(&rec_bytes);
        debug_assert_eq!(out.len(), total_len);
        Ok(out)
    }
}

/// Rank-one or dense multilinear term in `w_i` (verifier never materialises rank-one terms until `C_L`).
enum WeightTerm<K: Field> {
    Eq { coeff: K, point: Vec<K> },
    Basis { coeff: K, factors_msb: Vec<M31> },
    Dense { values: Vec<K> },
}

impl<K: Field> WeightTerm<K> {
    fn fold_prefix(&mut self, r: &[K]) -> Result<(), RecursiveError> {
        let one = K::from_i64(1);
        match self {
            Self::Eq { coeff, point } => {
                let mut acc = one;
                for (&p, &x) in point[..r.len()].iter().zip(r) {
                    acc = acc * ((one - p) * (one - x) + p * x);
                }
                *coeff = *coeff * acc;
                point.drain(..r.len());
            }
            Self::Basis { coeff, factors_msb } => {
                let mut acc = one;
                for (&f, &x) in factors_msb[..r.len()].iter().zip(r) {
                    acc = acc * (one - x + x.mul_m31(f));
                }
                *coeff = *coeff * acc;
                factors_msb.drain(..r.len());
            }
            Self::Dense { values } => {
                let eq = stele_poly::eq_table(r).map_err(|_| RecursiveError::Capacity)?;
                let cols = values.len() / eq.len();
                let mut next = reserve_vec(cols)?;
                next.resize(cols, K::from_i64(0));
                for (row, &w) in values.chunks_exact(cols).zip(&eq) {
                    for (dst, &v) in next.iter_mut().zip(row) {
                        *dst = *dst + w * v;
                    }
                }
                *values = next;
            }
        }
        Ok(())
    }

    fn dot_final(&self, u_final: &[K], basis_buf: &mut [M31]) -> Result<K, RecursiveError> {
        match self {
            Self::Eq { coeff, point } => {
                let eq = stele_poly::eq_table(point).map_err(|_| RecursiveError::Capacity)?;
                Ok(*coeff * dot_ext(&eq, u_final))
            }
            Self::Basis { coeff, factors_msb } => {
                fill_basis_table(factors_msb, basis_buf);
                let mut acc = K::from_i64(0);
                for (&u, &b) in u_final.iter().zip(basis_buf.iter()) {
                    acc = acc + u.mul_m31(b);
                }
                Ok(*coeff * acc)
            }
            Self::Dense { values } => Ok(dot_ext(values, u_final)),
        }
    }
}

/// Verify a fresh-mode recursive opening at a caller-derived fresh point `point` (`len == ell_0 + m_0`)
/// and claimed value `value` (RFC-0029 §§1.3, 2, 4, 5).
///
/// # Security Invariant
/// Fresh-mode proximity soundness (`RFC-0029 §1.3`, `formal/tensor-opening.md`) requires that
/// `source.root()` was already absorbed into `t` **before** `point` was derived from the
/// transcript (e.g. via RFC-0006 A2 mode-1 batching). Callers without an already-derived fresh
/// transcript point MUST use [`verify_fresh_claims`].
pub fn verify_fresh_at_point<K: ChallengeField>(
    t: &mut Transcript<K>,
    source: &RecursiveSource<K>,
    opening_id: u64,
    point: &[K],
    value: K,
    proof: &[u8],
) -> Result<VerifiedRecursiveOpening<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    verify_fresh_at_point_inner(t, source, opening_id, point, value, proof, 0, 0)
}

#[allow(clippy::too_many_arguments)]
fn verify_fresh_at_point_inner<K: ChallengeField>(
    t: &mut Transcript<K>,
    source: &RecursiveSource<K>,
    opening_id: u64,
    point: &[K],
    value: K,
    proof: &[u8],
    batch_rlc_numerator: u64,
    batch_sc_numerator: u64,
) -> Result<VerifiedRecursiveOpening<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan = &source.plan;
    let l = plan.levels.len();
    let l0 = plan.levels[0];
    let ell0 = usize::from(l0.ell);
    let m0 = usize::from(l0.m);
    if point.len() != ell0 + m0 {
        return Err(RecursiveError::MessageShape);
    }
    // Check header & complete proof length before touching the transcript (NC-0633).
    let mut cursor = plan.check_header(proof)?;

    absorb_opening_statement(t, opening_id, source, point, value)?;

    let elem_ext = 4 * K::DEGREE;
    let mut terms = reserve_vec(1)?;
    terms.push(WeightTerm::Eq {
        coeff: K::from_i64(1),
        point: point[ell0..].to_vec(),
    });
    let mut cur_root = source.root;
    let mut cur_claim = value;
    let mut merkle_usage = HashUsage::default();
    let mut level_ledgers = reserve_vec(l)?;

    for i in 0..l {
        let spec = plan.levels[i];
        let q_i = usize::from(plan.queries[i]);
        let code_i = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;
        let (_, n_i, d_i, e_i) = circle_coeff_params(spec.m, spec.b)?;

        // Step 1 (i >= 1): ell_i degree-2 row-round sumcheck.
        let eq_row = if i == 0 {
            stele_poly::eq_table(&point[..ell0]).map_err(|_| RecursiveError::Capacity)?
        } else {
            let (r_i, v_prime) = verify_row_sumcheck(
                t,
                opening_id,
                i as u8,
                spec.ell,
                cur_claim,
                proof,
                &mut cursor,
            )?;
            for term in &mut terms {
                term.fold_prefix(&r_i)?;
            }
            cur_claim = v_prime;
            stele_poly::eq_table(&r_i).map_err(|_| RecursiveError::Capacity)?
        };

        // Step 2: read & absorb next root (i < L - 1) or clear u_L (i == L - 1) BEFORE Step 3 queries.
        let mut next_root = [0u8; 32];
        let mut final_u: Option<Vec<K>> = None;
        if i + 1 < l {
            let slice = take_slice(proof, &mut cursor, 32)?;
            next_root.copy_from_slice(slice);
            t.absorb(AbsorbLabel::PcsLevelRoot, &next_root)?;
        } else {
            let c_final = spec.columns()?;
            let bytes = take_slice(proof, &mut cursor, mul_usize(c_final, elem_ext)?)?;
            let decoded = decode_ext_slice::<K>(bytes)?;
            t.absorb(AbsorbLabel::PcsLevelRoot, bytes)?;
            final_u = Some(decoded);
        }

        // Step 3: draw q_i column indices, verify Merkle paths, decode columns, absorb OpeningColumns.
        let elem_i = if i == 0 { 4usize } else { elem_ext };
        let desc_i = level_descriptor(source.id, i as u8, spec, elem_i)?;
        let col_width = usize::try_from(desc_i.width).map_err(|_| RecursiveError::Capacity)?;
        let path_height = spec.path_height();
        let path_bytes = mul_usize(path_height, 32)?;
        let per_query = add_usize(col_width, path_bytes)?;
        let resp_start = cursor;
        let resp_len = mul_usize(q_i, per_query)?;
        let resp_end = add_usize(resp_start, resp_len)?;
        if resp_end > proof.len() {
            return Err(RecursiveError::ProofShape);
        }

        let mut queried = reserve_vec(q_i)?;
        let mut ys = reserve_vec(q_i)?;
        let mut siblings = reserve_vec(path_height)?;
        for _ in 0..q_i {
            let idx = t.opening_column(n_i)?;
            let payload = take_slice(proof, &mut cursor, col_width)?;
            let sib_bytes = take_slice(proof, &mut cursor, path_bytes)?;
            siblings.clear();
            for chunk in sib_bytes.chunks_exact(32) {
                let mut d = [0u8; 32];
                d.copy_from_slice(chunk);
                siblings.push(d);
            }
            merkle::verify_with_usage(
                desc_i,
                &cur_root,
                idx,
                merkle::Opening {
                    payload,
                    siblings: &siblings,
                },
                &mut merkle_usage,
            )?;
            let y = if i == 0 {
                column_dot_m31(&eq_row, payload)?
            } else {
                column_dot_ext(&eq_row, payload)?
            };
            queried.push(idx);
            ys.push(y);
        }
        t.absorb(AbsorbLabel::OpeningColumns, &proof[resp_start..resp_end])?;

        // Record exact RFC-0029 §5 / RFC-0012 A20 ledger line for level `i`.
        level_ledgers.push(LevelLedger {
            level: i as u8,
            ell: spec.ell,
            m: spec.m,
            b: spec.b,
            length: n_i,
            distance: d_i,
            radius: e_i,
            queries: plan.queries[i],
            blocks: 1,
            proximity_numerator: 2u64
                .saturating_mul(u64::from(spec.ell))
                .saturating_mul(e_i.saturating_add(1)),
            sumcheck_numerator: if i >= 1 { 2 * u64::from(spec.ell) } else { 0 },
            beta_numerator: if i + 1 < l {
                u64::from(plan.queries[i])
            } else {
                0
            },
            gamma_numerator: 0,
            field_degree: K::DEGREE as u8,
            target_bits: plan.target_bits,
        });

        if i + 1 < l {
            // Step 4: draw beta_i and derive next-level claim.
            let beta = t.challenge(ChallengeLabel::PcsLevelBeta)?;
            let mut beta_pow = beta;
            for (&idx, &y) in queried.iter().zip(&ys) {
                cur_claim = cur_claim + beta_pow * y;
                let mut factors_msb = code_i.basis_factors(idx as usize)?;
                factors_msb.reverse();
                terms.try_reserve(1).map_err(|_| RecursiveError::Capacity)?;
                terms.push(WeightTerm::Basis {
                    coeff: beta_pow,
                    factors_msb,
                });
                beta_pow = beta_pow * beta;
            }
            cur_root = next_root;
        } else {
            // Step 6: re-encode u_L, check queried columns directly (`ColumnMismatch`),
            // then check `⟨w_L, u_L⟩ == cur_claim` (`ValueMismatch`).
            let u_l = final_u.ok_or(RecursiveError::ProofShape)?;
            let encoded = code_i.encode(&u_l)?;
            for (&idx, &y) in queried.iter().zip(&ys) {
                if encoded[idx as usize].to_le_bytes().as_ref() != y.to_le_bytes().as_ref() {
                    return Err(RecursiveError::ColumnMismatch);
                }
            }
            let mut basis_buf = reserve_vec(u_l.len())?;
            basis_buf.resize(u_l.len(), M31::ZERO);
            let mut dot = K::from_i64(0);
            for term in &terms {
                dot = dot + term.dot_final(&u_l, &mut basis_buf)?;
            }
            if dot.to_le_bytes().as_ref() != cur_claim.to_le_bytes().as_ref() {
                return Err(RecursiveError::ValueMismatch);
            }
        }
    }

    if cursor != proof.len() {
        return Err(RecursiveError::ProofShape);
    }

    Ok(VerifiedRecursiveOpening {
        source_id: source.id,
        opening_id,
        point: point.to_vec(),
        value,
        ledger: RecursiveLedger {
            opening_id,
            batch_rlc_numerator,
            batch_sc_numerator,
            levels: level_ledgers,
            merkle_usage,
        },
    })
}

/// Verify a complete fresh-mode proof for one or more point claims `(point_c, value_c)` on `source`
/// (RFC-0029 §1.3 & §2).
pub fn verify_fresh_claims<K: ChallengeField>(
    t: &mut Transcript<K>,
    source: &RecursiveSource<K>,
    opening_id: u64,
    claims: &[(&[K], K)],
    proof: &[u8],
) -> Result<VerifiedRecursiveOpening<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let vars = source.plan.level0_vars();
    if claims.is_empty() || claims.iter().any(|(p, _)| p.len() != vars) {
        return Err(RecursiveError::MessageShape);
    }
    let elem_bytes = 4 * K::DEGREE;
    let batch_prefix_len = add_usize(mul_usize(vars, mul_usize(3, elem_bytes)?)?, elem_bytes)?;
    let expected_len = add_usize(batch_prefix_len, source.plan.proof_size()?)?;
    if proof.len() != expected_len {
        return Err(RecursiveError::ProofShape);
    }
    // Also validate recursive proof header before transcript work.
    let _ = source.plan.check_header(&proof[batch_prefix_len..])?;

    let source_bytes = source.bytes()?;
    t.absorb(AbsorbLabel::FieldSources, &source_bytes)?;
    absorb_claims_header(t, opening_id, claims)?;

    let lambda = if claims.len() > 1 {
        t.challenge(ChallengeLabel::BatchCoefficient)?
    } else {
        K::from_i64(1)
    };
    let mut batch_claim = K::from_i64(0);
    let mut lam_pow = K::from_i64(1);
    for &(_, val) in claims {
        batch_claim = batch_claim + lam_pow * val;
        lam_pow = lam_pow * lambda;
    }

    absorb_sumcheck_instance(t, opening_id, 0xff, vars as u8, batch_claim)?;

    let mut cursor = 0usize;
    let mut r_star = reserve_vec(vars)?;
    let mut running = batch_claim;
    for round in 0..vars {
        let round_vals = decode_ext_slice::<K>(take_slice(proof, &mut cursor, 3 * elem_bytes)?)?;
        let (y0, y1, y2) = (round_vals[0], round_vals[1], round_vals[2]);
        if (y0 + y1).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
            return Err(RecursiveError::RoundSumMismatch);
        }
        absorb_sumcheck_round(t, opening_id, round as u32, [y0, y1, y2])?;
        let r = t.challenge(ChallengeLabel::Sumcheck)?;
        running = interpolate_deg2([y0, y1, y2], r);
        r_star.push(r);
    }

    let v_star_bytes = take_slice(proof, &mut cursor, elem_bytes)?;
    let v_star = decode_ext::<K>(v_star_bytes)?;
    t.absorb(AbsorbLabel::Final, v_star_bytes)?;

    // Check `(Σ_c lambda^c eq(p_c, r_star)) * v_star == running` (NC-0634).
    let mut w_at_r = K::from_i64(0);
    let mut lam_pow = K::from_i64(1);
    for &(point, _) in claims {
        let eq_val =
            stele_poly::eq_evaluate(point, &r_star).map_err(|_| RecursiveError::Capacity)?;
        w_at_r = w_at_r + lam_pow * eq_val;
        lam_pow = lam_pow * lambda;
    }
    if (w_at_r * v_star).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
        return Err(RecursiveError::RoundSumMismatch);
    }

    let batch_rlc = (claims.len() - 1) as u64;
    let batch_sc = 2 * (vars as u64);
    verify_fresh_at_point_inner(
        t,
        source,
        opening_id,
        &r_star,
        v_star,
        &proof[cursor..],
        batch_rlc,
        batch_sc,
    )
}

// ---------- Helpers ----------

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], RecursiveError> {
    let end = add_usize(*cursor, len)?;
    let slice = bytes.get(*cursor..end).ok_or(RecursiveError::ProofShape)?;
    *cursor = end;
    Ok(slice)
}

fn decode_ext<K: ChallengeField>(bytes: &[u8]) -> Result<K, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let arr = K::Bytes::try_from(bytes).map_err(|_| RecursiveError::NoncanonicalField)?;
    K::from_le_bytes(arr).ok_or(RecursiveError::NoncanonicalField)
}

fn decode_ext_slice<K: ChallengeField>(bytes: &[u8]) -> Result<Vec<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let stride = 4 * K::DEGREE;
    if !bytes.len().is_multiple_of(stride) {
        return Err(RecursiveError::ProofShape);
    }
    let count = bytes.len() / stride;
    let mut out = reserve_vec(count)?;
    for chunk in bytes.chunks_exact(stride) {
        out.push(decode_ext::<K>(chunk)?);
    }
    Ok(out)
}

fn column_dot_m31<K: ChallengeField>(eq_row: &[K], payload: &[u8]) -> Result<K, RecursiveError> {
    if payload.len() != eq_row.len() * 4 {
        return Err(RecursiveError::ProofShape);
    }
    let mut acc = K::from_i64(0);
    for (&w, chunk) in eq_row.iter().zip(payload.chunks_exact(4)) {
        let arr: [u8; 4] = chunk.try_into().map_err(|_| RecursiveError::ProofShape)?;
        let val = M31::from_le_bytes(arr).ok_or(RecursiveError::NoncanonicalField)?;
        acc = acc + w.mul_m31(val);
    }
    Ok(acc)
}

fn column_dot_ext<K: ChallengeField>(eq_row: &[K], payload: &[u8]) -> Result<K, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let stride = 4 * K::DEGREE;
    if payload.len() != eq_row.len() * stride {
        return Err(RecursiveError::ProofShape);
    }
    let mut acc = K::from_i64(0);
    for (&w, chunk) in eq_row.iter().zip(payload.chunks_exact(stride)) {
        let val = decode_ext::<K>(chunk)?;
        acc = acc + w * val;
    }
    Ok(acc)
}

fn dot_ext<K: Field>(a: &[K], b: &[K]) -> K {
    let mut acc = K::from_i64(0);
    for (&x, &y) in a.iter().zip(b) {
        acc = acc + x * y;
    }
    acc
}

/// Fill `out[idx] = Π_{k: (idx >> (m - 1 - k)) & 1 == 1} factors_msb[k]` in `O(2^m)` M31 ops.
fn fill_basis_table(factors_msb: &[M31], out: &mut [M31]) {
    out[0] = M31::ONE;
    let mut width = 1usize;
    for &f in factors_msb {
        for idx in (0..width).rev() {
            let parent = out[idx];
            out[2 * idx] = parent;
            out[2 * idx + 1] = parent * f;
        }
        width *= 2;
    }
}

/// Exact degree-2 Lagrange interpolation at `r` from `[y(0), y(1), y(2)]`.
/// Over M31 (`p = 2^31 - 1`), `2^{-1} = (p + 1) / 2 = 2^30 = 1073741824`.
fn interpolate_deg2<K: Field>(y: [K; 3], r: K) -> K {
    let one = K::from_i64(1);
    let two = K::from_i64(2);
    let inv2 = M31::from_i64(1 << 30);
    let r_m1 = r - one;
    let r_m2 = r - two;
    let t0 = (y[0] * (r_m1 * r_m2)).mul_m31(inv2);
    let t1 = -(y[1] * (r * r_m2));
    let t2 = (y[2] * (r * r_m1)).mul_m31(inv2);
    t0 + t1 + t2
}

fn absorb_opening_statement<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    source: &RecursiveSource<K>,
    point: &[K],
    value: K,
) -> Result<(), RecursiveError> {
    let src_bytes = source.bytes()?;
    let elem = 4 * K::DEGREE;
    let pv_len = mul_usize(add_usize(point.len(), 1)?, elem)?;
    let total = add_usize(add_usize(8, src_bytes.len())?, pv_len)?;
    let mut frame = reserve_vec(total)?;
    frame.extend_from_slice(&opening_id.to_le_bytes());
    frame.extend_from_slice(&src_bytes);
    for p in point {
        frame.extend_from_slice(p.to_le_bytes().as_ref());
    }
    frame.extend_from_slice(value.to_le_bytes().as_ref());
    t.absorb(AbsorbLabel::Opening, &frame)?;
    Ok(())
}

fn absorb_claims_header<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    claims: &[(&[K], K)],
) -> Result<(), RecursiveError> {
    let count = u32::try_from(claims.len()).map_err(|_| RecursiveError::Capacity)?;
    let elem = 4 * K::DEGREE;
    let vars = claims[0].0.len();
    let per_claim = mul_usize(add_usize(vars, 1)?, elem)?;
    let total = add_usize(12, mul_usize(claims.len(), per_claim)?)?;
    let mut frame = reserve_vec(total)?;
    frame.extend_from_slice(&opening_id.to_le_bytes());
    frame.extend_from_slice(&count.to_le_bytes());
    for &(point, val) in claims {
        for p in point {
            frame.extend_from_slice(p.to_le_bytes().as_ref());
        }
        frame.extend_from_slice(val.to_le_bytes().as_ref());
    }
    t.absorb(AbsorbLabel::Batch, &frame)?;
    Ok(())
}

fn absorb_sumcheck_instance<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    tag: u8,
    num_vars: u8,
    claim: K,
) -> Result<(), RecursiveError> {
    let mut buf = [0u8; 43];
    let elem = 4 * K::DEGREE;
    buf[..8].copy_from_slice(&opening_id.to_le_bytes());
    buf[8] = tag;
    buf[9] = num_vars;
    buf[10] = 2; // degree 2
    buf[11..11 + elem].copy_from_slice(claim.to_le_bytes().as_ref());
    t.absorb(AbsorbLabel::Instance, &buf[..11 + elem])?;
    Ok(())
}

fn absorb_sumcheck_round<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    round: u32,
    vals: [K; 3],
) -> Result<(), RecursiveError> {
    let elem = 4 * K::DEGREE;
    let mut buf = [0u8; 108]; // 12 + 3 * 32 max (OM31)
    buf[..8].copy_from_slice(&opening_id.to_le_bytes());
    buf[8..12].copy_from_slice(&round.to_le_bytes());
    for (k, v) in vals.iter().enumerate() {
        let off = 12 + k * elem;
        buf[off..off + elem].copy_from_slice(v.to_le_bytes().as_ref());
    }
    t.absorb(AbsorbLabel::Round, &buf[..12 + 3 * elem])?;
    Ok(())
}

struct RowSumcheckResult<K> {
    next_w: Vec<K>,
    next_u: Vec<K>,
    challenges: Vec<K>,
    running: K,
}

#[allow(clippy::too_many_arguments)]
fn run_row_sumcheck_prover<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    level: u8,
    ell: u8,
    cols: usize,
    mut cur_w: Vec<K>,
    mut cur_m: Vec<K>,
    mut running: K,
    out: &mut Vec<u8>,
) -> Result<RowSumcheckResult<K>, RecursiveError> {
    absorb_sumcheck_instance(t, opening_id, level, ell, running)?;
    let mut challenges = reserve_vec(usize::from(ell))?;
    let mut rows = 1usize << ell;
    for round in 0..usize::from(ell) {
        let half = rows / 2;
        let stride = half * cols;
        let (w_lo, w_hi) = cur_w.split_at(stride);
        let (m_lo, m_hi) = cur_m.split_at(stride);
        let (mut y0, mut y1, mut y2) = (K::from_i64(0), K::from_i64(0), K::from_i64(0));
        for i in 0..stride {
            let (w0, w1, m0, m1) = (w_lo[i], w_hi[i], m_lo[i], m_hi[i]);
            y0 = y0 + w0 * m0;
            y1 = y1 + w1 * m1;
            let w2 = w1 + w1 - w0;
            let m2 = m1 + m1 - m0;
            y2 = y2 + w2 * m2;
        }
        if (y0 + y1).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
            return Err(RecursiveError::RoundSumMismatch);
        }
        for v in [y0, y1, y2] {
            out.extend_from_slice(v.to_le_bytes().as_ref());
        }
        absorb_sumcheck_round(t, opening_id, round as u32, [y0, y1, y2])?;
        let r = t.challenge(ChallengeLabel::Sumcheck)?;
        running = interpolate_deg2([y0, y1, y2], r);
        challenges.push(r);

        let mut next_w = reserve_vec(stride)?;
        let mut next_m = reserve_vec(stride)?;
        for i in 0..stride {
            next_w.push(w_lo[i] + r * (w_hi[i] - w_lo[i]));
            next_m.push(m_lo[i] + r * (m_hi[i] - m_lo[i]));
        }
        cur_w = next_w;
        cur_m = next_m;
        rows = half;
    }
    Ok(RowSumcheckResult {
        next_w: cur_w,
        next_u: cur_m,
        challenges,
        running,
    })
}

fn verify_row_sumcheck<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    level: u8,
    ell: u8,
    mut running: K,
    proof: &[u8],
    cursor: &mut usize,
) -> Result<(Vec<K>, K), RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    absorb_sumcheck_instance(t, opening_id, level, ell, running)?;
    let elem = 4 * K::DEGREE;
    let mut challenges = reserve_vec(usize::from(ell))?;
    for round in 0..usize::from(ell) {
        let vals = decode_ext_slice::<K>(take_slice(proof, cursor, 3 * elem)?)?;
        let (y0, y1, y2) = (vals[0], vals[1], vals[2]);
        if (y0 + y1).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
            return Err(RecursiveError::RoundSumMismatch);
        }
        absorb_sumcheck_round(t, opening_id, round as u32, [y0, y1, y2])?;
        let r = t.challenge(ChallengeLabel::Sumcheck)?;
        running = interpolate_deg2([y0, y1, y2], r);
        challenges.push(r);
    }
    Ok((challenges, running))
}

fn run_batch_sumcheck_prover<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    vars: usize,
    mut cur_w: Vec<K>,
    message: &[M31],
    mut running: K,
    out: &mut Vec<u8>,
) -> Result<(Vec<K>, K), RecursiveError> {
    let mut challenges = reserve_vec(vars)?;
    // Round 0 operates directly on the base-field M31 message, then folds into extension K.
    let half0 = message.len() / 2;
    let (w_lo0, w_hi0) = cur_w.split_at(half0);
    let (m_lo0, m_hi0) = message.split_at(half0);
    let (mut y0, mut y1, mut y2) = (K::from_i64(0), K::from_i64(0), K::from_i64(0));
    for i in 0..half0 {
        let (w0, w1, m0, m1) = (w_lo0[i], w_hi0[i], m_lo0[i], m_hi0[i]);
        y0 = y0 + w0.mul_m31(m0);
        y1 = y1 + w1.mul_m31(m1);
        let w2 = w1 + w1 - w0;
        let m2 = m1 + m1 - m0;
        y2 = y2 + w2.mul_m31(m2);
    }
    if (y0 + y1).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
        return Err(RecursiveError::RoundSumMismatch);
    }
    for v in [y0, y1, y2] {
        out.extend_from_slice(v.to_le_bytes().as_ref());
    }
    absorb_sumcheck_round(t, opening_id, 0, [y0, y1, y2])?;
    let r0 = t.challenge(ChallengeLabel::Sumcheck)?;
    running = interpolate_deg2([y0, y1, y2], r0);
    challenges.push(r0);

    let one = K::from_i64(1);
    let mut next_w = reserve_vec(half0)?;
    let mut cur_m = reserve_vec(half0)?;
    for i in 0..half0 {
        next_w.push(w_lo0[i] + r0 * (w_hi0[i] - w_lo0[i]));
        let m0 = m_lo0[i];
        let diff = m_hi0[i] - m0;
        cur_m.push(one.mul_m31(m0) + r0.mul_m31(diff));
    }
    cur_w = next_w;

    for round in 1..vars {
        let half = cur_m.len() / 2;
        let (w_lo, w_hi) = cur_w.split_at(half);
        let (m_lo, m_hi) = cur_m.split_at(half);
        let (mut y0, mut y1, mut y2) = (K::from_i64(0), K::from_i64(0), K::from_i64(0));
        for i in 0..half {
            let (w0, w1, m0, m1) = (w_lo[i], w_hi[i], m_lo[i], m_hi[i]);
            y0 = y0 + w0 * m0;
            y1 = y1 + w1 * m1;
            let w2 = w1 + w1 - w0;
            let m2 = m1 + m1 - m0;
            y2 = y2 + w2 * m2;
        }
        if (y0 + y1).to_le_bytes().as_ref() != running.to_le_bytes().as_ref() {
            return Err(RecursiveError::RoundSumMismatch);
        }
        for v in [y0, y1, y2] {
            out.extend_from_slice(v.to_le_bytes().as_ref());
        }
        absorb_sumcheck_round(t, opening_id, round as u32, [y0, y1, y2])?;
        let r = t.challenge(ChallengeLabel::Sumcheck)?;
        running = interpolate_deg2([y0, y1, y2], r);
        challenges.push(r);

        let mut nw = reserve_vec(half)?;
        let mut nm = reserve_vec(half)?;
        for i in 0..half {
            nw.push(w_lo[i] + r * (w_hi[i] - w_lo[i]));
            nm.push(m_lo[i] + r * (m_hi[i] - m_lo[i]));
        }
        cur_w = nw;
        cur_m = nm;
    }

    Ok((challenges, cur_m[0]))
}

// ============================================================================
// Certified mode for model sources (RFC-0029 §1.3, §2, §5, §6; RFC-0010 A9/A10/A17; E19-05)
// ============================================================================

const CERT_PUBLIC_PREFIX: &[u8] = b"stele/v0.1/pcs-certificate/public";
const CERTIFIED_LAYOUT: u8 = 1;
const MAX_CERT_QUERIES: u32 = 1 << 18;

/// Exact Policy 3 certified-mode query counts `(q_cert, q_open, N, D)` for a plan-stated
/// certified radius `1 <= certified_radius <= floor((D - 1) / 3)` (RFC-0029 §5, RFC-0010 A17).
pub fn policy3_certified_queries(
    m: u8,
    b: u8,
    certified_radius: u64,
    target_bits: u16,
) -> Result<(u32, u16, u64, u64), RecursiveError> {
    if target_bits == 0 || target_bits > MAX_TARGET_BITS {
        return Err(RecursiveError::UnsupportedSource);
    }
    let (_, n, d, e_max) = circle_coeff_params(m, b)?;
    if certified_radius == 0 || certified_radius > e_max {
        return Err(RecursiveError::UnsupportedSource);
    }
    let log_n = m + b;
    let q_cert = least_q_pow2_denom(
        log_n,
        n - certified_radius - 1,
        target_bits,
        MAX_CERT_QUERIES,
    )?;
    let q_open_u32 = least_q_pow2_denom(
        log_n,
        n - d + certified_radius,
        target_bits,
        u32::from(u16::MAX),
    )?;
    let q_open = u16::try_from(q_open_u32).map_err(|_| RecursiveError::UnsupportedSource)?;
    Ok((q_cert, q_open, n, d))
}

/// Verifier-owned certified-mode recursion plan for a model source (RFC-0029 §1.3, RFC-0010 A17).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedPlan {
    target_bits: u16,
    ext_degree: u8,
    certified_radius: u64,
    cert_queries: u32,
    levels: Vec<LevelSpec>,
    level_queries: Vec<u16>,
}

impl CertifiedPlan {
    /// Validate level geometry, enforce the unconditional single-round registration certificate
    /// proximity cap `2 * ell_0 * (e_c + 1) <= floor(|K| / 2^T)` (RFC-0010 A17), and derive exact
    /// `(q_cert, q_open, q_1..q_{L-1})`.
    pub fn new(
        levels: Vec<LevelSpec>,
        ext_degree: u8,
        target_bits: u16,
        certified_radius: u64,
    ) -> Result<Self, RecursiveError> {
        if levels.is_empty()
            || levels.len() > MAX_LEVELS
            || (ext_degree != 4 && ext_degree != 8)
            || target_bits == 0
            || target_bits > MAX_TARGET_BITS
        {
            return Err(RecursiveError::UnsupportedSource);
        }
        let cap = field_cap(ext_degree, target_bits)?;
        let mut level_queries = reserve_vec(levels.len())?;
        let mut cert_queries = 0u32;

        for (i, &spec) in levels.iter().enumerate() {
            if spec.ell == 0
                || spec.ell > MAX_DOMAIN_BITS
                || spec.randomisers != 0
                || spec.mask_rows != 0
            {
                return Err(RecursiveError::UnsupportedSource);
            }
            if i + 1 < levels.len() && spec.m == 0 {
                return Err(RecursiveError::UnsupportedSource);
            }
            let _ =
                CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).map_err(|e| match e {
                    stele_code::Error::Capacity => RecursiveError::Capacity,
                    _ => RecursiveError::UnsupportedSource,
                })?;
            let _ = spec.rows()?;
            if i + 1 < levels.len() {
                let next = levels[i + 1];
                if next.ell.checked_add(next.m) != Some(spec.m) {
                    return Err(RecursiveError::UnsupportedSource);
                }
            }
            if i == 0 {
                let (qc, qo, _, _) =
                    policy3_certified_queries(spec.m, spec.b, certified_radius, target_bits)?;
                let prox_num = 2u64
                    .checked_mul(u64::from(spec.ell))
                    .and_then(|v| v.checked_mul(certified_radius.checked_add(1)?))
                    .ok_or(RecursiveError::UnsupportedSource)?;
                if !BigUint::fits_cap(prox_num, &cap) {
                    return Err(RecursiveError::UnsupportedSource);
                }
                cert_queries = qc;
                level_queries.push(qo);
            } else {
                let (q, _, _, _) = policy3_fresh_queries(spec.m, spec.b, target_bits)?;
                level_queries.push(q);
            }
        }

        Ok(Self {
            target_bits,
            ext_degree,
            certified_radius,
            cert_queries,
            levels,
            level_queries,
        })
    }

    /// Target security bits `T`.
    pub fn target_bits(&self) -> u16 {
        self.target_bits
    }

    /// Extension field degree (`4` or `8`).
    pub fn ext_degree(&self) -> u8 {
        self.ext_degree
    }

    /// Plan-stated certified proximity radius `e_c`.
    pub fn certified_radius(&self) -> u64 {
        self.certified_radius
    }

    /// Registration certificate query count `q_cert`.
    pub fn cert_queries(&self) -> u32 {
        self.cert_queries
    }

    /// Ordered level specifications `0..L`.
    pub fn levels(&self) -> &[LevelSpec] {
        &self.levels
    }

    /// Per-level opening query counts (`level_queries[0] = q_open`, tail `q_1..q_{L-1}`).
    pub fn level_queries(&self) -> &[u16] {
        &self.level_queries
    }

    /// Exact registration certificate proof size in bytes.
    pub fn certificate_size(&self) -> Result<usize, RecursiveError> {
        let l0 = self.levels[0];
        let elem_ext = 4usize * usize::from(self.ext_degree);
        let row_bytes = mul_usize(l0.columns()?, elem_ext)?;
        let per_query = add_usize(mul_usize(l0.rows()?, 4)?, mul_usize(l0.path_height(), 32)?)?;
        let qc = usize::try_from(self.cert_queries).map_err(|_| RecursiveError::Capacity)?;
        let queries_bytes = mul_usize(qc, per_query)?;
        add_usize(add_usize(9, row_bytes)?, queries_bytes)
    }

    /// Fixed certified-opening header length: `version (1) + L (1) + radius (8) + 3 * L`.
    pub fn opening_header_bytes(&self) -> usize {
        10 + 3 * self.levels.len()
    }

    /// Exact certified-opening body bytes (`q_0 = q_open`, tail `q_{i >= 1}`).
    pub fn opening_body_bytes(&self) -> Result<usize, RecursiveError> {
        let elem_ext = 4usize * usize::from(self.ext_degree);
        let l = self.levels.len();
        let mut total = 0usize;
        for (i, (&spec, &q)) in self.levels.iter().zip(&self.level_queries).enumerate() {
            let elem = if i == 0 { 4usize } else { elem_ext };
            let rows = spec.rows()?;
            if i >= 1 {
                let sc = mul_usize(usize::from(spec.ell), mul_usize(3, elem_ext)?)?;
                total = add_usize(total, sc)?;
            }
            if i + 1 < l {
                total = add_usize(total, 32)?;
            } else {
                let final_vec = mul_usize(spec.columns()?, elem_ext)?;
                total = add_usize(total, final_vec)?;
            }
            let per_query = add_usize(mul_usize(elem, rows)?, mul_usize(32, spec.path_height())?)?;
            total = add_usize(total, mul_usize(usize::from(q), per_query)?)?;
        }
        Ok(total)
    }

    /// Exact complete certified-opening proof size (`opening_header_bytes() + opening_body_bytes()`).
    pub fn opening_proof_size(&self) -> Result<usize, RecursiveError> {
        add_usize(self.opening_header_bytes(), self.opening_body_bytes()?)
    }

    fn write_opening_header(&self, out: &mut Vec<u8>) {
        out.push(RECURSIVE_VERSION);
        out.push(self.levels.len() as u8);
        out.extend_from_slice(&self.certified_radius.to_le_bytes());
        for spec in &self.levels {
            out.push(spec.ell);
            out.push(spec.m);
            out.push(spec.b);
        }
    }

    fn check_opening_header(&self, proof: &[u8]) -> Result<usize, RecursiveError> {
        let header_len = self.opening_header_bytes();
        if proof.len() < 10 || proof[0] != RECURSIVE_VERSION {
            return Err(RecursiveError::ProofShape);
        }
        let radius = u64::from_le_bytes(
            proof[2..10]
                .try_into()
                .map_err(|_| RecursiveError::ProofShape)?,
        );
        if radius != self.certified_radius {
            return Err(RecursiveError::CertificateContext);
        }
        let expected_len = self.opening_proof_size()?;
        if proof.len() != expected_len || usize::from(proof[1]) != self.levels.len() {
            return Err(RecursiveError::ProofShape);
        }
        for (i, spec) in self.levels.iter().enumerate() {
            let off = 10 + 3 * i;
            if proof[off] != spec.ell || proof[off + 1] != spec.m || proof[off + 2] != spec.b {
                return Err(RecursiveError::ProofShape);
            }
        }
        Ok(header_len)
    }
}

/// Verifier-owned version-4 certified model source context (RFC-0029 §1.3, RFC-0010 A17).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedSource<K: ChallengeField> {
    id: u64,
    plan: CertifiedPlan,
    root: merkle::Digest,
    field: PhantomData<K>,
}

impl<K: ChallengeField> CertifiedSource<K> {
    /// Construct a validated certified version-4 source context for field `K`.
    pub fn new(id: u64, plan: CertifiedPlan, root: merkle::Digest) -> Result<Self, RecursiveError> {
        if plan.ext_degree() != K::DEGREE as u8 {
            return Err(RecursiveError::UnsupportedSource);
        }
        Ok(Self {
            id,
            plan,
            root,
            field: PhantomData,
        })
    }

    /// Source identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Verifier-owned certified plan (including certified radius `e_c`).
    pub fn plan(&self) -> &CertifiedPlan {
        &self.plan
    }

    /// Expected level-0 Merkle root.
    pub fn root(&self) -> merkle::Digest {
        self.root
    }

    /// Canonical version-4 certified source bytes (`layout = 1`, `policy = 3`, binding `e_c`).
    pub fn bytes(&self) -> Result<Vec<u8>, RecursiveError> {
        let l0 = self.plan.levels[0];
        let code0 = CircleCoeff::new(u32::from(l0.m), u32::from(l0.b))?;
        let len = 122 + 7 * self.plan.levels.len();
        let mut out = reserve_vec(len)?;
        out.extend_from_slice(PURPOSE);
        out.push(RECURSIVE_VERSION);
        out.push(K::DEGREE as u8);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(l0.ell);
        out.extend_from_slice(&code0.code_id());
        out.extend_from_slice(&(1u64 << l0.ell).to_le_bytes());
        out.extend_from_slice(&(1u64 << l0.m).to_le_bytes());
        out.push(CERTIFIED_LAYOUT);
        out.push(POLICY_THREE);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.plan.target_bits.to_le_bytes());
        out.push(self.plan.levels.len() as u8);
        out.extend_from_slice(&self.plan.certified_radius.to_le_bytes());
        for spec in &self.plan.levels {
            out.push(spec.ell);
            out.push(spec.m);
            out.push(spec.b);
            out.extend_from_slice(&spec.randomisers.to_le_bytes());
            out.extend_from_slice(&spec.mask_rows.to_le_bytes());
        }
        Ok(out)
    }

    /// Parse exact canonical certified version-4 source bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecursiveError> {
        if bytes.len() < 122 || bytes[..23] != PURPOSE[..] {
            return Err(RecursiveError::UnsupportedSource);
        }
        if bytes[23] != RECURSIVE_VERSION
            || bytes[24] != K::DEGREE as u8
            || bytes[77] != CERTIFIED_LAYOUT
            || bytes[78] != POLICY_THREE
        {
            return Err(RecursiveError::UnsupportedSource);
        }
        let id = u64::from_le_bytes(
            bytes[25..33]
                .try_into()
                .map_err(|_| RecursiveError::UnsupportedSource)?,
        );
        let root: merkle::Digest = bytes[79..111]
            .try_into()
            .map_err(|_| RecursiveError::UnsupportedSource)?;
        let target_bits = u16::from_le_bytes([bytes[111], bytes[112]]);
        let level_count = usize::from(bytes[113]);
        if level_count == 0 || level_count > MAX_LEVELS || bytes.len() != 122 + 7 * level_count {
            return Err(RecursiveError::UnsupportedSource);
        }
        let certified_radius = u64::from_le_bytes(
            bytes[114..122]
                .try_into()
                .map_err(|_| RecursiveError::UnsupportedSource)?,
        );
        let mut levels = reserve_vec(level_count)?;
        for i in 0..level_count {
            let off = 122 + 7 * i;
            levels.push(LevelSpec {
                ell: bytes[off],
                m: bytes[off + 1],
                b: bytes[off + 2],
                randomisers: u16::from_le_bytes([bytes[off + 3], bytes[off + 4]]),
                mask_rows: u16::from_le_bytes([bytes[off + 5], bytes[off + 6]]),
            });
        }
        let plan = CertifiedPlan::new(levels, K::DEGREE as u8, target_bits, certified_radius)?;
        let source = Self::new(id, plan, root)?;
        if source.bytes()? != bytes {
            return Err(RecursiveError::UnsupportedSource);
        }
        Ok(source)
    }
}

/// Soundness ledger for a verified certified-mode registration certificate (RFC-0029 §5, A17).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateLedger {
    /// Codeword length `N_0`.
    pub length: u64,
    /// Code distance `D_0`.
    pub distance: u64,
    /// Certified proximity radius `e_c`.
    pub certified_radius: u64,
    /// Single-round proximity test numerator `2 * ell_0 * (e_c + 1)`.
    pub proximity_numerator: u64,
    /// Registration query count `q_cert`.
    pub cert_queries: u32,
    /// Extension field degree (`4` or `8`).
    pub field_degree: u8,
    /// Target security bits `T`.
    pub target_bits: u16,
    /// Local Merkle + ID hash work observed during registration verification.
    pub non_transcript_usage: HashUsage,
}

/// Opaque verified registration handle; constructed only by [`verify_certified_registration`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCertifiedSource<K: ChallengeField> {
    source: CertifiedSource<K>,
    id: merkle::Digest,
    ledger: CertificateLedger,
}

impl<K: ChallengeField> VerifiedCertifiedSource<K> {
    /// Verified certified source context (including `certified_radius`).
    pub fn source(&self) -> &CertifiedSource<K> {
        &self.source
    }

    /// Completed registration certificate identity (RFC-0012 A10).
    pub fn id(&self) -> merkle::Digest {
        self.id
    }

    /// Registration certificate soundness ledger.
    pub fn ledger(&self) -> CertificateLedger {
        self.ledger
    }

    /// Verify that this handle matches the consumer's expected source (including `e_c`);
    /// rejects any mismatch with [`RecursiveError::CertificateContext`] (NC-0635).
    pub fn check_source(&self, expected: &CertifiedSource<K>) -> Result<(), RecursiveError> {
        if self.source.bytes()? == expected.bytes()? {
            Ok(())
        } else {
            Err(RecursiveError::CertificateContext)
        }
    }
}

/// Column functional `b ∈ K^{C_0}` for a certified-mode opening `⟨a ⊗ b, M_0⟩ = v` (RFC-0029 §1.3).
#[derive(Clone, Copy)]
pub enum ColumnFunctional<'a, K: Field> {
    /// Multilinear point tensor `b = eq(·, point)` (`point.len() == m_0`).
    Tensor(&'a [K]),
    /// Arbitrary verifier-computable column weight vector `b` (`b.len() == 2^{m_0}`).
    Dense(&'a [K]),
}

/// Observed memory & recomputation work for a certified opening (E19-05 memory invariant).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedOpeningWork {
    /// Codeword bytes resident in [`CertifiedModelSource`] (always `0`).
    pub stored_codeword_bytes: usize,
    /// Peak codeword scratch bytes allocated during opening (`1` row + `q_open` columns).
    pub peak_codeword_bytes: usize,
    /// Full level-0 codeword size `R_0 * N_0 * 4` (never allocated during opening).
    pub full_codeword_bytes: usize,
    /// Number of queried columns recomputed on the fly (`q_open`).
    pub recomputed_columns: usize,
    /// Physical passes over the borrowed M31 weight matrix (`1` for `a^T M_0`, `1` for column recompute).
    pub weight_passes: usize,
}

/// Verified certified-mode recursive opening receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCertifiedOpening<K: ChallengeField> {
    source_id: u64,
    certificate_id: merkle::Digest,
    opening_id: u64,
    value: K,
    ledger: RecursiveLedger,
}

impl<K: ChallengeField> VerifiedCertifiedOpening<K> {
    /// Verified source id.
    pub fn source_id(&self) -> u64 {
        self.source_id
    }
    /// Bound registration certificate id.
    pub fn certificate_id(&self) -> merkle::Digest {
        self.certificate_id
    }
    /// Verified opening id.
    pub fn opening_id(&self) -> u64 {
        self.opening_id
    }
    /// Verified scalar functional value `⟨a ⊗ b, M_0⟩`.
    pub fn value(&self) -> K {
        self.value
    }
    /// Per-level opening soundness ledger (level-0 proximity paid in registration certificate).
    pub fn ledger(&self) -> &RecursiveLedger {
        &self.ledger
    }
}

fn cert_transcript<K: ChallengeField>(
    source: &CertifiedSource<K>,
) -> Result<Transcript<K>, RecursiveError> {
    let sb = source.bytes()?;
    let mut public = reserve_vec(add_usize(CERT_PUBLIC_PREFIX.len(), sb.len())?)?;
    public.extend_from_slice(CERT_PUBLIC_PREFIX);
    public.extend_from_slice(&sb);
    Ok(Transcript::new(&public)?)
}

fn absorb_certified_opening_statement<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    cert_id: &merkle::Digest,
    source: &CertifiedSource<K>,
    row_weights: &[K],
    col_functional: ColumnFunctional<'_, K>,
    value: K,
) -> Result<(), RecursiveError> {
    let sb = source.bytes()?;
    let elem = 4 * K::DEGREE;
    let (col_tag, col_slice) = match col_functional {
        ColumnFunctional::Tensor(pt) => (0u8, pt),
        ColumnFunctional::Dense(vec) => (1u8, vec),
    };
    let rw_len = mul_usize(row_weights.len(), elem)?;
    let cw_len = mul_usize(col_slice.len(), elem)?;
    let total = add_usize(
        add_usize(add_usize(8 + 32 + 1, sb.len())?, rw_len)?,
        add_usize(cw_len, elem)?,
    )?;
    let mut frame = reserve_vec(total)?;
    frame.extend_from_slice(&opening_id.to_le_bytes());
    frame.extend_from_slice(cert_id);
    frame.extend_from_slice(&sb);
    for w in row_weights {
        frame.extend_from_slice(w.to_le_bytes().as_ref());
    }
    frame.push(col_tag);
    for w in col_slice {
        frame.extend_from_slice(w.to_le_bytes().as_ref());
    }
    frame.extend_from_slice(value.to_le_bytes().as_ref());
    t.absorb(AbsorbLabel::Opening, &frame)?;
    Ok(())
}

/// Recompute ONLY `queried` level-0 columns from `message` by streaming one row at a time
/// into a single reusable `N_0`-element buffer (full `R_0 × N_0` codeword is NEVER resident).
fn recompute_queried_columns(
    spec: LevelSpec,
    message: &[M31],
    queried: &[u64],
) -> Result<(Vec<u8>, usize), RecursiveError> {
    let rows = spec.rows()?;
    let cols = spec.columns()?;
    let n = spec.codeword_len()?;
    if message.len() != mul_usize(rows, cols)? {
        return Err(RecursiveError::MessageShape);
    }
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;
    let col_width = mul_usize(rows, 4)?;
    let payloads_len = mul_usize(queried.len(), col_width)?;
    let mut payloads = reserve_vec(payloads_len)?;
    payloads.resize(payloads_len, 0u8);
    let mut row_buf = reserve_vec::<M31>(n)?;
    for (r, row) in message.chunks_exact(cols).enumerate() {
        code.encode_into(row, &mut row_buf)?;
        let row_off = r * 4;
        for (q_idx, &col_idx) in queried.iter().enumerate() {
            let j = usize::try_from(col_idx).map_err(|_| RecursiveError::Capacity)?;
            let dst = q_idx * col_width + row_off;
            payloads[dst..dst + 4].copy_from_slice(&row_buf[j].to_le_bytes());
        }
    }
    let peak_bytes = add_usize(mul_usize(row_buf.capacity(), 4)?, payloads.capacity())?;
    Ok((payloads, peak_bytes))
}

/// Registered model source for certified-mode recursive openings (RFC-0029 §1.3, E19-05).
/// Stores ONLY the Merkle digest tree and registration certificate — zero codeword bytes resident.
pub struct CertifiedModelSource<K: ChallengeField> {
    source: CertifiedSource<K>,
    tree: merkle::Tree,
    certificate_proof: Vec<u8>,
    cert_id: merkle::Digest,
}

impl<K: ChallengeField> CertifiedModelSource<K> {
    /// Commit a model weight matrix `message` (`R_0 × C_0` M31 elements), produce its
    /// registration certificate at `plan.certified_radius()`, and release all codeword storage.
    pub fn register(id: u64, plan: CertifiedPlan, message: &[M31]) -> Result<Self, RecursiveError> {
        if plan.ext_degree() != K::DEGREE as u8 {
            return Err(RecursiveError::UnsupportedSource);
        }
        let l0 = plan.levels[0];
        let mut usage = HashUsage::default();
        let committed = CommittedLevel::commit_m31(id, l0, message, &mut usage)?;
        let root = committed.root();
        let source = CertifiedSource::<K>::new(id, plan.clone(), root)?;

        // Build registration certificate at `plan.certified_radius()`.
        let mut t = cert_transcript(&source)?;
        let ell0 = usize::from(l0.ell);
        let mut r_cert = reserve_vec(ell0)?;
        for _ in 0..ell0 {
            r_cert.push(t.challenge(ChallengeLabel::CertificateWeight)?);
        }
        let eq_cert = stele_poly::eq_table(&r_cert).map_err(|_| RecursiveError::Capacity)?;
        let cols0 = l0.columns()?;
        let mut t_row = reserve_vec(cols0)?;
        t_row.resize(cols0, K::from_i64(0));
        for (row, &a) in message.chunks_exact(cols0).zip(&eq_cert) {
            for (dst, &val) in t_row.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(val);
            }
        }

        let mut cert_proof = reserve_vec(plan.certificate_size()?)?;
        cert_proof.push(RECURSIVE_VERSION);
        cert_proof.extend_from_slice(&plan.certified_radius().to_le_bytes());
        let row_start = cert_proof.len();
        for v in &t_row {
            cert_proof.extend_from_slice(v.to_le_bytes().as_ref());
        }
        t.absorb(AbsorbLabel::CertificateRow, &cert_proof[row_start..])?;
        let resp_start = cert_proof.len();
        let n0 = committed.descriptor.count;
        for _ in 0..plan.cert_queries() {
            let idx = t.certificate_column(n0)?;
            committed.append_response(idx, &mut cert_proof)?;
        }
        t.absorb(AbsorbLabel::CertificateColumns, &cert_proof[resp_start..])?;
        debug_assert_eq!(cert_proof.len(), plan.certificate_size()?);

        let cert_id = certificate_id(&source.bytes()?, &cert_proof, &mut usage)?;
        // Drop `committed.column_bytes`: keep ONLY the Merkle tree digests!
        let tree = committed.tree;
        Ok(Self {
            source,
            tree,
            certificate_proof: cert_proof,
            cert_id,
        })
    }

    /// Expected certified source context.
    pub fn source(&self) -> &CertifiedSource<K> {
        &self.source
    }

    /// Registration certificate proof bytes.
    pub fn certificate_proof(&self) -> &[u8] {
        &self.certificate_proof
    }

    /// Completed registration certificate digest.
    pub fn certificate_id(&self) -> merkle::Digest {
        self.cert_id
    }

    /// Codeword bytes stored inside this prepared model source (always `0`; E19-05 invariant).
    pub fn stored_codeword_bytes(&self) -> usize {
        0
    }

    /// Evaluate `⟨row_weights ⊗ col_functional, message⟩` over `K`.
    pub fn evaluate_functional(
        &self,
        message: &[M31],
        row_weights: &[K],
        col_functional: ColumnFunctional<'_, K>,
    ) -> Result<K, RecursiveError> {
        let l0 = self.source.plan.levels[0];
        let rows = l0.rows()?;
        let cols = l0.columns()?;
        if message.len() != mul_usize(rows, cols)? || row_weights.len() != rows {
            return Err(RecursiveError::MessageShape);
        }
        let col_vec = match col_functional {
            ColumnFunctional::Tensor(pt) => {
                if pt.len() != usize::from(l0.m) {
                    return Err(RecursiveError::MessageShape);
                }
                stele_poly::eq_table(pt).map_err(|_| RecursiveError::Capacity)?
            }
            ColumnFunctional::Dense(b) => {
                if b.len() != cols {
                    return Err(RecursiveError::MessageShape);
                }
                b.to_vec()
            }
        };
        let mut acc = K::from_i64(0);
        for (row, &a) in message.chunks_exact(cols).zip(row_weights) {
            let mut rdot = K::from_i64(0);
            for (&val, &b) in row.iter().zip(&col_vec) {
                rdot = rdot + b.mul_m31(val);
            }
            acc = acc + a * rdot;
        }
        Ok(acc)
    }

    /// Produce a certified-mode recursive opening for ANY verifier-computable `(row_weights, col_functional)`,
    /// recomputing ONLY the `q_open` queried level-0 columns from `message` without materializing the full codeword.
    pub fn open_certified_measured(
        &self,
        message: &[M31],
        t: &mut Transcript<K>,
        opening_id: u64,
        row_weights: &[K],
        col_functional: ColumnFunctional<'_, K>,
        value: K,
    ) -> Result<(Vec<u8>, CertifiedOpeningWork), RecursiveError>
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let plan = &self.source.plan;
        let l = plan.levels.len();
        let l0 = plan.levels[0];
        let rows0 = l0.rows()?;
        let cols0 = l0.columns()?;
        let n0 = l0.codeword_len()?;
        if message.len() != mul_usize(rows0, cols0)? || row_weights.len() != rows0 {
            return Err(RecursiveError::MessageShape);
        }

        let mut cur_w = match col_functional {
            ColumnFunctional::Tensor(pt) => {
                if pt.len() != usize::from(l0.m) {
                    return Err(RecursiveError::MessageShape);
                }
                stele_poly::eq_table(pt).map_err(|_| RecursiveError::Capacity)?
            }
            ColumnFunctional::Dense(b) => {
                if b.len() != cols0 {
                    return Err(RecursiveError::MessageShape);
                }
                b.to_vec()
            }
        };

        // Pass 1 over borrowed `message`: compute `u_1 = row_weights^T M_0`.
        let mut cur_u = reserve_vec(cols0)?;
        cur_u.resize(cols0, K::from_i64(0));
        for (row, &a) in message.chunks_exact(cols0).zip(row_weights) {
            for (dst, &val) in cur_u.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(val);
            }
        }
        let actual = dot_ext(&cur_w, &cur_u);
        if actual.to_le_bytes().as_ref() != value.to_le_bytes().as_ref() {
            return Err(RecursiveError::ValueMismatch);
        }

        absorb_certified_opening_statement(
            t,
            opening_id,
            &self.cert_id,
            &self.source,
            row_weights,
            col_functional,
            value,
        )?;

        let mut proof = reserve_vec(plan.opening_proof_size()?)?;
        plan.write_opening_header(&mut proof);

        let mut cur_committed: Option<CommittedLevel> = None;
        let mut cur_eq_row = row_weights.to_vec();
        let mut cur_claim = value;
        let mut commit_usage = HashUsage::default();
        let mut peak_codeword_bytes = 0usize;

        for i in 0..l {
            let spec = plan.levels[i];
            let q_i = usize::from(plan.level_queries[i]);
            let code_i = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;

            if i >= 1 {
                let res = run_row_sumcheck_prover(
                    t,
                    opening_id,
                    i as u8,
                    spec.ell,
                    spec.columns()?,
                    cur_w,
                    cur_u,
                    cur_claim,
                    &mut proof,
                )?;
                cur_w = res.next_w;
                cur_u = res.next_u;
                cur_eq_row =
                    stele_poly::eq_table(&res.challenges).map_err(|_| RecursiveError::Capacity)?;
                cur_claim = res.running;
            }

            let next_committed = if i + 1 < l {
                let next_spec = plan.levels[i + 1];
                let committed = CommittedLevel::commit_ext(
                    self.source.id,
                    (i + 1) as u8,
                    next_spec,
                    &cur_u,
                    &mut commit_usage,
                )?;
                let root = committed.root();
                proof.extend_from_slice(&root);
                t.absorb(AbsorbLabel::PcsLevelRoot, &root)?;
                Some(committed)
            } else {
                let start = proof.len();
                for elem in &cur_u {
                    proof.extend_from_slice(elem.to_le_bytes().as_ref());
                }
                t.absorb(AbsorbLabel::PcsLevelRoot, &proof[start..])?;
                None
            };

            let mut queried = reserve_vec(q_i)?;
            let mut ys = reserve_vec(q_i)?;
            let resp_start = proof.len();
            if i == 0 {
                for _ in 0..q_i {
                    queried.push(t.opening_column(n0 as u64)?);
                }
                // Pass 2 over `message`: recompute ONLY the `q_open` queried columns row-by-row.
                let (payloads, peak) = recompute_queried_columns(l0, message, &queried)?;
                peak_codeword_bytes = peak;
                let col_width = mul_usize(rows0, 4)?;
                for (q_idx, &col_idx) in queried.iter().enumerate() {
                    let pay = &payloads[q_idx * col_width..(q_idx + 1) * col_width];
                    proof.extend_from_slice(pay);
                    for sib in self.tree.path(col_idx)? {
                        proof.extend_from_slice(&sib);
                    }
                    if i + 1 < l {
                        ys.push(column_dot_m31(&cur_eq_row, pay)?);
                    }
                }
            } else {
                let active = cur_committed.as_ref().ok_or(RecursiveError::ProofShape)?;
                let n_i = active.descriptor.count;
                for _ in 0..q_i {
                    let idx = t.opening_column(n_i)?;
                    active.append_response(idx, &mut proof)?;
                    queried.push(idx);
                    if i + 1 < l {
                        ys.push(column_dot_ext(&cur_eq_row, active.payload(idx)?)?);
                    }
                }
            }
            t.absorb(AbsorbLabel::OpeningColumns, &proof[resp_start..])?;

            if i + 1 < l {
                let beta = t.challenge(ChallengeLabel::PcsLevelBeta)?;
                let mut beta_pow = beta;
                let mut basis_buf = reserve_vec(cur_w.len())?;
                basis_buf.resize(cur_w.len(), M31::ZERO);
                for (&idx, &y) in queried.iter().zip(&ys) {
                    cur_claim = cur_claim + beta_pow * y;
                    let mut factors = code_i.basis_factors(idx as usize)?;
                    factors.reverse();
                    fill_basis_table(&factors, &mut basis_buf);
                    for (dst, &b_val) in cur_w.iter_mut().zip(&basis_buf) {
                        *dst = *dst + beta_pow.mul_m31(b_val);
                    }
                    beta_pow = beta_pow * beta;
                }
                cur_committed = next_committed;
            }
        }

        debug_assert_eq!(proof.len(), plan.opening_proof_size()?);
        let full_codeword_bytes = mul_usize(mul_usize(rows0, n0)?, 4)?;
        let work = CertifiedOpeningWork {
            stored_codeword_bytes: 0,
            peak_codeword_bytes,
            full_codeword_bytes,
            recomputed_columns: usize::from(plan.level_queries[0]),
            weight_passes: 2,
        };
        Ok((proof, work))
    }

    /// Convenience wrapper around [`Self::open_certified_measured`].
    pub fn open_certified(
        &self,
        message: &[M31],
        t: &mut Transcript<K>,
        opening_id: u64,
        row_weights: &[K],
        col_functional: ColumnFunctional<'_, K>,
        value: K,
    ) -> Result<Vec<u8>, RecursiveError>
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        self.open_certified_measured(message, t, opening_id, row_weights, col_functional, value)
            .map(|(proof, _)| proof)
    }
}

/// Verify a certified-mode registration certificate at `source.plan().certified_radius()`
/// (RFC-0029 §1.3, RFC-0010 A9/A17). Rejects a certificate built for another radius with
/// [`RecursiveError::CertificateContext`] (NC-0635).
pub fn verify_certified_registration<K: ChallengeField>(
    source: CertifiedSource<K>,
    cert_proof: &[u8],
) -> Result<VerifiedCertifiedSource<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    if cert_proof.len() < 9 || cert_proof[0] != RECURSIVE_VERSION {
        return Err(RecursiveError::ProofShape);
    }
    let proof_radius = u64::from_le_bytes(
        cert_proof[1..9]
            .try_into()
            .map_err(|_| RecursiveError::ProofShape)?,
    );
    if proof_radius != source.plan.certified_radius() {
        return Err(RecursiveError::CertificateContext);
    }
    if cert_proof.len() != source.plan.certificate_size()? {
        return Err(RecursiveError::ProofShape);
    }

    let l0 = source.plan.levels[0];
    let elem_ext = 4 * K::DEGREE;
    let mut t = cert_transcript(&source)?;
    let ell0 = usize::from(l0.ell);
    let mut r_cert = reserve_vec(ell0)?;
    for _ in 0..ell0 {
        r_cert.push(t.challenge(ChallengeLabel::CertificateWeight)?);
    }
    let eq_cert = stele_poly::eq_table(&r_cert).map_err(|_| RecursiveError::Capacity)?;

    let mut cursor = 9usize;
    let row_bytes = take_slice(cert_proof, &mut cursor, mul_usize(l0.columns()?, elem_ext)?)?;
    let t_row = decode_ext_slice::<K>(row_bytes)?;
    t.absorb(AbsorbLabel::CertificateRow, row_bytes)?;

    let code0 = CircleCoeff::new(u32::from(l0.m), u32::from(l0.b))?;
    let (_, n0, d0, _) = circle_coeff_params(l0.m, l0.b)?;
    let desc0 = level_descriptor(source.id, 0, l0, 4)?;
    let col_width = usize::try_from(desc0.width).map_err(|_| RecursiveError::Capacity)?;
    let path_h = l0.path_height();
    let path_bytes = mul_usize(path_h, 32)?;
    let qc = usize::try_from(source.plan.cert_queries()).map_err(|_| RecursiveError::Capacity)?;
    let resp_start = cursor;
    let mut usage = HashUsage::default();
    let mut queried = reserve_vec(qc)?;
    let mut ys = reserve_vec(qc)?;
    let mut siblings = reserve_vec(path_h)?;
    for _ in 0..qc {
        let idx = t.certificate_column(n0)?;
        let payload = take_slice(cert_proof, &mut cursor, col_width)?;
        let sib_bytes = take_slice(cert_proof, &mut cursor, path_bytes)?;
        siblings.clear();
        for chunk in sib_bytes.chunks_exact(32) {
            let mut d = [0u8; 32];
            d.copy_from_slice(chunk);
            siblings.push(d);
        }
        merkle::verify_with_usage(
            desc0,
            &source.root,
            idx,
            merkle::Opening {
                payload,
                siblings: &siblings,
            },
            &mut usage,
        )?;
        ys.push(column_dot_m31(&eq_cert, payload)?);
        queried.push(idx);
    }
    if cursor != cert_proof.len() {
        return Err(RecursiveError::ProofShape);
    }
    t.absorb(AbsorbLabel::CertificateColumns, &cert_proof[resp_start..])?;

    let encoded = code0.encode(&t_row)?;
    for (&idx, &y) in queried.iter().zip(&ys) {
        if encoded[idx as usize].to_le_bytes().as_ref() != y.to_le_bytes().as_ref() {
            return Err(RecursiveError::ColumnMismatch);
        }
    }

    let id = certificate_id(&source.bytes()?, cert_proof, &mut usage)?;
    let e_c = source.plan.certified_radius();
    let ledger = CertificateLedger {
        length: n0,
        distance: d0,
        certified_radius: e_c,
        proximity_numerator: 2u64
            .saturating_mul(u64::from(l0.ell))
            .saturating_mul(e_c.saturating_add(1)),
        cert_queries: source.plan.cert_queries(),
        field_degree: K::DEGREE as u8,
        target_bits: source.plan.target_bits(),
        non_transcript_usage: usage,
    };
    Ok(VerifiedCertifiedSource { source, id, ledger })
}

/// Verify a certified-mode recursive opening for any verifier-computable `(row_weights, col_functional)`
/// against a [`VerifiedCertifiedSource`] (RFC-0029 §§1.3, 2, 4, 5).
#[allow(clippy::too_many_arguments)]
pub fn verify_certified_opening<K: ChallengeField>(
    t: &mut Transcript<K>,
    certificate: &VerifiedCertifiedSource<K>,
    expected: &CertifiedSource<K>,
    opening_id: u64,
    row_weights: &[K],
    col_functional: ColumnFunctional<'_, K>,
    value: K,
    proof: &[u8],
) -> Result<VerifiedCertifiedOpening<K>, RecursiveError>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    // NC-0635: reject certificate for another source or another certified radius BEFORE transcript work.
    certificate.check_source(expected)?;
    let plan = &expected.plan;
    let l = plan.levels.len();
    let l0 = plan.levels[0];
    if row_weights.len() != l0.rows()? {
        return Err(RecursiveError::MessageShape);
    }
    let init_term = match col_functional {
        ColumnFunctional::Tensor(pt) => {
            if pt.len() != usize::from(l0.m) {
                return Err(RecursiveError::MessageShape);
            }
            WeightTerm::Eq {
                coeff: K::from_i64(1),
                point: pt.to_vec(),
            }
        }
        ColumnFunctional::Dense(b) => {
            if b.len() != l0.columns()? {
                return Err(RecursiveError::MessageShape);
            }
            WeightTerm::Dense { values: b.to_vec() }
        }
    };
    let mut cursor = plan.check_opening_header(proof)?;

    absorb_certified_opening_statement(
        t,
        opening_id,
        &certificate.id,
        expected,
        row_weights,
        col_functional,
        value,
    )?;

    let elem_ext = 4 * K::DEGREE;
    let mut terms = reserve_vec(1)?;
    terms.push(init_term);
    let mut cur_root = expected.root;
    let mut cur_claim = value;
    let mut merkle_usage = HashUsage::default();
    let mut level_ledgers = reserve_vec(l)?;

    for i in 0..l {
        let spec = plan.levels[i];
        let q_i = usize::from(plan.level_queries[i]);
        let code_i = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b))?;
        let (_, n_i, d_i, e_fresh) = circle_coeff_params(spec.m, spec.b)?;
        let e_i = if i == 0 {
            plan.certified_radius()
        } else {
            e_fresh
        };

        let eq_row = if i == 0 {
            row_weights.to_vec()
        } else {
            let (r_i, v_prime) = verify_row_sumcheck(
                t,
                opening_id,
                i as u8,
                spec.ell,
                cur_claim,
                proof,
                &mut cursor,
            )?;
            for term in &mut terms {
                term.fold_prefix(&r_i)?;
            }
            cur_claim = v_prime;
            stele_poly::eq_table(&r_i).map_err(|_| RecursiveError::Capacity)?
        };

        let mut next_root = [0u8; 32];
        let mut final_u: Option<Vec<K>> = None;
        if i + 1 < l {
            let slice = take_slice(proof, &mut cursor, 32)?;
            next_root.copy_from_slice(slice);
            t.absorb(AbsorbLabel::PcsLevelRoot, &next_root)?;
        } else {
            let c_final = spec.columns()?;
            let bytes = take_slice(proof, &mut cursor, mul_usize(c_final, elem_ext)?)?;
            let decoded = decode_ext_slice::<K>(bytes)?;
            t.absorb(AbsorbLabel::PcsLevelRoot, bytes)?;
            final_u = Some(decoded);
        }

        let elem_i = if i == 0 { 4usize } else { elem_ext };
        let desc_i = level_descriptor(expected.id, i as u8, spec, elem_i)?;
        let col_width = usize::try_from(desc_i.width).map_err(|_| RecursiveError::Capacity)?;
        let path_height = spec.path_height();
        let path_bytes = mul_usize(path_height, 32)?;
        let per_query = add_usize(col_width, path_bytes)?;
        let resp_start = cursor;
        let resp_len = mul_usize(q_i, per_query)?;
        let resp_end = add_usize(resp_start, resp_len)?;
        if resp_end > proof.len() {
            return Err(RecursiveError::ProofShape);
        }

        let mut queried = reserve_vec(q_i)?;
        let mut ys = reserve_vec(q_i)?;
        let mut siblings = reserve_vec(path_height)?;
        for _ in 0..q_i {
            let idx = t.opening_column(n_i)?;
            let payload = take_slice(proof, &mut cursor, col_width)?;
            let sib_bytes = take_slice(proof, &mut cursor, path_bytes)?;
            siblings.clear();
            for chunk in sib_bytes.chunks_exact(32) {
                let mut d = [0u8; 32];
                d.copy_from_slice(chunk);
                siblings.push(d);
            }
            merkle::verify_with_usage(
                desc_i,
                &cur_root,
                idx,
                merkle::Opening {
                    payload,
                    siblings: &siblings,
                },
                &mut merkle_usage,
            )?;
            let y = if i == 0 {
                column_dot_m31(&eq_row, payload)?
            } else {
                column_dot_ext(&eq_row, payload)?
            };
            queried.push(idx);
            ys.push(y);
        }
        t.absorb(AbsorbLabel::OpeningColumns, &proof[resp_start..resp_end])?;

        level_ledgers.push(LevelLedger {
            level: i as u8,
            ell: spec.ell,
            m: spec.m,
            b: spec.b,
            length: n_i,
            distance: d_i,
            radius: e_i,
            queries: plan.level_queries[i],
            blocks: 1,
            // Level-0 proximity is paid once in the registration certificate ledger.
            proximity_numerator: if i == 0 {
                0
            } else {
                2u64.saturating_mul(u64::from(spec.ell))
                    .saturating_mul(e_i.saturating_add(1))
            },
            sumcheck_numerator: if i >= 1 { 2 * u64::from(spec.ell) } else { 0 },
            beta_numerator: if i + 1 < l {
                u64::from(plan.level_queries[i])
            } else {
                0
            },
            gamma_numerator: 0,
            field_degree: K::DEGREE as u8,
            target_bits: plan.target_bits,
        });

        if i + 1 < l {
            let beta = t.challenge(ChallengeLabel::PcsLevelBeta)?;
            let mut beta_pow = beta;
            for (&idx, &y) in queried.iter().zip(&ys) {
                cur_claim = cur_claim + beta_pow * y;
                let mut factors_msb = code_i.basis_factors(idx as usize)?;
                factors_msb.reverse();
                terms.try_reserve(1).map_err(|_| RecursiveError::Capacity)?;
                terms.push(WeightTerm::Basis {
                    coeff: beta_pow,
                    factors_msb,
                });
                beta_pow = beta_pow * beta;
            }
            cur_root = next_root;
        } else {
            let u_l = final_u.ok_or(RecursiveError::ProofShape)?;
            let encoded = code_i.encode(&u_l)?;
            for (&idx, &y) in queried.iter().zip(&ys) {
                if encoded[idx as usize].to_le_bytes().as_ref() != y.to_le_bytes().as_ref() {
                    return Err(RecursiveError::ColumnMismatch);
                }
            }
            let mut basis_buf = reserve_vec(u_l.len())?;
            basis_buf.resize(u_l.len(), M31::ZERO);
            let mut dot = K::from_i64(0);
            for term in &terms {
                dot = dot + term.dot_final(&u_l, &mut basis_buf)?;
            }
            if dot.to_le_bytes().as_ref() != cur_claim.to_le_bytes().as_ref() {
                return Err(RecursiveError::ValueMismatch);
            }
        }
    }

    if cursor != proof.len() {
        return Err(RecursiveError::ProofShape);
    }

    Ok(VerifiedCertifiedOpening {
        source_id: expected.id,
        certificate_id: certificate.id,
        opening_id,
        value,
        ledger: RecursiveLedger {
            opening_id,
            batch_rlc_numerator: 0,
            batch_sc_numerator: 0,
            levels: level_ledgers,
            merkle_usage,
        },
    })
}
