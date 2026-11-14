//! The LogUp `(β, α)` round and its grinding bits (RFC-0008 A8 item 2; RFC-0026 A14
//! for development byte 5), task E8-02e.
//!
//! Written from the RFC text and `research/fs-pcs/check_lu_grind.py` (ADR-128). A check
//! with `c` columns, `N = 2^m` positions and `t` table rows has one `(β, α)` round of
//! error `(c(N + t) − 1)/|K|`. It grinds the least `k` with
//! `(c(N + t) − 1)·2^108 ≤ p^d·2^k`. The nonce is checked on the state after the
//! check's last absorb before `lookup/beta` (RFC-0012 A17 item 5).
//!
//! `bits` compares both sides exactly as 256-bit numbers in two u128 limbs, for both
//! fields. Its first version was close to production's `lu_grind_bits`, so it was
//! rewritten this way after review (#377).

use stele_field::{Field, M31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};

/// Why a round was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// More than 32 bits would be needed (RFC-0008 A8 item 2: unsupported).
    Unsupported,
    /// A nonce where none is expected, or none where one is (RFC-0026 A14 item 5).
    ProofShape,
    /// The transcript refused an operation, including `GrindMismatch`.
    Transcript(stele_hash::Error),
}

impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Error::Transcript(e)
    }
}

/// `x·y` as `(high, low)` u128 limbs (schoolbook on 64-bit halves).
fn wide(x: u128, y: u128) -> (u128, u128) {
    let half = u128::from(u64::MAX);
    let (x1, x0, y1, y0) = (x >> 64, x & half, y >> 64, y & half);
    let (low, cross0, cross1, high) = (x0 * y0, x0 * y1, x1 * y0, x1 * y1);
    let middle = (low >> 64) + (cross0 & half) + (cross1 & half);
    (
        high + (cross0 >> 64) + (cross1 >> 64) + (middle >> 64),
        (low & half) | (middle << 64),
    )
}

/// RFC-0008 A8 item 2: the least `k ≥ 0` with `(c(N + t) − 1)·2^108 ≤ |K|·2^k`, for
/// `|K| = p^4` or `p^8`. `None` for another degree, for an empty check (`c = 0` or
/// `N + t = 0`), for a count past u128, or above 32 bits (unsupported).
pub fn bits(c: u64, positions: u64, rows: u64, degree: u8) -> Option<u8> {
    let p = u128::from(M31::MODULUS);
    let p4 = p * p * p * p;
    let field = match degree {
        4 => (0, p4),
        8 => wide(p4, p4),
        _ => return None,
    };
    let span = u128::from(positions).checked_add(u128::from(rows))?;
    let a = u128::from(c).checked_mul(span)?.checked_sub(1)?;
    // a·2^(108 − k) ≤ |K|, both sides as (high, low); 76 ≤ 108 − k ≤ 108 < 128.
    (0..=32u8).find(|k| {
        let shift = 108 - u32::from(*k);
        (a >> (128 - shift), a << shift) <= field
    })
}

/// The `(β, α)` round on `t`, which holds the check's absorbs. With `grind ≥ 1` the
/// proof's nonce must pass the predicate and is absorbed before `lookup/beta`; with
/// `grind = 0` there is no nonce. Returns `(β, α)`.
pub fn round<K: ChallengeField>(
    t: &mut Transcript<K>,
    grind: u8,
    nonce: Option<u64>,
) -> Result<(K, K), Error> {
    match (grind, nonce) {
        (0, None) => {}
        // RFC-0026 A14 / RFC-0012 A17 item 5: the nonce precedes `lookup/beta`.
        (k, Some(n)) if k > 0 => t.verify_grind(k, n)?,
        _ => return Err(Error::ProofShape),
    }
    let beta = t.challenge(ChallengeLabel::LookupBeta)?;
    let alpha = t.challenge(ChallengeLabel::LookupAlpha)?;
    Ok((beta, alpha))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two-limb product against values with known halves.
    #[test]
    fn multiplies_into_two_limbs() {
        assert_eq!(wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
        assert_eq!(wide(1 << 64, 1 << 64), (1, 0));
        assert_eq!(wide(1 << 127, 2), (1, 0));
        assert_eq!(wide(3, 5), (0, 15));
    }
}
