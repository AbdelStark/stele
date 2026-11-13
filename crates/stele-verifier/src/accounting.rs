//! Profile admission, RFC-0012 A17 item 4: the exact (C1)–(C4) checks over one
//! verification's Fiat–Shamir rounds (task E8-05b).
//!
//! The caller enumerates the rounds (a round is a maximal run of challenges with no
//! absorb between them, A17 item 3) and their errors; this module only decides. Every
//! comparison is exact integer arithmetic, and every intermediate is checked: a value
//! out of range is `Reject::Overflow`, never a panic. Round enumeration from a plan is
//! E8-05.
//!
//! - **Authority.** Accepted RFC-0012 A17 item 4 governs here. Draft RFC-0030 §4's
//!   `λ_min` reading does not; where they differ, A17 holds.
//! - **Completeness is the caller's.** The list must hold every round of one
//!   verification. `admit` cannot see a missing round: `admit(&STANDARD, &[], None, q)`
//!   is `Ok` whenever the H* endpoints hold.

use core::cmp::Ordering;

/// The M31 modulus `p`.
const P: u64 = (1 << 31) - 1;
/// Largest grinding bits A17 item 5 allows (`InvalidGrindBits` above).
pub const MAX_GRIND_BITS: u32 = 32;

/// A profile's admission parameters (RFC-0002 A1, RFC-0012 A17 item 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Security level λ.
    pub lambda: u32,
    /// Per-round slack g.
    pub slack: u32,
    /// `log2` of the query cap `Q_cap`.
    pub log2_query_cap: u32,
    /// Grinding bits `k_q` of every PCS column round (RFC-0010 A14 item 3).
    pub column_grind_bits: u32,
}

/// The standard profile: λ = 100, g = 8, `Q_cap = 2^80`, `k_q = 16`.
pub const STANDARD: Profile = Profile {
    lambda: 100,
    slack: 8,
    log2_query_cap: 80,
    column_grind_bits: 16,
};

/// A round family. Only lookup and PCS rounds may grind (A17 item 5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// One sumcheck round (an SC record split per round, A17 item 3).
    Sumcheck,
    /// A random linear combination.
    Rlc,
    /// A Schwartz–Zippel point.
    Sz,
    /// A mask coefficient (RFC-0013 A2).
    Mask,
    /// An LU check's `(β, α)` round.
    Lookup,
    /// A PCS tensor (certificate weight) round.
    PcsTensor,
    /// A PCS column round.
    PcsColumn,
}

/// An error bound `numerator / (p^field_degree · 2^log2_denominator)`.
///
/// An algebraic round over QM31 is `n / p^4`; a PCS column round is its A14 target
/// `1 / 2^92`; the A7 setup term is `200,431,782 / 2^160`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bound {
    /// Numerator.
    pub numerator: u128,
    /// Power of `p` in the denominator (0 to 8).
    pub field_degree: u8,
    /// Power of two in the denominator.
    pub log2_denominator: u32,
}

/// One Fiat–Shamir round with its RBR error `ε_i` and grinding bits `k_i`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Round {
    /// Its family.
    pub family: Family,
    /// `ε_i`.
    pub error: Bound,
    /// `k_i`; 0 means no nonce.
    pub grind_bits: u32,
}

/// Why a configuration is not admitted (each is `UnsupportedParameters` to callers).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// (C1): round `i` exceeds `2^-(λ+g)` at any allowed grinding.
    Round(usize),
    /// (C4): round `i` grinds outside the allowed families, above 32 bits, or not
    /// at the least sufficient (for PCS columns, the profile's) `k`.
    Grinding(usize),
    /// (C2): `ε_floor + ε_setup > 2^-λ`.
    Floor,
    /// (C3): an `H*` endpoint check fails.
    Hash,
    /// A field degree above 8, or an intermediate beyond the exact-integer width.
    Overflow,
}

/// Admit `rounds` (every round of one verification), the A7 `setup` term when a
/// v2 J ≥ 4 source is present, and `verifier_queries` (`Q_V`) to `profile`:
/// - (C1) every round has `ε_i·2^-k_i ≤ 2^-(λ+g)`;
/// - (C2) `Σ ε_i·2^-k_i + ε_setup ≤ 2^-λ`;
/// - (C3) `H*(1+Q_V) ≤ 2^-λ` and `H*(Q_cap+Q_V) ≤ (Q_cap+1)·2^-λ`, with
///   `H*(Q) = [C(Q,2) + 3·Q²]/2^256`;
/// - (C4) only lookup and PCS rounds grind; PCS column rounds at the profile's
///   `k_q`, lookup and tensor rounds at the least `k` meeting (C1).
///
/// The floor is a sum over every round, so it bounds A17's `ε_floor` (a maximum
/// over verification paths) from above.
pub fn admit(
    profile: &Profile,
    rounds: &[Round],
    setup: Option<Bound>,
    verifier_queries: u64,
) -> Result<(), Reject> {
    let target = profile
        .lambda
        .checked_add(profile.slack)
        .ok_or(Reject::Overflow)?;
    for (i, r) in rounds.iter().enumerate() {
        let k = r.grind_bits;
        if k > MAX_GRIND_BITS {
            return Err(Reject::Grinding(i));
        }
        match r.family {
            Family::PcsColumn => {
                if k != profile.column_grind_bits {
                    return Err(Reject::Grinding(i));
                }
                if !within(&r.error, k, target)? {
                    return Err(Reject::Round(i));
                }
            }
            Family::Lookup | Family::PcsTensor => {
                let mut least = None;
                for j in 0..=MAX_GRIND_BITS {
                    if within(&r.error, j, target)? {
                        least = Some(j);
                        break;
                    }
                }
                match least {
                    None => return Err(Reject::Round(i)),
                    Some(j) if j != k => return Err(Reject::Grinding(i)),
                    Some(_) => {}
                }
            }
            _ => {
                if k != 0 {
                    return Err(Reject::Grinding(i));
                }
                if !within(&r.error, 0, target)? {
                    return Err(Reject::Round(i));
                }
            }
        }
    }
    floor(profile.lambda, rounds, setup)?;
    hash(profile, verifier_queries)
}

/// `ε·2^-k ≤ 2^-target`, that is `n·2^target ≤ p^d·2^(s+k)`.
fn within(e: &Bound, k: u32, target: u32) -> Result<bool, Reject> {
    let lhs = Big::from(e.numerator).shl(target)?;
    let s = e.log2_denominator.checked_add(k).ok_or(Reject::Overflow)?;
    let rhs = pow_p(e.field_degree)?.shl(s)?;
    Ok(lhs <= rhs)
}

/// (C2) over the common denominator `p^D·2^S`.
fn floor(lambda: u32, rounds: &[Round], setup: Option<Bound>) -> Result<(), Reject> {
    let terms = rounds
        .iter()
        .map(|r| (r.error, r.grind_bits))
        .chain(setup.map(|b| (b, 0)));
    let (mut d, mut s) = (0u8, 0u32);
    for (b, k) in terms.clone() {
        d = d.max(b.field_degree);
        s = s.max(b.log2_denominator.checked_add(k).ok_or(Reject::Overflow)?);
    }
    let mut sum = Big::ZERO;
    for (b, k) in terms {
        // s ≥ log2_denominator + k and d ≥ field_degree by the loop above.
        let shift = s
            .checked_sub(b.log2_denominator)
            .and_then(|v| v.checked_sub(k))
            .ok_or(Reject::Overflow)?;
        let scale = pow_p(d - b.field_degree)?.shl(shift)?;
        sum = sum.add(&Big::from(b.numerator).mul(&scale)?)?;
    }
    if sum.shl(lambda)? <= pow_p(d)?.shl(s)? {
        Ok(())
    } else {
        Err(Reject::Floor)
    }
}

/// (C3). With `2·C(Q,2) + 6·Q² = 7·Q² − Q`, each check is
/// `(7·Q² − Q)·2^λ ≤ 2·m·2^256`, with `m = 1` or `Q_cap + 1`.
fn hash(profile: &Profile, verifier_queries: u64) -> Result<(), Reject> {
    let qv = Big::from(u128::from(verifier_queries));
    let one = Big::from(1);
    let cap = one.shl(profile.log2_query_cap)?;
    for (q, m) in [(one.add(&qv)?, one), (cap.add(&qv)?, cap.add(&one)?)] {
        // 7·Q²·2^λ ≤ 2·m·2^256 + Q·2^λ, so no subtraction is needed.
        let lhs = Big::from(7).mul(&q.mul(&q)?)?.shl(profile.lambda)?;
        let rhs = m.shl(257)?.add(&q.shl(profile.lambda)?)?;
        if lhs > rhs {
            return Err(Reject::Hash);
        }
    }
    Ok(())
}

fn pow_p(d: u8) -> Result<Big, Reject> {
    if d > 8 {
        return Err(Reject::Overflow);
    }
    let mut x = Big::from(1);
    for _ in 0..d {
        x = x.mul(&Big::from(u128::from(P)))?;
    }
    Ok(x)
}

/// A 1024-bit unsigned integer, little-endian limbs; every operation is checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Big([u64; 16]);

impl Big {
    const ZERO: Big = Big([0; 16]);

    fn from(x: u128) -> Big {
        let mut b = Big::ZERO;
        b.0[0] = x as u64;
        b.0[1] = (x >> 64) as u64;
        b
    }

    fn add(&self, o: &Big) -> Result<Big, Reject> {
        let mut out = Big::ZERO;
        let mut carry = 0u128;
        for i in 0..16 {
            let t = u128::from(self.0[i]) + u128::from(o.0[i]) + carry;
            out.0[i] = t as u64;
            carry = t >> 64;
        }
        if carry == 0 {
            Ok(out)
        } else {
            Err(Reject::Overflow)
        }
    }

    fn mul(&self, o: &Big) -> Result<Big, Reject> {
        let mut out = [0u128; 33];
        for i in 0..16 {
            for j in 0..16 {
                let t = u128::from(self.0[i]) * u128::from(o.0[j]);
                let mut at = i + j;
                let mut add = t;
                while add != 0 {
                    let s = out[at] + (add & u128::from(u64::MAX));
                    out[at] = s & u128::from(u64::MAX);
                    add = (add >> 64) + (s >> 64);
                    at += 1;
                }
            }
        }
        if out[16..].iter().any(|&x| x != 0) {
            return Err(Reject::Overflow);
        }
        let mut b = Big::ZERO;
        for (limb, x) in b.0.iter_mut().zip(out) {
            *limb = x as u64;
        }
        Ok(b)
    }

    fn shl(&self, n: u32) -> Result<Big, Reject> {
        let (limbs, bits) = ((n / 64) as usize, n % 64);
        let mut out = Big::ZERO;
        for i in (0..16).rev() {
            if self.0[i] == 0 {
                continue;
            }
            let lo = i + limbs;
            let wide = u128::from(self.0[i]) << bits;
            if lo >= 16 || (wide >> 64 != 0 && lo + 1 >= 16) {
                return Err(Reject::Overflow);
            }
            out.0[lo] |= wide as u64;
            if wide >> 64 != 0 {
                out.0[lo + 1] |= (wide >> 64) as u64;
            }
        }
        Ok(out)
    }
}

impl PartialOrd for Big {
    fn partial_cmp(&self, o: &Big) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Big {
    fn cmp(&self, o: &Big) -> Ordering {
        self.0.iter().rev().cmp(o.0.iter().rev())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P4: u128 = (P as u128) * (P as u128) * (P as u128) * (P as u128);

    fn qm31(numerator: u128) -> Bound {
        Bound {
            numerator,
            field_degree: 4,
            log2_denominator: 0,
        }
    }

    fn round(family: Family, numerator: u128, grind_bits: u32) -> Round {
        Round {
            family,
            error: qm31(numerator),
            grind_bits,
        }
    }

    /// A PCS column round at its A14 target `2^-92`, grinding `k_q = 16`.
    const COLUMN: Round = Round {
        family: Family::PcsColumn,
        error: Bound {
            numerator: 1,
            field_degree: 0,
            log2_denominator: 92,
        },
        grind_bits: 16,
    };

    // The largest QM31 numerator meeting (C1) unaided at λ+g = 108, by u128 arithmetic.
    const CAP: u128 = P4 >> 108;

    #[test]
    fn big_arithmetic_matches_u128() {
        let (a, b) = (0xdead_beef_1234_5678u128, 0x0123_4567_89ab_cdefu128);
        assert_eq!(Big::from(a).mul(&Big::from(b)), Ok(Big::from(a * b)));
        assert_eq!(Big::from(a).add(&Big::from(b)), Ok(Big::from(a + b)));
        assert_eq!(Big::from(a).shl(40), Ok(Big::from(a << 40)));
        assert_eq!(pow_p(4), Ok(Big::from(P4)));
        assert_eq!(Big::from(1).shl(1023).map(|_| ()), Ok(()));
        assert_eq!(Big::from(2).shl(1023), Err(Reject::Overflow));
        assert!(Big::from(1)
            .shl(700)
            .is_ok_and(|b| b > Big::from(u128::MAX)));
    }

    #[test]
    fn admits_rounds_at_the_c1_boundary_and_rejects_one_above() {
        const { assert!(CAP * (1 << 108) <= P4 && (CAP + 1) * (1 << 108) > P4) };
        for family in [Family::Sumcheck, Family::Rlc, Family::Sz, Family::Mask] {
            assert_eq!(admit(&STANDARD, &[round(family, CAP, 0)], None, 1), Ok(()));
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP + 1, 0)], None, 1),
                Err(Reject::Round(0))
            );
            // (C4): these families never grind.
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP + 1, 1)], None, 1),
                Err(Reject::Grinding(0))
            );
        }
    }

    #[test]
    fn lookup_and_tensor_rounds_grind_at_exactly_the_least_bits() {
        for family in [Family::Lookup, Family::PcsTensor] {
            assert_eq!(admit(&STANDARD, &[round(family, CAP, 0)], None, 1), Ok(()));
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP, 1)], None, 1),
                Err(Reject::Grinding(0))
            );
            // Just above the cap needs one bit: zero and two are both rejected.
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP + 1, 0)], None, 1),
                Err(Reject::Grinding(0))
            );
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP + 1, 1)], None, 1),
                Ok(())
            );
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP + 1, 2)], None, 1),
                Err(Reject::Grinding(0))
            );
            // 2^32·CAP is the most 32 bits can carry; one more is out of reach.
            let top = (CAP + 1) << 32;
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP << 32, 32)], None, 1),
                Ok(())
            );
            assert_eq!(
                admit(&STANDARD, &[round(family, top, 32)], None, 1),
                Err(Reject::Round(0))
            );
            assert_eq!(
                admit(&STANDARD, &[round(family, CAP, 33)], None, 1),
                Err(Reject::Grinding(0))
            );
        }
    }

    #[test]
    fn column_rounds_grind_at_the_profile_bits() {
        assert_eq!(admit(&STANDARD, &[COLUMN], None, 1), Ok(()));
        for k in [0, 15, 17] {
            let r = Round {
                grind_bits: k,
                ..COLUMN
            };
            assert_eq!(admit(&STANDARD, &[r], None, 1), Err(Reject::Grinding(0)));
        }
        // A column round above its target fails (C1) at k_q.
        let weak = Round {
            error: Bound {
                numerator: 3,
                field_degree: 0,
                log2_denominator: 93,
            },
            ..COLUMN
        };
        assert_eq!(admit(&STANDARD, &[weak], None, 1), Err(Reject::Round(0)));
    }

    #[test]
    fn floor_admits_exactly_two_to_the_minus_lambda() {
        // 256 column rounds at 2^-108 each sum to exactly 2^-100.
        let rounds = [COLUMN; 257];
        assert_eq!(admit(&STANDARD, &rounds[..256], None, 1), Ok(()));
        assert_eq!(admit(&STANDARD, &rounds, None, 1), Err(Reject::Floor));
        // Mixed denominators: one QM31 round of 1/p^4 tips the 256 over.
        let mut mixed = [COLUMN; 256];
        mixed[0] = round(Family::Sz, 1, 0);
        assert_eq!(admit(&STANDARD, &mixed, None, 1), Ok(()));
        let mut over = [COLUMN; 257];
        over[256] = round(Family::Sz, 1, 0);
        assert_eq!(admit(&STANDARD, &over, None, 1), Err(Reject::Floor));
    }

    #[test]
    fn floor_counts_the_setup_term() {
        // The A7 term, 200,431,782 / 2^160 ≈ 2^-132.4, fits beside 255 columns but
        // not beside 256.
        let setup = Some(Bound {
            numerator: 200_431_782,
            field_degree: 0,
            log2_denominator: 160,
        });
        let rounds = [COLUMN; 256];
        assert_eq!(admit(&STANDARD, &rounds[..255], setup, 1), Ok(()));
        assert_eq!(admit(&STANDARD, &rounds, setup, 1), Err(Reject::Floor));
    }

    #[test]
    fn hash_endpoints_hold_for_standard_and_treaty_and_fail_past_them() {
        assert_eq!(admit(&STANDARD, &[], None, u64::MAX), Ok(()));
        let treaty = Profile {
            lambda: 128,
            log2_query_cap: 100,
            ..STANDARD
        };
        // At λ = 128, H*(2^64) ≈ 2^-126.2 fails the first endpoint; 2^62 passes.
        assert_eq!(admit(&treaty, &[], None, 1 << 62), Ok(()));
        assert_eq!(admit(&treaty, &[], None, u64::MAX), Err(Reject::Hash));
        // λ = 200: H*(1+Q_V) ≤ 2^-200 needs 7·Q² − Q ≤ 2^57, so Q = 1 + Q_V is at
        // most 143,484,786 (exact integer search).
        let strict = Profile {
            lambda: 200,
            log2_query_cap: 0,
            ..STANDARD
        };
        assert_eq!(admit(&strict, &[], None, 143_484_785), Ok(()));
        assert_eq!(admit(&strict, &[], None, 143_484_786), Err(Reject::Hash));
        // The Q_cap endpoint alone: λ = 128 with Q_cap = 2^140 fails it, since
        // 7·2^280 > 2·(2^140 + 1)·2^256.
        let wide = Profile {
            log2_query_cap: 140,
            ..treaty
        };
        assert_eq!(admit(&wide, &[], None, 0), Err(Reject::Hash));
    }

    /// Guardrail: out-of-range inputs reject as `Overflow` and never panic, even with
    /// overflow checks on.
    #[test]
    fn rejects_overflowing_exponents_without_panicking() {
        let far = Round {
            error: Bound {
                numerator: 1,
                field_degree: 0,
                log2_denominator: u32::MAX - 10,
            },
            ..COLUMN
        };
        assert_eq!(admit(&STANDARD, &[far], None, 1), Err(Reject::Overflow));
        let lambda = Profile {
            lambda: u32::MAX,
            ..STANDARD
        };
        assert_eq!(admit(&lambda, &[], None, 1), Err(Reject::Overflow));
    }

    /// (C4): `k ≤ 32` holds even when a profile names more column bits.
    #[test]
    fn rejects_grinding_above_32_bits_for_any_profile() {
        let wide = Profile {
            column_grind_bits: 33,
            ..STANDARD
        };
        let r = Round {
            grind_bits: 33,
            ..COLUMN
        };
        assert_eq!(admit(&wide, &[r], None, 1), Err(Reject::Grinding(0)));
    }

    #[test]
    fn rejects_a_field_degree_above_eight() {
        let r = Round {
            error: Bound {
                numerator: 1,
                field_degree: 9,
                log2_denominator: 0,
            },
            ..round(Family::Sz, 1, 0)
        };
        assert_eq!(admit(&STANDARD, &[r], None, 1), Err(Reject::Overflow));
    }
}
