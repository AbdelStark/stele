//! RFC-0021 §3: exact normal integral, guarded alternating bounds and strict tail.
use super::{strict_exp, Descriptor, Endpoint, Error, Natural, Normalizer, Ordering, Ratio};

fn zero() -> Result<Ratio, Error> {
    Ok(Ratio {
        n: Natural::zero(),
        d: Natural::from_u64(1)?,
    })
}

fn signed_step(
    negative: &mut bool,
    partial: &Natural,
    factor: &Natural,
    term: &Natural,
    minus: bool,
) -> Result<Natural, Error> {
    let scaled = partial.mul(factor)?;
    if *negative == minus {
        return scaled.add(term);
    }
    match scaled.cmp(term) {
        Ordering::Greater => scaled.sub(term),
        Ordering::Less => {
            *negative = minus;
            term.sub(&scaled)
        }
        Ordering::Equal => {
            *negative = false;
            Ok(Natural::zero())
        }
    }
}

fn integral(a: &Natural, d: &Natural, bits: usize) -> Result<(Ratio, Ratio), Error> {
    let a2 = a.mul(a)?;
    let d2 = d.mul(d)?;
    let mut lower = zero()?;
    let mut upper = Ratio {
        n: a.try_clone()?,
        d: d.try_clone()?,
    };
    let (mut partial, mut divisor, mut term) = (a.try_clone()?, d.try_clone()?, a.try_clone()?);
    let mut negative = false;
    for step in 1..=512u64 {
        // term_n / term_(n-1) = a²(2n-1)/(d² 2n(2n+1)). Keeping a common
        // denominator preserves the exact reference partial, even before terms
        // decrease and the signed partial may be negative.
        let factor = d2.mul_u64(2 * step * (2 * step + 1))?;
        term = term.mul(&a2)?.mul_u64(2 * step - 1)?;
        partial = signed_step(&mut negative, &partial, &factor, &term, step % 2 == 1)?;
        divisor = divisor.mul(&factor)?;
        if d2.mul_u64(2 * step)?.cmp(&a2) != Ordering::Less {
            if step % 2 == 1 {
                lower = if negative {
                    zero()?
                } else {
                    Ratio {
                        n: partial.try_clone()?,
                        d: divisor.try_clone()?,
                    }
                };
            } else {
                if negative {
                    return Err(Error::Interval);
                }
                upper = if partial.mul(d)?.cmp(&a.mul(&divisor)?) == Ordering::Greater {
                    Ratio {
                        n: a.try_clone()?,
                        d: d.try_clone()?,
                    }
                } else {
                    Ratio {
                        n: partial.try_clone()?,
                        d: divisor.try_clone()?,
                    }
                };
            }
            let width = upper.n.mul(&lower.d)?.sub(&lower.n.mul(&upper.d)?)?;
            if width.shl(bits + 8)?.cmp(&upper.d.mul(&lower.d)?) == Ordering::Less {
                return Ok((lower, upper));
            }
        }
    }
    Err(Error::Precision)
}

fn complement(c: &Natural, i: &Ratio, precision: usize) -> Result<Ratio, Error> {
    let base = i.d.shl(precision)?;
    let product = c.mul(&i.n)?.mul_u64(2)?;
    // max(0, 1/2-c*I); the upper-tail endpoint already cannot exceed 1/2
    // because I's lower bound is nonnegative.
    if base.cmp(&product) != Ordering::Greater {
        return zero();
    }
    Ok(Ratio {
        n: base.sub(&product)?,
        d: base.mul_u64(2)?,
    })
}

pub(super) fn interval(
    d: &Descriptor,
    t: i32,
    bits: usize,
    c: Option<&Normalizer>,
) -> Result<(Endpoint, Endpoint), Error> {
    let p = d.parameters();
    let a = Natural::from_u64(u64::from(t.unsigned_abs()))?;
    let denominator = Natural::from_u64(1)?.shl(usize::from(p[0]))?;
    let (low, high) = if a.cmp(&denominator.mul_u64(8)?) != Ordering::Less {
        let (_, hi, precision) = strict_exp(
            &a.mul(&a)?,
            &denominator.mul(&denominator)?.mul_u64(2)?,
            bits,
        )?;
        // Phi(-a/d) < exp(-(a/d)^2/2)/(2*a/d), strictly for finite a.
        (
            zero()?,
            Ratio {
                n: hi.mul(&denominator)?,
                d: a.shl(precision + 1)?,
            },
        )
    } else {
        let c = c.ok_or(Error::Interval)?;
        let (i0, i1) = integral(&a, &denominator, bits)?;
        (
            complement(&c.high, &i1, c.precision)?,
            complement(&c.low, &i0, c.precision)?,
        )
    };
    if low.n.mul(&high.d)?.cmp(&high.n.mul(&low.d)?) != Ordering::Less
        || high.n.mul_u64(2)?.cmp(&high.d) == Ordering::Greater
    {
        return Err(Error::Interval);
    }
    let endpoint = |q: Ratio| -> Result<Endpoint, Error> {
        let num = if t > 0 { q.d.sub(&q.n)? } else { q.n };
        Ok(Endpoint {
            negative: t < 0,
            numerator: num.mul(&a)?.shl(usize::from(p[1]))?,
            denominator: q.d.mul(&denominator)?,
        })
    };
    Ok((endpoint(high)?, endpoint(low)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_signed_partial_crossings_and_exact_cancellation() {
        for (p, term, minus, expected) in [
            (-5i32, 2, true, -37i32),
            (-5, 40, false, 5),
            (5, 40, true, -5),
            (5, 35, true, 0),
            (-5, 35, false, 0),
            (5, 2, false, 37),
        ] {
            let mut negative = p < 0;
            let result = signed_step(
                &mut negative,
                &Natural::from_u64(u64::from(p.unsigned_abs())).expect("partial"),
                &Natural::from_u64(7).expect("factor"),
                &Natural::from_u64(term).expect("term"),
                minus,
            )
            .expect("signed sum");
            assert_eq!(result.to_u32(), Ok(expected.unsigned_abs()));
            assert_eq!(negative, expected < 0);
        }
    }
}
