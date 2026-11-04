//! RFC-0025 decoding-bound §§1–3: full logits, temperature and sampled selection.
use super::{term, Builder, Error, Exponential, Record, Word};

/// Full vocabulary logit parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Logits {
    /// Vocabulary size, in 1..=2^20.
    pub vocabulary: u32,
    /// Common logit fraction, in 0..=30.
    pub fraction: u8,
}
/// One-round temperature parameters, distinct from greedy decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Temperature {
    /// Original logit fraction, in 0..=30.
    pub logits_fraction: u8,
    /// Reduced positive u32 numerator/denominator.
    pub temperature: (u32, u32),
    /// Exact selected exp, whose count is the full vocabulary.
    pub exp: Exponential,
}
/// Complete sampled selection parameters, retaining the inclusive 2^32 endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sampling {
    /// Full vocabulary size, in 1..=2^20.
    pub vocabulary: u32,
    /// Selected exp output fraction, in 0..=14.
    pub exp_fraction: u8,
    /// Reduced positive numerator/denominator, with numerator<=denominator.
    pub top_p: (u32, u32),
}
fn rational((n, d): (u32, u32), probability: bool) -> Result<(), Error> {
    if n == 0 || d == 0 || (probability && n > d) {
        return Err(Error::Parameters);
    }
    let (mut a, mut b) = (n, d);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    if a != 1 {
        return Err(Error::Parameters);
    }
    Ok(())
}
impl Record {
    /// Derive schema 15 from the complete original vocabulary and units.
    pub fn logits(p: Logits) -> Result<Self, Error> {
        if !(1..=1 << 20).contains(&p.vocabulary) || p.fraction > 30 {
            return Err(Error::Parameters);
        }
        let v = u64::from(p.vocabulary);
        let pad = v.next_power_of_two();
        let scalars = [32768, 65535, v - 1, pad, 2 * pad - 1].map(Word::from);
        let mut params = [0; 5];
        params[..4].copy_from_slice(&p.vocabulary.to_le_bytes());
        params[4] = p.fraction;
        let mut b = Builder::new(15, &params, 8, &scalars, &[], 4)?;
        b.column(&[term(65535, 1), term(65535, 1)])?;
        b.column(&[term(65535, 1), term(1, 1)])?;
        b.column(&[term(65535, 1), term(32768, 2)])?;
        b.column(&[term(32768, 1), term(32768, 1)])?;
        b.finish()
    }
    /// Derive schema 16; actual exp-argument range failure remains a runtime check.
    pub fn temperature(p: Temperature) -> Result<Self, Error> {
        p.exp.check()?;
        rational(p.temperature, false)?;
        if p.logits_fraction > 30 {
            return Err(Error::Parameters);
        }
        let (tn, td) = (u64::from(p.temperature.0), u64::from(p.temperature.1));
        let pre = 65535 * td;
        let factor = 1u64 << p.exp.source_fraction;
        let numerator = Word::from(pre).mul(factor.into())?;
        let d = tn << p.logits_fraction;
        let bias = d / 2;
        let biased = numerator.add(bias.into())?;
        let domain = 1u32 << p.exp.domain_bits;
        let q = biased.quotient_cap(d.into(), domain)?;
        let qd = q.mul(d.into())?;
        let v = u64::from(p.exp.count);
        let pad = v.next_power_of_two();
        let scalars = [
            65535.into(),
            pre.into(),
            factor.into(),
            numerator,
            d.into(),
            bias.into(),
            biased,
            u64::from(domain).into(),
            q,
            qd,
            (d - 1).into(),
            (v - 1).into(),
            pad.into(),
            (2 * pad - 1).into(),
        ];
        let mut params = [0; 18];
        params[..4].copy_from_slice(&p.exp.count.to_le_bytes());
        params[4] = p.logits_fraction;
        params[5..9].copy_from_slice(&p.temperature.0.to_le_bytes());
        params[9..13].copy_from_slice(&p.temperature.1.to_le_bytes());
        let (exp, length) = p.exp.parameters();
        params[13..13 + length - 4].copy_from_slice(&exp[4..length]);
        let mut b = Builder::new(16, &params[..length + 9], 8, &scalars, &[], 7)?;
        b.column(&[term(65535, td)])?;
        b.column(&[term(pre, factor)])?;
        b.column(&[term(numerator, 1), term(bias, 1)])?;
        b.column(&[term(q, d)])?;
        b.column(&[term(qd, 1), term(d - 1, 1)])?;
        b.column(&[term(d - 1, 1), term(d - 1, 1), term(1, 1)])?;
        b.column(&[term(q, 1), term(u64::from(domain), 1)])?;
        b.finish()
    }
    /// Derive schema 17, preserving all original ranks and complete CDF words.
    pub fn sampling(p: Sampling) -> Result<Self, Error> {
        if !(1..=1 << 20).contains(&p.vocabulary) || p.exp_fraction > 14 {
            return Err(Error::Parameters);
        }
        rational(p.top_p, true)?;
        let v = u64::from(p.vocabulary);
        let q = 1u64 << p.exp_fraction;
        let j = 1u64 << 32;
        let pad = v.next_power_of_two();
        let mass = v * q;
        let pn = u64::from(p.top_p.0);
        let pd = u64::from(p.top_p.1);
        let threshold = Word::from(mass).mul(pn.into())?;
        let upper = Word::from(mass).mul(pd.into())?;
        let jm = Word::from(j).mul(mass.into())?;
        let scalars = [
            q.into(),
            mass.into(),
            j.into(),
            (j - 1).into(),
            threshold,
            upper,
            jm,
            (mass - 1).into(),
            (v - 1).into(),
            pad.into(),
            (2 * pad - 1).into(),
            255.into(),
            (1 << 24).into(),
        ];
        let mut params = [0; 13];
        params[..4].copy_from_slice(&p.vocabulary.to_le_bytes());
        params[4] = p.exp_fraction;
        params[5..9].copy_from_slice(&p.top_p.0.to_le_bytes());
        params[9..].copy_from_slice(&p.top_p.1.to_le_bytes());
        let mut b = Builder::new(17, &params, 8, &scalars, &[], 19)?;
        b.column(&[(p.vocabulary, q.into(), 1.into())])?;
        b.column(&[term(q, 1), term(q, 1)])?;
        b.column(&[term(v - 1, 1), term(v - 1, 1), term(1, 1)])?;
        b.column(&[term(v - 1, 1)])?;
        b.column(&[term(mass, 1), term(q, 1)])?;
        b.column(&[term(mass, pn)])?;
        b.column(&[term(mass, pd)])?;
        b.column(&[term(mass, pd)])?;
        b.column(&[term(threshold, 1), term(upper, 1)])?;
        b.column(&[
            term(upper, 1),
            term(threshold.sub(1.into())?, 1),
            term(1, 1),
        ])?;
        b.column(&[term(mass, 1)])?;
        b.column(&[term(mass, j)])?;
        b.column(&[term(j, mass)])?;
        b.column(&[term(jm, 1), term(mass - 1, 1)])?;
        b.column(&[term(mass - 1, 1), term(mass - 1, 1), term(1, 1)])?;
        b.column(&[term(mass, 1)])?;
        b.column(&[term(j, 1), term(j - 1, 1)])?;
        b.column(&[term(j - 1, 1), term(j - 1, 1), term(1, 1)])?;
        b.column(&[
            term(255, 1),
            term(255, 256),
            term(255, 65536),
            term(255, 1 << 24),
        ])?;
        b.finish()
    }
}
