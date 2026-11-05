//! RFC-0025 weighted §§1–3: full-context radix-16 weighted and normalized bounds.
use super::{attention::policy, term, AttentionShape, Builder, Error, Record, Word};

/// Original value/probability operation; all domains are checked on derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Weighted {
    /// Full original attention geometry.
    pub shape: AttentionShape,
    /// Value projection fraction, in 0..=30.
    pub value_fraction: u8,
    /// Selected exp output fraction, in 0..=14.
    pub exp_fraction: u8,
    /// Whole-row value policy (mode, configured scale).
    pub policy: (u8, u16),
    /// Exact=0 or block1024=1.
    pub mode: u8,
    /// Zero for exact, otherwise a shift in 0..=62.
    pub drop: u8,
}
/// Normalization of the same complete weighted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Normalize {
    /// Original weighted operation, including its block admission rule.
    pub source: Weighted,
    /// Output fraction, in 0..=30.
    pub output_fraction: u8,
}
impl Weighted {
    fn constants(self) -> Result<[u64; 14], Error> {
        self.shape.check()?;
        if self.value_fraction > 30
            || self.exp_fraction > 14
            || self.mode > 1
            || self.drop > 62
            || (self.mode == 0 && self.drop != 0)
        {
            return Err(Error::Parameters);
        }
        let (code, low, scale) = policy(self.policy)?;
        let s = code * scale;
        let q = 1u64 << self.exp_fraction;
        let n = u64::from(self.shape.context);
        // RFC-0025 weighted §1: the admission bound uses 1024 even when n=1.
        let count = if self.mode == 1 { 1024 } else { n };
        let zl = count * q;
        let h = zl * s;
        let blocks = if self.mode == 1 { n.div_ceil(1024) } else { 0 };
        let d = 1u64 << self.drop;
        let bias = d / 2;
        let bound = if self.mode == 1 { (h + bias) / d } else { 0 };
        if bound > 32767 {
            return Err(Error::BlockBound);
        }
        let total = if self.mode == 1 { blocks * bound } else { h };
        // The checked domains give H<2^50 (block H<2^40), H+bias<2^62.
        Ok([
            code,
            low,
            scale,
            s,
            q,
            count,
            zl,
            h,
            n * q,
            blocks,
            d,
            bias,
            bound,
            total,
        ])
    }
    fn parameters(self) -> [u8; 17] {
        let mut raw = [0; 17];
        raw[..10].copy_from_slice(&self.shape.parameters());
        raw[10..13].copy_from_slice(&[self.value_fraction, self.exp_fraction, self.policy.0]);
        raw[13..15].copy_from_slice(&self.policy.1.to_le_bytes());
        raw[15..].copy_from_slice(&[self.mode, self.drop]);
        raw
    }
}
impl Record {
    /// Derive schema 12 with the prescribed nibble radix and full absolute blocks.
    pub fn weighted(p: Weighted) -> Result<Self, Error> {
        let [code, low, scale, s, q, count, zl, h, z, blocks, d, bias, bound, total] =
            p.constants()?;
        let (heads, g, w, n) = (
            u64::from(p.shape.heads),
            u64::from(p.shape.groups),
            u64::from(p.shape.width),
            u64::from(p.shape.context),
        );
        let scalars = [
            heads - 1,
            g - 1,
            w - 1,
            n - 1,
            heads * w,
            g * w,
            heads / g,
            code,
            low,
            scale,
            s,
            2 * s,
            q,
            count,
            zl,
            h,
            2 * h,
            z,
            blocks,
            if p.mode == 1 { blocks - 1 } else { 0 },
            d,
            bias,
            bound,
            bound * d,
            d - 1,
            total,
            2 * total,
            2 * n.max(heads * w).max(1024 * blocks) - 1,
        ]
        .map(Word::from);
        let mut b = Builder::new(
            12,
            &p.parameters(),
            4,
            &scalars,
            &[],
            if p.mode == 1 { 21 } else { 9 },
        )?;
        b.column(&[term(code, scale)])?;
        b.column(&[term(2 * s, 1), term(s, 2)])?;
        b.column(&[term(s, 1), term(s, 1)])?;
        b.column(&[(count as u32, q.into(), 1.into())])?;
        b.column(&[term(zl, s)])?;
        b.column(&[(count as u32, q.into(), (2 * s).into())])?;
        b.column(&[term(2 * h, 1), term(h, 2)])?;
        b.column(&[term(h, 1), term(h, 1)])?;
        b.column(&[term(h, 1), term(1, 1)])?;
        if p.mode == 1 {
            b.column(&[term(h, 1), term(bias, 1)])?;
            b.column(&[term(bound, d)])?;
            b.column(&[term(bound * d, 1), term(d - 1, 1)])?;
            b.column(&[term(d - 1, 1), term(d - 1, 1), term(1, 1)])?;
            b.column(&[term(2 * bound, 1), term(bound, 2)])?;
            b.column(&[term(bound, 1), term(bound, 1)])?;
            b.column(&[(blocks as u32, (2 * bound).into(), 1.into())])?;
            b.column(&[(blocks as u32, zl.into(), 1.into())])?;
            b.column(&[term(2 * total, 1), term(total, 2)])?;
            b.column(&[term(total, 1), term(total, 1)])?;
            b.column(&[term(total, 1), term(1, 1)])?;
            b.column(&[term(blocks - 1, 1024), term(1023, 1)])?;
        }
        b.finish()
    }
    /// Derive schema 13; the quotient uses Dmin, retaining variable Dmax words.
    pub fn normalize(p: Normalize) -> Result<Self, Error> {
        let s = p.source;
        let [_, _, _, _, q, _, _, _, z, _, _, _, _, total] = s.constants()?;
        if p.output_fraction > 30 {
            return Err(Error::Parameters);
        }
        let e = i16::from(p.output_fraction) - i16::from(s.value_fraction) + i16::from(s.drop);
        let (l, r) = (Word::power(e.max(0))?, Word::power((-e).max(0))?);
        let (u, dmin, dm) = (l.mul(total.into())?, r.mul(q.into())?, r.mul(z.into())?);
        let quotient = u.quotient_cap(dmin, 32768)?;
        let qd = quotient.mul(dm)?;
        let rem = dm.sub(1.into())?;
        let twice = rem.mul(2.into())?;
        let (width, kv, n) = (
            u64::from(s.shape.heads) * u64::from(s.shape.width),
            u64::from(s.shape.groups) * u64::from(s.shape.width),
            u64::from(s.shape.context),
        );
        let scalars = [
            total.into(),
            (2 * total).into(),
            q.into(),
            z.into(),
            l,
            r,
            u,
            dmin,
            dm,
            quotient,
            qd,
            rem,
            twice,
            32768.into(),
            65535.into(),
            131071.into(),
            65536.into(),
            width.into(),
            (width - 1).into(),
            kv.into(),
            (2 * n.max(width) - 1).into(),
        ];
        let mut params = [0; 18];
        params[..17].copy_from_slice(&s.parameters());
        params[17] = p.output_fraction;
        let mut b = Builder::new(13, &params, 4, &scalars, &[e], 11)?;
        b.column(&[term(total, l)])?;
        b.column(&[term(z, r)])?;
        b.column(&[term(quotient, dm)])?;
        b.column(&[term(qd, 1), term(rem, 1)])?;
        b.column(&[term(rem, 1), term(rem, 1), term(1, 1)])?;
        b.column(&[term(rem, 2)])?;
        b.column(&[term(twice, 1), term(rem, 1), term(1, 1)])?;
        b.column(&[term(dm, 1), term(rem, 1)])?;
        b.column(&[term(quotient, 1), term(1, 1)])?;
        b.column(&[term(65535, 1), term(32768, 2)])?;
        b.column(&[term(32768, 1), term(32768, 1)])?;
        b.finish()
    }
}
