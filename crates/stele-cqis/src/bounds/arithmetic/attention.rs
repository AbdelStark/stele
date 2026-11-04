//! RFC-0025 attention-input §§1–3: rotary addresses, scaled scores, causal maximum.
use super::{field_bound, term, Builder, Error, Record, Word};

/// Attention geometry; checked against the full static shape domain on derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttentionShape {
    /// Query head count, in 1..=128.
    pub heads: u16,
    /// KV group count, a positive divisor of heads.
    pub groups: u16,
    /// Per-head width, with heads*width<=16384.
    pub width: u16,
    /// Full context capacity, in 1..=2^20.
    pub context: u32,
}
fn row_shape(heads: u16, width: u16, context: u32) -> Result<(), Error> {
    if !(1..=128).contains(&heads)
        || width == 0
        || u32::from(heads) * u32::from(width) > 16384
        || !(1..=1 << 20).contains(&context)
    {
        return Err(Error::Parameters);
    }
    Ok(())
}
impl AttentionShape {
    pub(super) fn check(self) -> Result<(), Error> {
        row_shape(self.heads, self.width, self.context)?;
        if self.groups == 0 || self.groups > self.heads || !self.heads.is_multiple_of(self.groups) {
            return Err(Error::Parameters);
        }
        Ok(())
    }
    pub(super) fn parameters(self) -> [u8; 10] {
        let mut raw = [0; 10];
        for (v, at) in [(self.heads, 0), (self.groups, 2), (self.width, 4)] {
            raw[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        raw[6..].copy_from_slice(&self.context.to_le_bytes());
        raw
    }
}
pub(super) fn policy((mode, scale): (u8, u16)) -> Result<(u64, u64, u64), Error> {
    match (mode, scale) {
        (0, 0) => Ok((127, 0, 259)),
        (1, 1..=65535) => {
            let s = u64::from(scale);
            Ok((127.min((65536 + s) / (2 * s)), s, s))
        }
        _ => Err(Error::Parameters),
    }
}

/// Rotary application and original coefficient-address parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rotary {
    /// Heads/groups in this Q or K row.
    pub heads: u16,
    /// Per-head width.
    pub width: u16,
    /// Even rotary width in 2..=width.
    pub rotary_width: u16,
    /// Full context capacity.
    pub context: u32,
    /// Adjacent=0 or split=1.
    pub layout: u8,
    /// Original source fraction in 0..=30.
    pub fraction: u8,
}
/// Scaled QK parameters; no witness-dependent admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Score {
    /// Full original attention geometry.
    pub shape: AttentionShape,
    /// Query projection fraction.
    pub query_fraction: u8,
    /// Key projection fraction.
    pub key_fraction: u8,
    /// Selected exp input fraction.
    pub exp_fraction: u8,
    /// Query policy (mode, configured scale); dynamic=(0,0).
    pub query_policy: (u8, u16),
    /// Key policy (mode, configured scale); dynamic=(0,0).
    pub key_policy: (u8, u16),
    /// Positive configured multiplier mantissa.
    pub multiplier: u16,
    /// Configured multiplier exponent, in -62..=30.
    pub exponent: i8,
}
/// Causal maximum/index parameters, with a separately derived score bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Maximum {
    /// Full context capacity.
    pub context: u32,
    /// Expected symmetric score bound, strictly below 2^31.
    pub score_bound: u32,
    /// Selected exp domain bits, in 7..=31.
    pub domain_bits: u8,
    /// Selected exp input fraction, in 0..=30.
    pub fraction: u8,
}

impl Record {
    /// Derive schema 7, retaining full-context coefficient addresses.
    pub fn rotary(p: Rotary) -> Result<Self, Error> {
        row_shape(p.heads, p.width, p.context)?;
        if p.rotary_width < 2
            || p.rotary_width > p.width
            || !p.rotary_width.is_multiple_of(2)
            || p.layout > 1
            || p.fraction > 30
        {
            return Err(Error::Parameters);
        }
        let (heads, w, r, n) = (
            u64::from(p.heads),
            u64::from(p.width),
            u64::from(p.rotary_width),
            u64::from(p.context),
        );
        // RFC-0025 attention §1 proves this coupled canonical Q14 envelope.
        let (h, u, envelope) = (32768u64, 16384u64, 23171u64);
        let maximum = h * envelope;
        let size = n * (r / 2);
        let index_side = 2 * n.max(heads * w) - 1;
        for side in [
            h * u,
            maximum,
            maximum + u / 2,
            h * u + u - 1,
            h,
            2 * u,
            index_side,
        ] {
            field_bound(side)?;
        }
        let scalars = [
            heads * w,
            heads * (r / 2),
            heads * (w - r),
            n - 1,
            r / 2 - 1,
            heads - 1,
            size - 1,
            4 * (size - 1),
            4 * size - 1,
            h,
            u,
            envelope,
            h * u,
            maximum,
            u,
            u / 2,
            maximum + u / 2,
            h,
            u - 1,
            h * u + u - 1,
            h,
            2 * u,
            index_side,
        ]
        .map(Word::from);
        let mut params = [0; 12];
        for (v, at) in [(p.heads, 0), (p.width, 2), (p.rotary_width, 4)] {
            params[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        params[6..10].copy_from_slice(&p.context.to_le_bytes());
        params[10..].copy_from_slice(&[p.layout, p.fraction]);
        let mut b = Builder::new(7, &params, 8, &scalars, &[], 3)?;
        b.column(&[term(n - 1, r / 2), term(r / 2 - 1, 1)])?;
        b.column(&[term(size - 1, 4)])?;
        b.column(&[term(4 * (size - 1), 1), term(3, 1)])?;
        b.finish()
    }
    /// Derive schema 8 and its exact symmetric bound for the same maximum role.
    pub fn score(p: Score) -> Result<(Self, u32), Error> {
        p.shape.check()?;
        if [p.query_fraction, p.key_fraction, p.exp_fraction]
            .iter()
            .any(|v| *v > 30)
            || p.multiplier == 0
            || !(-62..=30).contains(&p.exponent)
        {
            return Err(Error::Parameters);
        }
        let (cq, qmin, sq) = policy(p.query_policy)?;
        let (ck, kmin, sk) = policy(p.key_policy)?;
        let (h, g, w, n) = (
            u64::from(p.shape.heads),
            u64::from(p.shape.groups),
            u64::from(p.shape.width),
            u64::from(p.shape.context),
        );
        let a = w * cq * ck;
        field_bound(a + 1)?;
        // Successful static conversion has C*S<=65535; hence Pm<2^62.
        let pq = a * sq;
        let pk = pq * sk;
        let pm = pk * u64::from(p.multiplier);
        let shift = i16::from(p.exponent) - i16::from(p.query_fraction) - i16::from(p.key_fraction)
            + i16::from(p.exp_fraction);
        let (l, d) = (Word::power(shift.max(0))?, Word::power((-shift).max(0))?);
        let bias = if shift < 0 {
            Word::power(-shift - 1)?
        } else {
            0.into()
        };
        let maximum = Word::from(pm).mul(l)?;
        let bound = maximum.add(bias)?.quotient_cap(d, 1 << 31)?.to_u32()?;
        if bound >= 1 << 31 {
            return Err(Error::ScoreBound);
        }
        let bv = Word::from(u64::from(bound));
        let bd = bv.mul(d)?;
        let rem = d.sub(1.into())?;
        let scalars = [
            (h - 1).into(),
            (g - 1).into(),
            (w - 1).into(),
            (n - 1).into(),
            (h * w).into(),
            (g * w).into(),
            (h / g).into(),
            cq.into(),
            ck.into(),
            qmin.into(),
            sq.into(),
            kmin.into(),
            sk.into(),
            a.into(),
            (a + 1).into(),
            pq.into(),
            pk.into(),
            pm.into(),
            l,
            d,
            bias,
            maximum,
            bv,
            bd,
            rem,
            (2 * u64::from(bound)).into(),
            (2 * n.max(h * w) - 1).into(),
        ];
        let mut params = [0; 22];
        params[..10].copy_from_slice(&p.shape.parameters());
        params[10..14].copy_from_slice(&[
            p.query_fraction,
            p.key_fraction,
            p.exp_fraction,
            p.query_policy.0,
        ]);
        params[14..16].copy_from_slice(&p.query_policy.1.to_le_bytes());
        params[16] = p.key_policy.0;
        params[17..19].copy_from_slice(&p.key_policy.1.to_le_bytes());
        params[19..21].copy_from_slice(&p.multiplier.to_le_bytes());
        params[21] = p.exponent as u8;
        let mut b = Builder::new(8, &params, 8, &scalars, &[shift], 10)?;
        b.column(&[term(a, sq)])?;
        b.column(&[term(pq, sk)])?;
        b.column(&[term(pk, u64::from(p.multiplier))])?;
        b.column(&[term(pm, l)])?;
        b.column(&[term(maximum, 1), term(bias, 1)])?;
        b.column(&[term(bv, d)])?;
        b.column(&[term(bd, 1), term(rem, 1)])?;
        b.column(&[term(rem, 1), term(rem, 1), term(1, 1)])?;
        b.column(&[term(2 * u64::from(bound), 1), term(bv, 2)])?;
        b.column(&[term(bv, 1), term(bv, 1)])?;
        Ok((b.finish()?, bound))
    }
    /// Derive schema 9, retaining the inclusive 2^31 exp index endpoint.
    pub fn maximum(p: Maximum) -> Result<Self, Error> {
        if !(1..=1 << 20).contains(&p.context)
            || p.score_bound >= 1 << 31
            || !(7..=31).contains(&p.domain_bits)
            || p.fraction > 30
        {
            return Err(Error::Parameters);
        }
        let (n, offset, domain) = (
            u64::from(p.context),
            2 * u64::from(p.score_bound),
            1u64 << p.domain_bits,
        );
        let delta = offset.min(domain);
        let scalars = [n - 1, offset, domain, delta, 1, 2 * n - 1, domain].map(Word::from);
        let mut params = [0; 10];
        params[..4].copy_from_slice(&p.context.to_le_bytes());
        params[4..8].copy_from_slice(&p.score_bound.to_le_bytes());
        params[8..].copy_from_slice(&[p.domain_bits, p.fraction]);
        let mut b = Builder::new(9, &params, 8, &scalars, &[], 6)?;
        b.column(&[term(offset, 1)])?;
        b.column(&[term(offset, 1), term(delta, 1)])?;
        b.column(&[term(offset, 1)])?;
        b.column(&[term(delta, 1), term(1, 1)])?;
        b.column(&[term(delta, 1), term(domain, 1)])?;
        b.column(&[term(domain, 1)])?;
        b.finish()
    }
}
