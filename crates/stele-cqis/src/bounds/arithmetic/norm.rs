//! RFC-0025 static §6 and RMSNorm §§1–3: complete closed normalization records,
//! plus RFC-0004 A14's schema 20 for rmsnorm_q version 2 (int24 X).
use super::{term, Builder, Error, Record, Word};
use crate::functions::Descriptor;

struct Norm {
    d: u64,
    f: i16,
    g: i16,
    e: i16,
    gb: i16,
    en: Word,
    ed: Word,
}
impl Norm {
    fn read(function: Descriptor, layer: bool) -> Result<Self, Error> {
        let p = function.parameters();
        let expected = if layer { "layernorm_q" } else { "rmsnorm_q" };
        if function.name() != expected || p.len() != if layer { 14 } else { 13 } {
            return Err(Error::Parameters);
        }
        // Descriptor's private checked state fixes dimensions, fractions and
        // reduced positive epsilon; the exact lengths above bound these reads.
        let start = if layer { 6 } else { 5 };
        let uint = |at| u32::from_le_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
        Ok(Self {
            d: u64::from(u16::from_le_bytes([p[0], p[1]])),
            f: i16::from(p[2]),
            g: i16::from(p[3]),
            e: i16::from(p[4]),
            gb: if layer { i16::from(p[5]) } else { 0 },
            en: u64::from(uint(start)).into(),
            ed: u64::from(uint(start + 4)).into(),
        })
    }
}

impl Record {
    /// Derive schema 3 from the exact checked LayerNorm descriptor.
    /// Common bounds do not authorize independently selected branch factors.
    pub fn layernorm(function: Descriptor) -> Result<Self, Error> {
        let p = Norm::read(function, true)?;
        let (h, o) = (32768u64, 65535u64);
        let (s, os, q, c, v) = (
            p.d * h,
            p.d * o,
            p.d * h * h,
            o * (p.d - 1),
            p.d * p.d * h * h,
        );
        let unit = Word::from(p.d * p.d).shl((2 * p.f) as usize)?;
        let n = p.ed.mul(v.into())?.add(p.en.mul(unit)?)?;
        let denominator = p.ed.mul(unit)?;
        let (fa, fd) = (Word::power(46)?, Word::power(18)?);
        let (aa, dd) = (n.mul(fa)?, denominator.mul(fd)?);
        let (md, ch, t) = (dd.mul(o.into())?, c * h, c * h * 16384);
        let (mut lt_shift, mut lb_shift, mut power_shift) = (0, 0, 0);
        let (mut emin, mut emax, mut kmin, mut kmax) = (i16::MAX, i16::MIN, i16::MAX, i16::MIN);
        // RFC-0025 static §6: all maxima come from the same closed 33 tuples.
        for a in -23..=9 {
            let e = p.f + p.g + 21 + a - p.e;
            let k = e.max(p.gb - p.e).max(0);
            lt_shift = lt_shift.max(k - e);
            lb_shift = lb_shift.max(k + p.e - p.gb);
            power_shift = power_shift.max(k);
            emin = emin.min(e);
            emax = emax.max(e);
            kmin = kmin.min(k);
            kmax = kmax.max(k);
        }
        let (lt, lb, power) = (
            Word::power(lt_shift)?,
            Word::power(lb_shift)?,
            Word::power(power_shift)?,
        );
        let (dlb, dout) = (lb.mul(p.d.into())?, power.mul(p.d.into())?);
        let maximum = lt.mul(t.into())?.add(dlb.mul(h.into())?)?;
        let qd = dout.mul(h.into())?;
        let scalars = [
            h.into(),
            o.into(),
            s.into(),
            os.into(),
            q.into(),
            c.into(),
            v.into(),
            unit,
            n,
            denominator,
            fa,
            fd,
            aa,
            dd,
            md,
            16384.into(),
            ch.into(),
            t.into(),
            lt,
            lb,
            power,
            dlb,
            maximum,
            dout,
            h.into(),
            qd,
            131071.into(),
            65536.into(),
        ];
        let mut b = Builder::new(
            3,
            function.parameters(),
            8,
            &scalars,
            &[emin, emax, kmin, kmax],
            33,
        )?;
        b.column(&[(p.d as u32, o.into(), 1.into())])?;
        b.column(&[(p.d as u32, h.into(), h.into())])?;
        b.column(&[term(os, 1), term(s, 2)])?;
        b.column(&[term(s, 1), term(s, 1)])?;
        b.column(&[term(o, p.d), term(c, 1)])?;
        b.column(&[term(2 * c, 1), term(os, 1)])?;
        b.column(&[term(2 * c, 1), term(c, 2)])?;
        b.column(&[term(c, 1), term(c, 1)])?;
        b.column(&[term(s, s)])?;
        b.column(&[term(q, p.d)])?;
        b.column(&[term(v, 1), term(v, 1)])?;
        b.column(&[term(v, p.ed), term(unit, p.en)])?;
        b.column(&[term(n, fa)])?;
        b.column(&[term(denominator, fd)])?;
        b.column(&[term(o, dd)])?;
        let remainder = dd.sub(1.into())?;
        b.column(&[term(md, 1), term(remainder, 1)])?;
        b.column(&[term(remainder, 1), term(remainder, 1), term(1, 1)])?;
        b.column(&[term(c, h)])?;
        b.column(&[term(ch, 16384)])?;
        b.column(&[term(2 * t, 1), term(t, 2)])?;
        b.column(&[term(t, 1), term(t, 1)])?;
        b.column(&[term(p.d, lb)])?;
        b.column(&[term(t, lt), term(h, dlb)])?;
        b.column(&[term(2 * t, lt), term(o, dlb)])?;
        b.column(&[term(maximum.mul(2.into())?, 1), term(maximum, 2)])?;
        b.column(&[term(maximum, 1), term(maximum, 1)])?;
        b.column(&[term(p.d, power)])?;
        // The variable original Dout uses the common qmax=32768, not Ucap/Doutmax.
        b.column(&[term(h, dout)])?;
        let remainder = dout.sub(1.into())?;
        b.column(&[term(qd, 1), term(remainder, 1)])?;
        b.column(&[term(remainder, 1), term(remainder, 1), term(1, 1)])?;
        b.column(&[term(remainder, 2)])?;
        b.column(&[
            term(remainder.mul(2.into())?, 1),
            term(remainder, 1),
            term(1, 1),
        ])?;
        b.column(&[term(dout, 1), term(remainder, 1)])?;
        b.finish()
    }
    /// Derive schema 14 without changing RFC-0022's original RMSNorm record, or
    /// schema 20 for version 2: X is int24 (Hx=2^23), gains and outputs stay int16.
    pub fn rmsnorm(function: Descriptor) -> Result<Self, Error> {
        let p = Norm::read(function, false)?;
        let wide = function.version() == 2;
        let (h, o) = (32768u64, 65535u64);
        let (hx, amax) = if wide { (1u64 << 23, 16) } else { (h, 9) };
        let ox = 2 * hx - 1;
        let unit = Word::from(p.d).shl((2 * p.f) as usize)?;
        // Version 2 has d <= 8192, so d*Hx^2 <= 2^59.
        let statistic = p.d * hx * hx;
        let n = p.ed.mul(statistic.into())?.add(p.en.mul(unit)?)?;
        let denominator = p.ed.mul(unit)?;
        let (fa, fd) = (Word::power(46)?, Word::power(2 * amax)?);
        let (aa, dd) = (n.mul(fa)?, denominator.mul(fd)?);
        let (md, xy, t) = (dd.mul(o.into())?, hx * h, hx * h * 16384);
        let (emin, emax) = (p.f + p.g - 2 - p.e, p.f + p.g + 21 + amax - p.e);
        let (l, dr) = (Word::power((-emin).max(0))?, Word::power(emax.max(0))?);
        let bias = if emax > 0 {
            Word::power(emax - 1)?
        } else {
            0.into()
        };
        let (u, qd) = (l.mul(t.into())?, dr.mul(h.into())?);
        let mut scalars = alloc::vec![
            h.into(),
            o.into(),
            unit,
            statistic.into(),
            n,
            denominator,
            fa,
            fd,
            aa,
            dd,
            md,
            8192.into(),
            16384.into(),
            xy.into(),
            t.into(),
            l,
            dr,
            bias,
            u,
            u.add(bias)?,
            h.into(),
            qd,
            (p.d - 1).into(),
            p.d.next_power_of_two().into(),
            (2 * p.d - 1).into(),
            131071.into(),
            65536.into(),
            (amax as u64 + 23).into(),
            (amax as u64 + 24).into(),
            64.into(),
            16384.into(),
            65535.into(),
            49152.into(),
            65536.into(),
            49151.into(),
            524288.into(),
            524350.into(),
            3.into(),
        ];
        if wide {
            scalars.extend([hx, ox, 4 * hx - 1, 2 * hx].map(Word::from));
        }
        let (schema, roles) = if wide { (20, 28) } else { (14, 26) };
        let mut b = Builder::new(
            schema,
            function.parameters(),
            8,
            &scalars,
            &[emin, emax],
            roles,
        )?;
        // Roles 1/2 bind X; version 2's roles 27/28 bind the int16 gain separately.
        b.column(&[term(ox, 1), term(hx, 2)])?;
        b.column(&[term(hx, 1), term(hx, 1)])?;
        b.column(&[(p.d as u32, hx.into(), hx.into())])?;
        b.column(&[term(statistic, p.ed), term(unit, p.en)])?;
        b.column(&[term(n, fa)])?;
        b.column(&[term(denominator, fd)])?;
        b.column(&[term(o, dd)])?;
        let remainder = dd.sub(1.into())?;
        b.column(&[term(md, 1), term(remainder, 1)])?;
        b.column(&[term(remainder, 1), term(remainder, 1), term(1, 1)])?;
        b.column(&[term(hx, h)])?;
        b.column(&[term(xy, 16384)])?;
        b.column(&[term(t, l)])?;
        b.column(&[term(u, 1), term(bias, 1)])?;
        b.column(&[term(h, dr)])?;
        let remainder = dr.sub(1.into())?;
        b.column(&[term(qd, 1), term(remainder, 1)])?;
        b.column(&[term(remainder, 1), term(remainder, 1), term(1, 1)])?;
        b.column(&[term(o, 1), term(h, 2)])?;
        b.column(&[term(h, 1), term(h, 1)])?;
        b.column(&[term(49151, 1), term(16384, 1)])?;
        b.column(&[term(amax as u64 + 23, 1)])?;
        b.column(&[term(65535, 8)])?;
        b.column(&[term(524280, 1), term(7, 1), term(62, 1)])?;
        b.column(&[term(1, 1)])?;
        b.column(&[term(1, 1), term(1, 1)])?;
        b.column(&[term(1, 1), term(1, 2)])?;
        b.column(&[term(1, 1)])?;
        if wide {
            b.column(&[term(o, 1), term(h, 2)])?;
            b.column(&[term(h, 1), term(h, 1)])?;
        }
        b.finish()
    }
}
