//! RFC-0022 §§2.2-2.3: fixed role derivation; no witness-dependent bounds.
use super::{field_bound, Descriptor, Error, Format, Record, Requant, U160};

pub(super) fn requant(config: Requant, format: Format) -> Result<Record, Error> {
    let m = u64::try_from(config.mantissa).map_err(|_| Error::Parameters)?;
    let bits = match format {
        Format::Int8 => 8,
        Format::Int16 => 16,
    };
    let v = 1u64 << 31;
    let h_target = 1u64 << (bits - 1);
    let d = 1u64.checked_shl(config.shift).ok_or(Error::Arithmetic)?;
    let bias = if config.shift == 0 { 0 } else { d / 2 };
    let a = v.checked_mul(m).ok_or(Error::Arithmetic)?;
    let q = h_target.min(a.checked_add(bias).ok_or(Error::Arithmetic)? / d);
    let qd = q.checked_mul(d).ok_or(Error::Arithmetic)?;
    let left = 4 * h_target - 1;
    let right = 2 * h_target;
    field_bound(left)?;
    field_bound(right)?;
    let mut params = [0; 4];
    // Existing checked Requant has m<=65535 and shift<=62; these casts are exact.
    params[..2].copy_from_slice(&(m as u16).to_le_bytes());
    params[2] = config.shift as u8;
    params[3] = bits;
    let scalars = [d, bias, a, q, h_target, left, right].map(U160::from);
    let mut out = Record::header(1, &params, &scalars, &[], 6)?;
    let roles = [
        (2, (1u64 << 32) - 1, 2),
        (2, v, 1),
        (1, v, m),
        (2, a.max(bias), 1),
        (1, q, d),
        (2, qd.max(d - 1), 1),
    ];
    for (i, (count, a, b)) in roles.into_iter().enumerate() {
        out.column((i + 1) as u8, count, a.into(), b.into())?;
    }
    Ok(out)
}

pub(super) fn rmsnorm(function: Descriptor) -> Result<Record, Error> {
    if function.name() != "rmsnorm_q" {
        return Err(Error::Parameters);
    }
    let p = function.parameters();
    // The private checked RFC-0021 descriptor fixes this exact thirteen-byte schema.
    let [d0, d1, f, g, e, n0, n1, n2, n3, p0, p1, p2, p3] = p else {
        return Err(Error::Parameters);
    };
    let d = u16::from_le_bytes([*d0, *d1]);
    let en = u64::from(u32::from_le_bytes([*n0, *n1, *n2, *n3]));
    let ed = u64::from(u32::from_le_bytes([*p0, *p1, *p2, *p3]));
    let unit = U160::from(u64::from(d)).shl(2 * u32::from(*f))?;
    let statistic = U160::from(u64::from(d)).shl(30)?;
    let numerator = statistic.mul(ed.into())?.add(unit.mul(en.into())?)?;
    let denominator = unit.mul(ed.into())?;
    let amax = numerator.shl(46)?;
    let dmax = denominator.shl(18)?;
    let mdmax = dmax.mul(65535.into())?;
    let low = i16::from(*f) + i16::from(*g) - 2 - i16::from(*e);
    let high = i16::from(*f) + i16::from(*g) + 30 - i16::from(*e);
    let power = |n: i16| U160::from(1).shl(u32::try_from(n.max(0)).map_err(|_| Error::Arithmetic)?);
    let divisor = power(high)?;
    let bias = if high > 0 { power(high - 1)? } else { 0.into() };
    let left_factor = power(-low)?;
    let product = U160::from(1).shl(44)?;
    field_bound(131071)?;
    field_bound(65536)?;
    let scalars = [
        unit,
        statistic,
        numerator,
        denominator,
        amax,
        dmax,
        mdmax,
        divisor,
        bias,
        left_factor,
        131071.into(),
        65536.into(),
    ];
    let mut out = Record::header(2, p, &scalars, &[low, high], 11)?;
    let roles = [
        (u32::from(d), 32768.into(), 32768.into()),
        (2, statistic.max(unit), en.max(ed).into()),
        (1, numerator, U160::from(1).shl(46)?),
        (1, 65535.into(), dmax),
        (2, mdmax, 1.into()),
        (1, 32768.into(), 32768.into()),
        (1, (1u64 << 30).into(), 16384.into()),
        (2, product.max(bias), 1.into()),
        (1, 32768.into(), divisor),
        (2, divisor.mul(32768.into())?, 1.into()),
        (1, product, left_factor),
    ];
    for (i, (count, a, b)) in roles.into_iter().enumerate() {
        out.column((i + 1) as u8, count, a, b)?;
    }
    Ok(out)
}
