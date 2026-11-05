//! RFC-0025 execution / RFC-0021 §3: bounded definition-only point memoization.
//! A point is not a complete generated Table and cannot admit Registry data.
use super::{activation, exp, gaussian::Gaussian, Descriptor, Error, Kind};
use alloc::vec::Vec;

pub(crate) struct Points {
    entries: Vec<Option<(Descriptor, i32, i32)>>,
    gaussian: Gaussian,
}
impl Points {
    pub(crate) fn new() -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(65536)
            .map_err(|_| Error::Capacity)?;
        entries.resize(65536, None);
        Ok(Self {
            entries,
            gaussian: Gaussian::new(),
        })
    }
    pub(crate) fn value(&mut self, d: Descriptor, t: i32) -> Result<i32, Error> {
        // Collisions only evict derived values; full descriptor/input equality is
        // required for every hit. No supplied value or digest can populate this cache.
        let slot = t as u32 as usize & 65535;
        if let Some((old, input, value)) = self.entries[slot] {
            if old == d && input == t {
                return Ok(value);
            }
        }
        let p = d.parameters();
        let value = match d.kind {
            Kind::Silu | Kind::Sigmoid | Kind::Softcap => activation::certify(&d, t)?,
            Kind::Gelu | Kind::GeluTanh => self.gaussian.certify(&d, t)?,
            Kind::Direct | Kind::Correction => {
                if i64::from(t) < -(1i64 << p[0]) || t > 0 {
                    return Err(Error::Parameters);
                }
                let n = u64::from(t.unsigned_abs());
                let direct = exp::certify(n, p[1], p[2])?;
                if d.kind == Kind::Correction {
                    let high = exp::certify((n >> p[3]) << p[3], p[1], p[2])?;
                    let low = exp::certify(n % (1u64 << p[3]), p[1], p[2])?;
                    let correction = direct - high * low / (1i32 << p[2]);
                    if !(-1..=2).contains(&correction) {
                        return Err(Error::Interval);
                    }
                    correction
                } else {
                    direct
                }
            }
            Kind::High | Kind::Low => {
                if t < 0 || t as u32 >= d.shape().rows() {
                    return Err(Error::Parameters);
                }
                let n = if d.kind == Kind::High {
                    (t as u64) << p[3]
                } else {
                    t as u64
                };
                exp::certify(n, p[1], p[2])?
            }
            _ => return Err(Error::Parameters),
        };
        self.entries[slot] = Some((d, t, value));
        Ok(value)
    }
}
