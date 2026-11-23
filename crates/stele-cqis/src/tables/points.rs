//! RFC-0025 execution / RFC-0021 §3: bounded definition-only point memoization.
//! A point is not a complete generated Table and cannot admit Registry data.
use super::{activation, exp, gaussian::Gaussian, Descriptor, Error, Kind};
use alloc::vec::Vec;

/// Descriptors that own a block of 65536 slots; any further one shares the last block.
/// One block for all made an activation and an exponential evict each other on every
/// shared input: 60,146 of the 62,321 certifications of an L2a window.
const BLOCKS: usize = 4;

pub(crate) struct Points {
    entries: Vec<Option<(Descriptor, i32, i32)>>,
    /// The descriptors that own a block, in order of first use.
    owners: Vec<Descriptor>,
    gaussian: Gaussian,
    #[cfg(test)]
    certified: usize,
}
impl Points {
    pub(crate) fn new() -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(BLOCKS << 16)
            .map_err(|_| Error::Capacity)?;
        entries.resize(BLOCKS << 16, None);
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(BLOCKS)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            entries,
            owners,
            gaussian: Gaussian::new(),
            #[cfg(test)]
            certified: 0,
        })
    }
    pub(crate) fn value(&mut self, d: Descriptor, t: i32) -> Result<i32, Error> {
        let block = match self.owners.iter().position(|owner| *owner == d) {
            Some(block) => block,
            None if self.owners.len() < BLOCKS => {
                self.owners.push(d);
                self.owners.len() - 1
            }
            None => BLOCKS - 1,
        };
        // Collisions only evict derived values; full descriptor/input equality is
        // required for every hit. No supplied value or digest can populate this cache.
        let slot = (block << 16) | (t as u32 as usize & 65535);
        if let Some((old, input, value)) = self.entries[slot] {
            if old == d && input == t {
                return Ok(value);
            }
        }
        #[cfg(test)]
        {
            self.certified += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Descriptors that read the same inputs do not evict each other: each point is
    /// certified once, and read again it is the certified value. A descriptor past the
    /// owned blocks shares the last one and still returns certified values.
    #[test]
    fn matches_reference_points_of_descriptors_that_share_inputs() {
        let descriptors: Vec<Descriptor> = [("sigmoid_q", 12u8), ("silu_q", 12), ("sigmoid_q", 11)]
            .into_iter()
            .chain([("silu_q", 11), ("sigmoid_q", 10)])
            .map(|(name, fraction)| Descriptor::new(name, 1, &[8, fraction]).expect("descriptor"))
            .collect();
        let inputs = [-300, -1, 0, 1, 77, 300];
        let mut points = Points::new().expect("points");
        for round in 0..2 {
            for t in inputs {
                for d in &descriptors[..BLOCKS] {
                    assert_eq!(points.value(*d, t), activation::certify(d, t));
                }
            }
            assert_eq!(points.certified, BLOCKS * inputs.len(), "round {round}");
        }
        // The fifth descriptor shares the last block: it evicts, and both stay correct.
        let (last, fifth) = (descriptors[BLOCKS - 1], descriptors[BLOCKS]);
        for d in [fifth, last, fifth] {
            assert_eq!(points.value(d, 77), activation::certify(&d, 77));
        }
        assert_eq!(points.certified, BLOCKS * inputs.len() + 3);
    }
}
