//! RFC-0013 A5. Stage the exact constructed CPU relation tables; the masks are embedded M31.
use super::{Buf, Device, DeviceMasked, Error, Factor};
use crate::{round::Terms, K, M31};
use stele_reductions::zk::claims::bench::Masked;

pub(crate) struct Work {
    pub values: usize,
    pub masks: usize,
    pub peak: usize,
}
impl Device {
    pub(crate) fn relation(&self, input: &Masked<K>) -> Result<(DeviceMasked<'_>, Work), Error> {
        let n = input.variables();
        let len = 1usize
            .checked_shl(n)
            .ok_or(Error::Shape("relation dimensions"))?;
        let nodes = input
            .degree()
            .checked_add(1)
            .ok_or(Error::Shape("relation degree"))?;
        let terms: Vec<_> = input
            .terms()
            .iter()
            .map(|term| (term.coefficient, term.factors.clone()))
            .collect();
        let count = input.tables().count();
        let descriptors = Terms::new(count, &terms, nodes).map_err(Error::Shape)?;
        if input.is_compact() || count == 0 || n > 30 {
            return Err(Error::Shape("relation factors"));
        }
        let mut masks = 0usize;
        for ((x, r), v) in input.tables().zip(input.vanishing()) {
            if x.len() != len
                || v.is_some_and(|v| v >= n as usize)
                || r.len() != if v.is_some() { len } else { 0 }
            {
                return Err(Error::Shape("relation mask extent"));
            }
            masks += usize::from(v.is_some());
        }
        let descriptors_bytes = 20 * count as u128
            + 4 * (descriptors.offsets.len() as u128 + descriptors.factors.len().max(1) as u128)
            + 16 * terms.len().max(1) as u128;
        let grid = self.grid((len / 2).max(1)).grid_dim.0 as u128;
        // x is already QM31. Each still-live M31 mask can overlap its old allocation with its
        // first QM31 promotion; charging every such promotion simultaneously is conservative.
        let values = 16 * len as u128 * count as u128;
        let mask_bytes = 4 * len as u128 * masks as u128;
        let peak = usize::try_from(
            values + 3 * mask_bytes + descriptors_bytes + 16 * (grid + 1) * nodes as u128,
        )
        .map_err(|_| Error::Shape("relation allocation bound"))?;
        self.require_budget(peak)?;
        let mut factors = Vec::with_capacity(count);
        for ((x, r), v) in input.tables().zip(input.vanishing()) {
            let x = Buf::Ext(self.qm31s(x)?);
            let r = if v.is_some() {
                let mut base = Vec::with_capacity(r.len());
                for &k in r {
                    if k.0 .1 != M31::ZERO || k.1 .0 != M31::ZERO || k.1 .1 != M31::ZERO {
                        return Err(Error::Value);
                    }
                    base.push(k.0 .0.as_u32());
                }
                Some(Buf::Base(self.stream.clone_htod(&base)?))
            } else {
                None
            };
            factors.push(Factor { x, r, v });
        }
        let state = self.summand(factors, &terms, descriptors, nodes, len)?;
        self.sync()?;
        Ok((
            state,
            Work {
                values: values as usize,
                masks: mask_bytes as usize,
                peak,
            },
        ))
    }
}
