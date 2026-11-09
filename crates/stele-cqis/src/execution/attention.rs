//! RFC-0025 §2.4: complete-row Q/K/V scales and absolute 1024-key blocks.
use super::{
    capture::{self, put},
    copy, reserved, wide, Error, Executor,
};
use crate::{model::Rotation, numerics, row::QuantisedRow};
use alloc::vec::Vec;

impl Executor<'_> {
    pub(super) fn rotate(
        &mut self,
        r: Option<&Rotation>,
        input: &[i16],
        position: usize,
        heads: u16,
        mut w: Option<&mut capture::Rotation>,
    ) -> Result<Vec<i16>, Error> {
        let mut out = copy(input)?;
        if let Some(r) = r {
            self.rotate_pairs(r, input, &mut out, position, heads, w.as_deref_mut())?;
        }
        if let Some(w) = w {
            for v in &out {
                put(&mut w.output, i64::from(*v))?;
            }
        }
        Ok(out)
    }
    fn rotate_pairs(
        &mut self,
        r: &Rotation,
        input: &[i16],
        out: &mut [i16],
        position: usize,
        heads: u16,
        mut w: Option<&mut capture::Rotation>,
    ) -> Result<(), Error> {
        let width = usize::from(self.data.model.shape().head_width());
        for j in 0..r.width() / 2 {
            let slot = (position * usize::from(r.width() / 2) + usize::from(j)) & 65535;
            let value = match self.rotations[slot] {
                Some((old, p, k, value)) if old == *r && p == position as u32 && k == j => value,
                _ => {
                    let value = r.coefficient(position as u32, j)?;
                    self.rotations[slot] = Some((*r, position as u32, j, value));
                    value
                }
            };
            let (c, s) = (i128::from(value.0), i128::from(value.1));
            if let Some(w) = w.as_deref_mut() {
                put(&mut w.pair, u32::from(j))?;
                put(&mut w.cos, i64::from(value.0))?;
                put(&mut w.sin, i64::from(value.1))?;
            }
            for h in 0..usize::from(heads) {
                let left = h * width
                    + if r.layout() == 0 {
                        2 * usize::from(j)
                    } else {
                        usize::from(j)
                    };
                let right = left
                    + if r.layout() == 0 {
                        1
                    } else {
                        usize::from(r.width() / 2)
                    };
                let (x, y) = (i128::from(input[left]), i128::from(input[right]));
                let (a, b) = (x * c - y * s, x * s + y * c);
                let (ra, rb) = (
                    numerics::round_ratio(a, 16384)?,
                    numerics::round_ratio(b, 16384)?,
                );
                out[left] = wide(ra)?;
                out[right] = wide(rb)?;
                if let Some(w) = w.as_deref_mut() {
                    put(&mut w.left, left as u32)?;
                    put(&mut w.right, right as u32)?;
                    w.rounding.push(a, 16384, ra)?;
                    w.rounding.push(b, 16384, rb)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn attend(
        &mut self,
        layer: usize,
        query: &QuantisedRow,
        position: usize,
        keys: &[(QuantisedRow, QuantisedRow)],
        mut w: Option<&mut capture::Attention>,
    ) -> Result<Vec<i16>, Error> {
        let b = self.data.model.blocks()[layer].clone();
        let s = self.data.model.shape();
        let fractions = b.projection_fractions();
        let ep = b.exponential().function().parameters();
        let shift =
            i32::from(b.score_multiplier().1) - i32::from(fractions[0]) - i32::from(fractions[1])
                + i32::from(ep[1]);
        let width = usize::from(s.head_width());
        if position >= keys.len() {
            return Err(Error::Arithmetic);
        }
        let mut out = reserved(usize::from(s.width()))?;
        for head in 0..usize::from(s.heads()) {
            let group = head / usize::from(s.heads() / s.groups());
            let mut scores = reserved(keys.len())?;
            for (k, _) in keys {
                let dot: i32 = query.codes()[head * width..(head + 1) * width]
                    .iter()
                    .zip(&k.codes()[group * width..(group + 1) * width])
                    .map(|(a, b)| i32::from(*a) * i32::from(*b))
                    .sum();
                let product = i128::from(dot)
                    * i128::from(query.scale())
                    * i128::from(k.scale())
                    * i128::from(b.score_multiplier().0);
                let score = numerics::scaled_sum(product, shift, 0, 0, 1)?;
                if let Some(w) = w.as_deref_mut() {
                    put(&mut w.dot, i64::from(dot))?;
                    w.score.scaled((product, shift), (0, 0), 1, score)?;
                }
                scores.push(i32::try_from(score).map_err(|_| Error::Range)?);
            }
            let maximum = *scores[..=position].iter().max().ok_or(Error::Arithmetic)?;
            if let Some(w) = w.as_deref_mut() {
                put(&mut w.maximum, i64::from(maximum))?;
            }
            let mut weights = reserved(keys.len())?;
            let mut z = 0u128;
            for (i, score) in scores.iter().enumerate() {
                let weight = if i <= position {
                    self.exponential(
                        b.exponential(),
                        i64::from(*score) - i64::from(maximum),
                        w.as_deref_mut().map(|w| &mut w.exp),
                    )?
                } else {
                    0
                };
                z += weight as u128;
                weights.push(i64::from(weight));
            }
            if z == 0 {
                return Err(Error::Arithmetic);
            }
            if let Some(w) = w.as_deref_mut() {
                put(&mut w.normaliser, z)?;
            }
            for lane in 0..width {
                let (mut total, mut partial) = (0i128, 0i128);
                for (j, ((_, v), p)) in keys.iter().zip(&weights).enumerate() {
                    partial += i128::from(*p)
                        * i128::from(v.scale())
                        * i128::from(v.codes()[group * width + lane]);
                    if b.accumulation() == 1 && ((j + 1) % 1024 == 0 || j + 1 == keys.len()) {
                        let block = numerics::round_ratio(partial, 1u128 << b.drop())?;
                        if let Some(w) = w.as_deref_mut() {
                            w.block.push(partial, 1u128 << b.drop(), block)?;
                        }
                        total += i128::from(wide(block)?);
                        partial = 0;
                    }
                }
                if b.accumulation() == 0 {
                    total = partial;
                }
                let exponent = i32::from(b.attention_fraction()) - i32::from(fractions[2])
                    + i32::from(b.drop());
                // |T|<2^50 and exponent<=92, so use exact wide scratch when
                // necessary rather than truncating a normalized numerator.
                let z = u64::try_from(z).map_err(|_| Error::Arithmetic)?;
                let value = numerics::scaled_sum(total, exponent, 0, 0, z)?;
                if let Some(w) = w.as_deref_mut() {
                    put(&mut w.total, total)?;
                    w.output.scaled((total, exponent), (0, 0), z, value)?;
                }
                out.push(wide(value)?);
            }
        }
        Ok(out)
    }
}
