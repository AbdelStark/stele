//! RFC-0023 §§2.1,3: deterministic integer advice, O((4+R+E)N) witness work.
//! These untrusted matrices grant no source, range, arithmetic or output authority.
use super::{buffer, Block, Error, Format, Requant, Schema};
use alloc::vec::Vec;
use stele_field::{Field, M31};

/// Canonical row-major byte matrices and real signed outputs, before registration.
#[derive(Debug)]
pub struct Witness {
    input: Vec<M31>,
    advice: Vec<M31>,
    output: Vec<i16>,
}
impl Witness {
    /// Four offset-byte rows, with zero padding to the next power of two.
    pub fn input(&self) -> &[M31] {
        &self.input
    }
    /// Complete deterministic advice cut, including all zero reserved rows.
    pub fn advice(&self) -> &[M31] {
        &self.advice
    }
    /// Exact real outputs; no padded outputs are allocated or committed.
    pub fn output(&self) -> &[i16] {
        &self.output
    }
    /// Actual retained capacities of all three owned buffers, excluding stack/allocator.
    pub fn owned_bytes(&self) -> Result<usize, Error> {
        self.input
            .capacity()
            .checked_add(self.advice.capacity())
            .and_then(|n| n.checked_mul(core::mem::size_of::<M31>()))
            .and_then(|n| {
                self.output
                    .capacity()
                    .checked_mul(core::mem::size_of::<i16>())
                    .and_then(|out| n.checked_add(out))
            })
            .ok_or(Error::Capacity)
    }
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Witness)
}
fn mul(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_mul(b).ok_or(Error::Witness)
}
fn digit(value: u64, k: usize) -> u64 {
    value.checked_shr((8 * k) as u32).unwrap_or(0) & 255
}
fn put(
    out: &mut [M31],
    n: usize,
    at: usize,
    rows: core::ops::Range<usize>,
    value: u64,
) -> Result<(), Error> {
    if rows.len() < 8 && value >> (8 * rows.len()) != 0 {
        return Err(Error::Witness);
    }
    for (k, row) in rows.enumerate() {
        out[row * n + at] = M31::from_i64(digit(value, k) as i64);
    }
    Ok(())
}
fn cap(out: &mut [M31], n: usize, at: usize, block: &Block, value: u64) -> Result<(), Error> {
    let slack = block.cap().checked_sub(value).ok_or(Error::Witness)?;
    put(out, n, at, block.value(), value)?;
    put(out, n, at, block.slack(), slack)?;
    let mut carry = 0;
    for k in 0..block.value().len() {
        let sum = add(add(digit(value, k), digit(slack, k))?, carry)?;
        if sum % 256 != digit(block.cap(), k) {
            return Err(Error::Witness);
        }
        carry = sum / 256;
        if carry > 1 {
            return Err(Error::Witness);
        }
        if k < block.carry().len() {
            out[(block.carry().start + k) * n + at] = M31::from_i64(carry as i64);
        }
    }
    if carry != 0 {
        return Err(Error::Witness);
    }
    Ok(())
}

impl Schema {
    /// Generate exact untrusted bytes for every supported parameter and int32 input.
    /// `positions` admits both full matrices, (4+R)*next_power_of_two(input.len()).
    /// Output overflow, resource failure or an invalid carry returns no partial witness.
    pub fn witness(&self, inputs: &[i32], positions: usize) -> Result<Witness, Error> {
        if inputs.is_empty() {
            return Err(Error::Statement);
        }
        let n = inputs
            .len()
            .checked_next_power_of_two()
            .ok_or(Error::Capacity)?;
        let count = self
            .rows()
            .checked_add(4)
            .and_then(|p| p.checked_mul(n))
            .ok_or(Error::Capacity)?;
        if count > positions {
            return Err(Error::ResourceLimit);
        }
        let p = self.layout.params;
        let mantissa = u64::from(u16::from_le_bytes([p[0], p[1]]));
        let config = Requant::new(mantissa as u32, u32::from(p[2])).map_err(Error::Parameters)?;
        let format = if p[3] == 8 {
            Format::Int8
        } else {
            Format::Int16
        };
        let mut output = buffer(inputs.len())?;
        for acc in inputs {
            output.push(config.apply(*acc, format).map_err(Error::Parameters)?);
        }
        let d = 1u64 << p[2];
        let h = if p[2] == 0 { 0 } else { d / 2 };
        let target = 1u64 << (p[3] - 1);
        let mut input = buffer(4 * n)?;
        input.resize(4 * n, M31::from_i64(0));
        let mut advice = buffer(self.rows() * n)?;
        advice.resize(self.rows() * n, M31::from_i64(0));
        for (at, acc) in inputs.iter().enumerate() {
            let offset = (i64::from(*acc) + (1 << 31)) as u64;
            let v = i64::from(*acc).unsigned_abs();
            let s = u64::from(*acc < 0);
            let a = mul(v, mantissa)?;
            let t = add(a, h)?;
            let q = t / d;
            let qd = mul(q, d)?;
            let values = [
                v,
                a,
                q,
                qd,
                t - qd,
                t,
                add(1 << 31, v)?,
                v.checked_sub(s).ok_or(Error::Witness)?,
                add(target - 1, s)?.checked_sub(q).ok_or(Error::Witness)?,
            ];
            put(&mut input, n, at, 0..4, offset)?;
            advice[at] = M31::from_i64(s as i64);
            for (block, value) in self.values().iter().zip(values) {
                cap(&mut advice, n, at, block, value)?;
            }
            let pairs: [&[(u64, u64)]; 6] = [
                &[(offset, 1), (v, 2 * s)],
                &[(1 << 31, 1), (v, 1)],
                &[(v, mantissa)],
                &[(a, 1), (h, 1)],
                &[(q, d)],
                &[(qd, 1), (t - qd, 1)],
            ];
            for ((role, pairs), result) in self
                .roles()
                .iter()
                .zip(pairs)
                .zip([values[6], values[6], a, t, qd, t])
            {
                if let Some(block) = role.result_cap() {
                    cap(&mut advice, n, at, block, result)?;
                }
                let [wa, wb, columns] = role.widths().map(usize::from);
                let mut carry = 0;
                for k in 0..columns {
                    let mut sum = carry;
                    for (left, right) in pairs {
                        for i in 0..wa {
                            if let Some(j) = k.checked_sub(i).filter(|j| *j < wb) {
                                sum = add(sum, mul(digit(*left, i), digit(*right, j))?)?;
                            }
                        }
                    }
                    let residual = sum.checked_sub(digit(result, k)).ok_or(Error::Witness)?;
                    if residual % 256 != 0 {
                        return Err(Error::Witness);
                    }
                    carry = residual / 256;
                    if let Some(block) = role.carries().get(k) {
                        cap(&mut advice, n, at, block, carry)?;
                    }
                }
                if carry != 0 {
                    return Err(Error::Witness);
                }
            }
            let mut carry = 0;
            for k in 0..4 {
                let sum = add(add(digit(values[7], k), if k == 0 { s } else { 0 })?, carry)?;
                if sum % 256 != digit(v, k) {
                    return Err(Error::Witness);
                }
                carry = sum / 256;
                if carry > 1 {
                    return Err(Error::Witness);
                }
                if k < 3 {
                    advice[(self.u_carries().start + k) * n + at] = M31::from_i64(carry as i64);
                }
            }
            if carry != 0 {
                return Err(Error::Witness);
            }
        }
        Ok(Witness {
            input,
            advice,
            output,
        })
    }
}

#[cfg(test)]
#[path = "requant_witness_tests.rs"]
mod tests;
