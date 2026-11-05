//! RFC-0025 function-bound §§1–3: complete component and source-word bounds.
use super::{term, Builder, Error, Record, Word};

/// Exponential parameters; static derivation does not admit a canonical table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exponential {
    /// Original attention context or sampling vocabulary capacity.
    pub count: u32,
    /// Domain bits, 7..=31 for product and 7..=15 otherwise.
    pub domain_bits: u8,
    /// Input fraction, in 0..=30.
    pub source_fraction: u8,
    /// Output fraction, in 0..=14.
    pub output_fraction: u8,
    /// Existing direct=0, product=1, corrected=2 representation.
    pub mode: u8,
    /// Zero for direct; otherwise the exact selected split.
    pub split: u8,
}
impl Exponential {
    pub(super) fn check(self) -> Result<(), Error> {
        if !(1..=1 << 20).contains(&self.count)
            || self.mode > 2
            || !(7..=if self.mode == 1 { 31 } else { 15 }).contains(&self.domain_bits)
            || self.source_fraction > 30
            || self.output_fraction > 14
        {
            return Err(Error::Parameters);
        }
        if (self.mode == 0 && self.split != 0)
            || (self.mode != 0
                && !(self.domain_bits.saturating_sub(15).max(1)..=self.domain_bits.min(16))
                    .contains(&self.split))
        {
            return Err(Error::Parameters);
        }
        Ok(())
    }
    pub(super) fn parameters(self) -> ([u8; 9], usize) {
        let mut raw = [0; 9];
        raw[..4].copy_from_slice(&self.count.to_le_bytes());
        raw[4..].copy_from_slice(&[
            self.domain_bits,
            self.source_fraction,
            self.output_fraction,
            self.mode,
            self.split,
        ]);
        (raw, if self.mode == 0 { 8 } else { 9 })
    }
}
/// Complete activation-table/source-word parameters, checked during derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
    /// Full FFN row width, in 1..=16384.
    pub dimension: u16,
    /// Sigmoid=0, SiLU=1, softcap=2, GeLU=3, tanh-GeLU=4.
    pub kind: u8,
    /// Input fraction, in 0..=30.
    pub source_fraction: u8,
    /// Output fraction, in 0..=14.
    pub output_fraction: u8,
    /// Positive softcap mantissa; zero for other kinds.
    pub cap_m: u16,
    /// Softcap fraction, in 0..=30; zero for other kinds.
    pub cap_f: u8,
}
fn component_scalars(out: &mut [Word], at: usize, n: u64) -> Result<(), Error> {
    let padded = n.next_power_of_two();
    out.get_mut(at..at + 6)
        .ok_or(Error::Capacity)?
        .copy_from_slice(
            &[n, padded, n - 1, padded - 1, 8 * padded, 62 + 8 * padded].map(Word::from),
        );
    Ok(())
}
fn component_columns(b: &mut Builder, n: u64) -> Result<(), Error> {
    let padded = n.next_power_of_two();
    b.column(&[term(padded - 1, 8)])?;
    b.column(&[term(8 * (padded - 1), 1), term(7, 1), term(62, 1)])
}
impl Record {
    /// Derive schema 10 for every existing exp representation and endpoint.
    pub fn exponential(p: Exponential) -> Result<Self, Error> {
        p.check()?;
        let (u, q) = (1u64 << p.domain_bits, 1u64 << p.output_fraction);
        let (high, low) = if p.mode == 0 {
            (0, 0)
        } else {
            (1u64 << (p.domain_bits - p.split), (1u64 << p.split) - 1)
        };
        let counts = if p.mode == 0 {
            [u + 1, 0, 0]
        } else {
            [high + 1, low + 1, u + 1]
        };
        let count = usize::from(p.mode) + 1;
        let n = u64::from(p.count);
        let padded = n.next_power_of_two();
        let mut scalars = [Word::from(0); 33];
        scalars[..15].copy_from_slice(
            &[
                u,
                q,
                q * q,
                q - 1,
                high,
                low,
                count as u64,
                2 * u,
                q * q + q - 1,
                q + 3,
                2 * q - 1,
                n - 1,
                padded,
                2 * padded - 1,
                62,
            ]
            .map(Word::from),
        );
        for (i, n) in counts[..count].iter().enumerate() {
            component_scalars(&mut scalars, 15 + 6 * i, *n)?;
        }
        let (params, length) = p.parameters();
        let roles = match p.mode {
            0 => 4,
            1 => 11,
            _ => 15,
        };
        let mut b = Builder::new(
            10,
            &params[..length],
            8,
            &scalars[..15 + 6 * count],
            &[],
            roles,
        )?;
        b.column(&[term(u, 1), term(u, 1)])?;
        b.column(&[term(u, 1)])?;
        if p.mode != 0 {
            b.column(&[term(high, 1u64 << p.split), term(low, 1)])?;
            b.column(&[term(q, q)])?;
            b.column(&[term(q, q)])?;
            b.column(&[term(q * q, 1), term(q - 1, 1)])?;
            b.column(&[term(q - 1, 1), term(q - 1, 1), term(1, 1)])?;
        }
        if p.mode == 2 {
            b.column(&[term(q, 1), term(3, 1)])?;
            b.column(&[term(q, 1), term(1, 1)])?;
        }
        for n in &counts[..count] {
            component_columns(&mut b, *n)?;
        }
        b.finish()
    }
    /// Derive schema 11; full table generation/admission remains mandatory.
    pub fn activation(p: Activation) -> Result<Self, Error> {
        if !(1..=16384).contains(&p.dimension)
            || p.kind > 4
            || p.source_fraction > 30
            || p.output_fraction > 14
            || (p.kind != 2 && (p.cap_m != 0 || p.cap_f != 0))
            || (p.kind == 2
                && (p.cap_m == 0 || p.cap_f > 30 || (p.cap_f > 0 && p.cap_m.is_multiple_of(2))))
        {
            return Err(Error::Parameters);
        }
        let d = u64::from(p.dimension);
        let padded = d.next_power_of_two();
        let mut scalars = [Word::from(0); 16];
        scalars[..10].copy_from_slice(
            &[
                d - 1,
                padded,
                2 * padded - 1,
                32768,
                65535,
                65536,
                98303,
                131071,
                (1 << 32) - 1,
                65535 * 65536,
            ]
            .map(Word::from),
        );
        component_scalars(&mut scalars, 10, 65536)?;
        let mut params = [0; 8];
        params[..2].copy_from_slice(&p.dimension.to_le_bytes());
        params[2..5].copy_from_slice(&[p.kind, p.source_fraction, p.output_fraction]);
        params[5..7].copy_from_slice(&p.cap_m.to_le_bytes());
        params[7] = p.cap_f;
        let mut b = Builder::new(
            11,
            &params[..if p.kind == 2 { 8 } else { 5 }],
            8,
            &scalars,
            &[],
            5,
        )?;
        b.column(&[term(65535, 1), term(32768, 1)])?;
        b.column(&[term(65535, 1), term(1, 65536)])?;
        b.column(&[term(65535, 1), term(1, 65535 * 65536)])?;
        component_columns(&mut b, 65536)?;
        b.finish()
    }
}
