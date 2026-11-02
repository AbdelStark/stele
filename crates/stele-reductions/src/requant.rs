//! RFC-0023 §§2.1-2.4: immutable advice layout, expected frames and untrusted codec.
//! Static metadata alone authenticates no source, witness, or inference claim.
use alloc::vec::Vec;
use core::ops::Range;
use stele_cqis::{bounds, Format, Requant};
#[path = "requant_constraints.rs"]
mod constraints;
pub use constraints::Constraints;
#[path = "requant_codec.rs"]
mod codec;
pub use crate::lookup::Limits;
pub use codec::{Descriptor, Statement};

/// Failure during schema, expected descriptor or untrusted codec validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported separately supplied scalar configuration.
    Parameters(stele_cqis::Error),
    /// Actual static bound derivation failed.
    Bounds(bounds::Error),
    /// Generated record has an unexpected schema or cannot be narrowed exactly.
    Encoding,
    /// Checked row arithmetic or bounded allocation failed.
    Capacity,
    /// Invalid independently expected operation geometry or fixed parameters.
    Statement,
    /// Genuine input/advice context differs from the fixed source roster.
    SourceRoster,
    /// Cumulative padded positions, public payload or proof cap is exceeded.
    ResourceLimit,
    /// Complete untrusted wire shape or outer version/field differs.
    ProofShape,
    /// An outer arithmetic scalar has a noncanonical base limb.
    NoncanonicalField,
    /// Preserve the actual A9 shape/context cause.
    Pcs(stele_pcs::Error),
    /// Preserve the actual A5 descriptor/preflight cause.
    Lookup(crate::lookup::Error),
    /// Preserve the actual A1 descriptor cause.
    Sumcheck(stele_sumcheck::Error),
}

/// One whole-value cap, including its slack and interior Boolean carries.
#[derive(Debug)]
pub struct Block {
    cap: u64,
    value: Range<usize>,
    slack: Range<usize>,
    carry: Range<usize>,
}
impl Block {
    /// Whole integer upper bound, not independent byte maxima.
    pub fn cap(&self) -> u64 {
        self.cap
    }
    /// Little-endian value planes; a tighter cap shares the original range.
    pub fn value(&self) -> Range<usize> {
        self.value.clone()
    }
    /// Little-endian slack planes at the complete value width.
    pub fn slack(&self) -> Range<usize> {
        self.slack.clone()
    }
    /// Interior cap-addition carries; endpoints are literal zero.
    pub fn carry(&self) -> Range<usize> {
        self.carry.clone()
    }
}

/// One of the six ordered roles, read from the generated static record.
#[derive(Debug)]
pub struct Role {
    count: u32,
    bounds: [u64; 3],
    widths: [u8; 3],
    result_cap: Option<Block>,
    carries: Vec<Block>,
}
impl Role {
    /// Number of products in each column relation.
    pub fn count(&self) -> u32 {
        self.count
    }
    /// Recorded whole bounds A, C, Z.
    pub fn bounds(&self) -> [u64; 3] {
        self.bounds
    }
    /// Recorded w(A), w(C), K; high zero columns are retained.
    pub fn widths(&self) -> [u8; 3] {
        self.widths
    }
    /// Additional full-width cap when the shared result has a looser bound.
    pub fn result_cap(&self) -> Option<&Block> {
        self.result_cap.as_ref()
    }
    /// Interior column carries in order, each with its own cap block.
    pub fn carries(&self) -> &[Block] {
        &self.carries
    }
}

/// Deterministic static layout; no supplied record or mutable authority enters.
#[derive(Debug)]
pub struct Schema {
    bounds: bounds::Record,
    layout: Layout,
}
impl Schema {
    /// Validate expected parameters, derive the actual CQIS record, then read it.
    pub fn new(mantissa: u32, shift: u32, format: Format) -> Result<Self, Error> {
        let config = Requant::new(mantissa, shift).map_err(Error::Parameters)?;
        let bounds = bounds::Record::requant(config, format).map_err(Error::Bounds)?;
        let layout = read_layout(bounds.as_bytes())?;
        Ok(Self { bounds, layout })
    }
    /// Actual generated expected record, including all field-bound checks.
    pub fn bounds(&self) -> &bounds::Record {
        &self.bounds
    }
    /// Nine value blocks in order v,a,q,qd,r0,t,w0,u,z0; sign is plane zero.
    pub fn values(&self) -> &[Block] {
        &self.layout.values
    }
    /// Six roles in RFC-0022 §2.2 order, with their result and carry caps.
    pub fn roles(&self) -> &[Role] {
        &self.layout.roles
    }
    /// Three interior carries for u+s=v, after all role allocations.
    pub fn u_carries(&self) -> Range<usize> {
        self.layout.u_carries.clone()
    }
    /// L nonreserved planes, including sign.
    pub fn allocated_rows(&self) -> usize {
        self.layout.allocated
    }
    /// R power-of-two planes; [L,R) are reserved zeros.
    pub fn rows(&self) -> usize {
        self.layout.rows
    }
}

#[derive(Debug)]
struct Layout {
    params: [u8; 4],
    values: Vec<Block>,
    roles: Vec<Role>,
    u_carries: Range<usize>,
    allocated: usize,
    rows: usize,
}

fn width(cap: u64) -> usize {
    ((64 - cap.leading_zeros()) as usize).div_ceil(8).max(1)
}

fn allocate(at: &mut usize, count: usize) -> Result<Range<usize>, Error> {
    let end = at
        .checked_add(count)
        .filter(|end| *end < 2048)
        .ok_or(Error::Capacity)?;
    let range = *at..end;
    *at = end;
    Ok(range)
}

fn cap_block(at: &mut usize, cap: u64, value: Range<usize>) -> Result<Block, Error> {
    let slack = allocate(at, value.len())?;
    let carry = allocate(at, value.len().checked_sub(1).ok_or(Error::Encoding)?)?;
    Ok(Block {
        cap,
        value,
        slack,
        carry,
    })
}

fn buffer<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    Ok(out)
}

// This private reader only receives freshly generated bytes in production.
// It consumes the schema, never duplicates Record::column's bound derivation.
fn read_layout(raw: &[u8]) -> Result<Layout, Error> {
    let mut r = Reader(raw);
    r.expect(b"stele/v0.1/cqis/bounds\x01\0\0\0\x01\x04\0")?;
    let params: [u8; 4] = r.take(4)?.try_into().map_err(|_| Error::Encoding)?;
    if params[0..2] == [0, 0] || params[2] > 62 || ![8, 16].contains(&params[3]) {
        return Err(Error::Encoding);
    }
    r.expect(&[255, 255, 255, 127, 8, 7])?;
    let mut scalar = [0; 7];
    for s in &mut scalar {
        *s = r.wide()?;
    }
    r.expect(&[0, 6])?;
    let [d, h, a, q, output, _, _] = scalar;
    let caps = [
        1 << 31,
        a,
        q,
        q.checked_mul(d).ok_or(Error::Capacity)?,
        d.checked_sub(1).ok_or(Error::Encoding)?,
        a.checked_add(h).ok_or(Error::Capacity)?,
        1 << 32,
        1 << 31,
        output,
    ];
    let mut at = 1;
    let mut ranges: [Range<usize>; 9] = core::array::from_fn(|_| 0..0);
    for (range, cap) in ranges.iter_mut().zip(caps) {
        *range = allocate(&mut at, width(cap))?;
    }
    let mut values = buffer(9)?;
    for (range, cap) in ranges.into_iter().zip(caps) {
        values.push(cap_block(&mut at, cap, range)?);
    }
    let mut roles = buffer(6)?;
    for (i, (count, target)) in [(2, 6), (2, 6), (1, 1), (2, 5), (1, 3), (2, 5)]
        .into_iter()
        .enumerate()
    {
        r.expect(&[(i + 1) as u8])?;
        if r.word()? != count {
            return Err(Error::Encoding);
        }
        let bounds = [r.wide()?, r.wide()?, r.wide()?];
        let widths: [u8; 3] = r.take(3)?.try_into().map_err(|_| Error::Encoding)?;
        if widths.iter().any(|w| !(1..=20).contains(w)) {
            return Err(Error::Encoding);
        }
        r.take(widths.iter().map(|w| usize::from(*w)).sum())?;
        let shared = &values[target];
        let result_cap = if shared.cap > bounds[2] {
            // RFC-0023 §2.1: retain the shared value's ENTIRE width, even above K.
            Some(cap_block(&mut at, bounds[2], shared.value())?)
        } else {
            None
        };
        let k = usize::from(widths[2]);
        let mut carries = buffer(k - 1)?;
        if r.word()? != 0 {
            return Err(Error::Encoding);
        }
        for _ in 1..k {
            let cap = u64::from(r.word()?);
            let range = allocate(&mut at, width(cap))?;
            carries.push(cap_block(&mut at, cap, range)?);
        }
        if r.word()? != 0 {
            return Err(Error::Encoding);
        }
        r.take(8 * k)?; // Both K-word side-bound arrays remain in the actual Record.
        roles.push(Role {
            count,
            bounds,
            widths,
            result_cap,
            carries,
        });
    }
    if !r.0.is_empty() {
        return Err(Error::Encoding);
    }
    let u_carries = allocate(&mut at, 3)?;
    let rows = at.checked_next_power_of_two().ok_or(Error::Capacity)?;
    Ok(Layout {
        params,
        values,
        roles,
        u_carries,
        allocated: at,
        rows,
    })
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let raw = self.0.get(..count).ok_or(Error::Encoding)?;
        self.0 = &self.0[count..];
        Ok(raw)
    }
    fn expect(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.take(expected.len())? != expected {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn word(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    fn wide(&mut self) -> Result<u64, Error> {
        let raw = self.take(20)?;
        if raw[8..].iter().any(|v| *v != 0) {
            return Err(Error::Encoding);
        }
        Ok(u64::from_le_bytes(
            raw[..8].try_into().map_err(|_| Error::Encoding)?,
        ))
    }
}

#[cfg(test)]
#[path = "requant_tests.rs"]
mod tests;
