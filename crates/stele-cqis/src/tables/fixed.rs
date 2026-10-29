//! RFC-0021 §§2.2-2.3,4: range/rsqrt generation and complete integer-data checking.
use super::{activation, exp, gaussian::Gaussian, Descriptor, Error, Kind, Reader};
use alloc::vec::Vec;
use core::mem::size_of;

const PREFIX: &[u8] = b"stele/v0.1/table/data";
const HEADER_LENGTH: usize = PREFIX.len() + 32 + 9;

fn reserved<T>(length: usize) -> Result<Vec<T>, Error> {
    length
        .checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::Capacity)?;
    Ok(values)
}

fn cells(d: &Descriptor, padded: bool) -> Result<usize, Error> {
    let shape = d.shape();
    let rows = if padded { shape.padded() } else { shape.rows() };
    usize::try_from(rows)
        .map_err(|_| Error::Capacity)?
        .checked_mul(usize::from(shape.columns()))
        .ok_or(Error::Capacity)
}

fn zero_entries(d: &Descriptor) -> Result<Vec<i32>, Error> {
    let length = cells(d, true)?;
    let mut values = reserved(length)?;
    // The exact capacity is reserved before initialization; resize cannot allocate.
    values.resize(length, 0);
    Ok(values)
}

pub(super) fn rsqrt(m: u32) -> Result<i32, Error> {
    if !(16384..65536).contains(&m) {
        return Err(Error::Parameters);
    }
    // RFC-0021 §2.3: floor sqrt followed by the exact half-away threshold.
    // The supported mantissa interval makes all threshold products < 2^47.
    let m = u64::from(m);
    let mut b = ((1u64 << 42) / m).isqrt();
    let odd = b
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or(Error::Parameters)?;
    let threshold = odd
        .checked_mul(odd)
        .and_then(|v| v.checked_mul(m))
        .ok_or(Error::Parameters)?;
    if (1u64 << 44) >= threshold {
        b = b.checked_add(1).ok_or(Error::Parameters)?;
    }
    i32::try_from(b).map_err(|_| Error::Parameters)
}

/// Immutable definition-generated integer rows with canonical zero padding.
///
/// Constructors cover every registered component under RFC-0021 §2.
/// No raw-row constructor, table-truth callback or configuration authority exists.
/// ```compile_fail
/// use stele_cqis::tables::Table;
/// let table = Table::range(8).unwrap();
/// table.entries()[0] = 1;
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Table {
    descriptor: Descriptor,
    entries: Vec<i32>,
}

impl Table {
    /// Generate a complete registered component from checked metadata.
    /// This always evaluates the definition; no supplied rows or digest are trusted.
    pub fn generate(descriptor: Descriptor) -> Result<Self, Error> {
        match descriptor.kind {
            Kind::High | Kind::Low | Kind::Direct | Kind::Correction => {
                Self::exponential(descriptor)
            }
            Kind::Sigmoid | Kind::Silu | Kind::Softcap | Kind::Gelu | Kind::GeluTanh => {
                Self::activation(descriptor)
            }
            Kind::Rsqrt => Self::rsqrt(),
            Kind::Range8 => Self::range(8),
            Kind::Range12 => Self::range(12),
            Kind::Range16 => Self::range(16),
        }
    }

    /// Generate every signed-int16 input for any registered activation component.
    /// Any uncertified or overflowing entry rejects the entire table.
    pub fn activation(descriptor: Descriptor) -> Result<Self, Error> {
        if !matches!(
            descriptor.kind,
            Kind::Sigmoid | Kind::Silu | Kind::Softcap | Kind::Gelu | Kind::GeluTanh
        ) {
            return Err(Error::Parameters);
        }
        let mut entries = zero_entries(&descriptor)?;
        let mut gaussian = Gaussian::new();
        for (i, row) in entries.chunks_exact_mut(2).enumerate() {
            let t = i32::try_from(i)
                .map_err(|_| Error::Capacity)?
                .checked_sub(32768)
                .ok_or(Error::Interval)?;
            row[0] = t;
            row[1] = if matches!(descriptor.kind, Kind::Gelu | Kind::GeluTanh) {
                gaussian.certify(&descriptor, t)?
            } else {
                activation::certify(&descriptor, t)?
            };
        }
        Ok(Self {
            descriptor,
            entries,
        })
    }

    /// Generate a complete high, low, direct or correction exponential component.
    pub fn exponential(descriptor: Descriptor) -> Result<Self, Error> {
        let kind = descriptor.kind;
        if !matches!(
            kind,
            Kind::High | Kind::Low | Kind::Direct | Kind::Correction
        ) {
            return Err(Error::Parameters);
        }
        let p = descriptor.parameters();
        // Correction depends on exactly these two complete components; recursion
        // ends at high/low and cannot be selected by a callback or supplied graph.
        let base = if kind == Kind::Correction {
            Some((
                Self::exponential(Descriptor::new("exp_q/hi", 1, p)?)?,
                Self::exponential(Descriptor::new("exp_q/lo", 1, p)?)?,
            ))
        } else {
            None
        };
        let mut entries = zero_entries(&descriptor)?;
        let rows = usize::try_from(descriptor.shape().rows()).map_err(|_| Error::Capacity)?;
        for (i, row) in entries.chunks_exact_mut(2).take(rows).enumerate() {
            let i = u64::try_from(i).map_err(|_| Error::Capacity)?;
            let n = match kind {
                Kind::High => i.checked_shl(u32::from(p[3])).ok_or(Error::Parameters)?,
                Kind::Low => i,
                _ => (1u64 << p[0]).checked_sub(i).ok_or(Error::Parameters)?,
            };
            row[0] = if matches!(kind, Kind::Direct | Kind::Correction) {
                i32::try_from(n)
                    .map_err(|_| Error::Parameters)?
                    .checked_neg()
                    .ok_or(Error::Parameters)?
            } else {
                i32::try_from(i).map_err(|_| Error::Parameters)?
            };
            let direct = exp::certify(n, p[1], p[2])?;
            row[1] = if let Some((high, low)) = &base {
                let a = i64::from(high.output(n >> p[3])?);
                let b = i64::from(low.output(n % (1u64 << p[3]))?);
                let product = a.checked_mul(b).ok_or(Error::Interval)? / (1i64 << p[2]);
                let correction = i64::from(direct)
                    .checked_sub(product)
                    .ok_or(Error::Interval)?;
                if !(-1..=2).contains(&correction) {
                    return Err(Error::Interval);
                }
                i32::try_from(correction).map_err(|_| Error::Interval)?
            } else {
                direct
            };
        }
        Ok(Self {
            descriptor,
            entries,
        })
    }

    fn output(&self, row: u64) -> Result<i32, Error> {
        if row >= u64::from(self.descriptor.shape().rows()) {
            return Err(Error::Interval);
        }
        let index = usize::try_from(row)
            .map_err(|_| Error::Capacity)?
            .checked_mul(2)
            .and_then(|i| i.checked_add(1))
            .ok_or(Error::Capacity)?;
        self.entries.get(index).copied().ok_or(Error::Interval)
    }

    /// Generate every value of a registered range_8, range_12 or range_16 table.
    pub fn range(bits: u8) -> Result<Self, Error> {
        let name = match bits {
            8 => "range_8",
            12 => "range_12",
            16 => "range_16",
            _ => return Err(Error::Parameters),
        };
        let descriptor = Descriptor::new(name, 1, &[])?;
        let mut entries = zero_entries(&descriptor)?;
        for (i, entry) in entries.iter_mut().enumerate() {
            *entry = i32::try_from(i).map_err(|_| Error::Parameters)?;
        }
        Ok(Self {
            descriptor,
            entries,
        })
    }

    /// Generate all 49,152 certified rsqrt pairs followed by canonical zero rows.
    pub fn rsqrt() -> Result<Self, Error> {
        let descriptor = Descriptor::new("rsqrt_q", 1, &[])?;
        let mut entries = zero_entries(&descriptor)?;
        let rows = usize::try_from(descriptor.shape().rows()).map_err(|_| Error::Capacity)?;
        for (i, row) in entries.chunks_exact_mut(2).take(rows).enumerate() {
            let m = u32::try_from(i)
                .map_err(|_| Error::Parameters)?
                .checked_add(16384)
                .ok_or(Error::Parameters)?;
            row[0] = i32::try_from(m).map_err(|_| Error::Parameters)?;
            row[1] = rsqrt(m)?;
        }
        Ok(Self {
            descriptor,
            entries,
        })
    }

    /// The immutable expected component definition.
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Complete row-major signed integer entries, including canonical padding.
    pub fn entries(&self) -> &[i32] {
        &self.entries
    }

    fn encoded_length(&self) -> Result<usize, Error> {
        let count = cells(&self.descriptor, true)?;
        if count != self.entries.len() {
            return Err(Error::Shape);
        }
        count
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(HEADER_LENGTH))
            .ok_or(Error::Capacity)
    }

    /// Canonical complete integer-data bytes. Allocation failure returns no prefix.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = self.encoded_length()?;
        let identity = self.descriptor.identity()?;
        let shape = self.descriptor.shape();
        let mut bytes = reserved(length)?;
        // Reservation covers the whole result, including all padded tuples.
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&identity);
        bytes.extend_from_slice(&shape.rows().to_le_bytes());
        bytes.extend_from_slice(&shape.padded().to_le_bytes());
        bytes.push(shape.columns());
        for value in &self.entries {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Validate complete bytes against this generated definition without allocation.
    /// A matching descriptor/hash alone cannot authorize an altered integer row.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if raw.len() != self.encoded_length()? {
            return Err(Error::Length);
        }
        let mut reader = Reader { remaining: raw };
        if reader.take(PREFIX.len())? != PREFIX {
            return Err(Error::DataHeader);
        }
        if reader.take(32)? != self.descriptor.identity()? {
            return Err(Error::Identity);
        }
        let shape = self.descriptor.shape();
        if reader.take(4)? != shape.rows().to_le_bytes()
            || reader.take(4)? != shape.padded().to_le_bytes()
            || reader.take(1)? != [shape.columns()]
        {
            return Err(Error::Shape);
        }
        let real_cells = cells(&self.descriptor, false)?;
        for (i, encoded) in reader.remaining.chunks_exact(4).enumerate() {
            let value = i32::from_le_bytes(encoded.try_into().map_err(|_| Error::Encoding)?);
            let expected = self.entries.get(i).ok_or(Error::Shape)?;
            if value != *expected {
                return Err(if i >= real_cells {
                    Error::Padding
                } else {
                    Error::Entry
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_impossible_owned_capacity_before_initialization() {
        assert_eq!(reserved::<i32>(usize::MAX), Err(Error::Capacity));
        assert_eq!(reserved::<u8>(usize::MAX), Err(Error::Capacity));
        assert!(reserved::<i32>(0).expect("empty reservation").is_empty());
    }

    #[test]
    fn rejects_out_of_domain_rsqrt_mantissas() {
        for m in [0, 16383, 65536, u32::MAX] {
            assert_eq!(rsqrt(m), Err(Error::Parameters));
        }
    }
}
