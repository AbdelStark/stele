//! RFC-0021 §§2.2-2.3,4: range/rsqrt generation and complete integer-data checking.
use super::{Descriptor, Error, Reader};
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

fn rsqrt(m: u32) -> Result<i32, Error> {
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
/// Constructors currently cover the parameter-free range and rsqrt components.
/// E5-02 retains all other generators, function bytes and public MLE delivery.
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
