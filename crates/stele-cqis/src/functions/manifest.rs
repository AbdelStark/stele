//! RFC-0021 §4: exact sorted component closure and regenerated canonical data digests.
use super::{tables, Error, Representation};
use alloc::vec::Vec;
use core::mem::size_of;

const PREFIX: &[u8] = b"stele/v0.1/cqis/functions";
type Component = ([u8; 32], tables::Descriptor);

fn count(length: usize) -> Result<u32, Error> {
    u32::try_from(length).map_err(|_| Error::Capacity)
}

fn reserved<T>(length: usize) -> Result<Vec<T>, Error> {
    length
        .checked_mul(size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(Error::Capacity)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| Error::Capacity)?;
    Ok(result)
}

fn add_length(total: &mut usize, length: usize) -> Result<(), Error> {
    *total = total.checked_add(length).ok_or(Error::Capacity)?;
    Ok(())
}

fn append(output: &mut Vec<u8>, total: usize, part: &[u8]) -> Result<(), Error> {
    let end = output
        .len()
        .checked_add(part.len())
        .ok_or(Error::Capacity)?;
    if end > total || total > output.capacity() {
        return Err(Error::Capacity);
    }
    // The complete length was reserved before the first append; no growth allocates.
    output.extend_from_slice(part);
    Ok(())
}

fn sized(output: &mut Vec<u8>, total: usize, part: &[u8]) -> Result<(), Error> {
    let length = u16::try_from(part.len()).map_err(|_| Error::Capacity)?;
    append(output, total, &length.to_le_bytes())?;
    append(output, total, part)
}

fn deduplicate(components: &mut Vec<Component>) -> Result<(), Error> {
    components.sort_unstable_by_key(|entry| entry.0);
    let mut write = 0usize;
    for read in 0..components.len() {
        let entry = components[read];
        if write > 0 && components[write - 1].0 == entry.0 {
            if components[write - 1].1 != entry.1 {
                return Err(Error::IdentityCollision);
            }
        } else {
            // write <= read < len; only the already-visited prefix is overwritten.
            components[write] = entry;
            write += 1;
        }
    }
    components.truncate(write);
    count(write)?;
    Ok(())
}

/// Immutable complete expected record, constructed only by regenerating tables.
/// It is a function set, not operation order, a full cqis_id preimage or a passport.
/// ```compile_fail
/// use stele_cqis::functions::Manifest;
/// let mut m = Manifest::new(&[]).unwrap();
/// m.bytes[0] = 0;
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Manifest {
    bytes: Vec<u8>,
}

impl Manifest {
    /// Derive the complete closure from verifier-owned selections and regenerate
    /// every component data digest. Any failure returns no partial record and
    /// preserves the borrowed selections. No raw-row or table-authority hook exists.
    pub fn new(expected: &[Representation]) -> Result<Self, Error> {
        let function_count = count(expected.len())?;
        let mut functions = reserved(expected.len())?;
        for r in expected {
            functions.push((r.function().identity()?, *r));
        }
        functions.sort_unstable_by_key(|entry| entry.0);
        if functions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::DuplicateFunction);
        }
        let maximum_components = expected.len().checked_mul(3).ok_or(Error::Capacity)?;
        let mut components = reserved(maximum_components)?;
        for (_, r) in &functions {
            for d in r.components() {
                components.push((d.identity().map_err(Error::Table)?, *d));
            }
        }
        deduplicate(&mut components)?;
        let component_count = count(components.len())?;
        let mut length = PREFIX.len();
        add_length(&mut length, 8)?; // function count and component count
        for (_, r) in &functions {
            add_length(&mut length, 4)?;
            add_length(&mut length, r.function().encode()?.as_bytes().len())?;
            add_length(&mut length, r.encode()?.as_bytes().len())?;
        }
        for (_, d) in &components {
            add_length(&mut length, 2 + 32)?;
            add_length(
                &mut length,
                d.encode().map_err(Error::Table)?.as_bytes().len(),
            )?;
        }
        let mut bytes = reserved(length)?;
        append(&mut bytes, length, PREFIX)?;
        append(&mut bytes, length, &function_count.to_le_bytes())?;
        for (_, r) in functions {
            sized(&mut bytes, length, r.function().encode()?.as_bytes())?;
            sized(&mut bytes, length, r.encode()?.as_bytes())?;
        }
        append(&mut bytes, length, &component_count.to_le_bytes())?;
        for (_, d) in components {
            let table = tables::Table::generate(d).map_err(Error::Table)?;
            let data = table.encode().map_err(Error::Table)?;
            sized(
                &mut bytes,
                length,
                d.encode().map_err(Error::Table)?.as_bytes(),
            )?;
            append(&mut bytes, length, blake3::hash(&data).as_bytes())?;
        }
        if bytes.len() != length {
            return Err(Error::Manifest);
        }
        Ok(Self { bytes })
    }

    /// Exact canonical bytes, including all regenerated component data digests.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Compare the entire supplied record with this regenerated expected set.
    /// Supplied counts, table hashes or representations never grant authority.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if raw != self.as_bytes() {
            return Err(Error::Manifest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_capacity_before_allocation_or_partial_append() {
        assert_eq!(reserved::<Representation>(usize::MAX), Err(Error::Capacity));
        if let Ok(overflow) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(count(overflow), Err(Error::Capacity));
        }
        assert_eq!(count(0), Ok(0));
        let mut total = usize::MAX;
        assert_eq!(add_length(&mut total, 1), Err(Error::Capacity));
        assert_eq!(total, usize::MAX);
        let mut output = reserved(1).expect("capacity");
        append(&mut output, 1, &[7]).expect("one byte");
        assert_eq!(append(&mut output, 1, &[8]), Err(Error::Capacity));
        assert_eq!(output, [7]);
    }

    #[test]
    fn rejects_conflicting_descriptors_in_internal_collision_detection() {
        let a = tables::Descriptor::new("range_8", 1, &[]).expect("a");
        let b = tables::Descriptor::new("range_12", 1, &[]).expect("b");
        // Exercise collision rejection with explicit internal records. Public
        // construction derives these identities itself; no injection API exists.
        let mut records = alloc::vec![([0; 32], a), ([0; 32], b)];
        assert_eq!(deduplicate(&mut records), Err(Error::IdentityCollision));
    }
}
