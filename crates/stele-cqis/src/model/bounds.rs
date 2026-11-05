//! RFC-0025 collection §§1–4: complete ordered static Bounds from three checked inputs.
use super::{Error, Model, Registry, Scales};
use crate::bounds::arithmetic;
mod parameters;
mod records;
use parameters::Context;
use records::records;

const PREFIX: &[u8] = b"stele/v0.1/cqis/bounds";
const LIMIT: u64 = 1 << 29;

impl From<arithmetic::Error> for Error {
    fn from(error: arithmetic::Error) -> Self {
        Self::ArithmeticBounds(error)
    }
}

/// Completed static collection, retaining its identities without buffering its bytes.
/// All records have been derived, and any supplied stream has been exhausted.
/// These content joins do not authenticate source ownership or admit a proof.
/// ```compile_fail
/// fn change(b: &mut stele_cqis::model::Bounds) { b.record_count = 0; }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bounds {
    model_identity: [u8; 32],
    scales_identity: [u8; 32],
    registry_identity: [u8; 32],
    identity: [u8; 32],
    byte_length: u64,
    record_count: u16,
}
impl Bounds {
    /// Derive and hash every prescribed slot from complete validated inputs.
    pub fn new(model: &Model, scales: &Scales, registry: &Registry) -> Result<Self, Error> {
        Self::derive(model, scales, registry, |_| Ok(()))
    }

    /// Emit the header, then each ordinal/length and complete record in order.
    /// A failed sink may contain a prefix; only `Ok` returns a completed Bounds.
    /// Record storage is bounded by one 131072-byte arithmetic record.
    pub fn write_to<E>(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        mut write: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Self, Error> {
        Self::derive(model, scales, registry, |part| {
            write(part).map_err(|_| Error::Write)
        })
    }

    /// Compare every byte with its independently derived expected slot; require EOF.
    pub fn decode(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        mut raw: &[u8],
    ) -> Result<Self, Error> {
        if raw.len() as u64 > LIMIT {
            return Err(Error::Capacity);
        }
        let bounds = Self::derive(model, scales, registry, |part| {
            if raw.get(..part.len()) != Some(part) {
                return Err(Error::Bounds);
            }
            raw = &raw[part.len()..];
            Ok(())
        })?;
        if !raw.is_empty() {
            return Err(Error::Bounds);
        }
        Ok(bounds)
    }

    /// Validate the complete frame before checking its independently expected identity.
    pub fn decode_expected(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        expected: &[u8; 32],
        raw: &[u8],
    ) -> Result<Self, Error> {
        let bounds = Self::decode(model, scales, registry, raw)?;
        if &bounds.identity != expected {
            return Err(Error::Identity);
        }
        Ok(bounds)
    }

    /// Validate a stream with a declared byte length, allowing short reads.
    /// Check the cap before any read, compare every slot, then probe exact EOF.
    pub fn read_from<E>(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        length: u64,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        if length > LIMIT {
            return Err(Error::Capacity);
        }
        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        let bounds = Self::derive(model, scales, registry, |mut part| {
            remaining = remaining
                .checked_sub(part.len() as u64)
                .ok_or(Error::Bounds)?;
            while !part.is_empty() {
                let offered = part.len().min(buffer.len());
                let n = read(&mut buffer[..offered]).map_err(|_| Error::Read)?;
                if n > offered {
                    return Err(Error::Read);
                }
                if n == 0 || buffer[..n] != part[..n] {
                    return Err(Error::Bounds);
                }
                part = &part[n..];
            }
            Ok(())
        })?;
        if remaining != 0 {
            return Err(Error::Bounds);
        }
        match read(&mut buffer[..1]).map_err(|_| Error::Read)? {
            0 => Ok(bounds),
            1 => Err(Error::Bounds),
            _ => Err(Error::Read),
        }
    }

    fn derive(
        model: &Model,
        scales: &Scales,
        registry: &Registry,
        mut emit: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        // RFC-0025 collection §1: only complete typed inputs authorize derivation.
        if scales.model_identity() != model.identity()
            || registry.model_identity() != model.identity()
        {
            return Err(Error::Identity);
        }
        let shape = model.shape();
        let sampled = u16::from(model.decoding().sampling().is_some());
        let count = match shape.family() {
            0 => 39 * shape.layers() + 10 + 3 * sampled,
            1 => 36 * shape.layers() + 9 + 3 * sampled,
            _ => return Err(Error::Shape),
        };
        let mut header = [0; PREFIX.len() + 98];
        header[..PREFIX.len()].copy_from_slice(PREFIX);
        for (i, id) in [model.identity(), scales.identity(), registry.identity()]
            .iter()
            .enumerate()
        {
            let start = PREFIX.len() + 32 * i;
            header[start..start + 32].copy_from_slice(id);
        }
        header[PREFIX.len() + 96..].copy_from_slice(&count.to_le_bytes());
        let mut hash = blake3::Hasher::new();
        hash.update(&header);
        emit(&header)?;
        let mut length = header.len() as u64;
        let mut ordinal = 0u16;
        records(&Context { model, scales }, |record| {
            if ordinal >= count {
                return Err(Error::Bounds);
            }
            let raw = record.as_bytes();
            let n = u32::try_from(raw.len()).map_err(|_| Error::Capacity)?;
            length = length
                .checked_add(6 + u64::from(n))
                .filter(|v| *v <= LIMIT)
                .ok_or(Error::Capacity)?;
            let mut frame = [0u8; 6];
            frame[..2].copy_from_slice(&ordinal.to_le_bytes());
            frame[2..].copy_from_slice(&n.to_le_bytes());
            emit(&frame)?;
            emit(raw)?;
            hash.update(&frame);
            hash.update(raw);
            ordinal += 1;
            Ok(())
        })?;
        if ordinal != count {
            return Err(Error::Bounds);
        }
        Ok(Self {
            model_identity: model.identity(),
            scales_identity: scales.identity(),
            registry_identity: registry.identity(),
            identity: *hash.finalize().as_bytes(),
            byte_length: length,
            record_count: count,
        })
    }

    /// Identity of the complete Model used for every parameter source.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// Identity retaining every original channel mantissa, including nonmaxima.
    pub fn scales_identity(&self) -> [u8; 32] {
        self.scales_identity
    }
    /// Identity of the complete natively regenerated Registry.
    pub fn registry_identity(&self) -> [u8; 32] {
        self.registry_identity
    }
    /// BLAKE3 of the complete canonical collection frame.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Complete encoded size, including header and each slot's framing.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    /// Number of prescribed physical and arithmetic slots, including repetitions.
    pub fn record_count(&self) -> u16 {
        self.record_count
    }
}

#[cfg(test)]
mod tests;
