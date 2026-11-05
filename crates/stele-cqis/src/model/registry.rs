//! RFC-0025 encoding §6: complete regenerated Registry with metadata checked first.
use super::{
    codec::{reserved, Writer},
    Error, Model, Rotation,
};
use crate::{functions::ManifestLayout, tables};
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/registry";
const LIMIT: usize = 1 << 20;

#[derive(Clone, Copy)]
enum Definition {
    Table(tables::Descriptor),
    Rotation(Rotation),
}
struct Slot {
    offset: usize,
    definition: Definition,
}
struct Layout {
    bytes: Vec<u8>,
    slots: Vec<Slot>,
}
impl Layout {
    fn new(model: &Model) -> Result<Self, Error> {
        let role_count = model.function_roles().count();
        let mut functions = reserved(role_count)?;
        for r in model.function_roles() {
            functions.push((r.function().identity().map_err(Error::Function)?, *r));
        }
        functions.sort_unstable_by_key(|r| r.0);
        if functions
            .windows(2)
            .any(|p| p[0].0 == p[1].0 && p[0].1 != p[1].1)
        {
            return Err(Error::RepresentationConflict);
        }
        functions.dedup_by_key(|r| r.0);
        if functions.len() > 514 {
            return Err(Error::Capacity);
        }
        let mut selections = reserved(functions.len())?;
        for (_, r) in functions {
            selections.push(r);
        }
        let manifest = ManifestLayout::new(&selections).map_err(Error::Function)?;
        if manifest.metadata().len() > 1 << 18 || manifest.data_slots().len() > 516 {
            return Err(Error::Capacity);
        }
        let layers = model.shape().layers();
        let mut rotations = reserved(usize::from(layers))?;
        for b in model.blocks() {
            if let Some(r) = b.rotation() {
                rotations.push((*blake3::hash(&r.encode()?).as_bytes(), *r));
            }
        }
        rotations.sort_unstable_by_key(|r| r.0);
        if rotations
            .windows(2)
            .any(|p| p[0].0 == p[1].0 && p[0].1 != p[1].1)
        {
            return Err(Error::Registry);
        }
        rotations.dedup_by_key(|r| r.0);
        if rotations.len() > 128 {
            return Err(Error::Capacity);
        }
        // All terms derive from checked Model/Manifest domains; the conservative
        // reservation includes each inner Rotation's full 128-byte cap.
        let capacity = PREFIX.len()
            + 42
            + 64 * role_count
            + manifest.metadata().len()
            + 33 * usize::from(layers)
            + 164 * rotations.len();
        if capacity > LIMIT {
            return Err(Error::Capacity);
        }
        let mut w = Writer::new(capacity)?;
        let mut slots = reserved(manifest.data_slots().len() + rotations.len())?;
        w.push(PREFIX)?;
        w.push(&model.identity())?;
        w.push(
            &u16::try_from(role_count)
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        )?;
        for r in model.function_roles() {
            w.push(&r.function().identity().map_err(Error::Function)?)?;
            w.push(&r.identity().map_err(Error::Function)?)?;
        }
        let manifest_start = w.position().checked_add(4).ok_or(Error::Capacity)?;
        w.blob(manifest.metadata())?;
        for (offset, d) in manifest.data_slots() {
            slots.push(Slot {
                offset: manifest_start.checked_add(*offset).ok_or(Error::Capacity)?,
                definition: Definition::Table(*d),
            });
        }
        w.push(&layers.to_le_bytes())?;
        for b in model.blocks() {
            if let Some(r) = b.rotation() {
                w.push(&[1])?;
                w.push(blake3::hash(&r.encode()?).as_bytes())?;
            } else {
                w.push(&[0])?;
            }
        }
        w.push(
            &u16::try_from(rotations.len())
                .map_err(|_| Error::Capacity)?
                .to_le_bytes(),
        )?;
        for (_, r) in rotations {
            w.blob(&r.encode()?)?;
            slots.push(Slot {
                offset: w.position(),
                definition: Definition::Rotation(r),
            });
            w.push(&[0; 32])?;
        }
        Ok(Self {
            bytes: w.finish(),
            slots,
        })
    }
    fn check_metadata(&self, raw: &[u8]) -> Result<(), Error> {
        if raw.len() != self.bytes.len() {
            return Err(Error::Registry);
        }
        let mut start = 0;
        for slot in &self.slots {
            if raw.get(start..slot.offset).ok_or(Error::Registry)?
                != self.bytes.get(start..slot.offset).ok_or(Error::Registry)?
            {
                return Err(Error::Registry);
            }
            start = slot.offset.checked_add(32).ok_or(Error::Capacity)?;
        }
        if raw.get(start..).ok_or(Error::Registry)?
            != self.bytes.get(start..).ok_or(Error::Registry)?
        {
            return Err(Error::Registry);
        }
        Ok(())
    }
    fn generate(
        mut self,
        model_identity: [u8; 32],
        supplied: Option<&[u8]>,
    ) -> Result<Registry, Error> {
        if let Some(raw) = supplied {
            self.check_metadata(raw)?;
        }
        for slot in self.slots {
            let (digest, mismatch) = match slot.definition {
                Definition::Table(d) => {
                    let table = tables::Table::generate(d).map_err(Error::Generation)?;
                    let data = table.encode().map_err(Error::Generation)?;
                    (*blake3::hash(&data).as_bytes(), Error::TableData)
                }
                Definition::Rotation(r) => (r.data_digest()?, Error::RotationData),
            };
            let end = slot.offset.checked_add(32).ok_or(Error::Capacity)?;
            if let Some(raw) = supplied {
                if raw.get(slot.offset..end) != Some(digest.as_slice()) {
                    return Err(mismatch);
                }
            }
            self.bytes
                .get_mut(slot.offset..end)
                .ok_or(Error::Registry)?
                .copy_from_slice(&digest);
        }
        let identity = *blake3::hash(&self.bytes).as_bytes();
        Ok(Registry {
            bytes: self.bytes,
            model_identity,
            identity,
        })
    }
}

/// Complete native-regenerated neural Registry, bound to one full Model identity.
/// Static Bounds, original source authority and public-MLE/proof consumers are
/// additional obligations. There is no supplied digest or table-authority hook.
#[derive(Debug, Eq, PartialEq)]
pub struct Registry {
    bytes: Vec<u8>,
    model_identity: [u8; 32],
    identity: [u8; 32],
}
impl Registry {
    /// Construct the complete canonical record by generating every unique data set.
    pub fn new(model: &Model) -> Result<Self, Error> {
        Layout::new(model)?.generate(model.identity(), None)
    }
    /// Validate all metadata before regeneration, then check every complete digest.
    /// Failure returns no partial Registry, including on full-table overflow.
    pub fn decode(model: &Model, raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        Layout::new(model)?.generate(model.identity(), Some(raw))
    }
    /// Complete validation followed by a separately expected content-identity join.
    /// This does not authenticate the expected Model/Registry hashes themselves.
    pub fn decode_expected(model: &Model, expected: &[u8; 32], raw: &[u8]) -> Result<Self, Error> {
        let registry = Self::decode(model, raw)?;
        if &registry.identity != expected {
            return Err(Error::Identity);
        }
        Ok(registry)
    }
    /// Exact canonical bytes, with all locally regenerated data digests.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Complete Registry content hash, not full cqis_id or passport authority.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Complete expected Model identity, including its numerical configuration.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// Compare with this already regenerated immutable Registry without repeating
    /// generation. All metadata and every digest byte must match exactly.
    pub fn validate_encoding(&self, raw: &[u8]) -> Result<(), Error> {
        if raw != self.bytes {
            return Err(Error::Registry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
