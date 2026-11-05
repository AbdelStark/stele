//! RFC-0025 source architecture §§1–4: original config semantics and full joins.
use super::{json::Budget, Error, SourcePackage};
use crate::model::{codec::Writer, Model, Rotation, Shape};
use alloc::vec::Vec;
mod derive;
mod json;
mod number;
mod roles;

const LIMIT: usize = 1 << 20;
const ARCH: &[u8] = b"stele/v0.1/cqis/source-architecture";
const CONFIG: &[u8] = b"stele/v0.1/cqis/source-config";

/// Exact normalized configuration metadata, without source or proof authority.
/// Only SourceConfig joins this derivation to authenticated bytes and Model/Map.
/// ```compile_fail
/// fn change(a: &mut stele_cqis::model::Architecture) { a.bos = 0; }
/// ```
pub struct Architecture {
    layout: u8,
    shape: Shape,
    epsilon: (u32, u32),
    rotation: Option<Rotation>,
    bos: u32,
    pad: Option<u32>,
    eos: Vec<u32>,
}
impl Architecture {
    /// Parse the full original JSON under an explicitly expected layout. This
    /// metadata-only constructor does not authenticate its supplied byte slice.
    /// The budget conservatively charges requested tree/string/numeric storage,
    /// including freed temporaries. Borrowed input and allocator overhead are separate.
    pub fn derive(layout: u8, raw: &[u8], max_metadata_bytes: usize) -> Result<Self, Error> {
        Self::with_budget(layout, raw, &mut Budget::new(max_metadata_bytes))
    }
    fn with_budget(layout: u8, raw: &[u8], budget: &mut Budget) -> Result<Self, Error> {
        if layout > 2 {
            return Err(Error::SourceLayout);
        }
        derive::derive(layout, &json::parse(raw, budget)?, budget)
    }
    fn capacity(&self) -> usize {
        256 + 4 * self.eos.len()
    }
    /// Complete canonical Architecture frame, with full sorted EOS and rotation.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(self.capacity())?;
        w.push(ARCH)?;
        w.push(&[self.layout])?;
        w.push(&self.shape.encode())?;
        w.push(&self.epsilon.0.to_le_bytes())?;
        w.push(&self.epsilon.1.to_le_bytes())?;
        if let Some(rotation) = self.rotation {
            w.blob(&rotation.encode()?)?;
        } else {
            w.blob(&[])?;
        }
        w.push(&self.bos.to_le_bytes())?;
        w.push(&[u8::from(self.pad.is_some())])?;
        if let Some(pad) = self.pad {
            w.push(&pad.to_le_bytes())?;
        }
        w.push(&(self.eos.len() as u32).to_le_bytes())?;
        for id in &self.eos {
            w.push(&id.to_le_bytes())?;
        }
        Ok(w.finish())
    }
    /// Bare GPT-2=0, prefixed GPT-2=1, split-half HF Llama=2.
    pub fn layout(&self) -> u8 {
        self.layout
    }
    /// Full source geometry, including complete configured context capacity.
    pub fn shape(&self) -> Shape {
        self.shape
    }
    /// Exact positive reduced u32 normalization epsilon.
    pub fn epsilon(&self) -> (u32, u32) {
        self.epsilon
    }
    /// Complete source rotation, absent for GPT-2.
    pub fn rotation(&self) -> Option<&Rotation> {
        self.rotation.as_ref()
    }
    /// Configured BOS id; no automatic insertion is implied.
    pub fn bos(&self) -> u32 {
        self.bos
    }
    /// Optional pad id; absent/null config values normalize to None.
    pub fn pad(&self) -> Option<u32> {
        self.pad
    }
    /// Complete nonempty sorted distinct EOS ids; generation policy is separate.
    pub fn eos(&self) -> &[u32] {
        &self.eos
    }
}

/// Derived SourceConfig from a fully checked original SourcePackage and Model.
/// No opaque digest or supplied Architecture can construct this binding.
/// Expected passport authority, conversion and proof admission remain separate.
/// ```compile_fail
/// fn change(c: &mut stele_cqis::model::SourceConfig) { c.raw.clear(); }
/// ```
pub struct SourceConfig {
    architecture: Architecture,
    raw: Vec<u8>,
    identity: [u8; 32],
}
impl SourceConfig {
    /// Revalidate the config's original chunks, derive all architecture fields,
    /// and check Model's complete shape/norms/rotations and every source role.
    /// Package construction has already verified every exact auxiliary file.
    /// The budget includes the original JSON buffer, parser allocations and both
    /// output frames; one bounded snapshot read buffer and allocator overhead are separate.
    pub fn read_from<E>(
        model: &Model,
        package: &SourcePackage<'_>,
        layout: u8,
        max_metadata_bytes: usize,
        mut read_at: impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        if layout > 2 {
            return Err(Error::SourceLayout);
        }
        let file = package.assets().config();
        let length = usize::try_from(file.length()).map_err(|_| Error::Capacity)?;
        if length > LIMIT {
            return Err(Error::Capacity);
        }
        let mut budget = Budget::new(max_metadata_bytes);
        let mut raw = budget.bytes(length)?;
        let view = package.asset(file.name()).ok_or(Error::Assets)?;
        let mut at = 0;
        while at < length {
            let chunk = view.chunk(at as u64, &mut read_at)?;
            let end = at + chunk.as_bytes().len();
            raw[at..end].copy_from_slice(chunk.as_bytes());
            at = end;
        }
        let architecture = Architecture::with_budget(layout, &raw, &mut budget)?;
        roles::check(&architecture, model, package.source_map())?;
        budget.spend(architecture.capacity() + 128)?;
        let frame = architecture.encode()?;
        let capacity = CONFIG.len() + 96 + 4 + frame.len();
        if capacity > LIMIT {
            return Err(Error::Capacity);
        }
        budget.spend(capacity)?;
        let mut w = Writer::new(capacity)?;
        w.push(CONFIG)?;
        w.push(&model.identity())?;
        w.push(&package.source_map().identity())?;
        w.push(&package.assets().identity())?;
        w.blob(&frame)?;
        let raw = w.finish();
        let identity = *blake3::hash(&raw).as_bytes();
        Ok(Self {
            architecture,
            raw,
            identity,
        })
    }
    /// Compare the entire independently expected SourceConfig frame, including
    /// counts and fields. A supplied digest alone never establishes this join.
    pub fn verify(&self, expected: &[u8]) -> Result<(), Error> {
        if self.raw != expected {
            return Err(Error::SourceConfig);
        }
        Ok(())
    }
    /// Complete derived architecture, bound to this Model/Map/Assets triple.
    pub fn architecture(&self) -> &Architecture {
        &self.architecture
    }
    /// Complete canonical SourceConfig bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
    /// BLAKE3 of the complete canonical binding; external authority is required.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
}
