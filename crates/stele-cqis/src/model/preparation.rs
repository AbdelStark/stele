//! RFC-0025 encoding §3: exact Map and physical configuration Preparation join.
use super::{
    codec::{configuration, Reader, Writer},
    source_map, Error, Model, SourceMap,
};
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/quantiser";
const LIMIT: usize = 17 << 20;

/// Complete checked quantiser configuration, without original-source authority.
/// The Map borrows immutable input bytes. Runtime Model fields outside Shape
/// and physical configurations are not part of the canonical quantiser identity.
/// ```compile_fail
/// fn change(p: &mut stele_cqis::model::Preparation<'_>) { p.identity = [0; 32]; }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Preparation<'a> {
    map: SourceMap<'a>,
    configurations: Vec<u8>,
    model_identity: [u8; 32],
    identity: [u8; 32],
}
impl<'a> Preparation<'a> {
    /// Join a complete Map to the expected Model and derive the exact quantiser id.
    pub fn new(model: &Model, map: SourceMap<'a>) -> Result<Self, Error> {
        if map.shape() != model.shape() {
            return Err(Error::Shape);
        }
        let mut configurations = Writer::new(13 * usize::from(model.shape().record_count()))?;
        for ordinal in 0..model.shape().record_count() {
            let (raw, length) = configuration(model, ordinal)?;
            configurations.push(&raw[..length])?;
        }
        let configurations = configurations.finish();
        let mut hash = blake3::Hasher::new();
        hash.update(PREFIX);
        hash.update(&(map.as_bytes().len() as u32).to_le_bytes());
        hash.update(map.as_bytes());
        hash.update(&configurations);
        Ok(Self {
            map,
            configurations,
            model_identity: model.identity(),
            identity: *hash.finalize().as_bytes(),
        })
    }
    /// Parse the complete Map and compare each independently expected configuration.
    pub fn decode(model: &Model, raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let map = SourceMap::decode(r.blob(source_map::LIMIT)?)?;
        let preparation = Self::new(model, map)?;
        if r.take(preparation.configurations.len())? != preparation.configurations {
            return Err(Error::Physical);
        }
        r.end()?;
        Ok(preparation)
    }
    /// Complete validation followed by the externally expected quantiser identity.
    pub fn decode_expected(
        model: &Model,
        expected: &[u8; 32],
        raw: &'a [u8],
    ) -> Result<Self, Error> {
        let preparation = Self::decode(model, raw)?;
        if &preparation.identity != expected {
            return Err(Error::Identity);
        }
        Ok(preparation)
    }
    /// Canonical bounded metadata bytes; no tensor payloads are included.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = PREFIX
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(self.map.as_bytes().len()))
            .and_then(|n| n.checked_add(self.configurations.len()))
            .filter(|n| *n <= LIMIT)
            .ok_or(Error::Capacity)?;
        let mut w = Writer::new(length)?;
        w.push(PREFIX)?;
        w.blob(self.map.as_bytes())?;
        w.push(&self.configurations)?;
        Ok(w.finish())
    }
    /// Complete checked Map, with all source transforms and name-set obligations.
    pub fn map(&self) -> &SourceMap<'a> {
        &self.map
    }
    /// Model against which the shape and every physical configuration were checked.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// BLAKE3 of canonical Preparation, not a hash of original source tensors.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
}
