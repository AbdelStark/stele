//! RFC-0025 source §3: complete config/tokenizer/generation file declarations.
use super::{file, SourceFile, LIMIT};
use crate::model::{codec::Reader, Error};
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/source-assets";

/// Complete checked Assets metadata; expected role completeness and semantics
/// come from the independently authenticated model/text adapter.
/// ```compile_fail
/// fn change(a: &mut stele_cqis::model::Assets<'_>) { a.generation = None; }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Assets<'a> {
    raw: &'a [u8],
    config: SourceFile<'a>,
    tokenizers: Vec<SourceFile<'a>>,
    generation: Option<SourceFile<'a>>,
    identity: [u8; 32],
    total_length: u64,
}
impl<'a> Assets<'a> {
    /// Check all role tags, sorted unique names, lengths and exact frame exhaustion.
    /// This does not hash actual files or parse config/tokenizer/generation values.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let config = SourceFile::read(&mut r)?;
        if !config.name().ends_with(".json") {
            return Err(Error::Assets);
        }
        let (tokenizers, size) = file::files(&mut r, None, None)?;
        if tokenizers.is_empty() {
            return Err(Error::Assets);
        }
        let mut total_length = config.length().checked_add(size).ok_or(Error::FileLength)?;
        let contains = |name: &str| {
            tokenizers
                .binary_search_by(|f| f.name().as_bytes().cmp(name.as_bytes()))
                .is_ok()
        };
        if contains(config.name()) {
            return Err(Error::FileSet);
        }
        let generation = match r.u8()? {
            0 => None,
            1 => {
                let file = SourceFile::read(&mut r)?;
                if !file.name().ends_with(".json") {
                    return Err(Error::Assets);
                }
                if file.name() == config.name() || contains(file.name()) {
                    return Err(Error::FileSet);
                }
                total_length = total_length
                    .checked_add(file.length())
                    .ok_or(Error::FileLength)?;
                Some(file)
            }
            _ => return Err(Error::Assets),
        };
        r.end()?;
        Ok(Self {
            raw,
            config,
            tokenizers,
            generation,
            identity: *blake3::hash(raw).as_bytes(),
            total_length,
        })
    }
    /// Complete parsing followed by an independently expected assets_id check.
    pub fn decode_expected(expected: &[u8; 32], raw: &'a [u8]) -> Result<Self, Error> {
        let assets = Self::decode(raw)?;
        if &assets.identity != expected {
            return Err(Error::Identity);
        }
        Ok(assets)
    }
    /// Exact complete canonical Assets bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    /// Single expected config JSON file declaration.
    pub fn config(&self) -> &SourceFile<'a> {
        &self.config
    }
    /// Nonempty exact tokenizer file declarations in raw UTF-8 name order.
    pub fn tokenizers(&self) -> &[SourceFile<'a>] {
        &self.tokenizers
    }
    /// Original generation JSON declaration, only when the presence tag is one.
    pub fn generation(&self) -> Option<&SourceFile<'a>> {
        self.generation.as_ref()
    }
    /// assets_id, the BLAKE3 hash of this complete declaration.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Checked sum of all original auxiliary-file lengths.
    pub fn total_length(&self) -> u64 {
        self.total_length
    }
}
