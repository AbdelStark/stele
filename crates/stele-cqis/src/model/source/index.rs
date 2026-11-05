//! RFC-0025 source §2: strict original index structure, before package/shard joins.
use super::{
    file::validate_name,
    json::{Budget, Json},
    Error, SourceFile, SourceSnapshot, INDEX_LIMIT,
};
use alloc::{string::String, vec::Vec};

/// Complete original index metadata read from a verified file snapshot.
/// Shard membership, tensor coverage, recomputed total_size and independently
/// expected source authority remain mandatory package checks.
/// ```compile_fail
/// fn change(index: &mut stele_cqis::model::SourceIndex<'_>) { index.entries.clear(); }
/// ```
pub struct SourceIndex<'a> {
    file: SourceFile<'a>,
    entries: Vec<SourceIndexEntry>,
    total_size: u64,
}
/// One exact decoded tensor-to-shard assignment, without filesystem authority.
pub struct SourceIndexEntry {
    name: String,
    file_name: String,
}

impl<'a> SourceIndex<'a> {
    /// Revalidate every original index byte, then parse its complete closed JSON.
    /// Index length is at most 100000000 bytes. The metadata budget bounds the
    /// conservative sum of requested original-byte/string/vector allocations,
    /// including freed temporaries. Allocator overhead and one snapshot chunk
    /// of at most 65536 bytes are separate; original JSON is dropped after parsing.
    pub fn read_from<E>(
        snapshot: &SourceSnapshot<'a>,
        max_metadata_bytes: usize,
        read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        Self::read_with_budget(snapshot, &mut Budget::new(max_metadata_bytes), read_at)
    }
    pub(super) fn read_with_budget<E>(
        snapshot: &SourceSnapshot<'a>,
        budget: &mut Budget,
        mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let file = *snapshot.file();
        if !file.name().ends_with(".json") {
            return Err(Error::SourceIndex);
        }
        if file.length() > INDEX_LIMIT {
            return Err(Error::Capacity);
        }
        let mut raw = budget.bytes(file.length() as usize)?;
        for ordinal in 0..snapshot.chunk_count() {
            let chunk = snapshot.chunk(ordinal, &mut read_at)?;
            let start = usize::try_from(chunk.offset()).map_err(|_| Error::Capacity)?;
            let end = start
                .checked_add(chunk.as_bytes().len())
                .ok_or(Error::Capacity)?;
            raw.get_mut(start..end)
                .ok_or(Error::FileLength)?
                .copy_from_slice(chunk.as_bytes());
        }
        let mut json = Json::new(&raw)?;
        json.byte(b'{')?;
        let mut first = true;
        let mut seen = 0;
        let mut total_size = None;
        let mut entries = Vec::new();
        while json.next(&mut first, b'}')? {
            let key = json.key(budget)?;
            let bit = match key.as_str() {
                "metadata" => 1,
                "weight_map" => 2,
                _ => return Err(Error::SourceIndex),
            };
            if seen & bit != 0 {
                return Err(Error::SourceDuplicate);
            }
            seen |= bit;
            if bit == 1 {
                total_size = Some(metadata(&mut json, budget)?);
            } else {
                entries = mapping(&mut json, budget)?;
            }
        }
        json.end()?;
        if seen != 3 {
            return Err(Error::SourceIndex);
        }
        Ok(Self {
            file,
            entries,
            total_size: total_size.ok_or(Error::SourceIndex)?,
        })
    }
    /// Exact original index File, including the verified complete SHA-256.
    pub fn file(&self) -> &SourceFile<'a> {
        &self.file
    }
    /// Complete tensor assignments, sorted by exact decoded UTF-8 name.
    pub fn entries(&self) -> &[SourceIndexEntry] {
        &self.entries
    }
    /// Declared complete payload size; the package must independently recompute it.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}
impl SourceIndexEntry {
    /// Exact decoded tensor name, without normalization or inferred aliases.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Exact validated shard basename; this label cannot authorize filesystem access.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

fn metadata(json: &mut Json<'_>, budget: &mut Budget) -> Result<u64, Error> {
    json.byte(b'{')?;
    let mut first = true;
    let mut total = None;
    let mut names = Vec::new();
    while json.next(&mut first, b'}')? {
        let name = json.key(budget)?;
        if name == "total_size" {
            total = Some(json.unsigned()?);
        } else {
            json.string(budget)?;
        }
        budget.push(&mut names, name)?;
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::SourceDuplicate);
    }
    total.ok_or(Error::SourceIndex)
}
fn mapping(json: &mut Json<'_>, budget: &mut Budget) -> Result<Vec<SourceIndexEntry>, Error> {
    json.byte(b'{')?;
    let mut first = true;
    let mut entries = Vec::new();
    while json.next(&mut first, b'}')? {
        let name = json.key(budget)?;
        let file_name = json.string(budget)?;
        validate_name(&file_name)?;
        if !file_name.ends_with(".safetensors") {
            return Err(Error::SourceFiles);
        }
        budget.push(&mut entries, SourceIndexEntry { name, file_name })?;
    }
    if entries.is_empty() || entries.len() as u64 >= 1u64 << 32 {
        return Err(Error::SourceIndex);
    }
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(Error::SourceDuplicate);
    }
    Ok(entries)
}
