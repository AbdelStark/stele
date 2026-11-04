//! RFC-0025 source §2: complete safetensors structure from revalidated snapshots.
use super::{
    json::{Budget, Json},
    Error, SourceFile, SourceSnapshot,
};
use alloc::{string::String, vec::Vec};

/// Complete structurally checked container metadata, with no selected tensor
/// authority. Package selection, index, raw aliases and conversion remain required.
/// ```compile_fail
/// fn change(c: &mut stele_cqis::model::SourceContainer<'_>) { c.tensors.clear(); }
/// ```
pub struct SourceContainer<'a> {
    file: SourceFile<'a>,
    tensors: Vec<SourceTensor>,
    payload_offset: u64,
}
/// Structural dtype/shape/span metadata; it does not expose unchecked payloads.
pub struct SourceTensor {
    name: String,
    dtype: &'static str,
    dimensions: Vec<u64>,
    offset: u64,
    length: u64,
}
impl<'a> SourceContainer<'a> {
    /// Revalidate original header bytes, parse the closed JSON grammar and check
    /// every tensor and the complete payload coverage before returning metadata.
    /// The budget bounds the conservative sum of requested header/string/vector
    /// allocation bytes, including freed temporaries; allocator overhead and the
    /// at-most-65536-byte snapshot read buffer are separate. A chunk crossing the
    /// header boundary includes payload bytes; returned metadata retains none.
    pub fn read_from<E>(
        snapshot: &SourceSnapshot<'a>,
        max_metadata_bytes: usize,
        mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let file = *snapshot.file();
        if file.length() < 8 {
            return Err(Error::SourceHeader);
        }
        let first = snapshot.chunk(0, &mut read_at)?;
        let size = u64::from_le_bytes(
            first.as_bytes()[..8]
                .try_into()
                .map_err(|_| Error::SourceHeader)?,
        );
        if size > 100000000 || size > file.length() - 8 {
            return Err(Error::SourceHeader);
        }
        let mut budget = Budget::new(max_metadata_bytes);
        let mut header = budget.bytes(size as usize)?;
        let mut copied = (first.as_bytes().len() - 8).min(header.len());
        header[..copied].copy_from_slice(&first.as_bytes()[8..8 + copied]);
        drop(first);
        while copied < header.len() {
            let chunk = snapshot.chunk((8 + copied as u64) / 65536, &mut read_at)?;
            let n = chunk.as_bytes().len().min(header.len() - copied);
            header[copied..copied + n].copy_from_slice(&chunk.as_bytes()[..n]);
            copied += n;
        }
        if header.first() != Some(&b'{') {
            return Err(Error::SourceHeader);
        }
        let mut json = Json::new(&header)?;
        json.byte(b'{')?;
        let mut first = true;
        let mut metadata = false;
        let mut tensors = Vec::new();
        while json.next(&mut first, b'}')? {
            let name = json.key(&mut budget)?;
            if name == "__metadata__" {
                if metadata {
                    return Err(Error::SourceDuplicate);
                }
                metadata = true;
                annotations(&mut json, &mut budget)?;
            } else {
                let tensor = tensor(
                    name,
                    &mut json,
                    &mut budget,
                    8 + size,
                    file.length() - 8 - size,
                )?;
                budget.push(&mut tensors, tensor)?;
            }
        }
        json.end()?;
        tensors.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if tensors.windows(2).any(|p| p[0].name == p[1].name) {
            return Err(Error::SourceDuplicate);
        }
        tensors.sort_unstable_by(|a, b| {
            (a.offset, a.length, &a.name).cmp(&(b.offset, b.length, &b.name))
        });
        let mut cursor = 8 + size;
        for tensor in &tensors {
            if tensor.offset != cursor {
                return Err(Error::SourceCoverage);
            }
            cursor = cursor
                .checked_add(tensor.length)
                .ok_or(Error::SourceContainer)?;
        }
        if cursor != file.length() {
            return Err(Error::SourceCoverage);
        }
        tensors.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            file,
            tensors,
            payload_offset: 8 + size,
        })
    }
    /// Original File verified by the owning snapshot.
    pub fn file(&self) -> &SourceFile<'a> {
        &self.file
    }
    /// Every structural tensor, sorted by exact decoded UTF-8 name.
    pub fn tensors(&self) -> &[SourceTensor] {
        &self.tensors
    }
    /// Absolute original-file offset of the complete payload.
    pub fn payload_offset(&self) -> u64 {
        self.payload_offset
    }
    /// Complete payload length, including explicitly ignored tensors.
    pub fn payload_length(&self) -> u64 {
        self.file.length() - self.payload_offset
    }
}
impl SourceTensor {
    /// Exact decoded name, without normalization.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// One of all nineteen pinned structural storage dtype tags.
    pub fn dtype(&self) -> &str {
        self.dtype
    }
    /// Full u64 structural dimensions; scalars and empty tensors remain legal.
    pub fn dimensions(&self) -> &[u64] {
        &self.dimensions
    }
    /// Absolute original-file offset of the tensor payload.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Exact integral-byte payload length.
    pub fn length(&self) -> u64 {
        self.length
    }
}
fn annotations(json: &mut Json<'_>, budget: &mut Budget) -> Result<(), Error> {
    json.byte(b'{')?;
    let mut first = true;
    let mut names = Vec::new();
    while json.next(&mut first, b'}')? {
        let name = json.key(budget)?;
        json.string(budget)?;
        budget.push(&mut names, name)?;
    }
    names.sort_unstable();
    if names.windows(2).any(|p| p[0] == p[1]) {
        return Err(Error::SourceDuplicate);
    }
    Ok(())
}
fn tensor(
    name: String,
    json: &mut Json<'_>,
    budget: &mut Budget,
    base: u64,
    payload: u64,
) -> Result<SourceTensor, Error> {
    json.byte(b'{')?;
    let mut first = true;
    let mut seen = 0;
    let mut dtype = None;
    let mut dimensions = Vec::new();
    let mut offsets = [0; 2];
    while json.next(&mut first, b'}')? {
        let key = json.key(budget)?;
        let bit = match key.as_str() {
            "dtype" => 1,
            "shape" => 2,
            "data_offsets" => 4,
            _ => return Err(Error::SourceContainer),
        };
        if seen & bit != 0 {
            return Err(Error::SourceDuplicate);
        }
        seen |= bit;
        match bit {
            1 => {
                let name = json.string(budget)?;
                dtype = Some(storage(&name).ok_or(Error::SourceContainer)?);
            }
            2 => {
                json.byte(b'[')?;
                let mut first = true;
                while json.next(&mut first, b']')? {
                    let value = json.unsigned()?;
                    budget.push(&mut dimensions, value)?;
                }
            }
            _ => {
                json.byte(b'[')?;
                let mut first = true;
                let mut count = 0;
                while json.next(&mut first, b']')? {
                    if count >= 2 {
                        return Err(Error::SourceContainer);
                    }
                    offsets[count] = json.unsigned()?;
                    count += 1;
                }
                if count != 2 {
                    return Err(Error::SourceContainer);
                }
            }
        }
    }
    if seen != 7 {
        return Err(Error::SourceContainer);
    }
    let (dtype, width) = dtype.ok_or(Error::SourceContainer)?;
    let mut count = 1u64;
    for dimension in &dimensions {
        count = count
            .checked_mul(*dimension)
            .ok_or(Error::SourceContainer)?;
    }
    let bits = count.checked_mul(width).ok_or(Error::SourceContainer)?;
    let [start, end] = offsets;
    if bits % 8 != 0 || start > end || end > payload || end - start != bits / 8 {
        return Err(Error::SourceContainer);
    }
    Ok(SourceTensor {
        name,
        dtype,
        dimensions,
        offset: base.checked_add(start).ok_or(Error::SourceContainer)?,
        length: end - start,
    })
}
fn storage(name: &str) -> Option<(&'static str, u64)> {
    const TYPES: [(&str, u64); 19] = [
        ("BOOL", 8),
        ("F4", 4),
        ("F6_E2M3", 6),
        ("F6_E3M2", 6),
        ("U8", 8),
        ("I8", 8),
        ("F8_E5M2", 8),
        ("F8_E4M3", 8),
        ("F8_E8M0", 8),
        ("I16", 16),
        ("U16", 16),
        ("F16", 16),
        ("BF16", 16),
        ("I32", 32),
        ("U32", 32),
        ("F32", 32),
        ("F64", 64),
        ("I64", 64),
        ("U64", 64),
    ];
    TYPES.iter().copied().find(|(tag, _)| *tag == name)
}
