//! RFC-0025 encoding §2: complete physical-to-source map, without source authority.
use super::{
    codec::{reserved, Reader},
    Error, Physical, Role, Shape,
};
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/source-map";
pub(super) const LIMIT: usize = 1 << 24;

fn name<'a>(r: &mut Reader<'a>) -> Result<&'a str, Error> {
    let n = usize::from(r.u16()?);
    if !(1..=4096).contains(&n) {
        return Err(Error::SourceName);
    }
    let raw = r.take(n)?;
    if raw.contains(&0) {
        return Err(Error::SourceName);
    }
    core::str::from_utf8(raw).map_err(|_| Error::SourceName)
}

/// One checked Map entry. Its owning SourceMap fixes the physical ordinal.
#[derive(Debug, Eq, PartialEq)]
pub struct SourceEntry<'a> {
    name: &'a str,
    dtype: u8,
    rank: u8,
    dimensions: [u32; 2],
    transform: u8,
    part: Option<u8>,
    byte_length: u64,
}
impl<'a> SourceEntry<'a> {
    fn read(r: &mut Reader<'a>, physical: Physical, shape: Shape) -> Result<Self, Error> {
        let name = name(r)?;
        let dtype = r.u8()?;
        let size = match dtype {
            1 | 2 => 2u64,
            3 => 4,
            4 => 8,
            _ => return Err(Error::SourceDtype),
        };
        let rank = r.u8()?;
        if !matches!(rank, 1 | 2) {
            return Err(Error::SourceShape);
        }
        let mut dimensions = [0; 2];
        let mut byte_length = size;
        for d in &mut dimensions[..usize::from(rank)] {
            *d = r.u32()?;
            if *d == 0 {
                return Err(Error::SourceShape);
            }
            byte_length = byte_length
                .checked_mul(u64::from(*d))
                .ok_or(Error::SourceShape)?;
        }
        let transform = r.u8()?;
        let part = if matches!(transform, 2 | 3) {
            Some(r.u8()?)
        } else {
            None
        };
        let destination = physical.dimensions();
        let mut expected = [destination[0], *destination.get(1).unwrap_or(&0)];
        let mut expected_rank = destination.len();
        match transform {
            0 => {}
            1 if destination.len() == 2
                && !matches!(physical.role(), Role::Token | Role::Position) =>
            {
                expected.swap(0, 1)
            }
            2 | 3 if shape.family() == 0 => {
                let (expected_part, bias) = match physical.role() {
                    Role::Query => (0, false),
                    Role::Key => (1, false),
                    Role::Value => (2, false),
                    Role::QueryBias => (0, true),
                    Role::KeyBias => (1, true),
                    Role::ValueBias => (2, true),
                    _ => return Err(Error::SourceTransform),
                };
                if part != Some(expected_part) || (transform == 3) != bias {
                    return Err(Error::SourceTransform);
                }
                let width = u32::from(shape.width());
                if bias {
                    expected = [3 * width, 0];
                    expected_rank = 1;
                } else {
                    expected = [width, 3 * width];
                    expected_rank = 2;
                }
            }
            _ => return Err(Error::SourceTransform),
        }
        if usize::from(rank) != expected_rank || dimensions != expected {
            return Err(Error::SourceShape);
        }
        Ok(Self {
            name,
            dtype,
            rank,
            dimensions,
            transform,
            part,
            byte_length,
        })
    }
    /// Exact UTF-8 tensor name; no normalization or filesystem authority.
    pub fn name(&self) -> &'a str {
        self.name
    }
    /// F16=1, BF16=2, F32=3 or F64=4, independent of host scalar types.
    pub fn dtype(&self) -> u8 {
        self.dtype
    }
    /// Full original tensor shape, before its declared transform.
    pub fn dimensions(&self) -> &[u32] {
        &self.dimensions[..usize::from(self.rank)]
    }
    /// Copy=0, transpose=1, fused Q/K/V columns=2 or fused bias=3.
    pub fn transform(&self) -> u8 {
        self.transform
    }
    /// Prescribed Q/K/V part, present only for a fused transform.
    pub fn part(&self) -> Option<u8> {
        self.part
    }
    /// Full source tensor byte length, including all parts of a fused tensor.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// Complete canonical Map borrowing immutable bytes, with no source-file admission.
/// Every physical role has exactly one checked entry. Ignored buffers and the
/// optional token/head alias still require complete original-container checks.
/// ```compile_fail
/// fn change(m: &mut stele_cqis::model::SourceMap<'_>) { m.entries.clear(); }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct SourceMap<'a> {
    raw: &'a [u8],
    shape: Shape,
    entries: Vec<SourceEntry<'a>>,
    alias: Option<&'a str>,
    ignored: Vec<&'a str>,
    identity: [u8; 32],
}
impl<'a> SourceMap<'a> {
    /// Validate every role, complete fused partition and disjoint name set.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let shape = Shape::decode(r.blob(21)?)?;
        let count = usize::from(shape.record_count());
        // Even a rank-one entry requires ten bytes; both trailing counts remain.
        if r.0.len() < 10 * count + 8 {
            return Err(Error::Encoding);
        }
        let mut entries = reserved(count)?;
        let mut order = reserved(count)?;
        for ordinal in 0..shape.record_count() {
            entries.push(SourceEntry::read(
                &mut r,
                shape.physical(ordinal).ok_or(Error::Physical)?,
                shape,
            )?);
            order.push(usize::from(ordinal));
        }
        order.sort_unstable_by(|i, j| entries[*i].name.as_bytes().cmp(entries[*j].name.as_bytes()));
        partitions(shape, &entries, &order)?;
        let selected = |name: &str| {
            order
                .binary_search_by(|i| entries[*i].name.as_bytes().cmp(name.as_bytes()))
                .is_ok()
        };
        let aliases = r.u32()?;
        if aliases > u32::from(shape.family() == 0) {
            return Err(Error::SourceAlias);
        }
        let alias = if aliases == 1 {
            let alias = name(&mut r)?;
            if r.u16()? != 0 || selected(alias) || entries[0].transform != 0 {
                return Err(Error::SourceAlias);
            }
            Some(alias)
        } else {
            None
        };
        let count = usize::try_from(r.u32()?).map_err(|_| Error::Capacity)?;
        if count > r.0.len() / 3 {
            return Err(Error::Capacity);
        }
        // The 16-MiB raw cap and three-byte minimum name frame bound this
        // fallible reference array; names themselves are borrowed, never copied.
        let mut ignored = reserved(count)?;
        let mut previous: Option<&str> = None;
        for _ in 0..count {
            let current = name(&mut r)?;
            if previous.is_some_and(|p| p.as_bytes() >= current.as_bytes())
                || selected(current)
                || alias == Some(current)
            {
                return Err(Error::SourceIgnored);
            }
            ignored.push(current);
            previous = Some(current);
        }
        r.end()?;
        Ok(Self {
            raw,
            shape,
            entries,
            alias,
            ignored,
            identity: *blake3::hash(raw).as_bytes(),
        })
    }
    /// Complete validation followed by the independently expected content join.
    pub fn decode_expected(expected: &[u8; 32], raw: &'a [u8]) -> Result<Self, Error> {
        let map = Self::decode(raw)?;
        if &map.identity != expected {
            return Err(Error::Identity);
        }
        Ok(map)
    }
    /// Complete original canonical Map frame.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    /// BLAKE3 of all Map fields; this does not authenticate their publisher.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Checked complete destination shape.
    pub fn shape(&self) -> Shape {
        self.shape
    }
    /// Exactly one entry per physical ordinal, in Model order.
    pub fn entries(&self) -> &[SourceEntry<'a>] {
        &self.entries
    }
    /// Optional GPT-2 head name, whose only permitted target is token record zero.
    pub fn alias_name(&self) -> Option<&'a str> {
        self.alias
    }
    /// Exact sorted ignored-buffer names; their source bytes remain required.
    pub fn ignored(&self) -> &[&'a str] {
        &self.ignored
    }
}

fn partitions(shape: Shape, entries: &[SourceEntry<'_>], order: &[usize]) -> Result<(), Error> {
    let mut start = 0;
    while start < order.len() {
        let first = &entries[order[start]];
        let mut end = start + 1;
        while end < order.len() && entries[order[end]].name == first.name {
            end += 1;
        }
        if matches!(first.transform, 2 | 3) {
            if end - start != 3 {
                return Err(Error::SourcePartition);
            }
            let layer = shape
                .physical(order[start] as u16)
                .ok_or(Error::Physical)?
                .layer();
            let mut parts = 0u8;
            for &i in &order[start..end] {
                let e = &entries[i];
                if e.dtype != first.dtype
                    || e.dimensions != first.dimensions
                    || e.transform != first.transform
                    || shape.physical(i as u16).ok_or(Error::Physical)?.layer() != layer
                {
                    return Err(Error::SourcePartition);
                }
                parts |= 1 << e.part.ok_or(Error::SourcePartition)?;
            }
            if parts != 7 {
                return Err(Error::SourcePartition);
            }
        } else if end - start != 1 {
            return Err(Error::SourceAlias);
        }
        start = end;
    }
    Ok(())
}
