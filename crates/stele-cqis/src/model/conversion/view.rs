//! RFC-0025 conversion §§1–3: exact physical coordinates and bounded raw-byte reuse.
use super::{scalar::Scalar, Error};
use crate::model::{
    codec::reserved, Physical, SourceEntry, SourcePackage, SourceSlice, SourceView,
};
use alloc::vec::Vec;
const CHUNK: u64 = 65536; // Source §4's fixed authenticated snapshot chunk extent.

pub(super) struct Tensor<'s, 'a> {
    view: SourceView<'s, 'a>,
    entry: &'s SourceEntry<'a>,
    pub rows: u64,
    pub columns: u64,
    pub count: u64,
    size: u64,
    stride: u64,
    slots: usize,
    ordinal: u16,
}
impl<'s, 'a> Tensor<'s, 'a> {
    pub fn new(package: &'s SourcePackage<'a>, physical: Physical) -> Result<Self, Error> {
        let entry = package
            .source_map()
            .entries()
            .get(usize::from(physical.ordinal()))
            .ok_or(Error::Physical)?;
        let view = package.tensor(physical.ordinal()).ok_or(Error::Physical)?;
        let rows = u64::from(physical.dimensions()[0]);
        let columns = u64::from(*physical.dimensions().get(1).unwrap_or(&1));
        let count = rows.checked_mul(columns).ok_or(Error::SourceOffset)?;
        let size = Scalar::width(entry.dtype())?;
        let stride = u64::from(*entry.dimensions().get(1).unwrap_or(&1))
            .checked_mul(size)
            .ok_or(Error::SourceOffset)?;
        // Copy/fused bias traverse consecutive bytes and need one slot. For a
        // transposed source with >=one chunk per raw row, retain the current
        // chunk for each input column. Shorter raw rows occupy a contiguous set
        // of chunks; modulo that exact span avoids row-stride cache collisions.
        let slots = if matches!(entry.transform(), 1 | 2) {
            if stride >= CHUNK {
                columns
            } else {
                (view.offset() % CHUNK)
                    .checked_add(view.length())
                    .ok_or(Error::SourceOffset)?
                    .div_ceil(CHUNK)
            }
        } else {
            1
        };
        Ok(Self {
            view,
            entry,
            rows,
            columns,
            count,
            size,
            stride,
            slots: usize::try_from(slots).map_err(|_| Error::Capacity)?,
            ordinal: physical.ordinal(),
        })
    }
    pub fn slots(&self) -> usize {
        self.slots
    }
    pub fn scalar<E>(
        &self,
        k: u64,
        cache: &mut Cache,
        read: &mut impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Scalar, Error> {
        if k >= self.count {
            return Err(Error::SourceOffset);
        }
        cache.select(self.ordinal);
        let row = k / self.columns;
        let column = k % self.columns;
        let index = match self.entry.transform() {
            0 => k,
            1 | 2 => column
                .checked_mul(u64::from(self.entry.dimensions()[1]))
                .and_then(|i| i.checked_add(u64::from(self.entry.part().unwrap_or(0)) * self.rows))
                .and_then(|i| i.checked_add(row))
                .ok_or(Error::SourceOffset)?,
            3 => u64::from(self.entry.part().ok_or(Error::SourceTransform)?)
                .checked_mul(self.rows)
                .and_then(|i| i.checked_add(k))
                .ok_or(Error::SourceOffset)?,
            _ => return Err(Error::SourceTransform),
        };
        let at = index.checked_mul(self.size).ok_or(Error::SourceOffset)?;
        if at
            .checked_add(self.size)
            .is_none_or(|end| end > self.view.length())
        {
            return Err(Error::SourceOffset);
        }
        let mut raw = [0; 8];
        let mut copied = 0;
        while copied < self.size as usize {
            let relative = at + copied as u64;
            let absolute = self
                .view
                .offset()
                .checked_add(relative)
                .ok_or(Error::SourceOffset)?;
            let slot = if matches!(self.entry.transform(), 1 | 2) && self.stride >= CHUNK {
                column as usize
            } else {
                (absolute / CHUNK % self.slots as u64) as usize
            };
            let stored = cache.slots.get_mut(slot).ok_or(Error::Capacity)?;
            if !stored.as_ref().is_some_and(|s| {
                relative >= s.offset() && relative - s.offset() < s.as_bytes().len() as u64
            }) {
                // Release an old owned chunk before allocating its replacement.
                *stored = None;
                let begin = (absolute / CHUNK * CHUNK).saturating_sub(self.view.offset());
                *stored = Some(self.view.chunk(begin, &mut *read)?);
            }
            let stored = stored.as_ref().ok_or(Error::Read)?;
            let start =
                usize::try_from(relative - stored.offset()).map_err(|_| Error::SourceOffset)?;
            let n = (self.size as usize - copied).min(stored.as_bytes().len() - start);
            raw[copied..copied + n].copy_from_slice(&stored.as_bytes()[start..start + n]);
            copied += n;
        }
        Scalar::decode(self.entry.dtype(), &raw[..self.size as usize])
    }
}
pub(super) struct Cache {
    slots: Vec<Option<SourceSlice>>,
    ordinal: Option<u16>,
}
impl Cache {
    pub fn bytes(slots: usize) -> Result<usize, Error> {
        slots
            .checked_mul(CHUNK as usize + core::mem::size_of::<Option<SourceSlice>>())
            .ok_or(Error::Capacity)
    }
    pub fn new(slots: usize) -> Result<Self, Error> {
        let mut values = reserved(slots)?;
        values.resize_with(slots, || None);
        Ok(Self {
            slots: values,
            ordinal: None,
        })
    }
    // One cache belongs to one immutable package for the entire conversion.
    // Never reuse relative offsets across distinct physical source views.
    fn select(&mut self, ordinal: u16) {
        if self.ordinal != Some(ordinal) {
            for slot in &mut self.slots {
                *slot = None;
            }
            self.ordinal = Some(ordinal);
        }
    }
}
