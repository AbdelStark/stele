//! RFC-0025 encoding §3: bounded metadata comparison and complete code validation.
use super::{ArtifactLayout, ArtifactRecord, CHUNK, HEADER, LIMIT, PREFIX, TENSOR};
use crate::model::{codec::reserved, Error, Preparation, Scales};
use alloc::vec::Vec;

pub(super) enum Part<'a> {
    Metadata(&'a [u8]),
    Payload(&'a ArtifactRecord),
}
pub(super) fn buffer() -> Result<Vec<u8>, Error> {
    let mut bytes = reserved(CHUNK)?;
    bytes.resize(CHUNK, 0);
    Ok(bytes)
}

pub(super) fn walk(
    layout: &ArtifactLayout,
    preparation: &Preparation<'_>,
    scales: &Scales,
    mut visit: impl FnMut(Part<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut header = [0; HEADER];
    header[..PREFIX.len()].copy_from_slice(PREFIX);
    header[PREFIX.len()..PREFIX.len() + 32].copy_from_slice(&preparation.identity());
    header[PREFIX.len() + 32..].copy_from_slice(
        &u16::try_from(layout.records().len())
            .map_err(|_| Error::Capacity)?
            .to_le_bytes(),
    );
    visit(Part::Metadata(&header))?;
    let mut bytes = buffer()?;
    for r in layout.records() {
        visit(Part::Metadata(&r.record_length().to_le_bytes()))?;
        visit(Part::Metadata(TENSOR))?;
        visit(Part::Metadata(
            &(r.configuration_length as u32).to_le_bytes(),
        ))?;
        visit(Part::Metadata(&r.configuration[..r.configuration_length]))?;
        if let Some(channels) = r.channels {
            let scale = scales.matrix(r.ordinal()).ok_or(Error::Physical)?;
            if scale.mantissas().len() as u64 != u64::from(channels) {
                return Err(Error::Physical);
            }
            visit(Part::Metadata(&scale.exponent().to_le_bytes()))?;
            for chunk in scale.mantissas().chunks(CHUNK / 2) {
                for (word, pair) in chunk.iter().zip(bytes.chunks_exact_mut(2)) {
                    pair.copy_from_slice(&word.to_le_bytes());
                }
                visit(Part::Metadata(&bytes[..2 * chunk.len()]))?;
            }
        }
        visit(Part::Metadata(&r.payload_length().to_le_bytes()))?;
        visit(Part::Payload(r))?;
    }
    Ok(())
}

pub(super) struct Digest {
    pub hash: blake3::Hasher,
    pub length: u64,
}
impl Digest {
    pub fn new() -> Self {
        Self {
            hash: blake3::Hasher::new(),
            length: 0,
        }
    }
    pub fn update(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.length = self
            .length
            .checked_add(raw.len() as u64)
            .filter(|n| *n < LIMIT)
            .ok_or(Error::Capacity)?;
        self.hash.update(raw);
        Ok(())
    }
}

fn read_some<E>(
    read: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = read(out).map_err(|_| Error::Read)?;
    if n > out.len() {
        return Err(Error::Read);
    }
    Ok(n)
}
pub(super) fn eof<E>(read: &mut impl FnMut(&mut [u8]) -> Result<usize, E>) -> Result<(), Error> {
    if read_some(read, &mut [0; 1])? != 0 {
        return Err(Error::Artifact);
    }
    Ok(())
}
pub(super) fn expected<E>(
    mut part: &[u8],
    buffer: &mut [u8],
    read: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
    digest: &mut Digest,
) -> Result<(), Error> {
    while !part.is_empty() {
        let offered = part.len().min(buffer.len());
        let n = read_some(read, &mut buffer[..offered])?;
        if n == 0 || buffer[..n] != part[..n] {
            return Err(Error::Artifact);
        }
        digest.update(&buffer[..n])?;
        part = &part[n..];
    }
    Ok(())
}
pub(super) fn payload<E>(
    record: &ArtifactRecord,
    buffer: &mut [u8],
    read: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
    mut accept: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut remaining = record.payload_length();
    while remaining != 0 {
        let offered =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| Error::Capacity)?;
        let n = read_some(read, &mut buffer[..offered])?;
        if n == 0 {
            return Err(Error::Artifact);
        }
        remaining -= n as u64;
        let raw = &buffer[..n];
        match record.bits() {
            4 => {
                if raw.iter().any(|b| b & 15 == 8 || b >> 4 == 8) {
                    return Err(Error::ArtifactCode);
                }
                // Continuous packing: only the complete odd payload's final high
                // nibble is padding, never the end of a row or read chunk.
                if remaining == 0 && record.elements() % 2 == 1 && raw[n - 1] >> 4 != 0 {
                    return Err(Error::ArtifactPadding);
                }
            }
            8 if raw.contains(&128) => return Err(Error::ArtifactCode),
            8 | 16 => {}
            _ => return Err(Error::Physical),
        }
        accept(raw)?;
    }
    Ok(())
}
