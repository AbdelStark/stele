//! RFC-0010 A9 / RFC-0012 A3: selected source responses; no certificate authority.
use super::Timing;
use crate::gpu::{Device, Error};
use crate::source::{digest, payload, Material, Shape};
use cudarc::driver::CudaSlice;
use std::time::Instant;
use stele_reductions::stele_hash::merkle::Digest;

/// Immutable encoded columns and Merkle levels owned on one device.
pub struct Resident<'a> {
    pub(super) dev: &'a Device,
    pub(super) shape: &'a Shape,
    pub(super) encoded: CudaSlice<u32>,
    pub(super) levels: Vec<CudaSlice<u32>>,
    pub(super) root: Digest,
}

impl Resident<'_> {
    /// Untrusted producer root; the ordinary verifier authenticates responses.
    pub fn root(&self) -> Digest {
        self.root
    }

    /// Download one real column and bottom-up path, charging the preparation's times.
    /// Repeated requests repeat the transfer; no batch ordering or query policy is imposed.
    pub fn response(&self, index: u64, time: &mut Timing) -> Result<(Vec<u8>, Vec<Digest>), Error> {
        let mut position = usize::try_from(index).map_err(|_| Error::Value)?;
        let rows = self.shape.rows();
        if position >= self.encoded.len() / rows {
            return Err(Error::Value);
        }
        let at = position.checked_mul(rows).ok_or(Error::Value)?;
        let column = self.encoded.try_slice(at..at + rows).ok_or(Error::Value)?;
        let bytes = rows * 4 + (self.levels.len() - 1) * 32;
        time.download_bytes.checked_add(bytes).ok_or(Error::Value)?;
        let start = Instant::now();
        let encoded = self.dev.stream().clone_dtoh(&column)?;
        time.download_bytes += rows * 4;
        let mut path = Vec::new();
        path.try_reserve_exact(self.levels.len() - 1)
            .map_err(|_| Error::Value)?;
        for level in &self.levels[..self.levels.len() - 1] {
            let at = (position ^ 1) * 8;
            let sibling = level.try_slice(at..at + 8).ok_or(Error::Value)?;
            path.push(digest(&self.dev.stream().clone_dtoh(&sibling)?));
            time.download_bytes += 32;
            position >>= 1;
        }
        time.download += start.elapsed();
        let start = Instant::now();
        let payload = payload(self.shape, index, &encoded);
        time.assemble += start.elapsed();
        Ok((payload.ok_or(Error::Value)?, path))
    }

    /// Preserve E16-40b's full download and host assembly, including its root check.
    pub(super) fn material(self, time: &mut Timing) -> Result<Material, Error> {
        let start = Instant::now();
        let encoded = self.dev.stream().clone_dtoh(&self.encoded)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(self.levels.iter().map(|level| level.len()).sum())
            .map_err(|_| Error::Value)?;
        for level in &self.levels[..self.levels.len() - 1] {
            nodes.extend(self.dev.stream().clone_dtoh(level)?);
        }
        nodes.extend(
            self.root
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        );
        time.download = start.elapsed();
        time.download_bytes = time.retained_bytes;
        let start = Instant::now();
        let material = Material::new(self.shape, &encoded, nodes).ok_or(Error::Value)?;
        time.assemble = start.elapsed();
        if material.root() != self.root {
            return Err(Error::Value);
        }
        Ok(material)
    }
}
