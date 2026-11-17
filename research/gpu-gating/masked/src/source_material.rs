//! RFC-0010 A9: complete research source storage; no verifier authority.
use super::{encode_rows, tree_nodes, Shape, BLOWUP};
use crate::M31;
use stele_reductions::parallel::for_each_chunk_weighted;
use stele_reductions::stele_hash::mask::{MaskStream, SOURCE_SALT};
use stele_reductions::stele_hash::merkle::Digest;

pub(super) fn digest(words: &[u32]) -> Digest {
    let mut out = [0; 32];
    for (bytes, word) in out.chunks_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Salted columns and every Merkle level, leaves first and root last.
pub struct Material {
    columns: Vec<u8>,
    nodes: Vec<u32>,
    width: usize,
    leaves: usize,
    assembly_descriptor_bytes: usize,
}

impl Material {
    /// Assemble downloaded encoding and nodes; charge salt generation to the host.
    pub(crate) fn new(shape: &Shape, encoded: &[u32], nodes: Vec<u32>) -> Option<Self> {
        let source = shape.source()?;
        let leaves = usize::try_from(source.descriptor().count).ok()?;
        let width = usize::try_from(source.descriptor().width).ok()?;
        let rows = shape.rows();
        if encoded.len() != leaves.checked_mul(rows)?
            || nodes.len() != leaves.checked_mul(2)?.checked_sub(1)?.checked_mul(8)?
            || encoded.iter().any(|x| M31::from_canonical(*x).is_none())
        {
            return None;
        }
        let bytes = leaves.checked_mul(width)?;
        // RFC-0013 A2: prevalidate the complete salt range before disjoint workers.
        u64::try_from(leaves.checked_mul(32)?).ok()?;
        let mut columns = Vec::new();
        columns.try_reserve_exact(bytes).ok()?;
        columns.resize(bytes, 0);
        let salts = MaskStream::new(&shape.seed, SOURCE_SALT, shape.id);
        let mut payloads = Vec::new();
        payloads.try_reserve_exact(leaves).ok()?;
        payloads.extend(columns.chunks_exact_mut(width));
        let assembly_descriptor_bytes = payloads
            .capacity()
            .checked_mul(core::mem::size_of::<&mut [u8]>())?;
        for_each_chunk_weighted(&mut payloads, rows, |start, chunk| {
            for (local, column) in chunk.iter_mut().enumerate() {
                let index = start + local;
                salts.fill_at((index * 32) as u64, &mut column[..32]);
                for (bytes, word) in column[32..]
                    .chunks_mut(4)
                    .zip(&encoded[index * rows..(index + 1) * rows])
                {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
        });
        drop(payloads);
        Some(Self {
            columns,
            nodes,
            width,
            leaves,
            assembly_descriptor_bytes,
        })
    }

    /// Untrusted producer root; the ordinary verifier authenticates responses.
    pub fn root(&self) -> Digest {
        digest(&self.nodes[self.nodes.len() - 8..])
    }

    /// Owned vector capacities only; excludes runtime and caller storage.
    pub fn owned_bytes(&self) -> usize {
        self.columns.capacity() + self.nodes.capacity() * 4
    }

    /// Temporary descriptor vector capacity during assembly; not a process peak.
    pub fn assembly_descriptor_bytes(&self) -> usize {
        self.assembly_descriptor_bytes
    }

    /// Canonical payload and full bottom-up path for a real column.
    pub fn response(&self, index: u64) -> Option<(&[u8], Vec<Digest>)> {
        let mut index = usize::try_from(index).ok()?;
        if index >= self.leaves {
            return None;
        }
        let payload = &self.columns[index * self.width..(index + 1) * self.width];
        let (mut offset, mut width) = (0, self.leaves);
        let mut path = Vec::new();
        path.try_reserve_exact(width.trailing_zeros() as usize)
            .ok()?;
        while width > 1 {
            let at = (offset + (index ^ 1)) * 8;
            path.push(digest(&self.nodes[at..at + 8]));
            offset += width;
            width /= 2;
            index >>= 1;
        }
        Some((payload, path))
    }
}

/// Plain Rust counterpart of device material preparation, for parity only.
pub fn material(shape: &Shape, message: &[M31]) -> Option<Material> {
    let source = shape.source()?;
    if message.len()
        != shape
            .rows()
            .checked_mul(1usize.checked_shl(shape.log_n())?)?
    {
        return None;
    }
    let words: Vec<u32> = message.iter().map(|v| v.as_u32()).collect();
    let encoded = encode_rows(&words, shape.rows(), shape.log_n(), u32::from(BLOWUP));
    let nodes = tree_nodes(&source.descriptor(), &encoded, shape.rows(), &shape.seed);
    Material::new(shape, &encoded, nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_or_noncanonical_material() {
        let shape = Shape::new(3, 9, 1);
        let leaves = shape.source().unwrap().descriptor().count as usize;
        let mut encoded = vec![0; leaves * shape.rows()];
        let nodes = vec![0; (2 * leaves - 1) * 8];
        assert!(Material::new(&shape, &encoded, nodes.clone()).is_some());
        assert!(Material::new(&shape, &encoded[..encoded.len() - 1], nodes.clone()).is_none());
        assert!(Material::new(&shape, &encoded, nodes[..nodes.len() - 1].to_vec()).is_none());
        encoded[0] = 0x7fff_ffff;
        assert!(Material::new(&shape, &encoded, nodes).is_none());
        assert!(material(&shape, &[]).is_none());
        assert!(material(&Shape::new(30, 9, 1), &[]).is_none());
    }
}
