//! RFC-0010 A9: complete research source storage; no verifier authority.
use super::{encode_rows, tree_nodes, Shape, BLOWUP};
use crate::M31;
use stele_reductions::stele_hash::mask::{MaskStream, SOURCE_SALT};
use stele_reductions::stele_hash::merkle::Digest;

pub(crate) fn digest(words: &[u32]) -> Digest {
    let mut out = [0; 32];
    for (bytes, word) in out.chunks_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// RFC-0010 A9: serialize only a requested canonical column, including its salt.
#[cfg(any(test, feature = "cuda"))]
pub(crate) fn payload(shape: &Shape, index: u64, encoded: &[u32]) -> Option<Vec<u8>> {
    let desc = shape.source()?.descriptor();
    if index >= desc.count
        || encoded.len() != shape.rows()
        || encoded.iter().any(|x| M31::from_canonical(*x).is_none())
    {
        return None;
    }
    let width = usize::try_from(desc.width).ok()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(width).ok()?;
    bytes.resize(width, 0);
    MaskStream::new(&shape.seed, SOURCE_SALT, shape.id)
        .fill_at(index.checked_mul(32)?, &mut bytes[..32]);
    for (out, word) in bytes[32..].chunks_exact_mut(4).zip(encoded) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    Some(bytes)
}

/// Salted columns and every Merkle level, leaves first and root last.
pub struct Material {
    columns: Vec<u8>,
    nodes: Vec<u32>,
    width: usize,
    leaves: usize,
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
        let mut columns = Vec::new();
        columns.try_reserve_exact(bytes).ok()?;
        columns.resize(bytes, 0);
        let salts = MaskStream::new(&shape.seed, SOURCE_SALT, shape.id);
        for (index, column) in columns.chunks_exact_mut(width).enumerate() {
            salts.fill_at(
                u64::try_from(index.checked_mul(32)?).ok()?,
                &mut column[..32],
            );
            for (bytes, word) in column[32..]
                .chunks_mut(4)
                .zip(&encoded[index * rows..(index + 1) * rows])
            {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
        }
        Some(Self {
            columns,
            nodes,
            width,
            leaves,
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
    use crate::Field;

    #[test]
    fn matches_reference_selected_payload() {
        use stele_reductions::stele_hash::HashUsage;
        use stele_reductions::stele_pcs::{Policy, PreparedSource};
        let shape = Shape::new(3, 9, 19);
        let message = shape.message();
        let words: Vec<_> = message.iter().map(|v| v.as_u32()).collect();
        let encoded = encode_rows(&words, shape.rows(), shape.log_n(), u32::from(BLOWUP));
        let reference = PreparedSource::<crate::QM31>::hiding_with(
            shape.id,
            shape.ell,
            shape.m,
            BLOWUP,
            &message,
            &shape.seed,
            &mut HashUsage::default(),
            Policy::Two,
        )
        .unwrap();
        let last = reference.source().descriptor().count - 1;
        for index in [last, 0, last / 2, 1, last, 0] {
            let at = index as usize * shape.rows();
            assert_eq!(
                payload(&shape, index, &encoded[at..at + shape.rows()]).unwrap(),
                reference.response(index).unwrap().payload,
            );
        }
    }

    #[test]
    fn rejects_invalid_selected_payload() {
        let shape = Shape::new(3, 9, 1);
        let count = shape.source().unwrap().descriptor().count;
        let mut words = vec![0; shape.rows()];
        words[1] = 1;
        words[2] = M31::MODULUS - 1;
        let bytes = payload(&shape, 0, &words).unwrap();
        assert_eq!(&bytes[32..36], &0u32.to_le_bytes());
        assert_eq!(&bytes[36..40], &1u32.to_le_bytes());
        assert_eq!(&bytes[40..44], &(M31::MODULUS - 1).to_le_bytes());
        assert!(payload(&shape, count, &words).is_none());
        assert!(payload(&shape, u64::MAX, &words).is_none());
        assert!(payload(&shape, 0, &words[..words.len() - 1]).is_none());
        assert!(payload(&shape, 0, &vec![0; words.len() + 1]).is_none());
        assert!(payload(&Shape::new(30, 9, 1), 0, &[]).is_none());
        for invalid in [M31::MODULUS, M31::MODULUS + 1, u32::MAX] {
            words[0] = invalid;
            assert!(payload(&shape, 0, &words).is_none());
        }
    }

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
