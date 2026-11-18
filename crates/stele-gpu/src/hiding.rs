//! RFC-0014 A5. Device-resident A15 encoding and selected complete Merkle paths.
use crate::device::{Original, Session};
use crate::runtime::Error;
use cudarc::driver::{CudaSlice, PushKernelArg};
use stele_kernels::{HidingBackend, SourceColumn, SourceGeometry, M31};

#[path = "hiding_transform.rs"]
mod transform;

pub struct Columns<'s, 'd> {
    session: &'s Session<'d>,
    geometry: SourceGeometry,
    encoded: CudaSlice<u32>,
    nodes: CudaSlice<u32>,
    leaves: usize,
}

fn digest(words: &[u32]) -> [u8; 32] {
    let mut out = [0; 32];
    for (target, word) in out.chunks_exact_mut(4).zip(words) {
        target.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn prefix(geometry: SourceGeometry, count: usize, tag: u8) -> [u8; 43] {
    let mut out = [0; 43];
    out[0] = tag;
    out[1..18].copy_from_slice(b"stele/v0.1/merkle");
    // Offset 18 is Merkle Kind::Columns (zero) for both the leaf and node domains.
    out[19..27].copy_from_slice(&geometry.id.to_le_bytes());
    out[27..35].copy_from_slice(&(count as u64).to_le_bytes());
    out[35..].copy_from_slice(&(32 + 4 * geometry.rows as u64).to_le_bytes());
    out
}

impl<'d> HidingBackend for Session<'d> {
    type Columns<'s>
        = Columns<'s, 'd>
    where
        Self: 's;

    fn prepare_columns<'s>(
        &'s self,
        g: SourceGeometry,
        original: &Original<'_, 'd>,
        seed: &[u8; 32],
        hashes: &mut u64,
    ) -> Result<(Columns<'s, 'd>, [u8; 32]), Error> {
        let message = original.checked_words(self, g)?;
        let leaves = g.columns.checked_mul(4).ok_or(Error::Geometry)?;
        // The Circle domain and the 24-entry BLAKE3 chunk stack have fixed bounds.
        if leaves.ilog2() > 30 || g.rows > 1 << 30 {
            return Err(Error::Geometry);
        }
        let values = leaves.checked_mul(g.rows).ok_or(Error::Budget)?;
        let digests = leaves
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Error::Budget)?;
        // Reserve counter capacity before issuing the first hash.
        hashes.checked_add(digests as u64).ok_or(Error::Budget)?;
        let node_words = digests.checked_mul(8).ok_or(Error::Budget)?;
        let bytes = values
            .checked_add(node_words)
            .and_then(|n| n.checked_add(leaves))
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| n.checked_add(2 * 43 + 32 + 64))
            .ok_or(Error::Budget)?;
        let dev = self.device;
        let _guard = dev.allocation(bytes)?;
        let stream = &dev.stream;
        let mut encoded = stream.alloc_zeros::<u32>(values)?;
        transform::encode(dev, g.rows, g.columns, message, &mut encoded)?;
        let mut nodes = stream.alloc_zeros::<u32>(node_words)?;
        let leaf_prefix = dev.complete_transfer(stream.clone_htod(&prefix(g, leaves, 0)))?;
        let node_prefix = dev.complete_transfer(stream.clone_htod(&prefix(g, leaves, 1)))?;
        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ])
        });
        let key = dev.complete_transfer(stream.clone_htod(&key_words))?;
        let label = b"stele/v0.1/zk/source-salt";
        let mut block = [0; 64];
        block[..label.len()].copy_from_slice(label);
        block[label.len()..label.len() + 8].copy_from_slice(&g.id.to_le_bytes());
        let salt_words: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ])
        });
        let salt_block = dev.complete_transfer(stream.clone_htod(&salt_words))?;
        let slen = (label.len() + 8) as u32;
        let rows = g.rows as u64;
        let count = leaves as u64;
        let op = dev.kernel("leaf_kernel")?;
        let mut launch = stream.launch_builder(&op);
        launch
            .arg(&encoded)
            .arg(&rows)
            .arg(&count)
            .arg(&leaf_prefix)
            .arg(&key)
            .arg(&salt_block)
            .arg(&slen)
            .arg(&mut nodes);
        // SAFETY: each canonical leaf owns eight words; encoded covers every physical row.
        unsafe { launch.launch(dev.grid(leaves)) }?;
        stream.synchronize()?;
        *hashes += count;
        self.record(|c| c.source_hashes += count);
        let op = dev.kernel("node_kernel")?;
        let (mut offset, mut width, mut level) = (0usize, leaves, 1u32);
        while width > 1 {
            let next = offset + width * 8;
            let (before, mut after) = nodes.split_at_mut(next);
            let children = before.slice(offset..next);
            let mut parents = after.slice_mut(..width / 2 * 8);
            let count = (width / 2) as u64;
            let mut launch = stream.launch_builder(&op);
            launch
                .arg(&children)
                .arg(&mut parents)
                .arg(&count)
                .arg(&level)
                .arg(&node_prefix);
            // SAFETY: disjoint adjacent levels have exactly two child digests per parent.
            unsafe { launch.launch(dev.grid(width / 2)) }?;
            stream.synchronize()?;
            *hashes += count;
            self.record(|c| c.source_hashes += count);
            offset = next;
            width /= 2;
            level += 1;
        }
        let root = dev.complete_transfer(stream.clone_dtoh(&nodes.slice(offset..offset + 8)))?;
        let peak = dev.check_peak()?;
        self.record(|c| {
            c.source_visits += 1;
            c.source_uploaded_bytes += (4 * (g.columns - 1 + leaves - 1) + 2 * 43 + 32 + 64) as u64;
            c.source_downloaded_bytes += 32;
            c.source_observed_peak_bytes = c.source_observed_peak_bytes.max(peak);
        });
        Ok((
            Columns {
                session: self,
                geometry: g,
                encoded,
                nodes,
                leaves,
            },
            digest(&root),
        ))
    }

    fn selected_column(
        &self,
        g: SourceGeometry,
        tree: &Columns<'_, 'd>,
        index: usize,
    ) -> Result<SourceColumn, Error> {
        if !std::ptr::eq(self, tree.session) || tree.geometry != g {
            return Err(Error::Source);
        }
        if index >= tree.leaves {
            return Err(Error::Geometry);
        }
        let n = g.rows + 8 * tree.leaves.ilog2() as usize;
        let dev = self.device;
        let _guard = dev.allocation(n.checked_mul(4).ok_or(Error::Budget)?)?;
        let stream = &dev.stream;
        let mut output = stream.alloc_zeros::<u32>(n)?;
        let (rows, leaves, index, count) =
            (g.rows as u64, tree.leaves as u64, index as u64, n as u64);
        let op = dev.kernel("selected_column_kernel")?;
        let mut launch = stream.launch_builder(&op);
        launch
            .arg(&tree.encoded)
            .arg(&tree.nodes)
            .arg(&rows)
            .arg(&leaves)
            .arg(&index)
            .arg(&count)
            .arg(&mut output);
        // SAFETY: index < leaves, each derived sibling belongs to its complete level.
        unsafe { launch.launch(dev.grid(n)) }?;
        let result = dev.complete_transfer(stream.clone_dtoh(&output))?;
        let peak = dev.check_peak()?;
        let (values, path) = result.split_at(g.rows);
        let symbols = values
            .iter()
            .map(|w| M31::from_canonical(*w).ok_or(Error::Noncanonical))
            .collect::<Result<_, _>>()?;
        let siblings = path.chunks_exact(8).map(digest).collect();
        self.record(|c| {
            c.source_responses += 1;
            c.source_downloaded_bytes += n as u64 * 4;
            c.source_observed_peak_bytes = c.source_observed_peak_bytes.max(peak);
        });
        Ok(SourceColumn { symbols, siblings })
    }
}
