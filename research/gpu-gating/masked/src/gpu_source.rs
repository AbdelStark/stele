//! E16-36: hiding-source preparation on the device (feature `cuda`): `M'` uploaded,
//! transposed to symbol-major, Circle-encoded in place, leaves `salt || column` and
//! the Merkle tree hashed on the device; only the 32-byte root comes back.
use crate::gpu::{Device, Error};
use crate::source::{prefix, salt_block, twiddles, Shape, BLOWUP};
use crate::{Field, M31};
use cudarc::driver::{CudaSlice, LaunchConfig, PushKernelArg};
use std::time::{Duration, Instant};

/// Wall times of one device preparation.
pub struct Timing {
    /// `M'`, twiddles, descriptor prefixes and the salt key to the device.
    pub upload: Duration,
    /// Transpose, inverse and forward transforms.
    pub encode: Duration,
    /// Leaf digests and the tree.
    pub merkle: Duration,
}

/// Prepare `shape` from its row-major `M'` on `dev`: the root and the phase times.
pub fn prepare(dev: &Device, shape: &Shape, message: &[M31]) -> Result<([u8; 32], Timing), Error> {
    let source = shape.source().ok_or(Error::Value)?;
    let desc = source.descriptor();
    let (rows, log_n) = (shape.rows(), shape.log_n());
    let log_big = log_n + u32::from(BLOWUP);
    let (n, big) = (1usize << log_n, 1usize << log_big);
    if desc.count != big as u64 || desc.width != 32 + 4 * rows as u64 {
        return Err(Error::Value);
    }
    let inv = twiddles(log_n, true);
    let fwd = twiddles(log_big, false);
    let scale = M31::from_u64(n as u64)
        .pow(u64::from(M31::MODULUS) - 2)
        .as_u32();
    let (sblock, slen) = salt_block(shape.id);
    let key: Vec<u32> = shape
        .seed
        .chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // Upload.
    let start = Instant::now();
    let host: Vec<u32> = message.iter().map(|v| v.as_u32()).collect();
    let msg = dev.stream().clone_htod(&host)?;
    let upload_levels = |levels: &[Vec<u32>]| -> Result<Vec<CudaSlice<u32>>, Error> {
        levels
            .iter()
            .map(|l| Ok(dev.stream().clone_htod(l)?))
            .collect()
    };
    let (inv_dev, fwd_dev) = (upload_levels(&inv)?, upload_levels(&fwd)?);
    let leaf_prefix = dev.stream().clone_htod(&prefix(&desc, desc.kind as u8))?;
    let node_prefix = dev.stream().clone_htod(&prefix(&desc, 1))?;
    let key_dev = dev.stream().clone_htod(&key)?;
    let sblock_dev = dev.stream().clone_htod(&sblock.to_vec())?;
    dev.sync()?;
    let upload = start.elapsed();

    // Encode: transpose into the head of the codeword buffer, inverse on the head,
    // forward on the whole (the tail stays zero).
    let start = Instant::now();
    let x = dev.stream().alloc_zeros::<u32>(big * rows)?;
    let (xp, mp) = (dev.ptr(&x), dev.ptr(&msg));
    let (rows64, n64) = (rows as u64, n as u64);
    {
        let f = dev.function("transpose_kernel")?;
        let mut b = dev.stream().launch_builder(&f);
        b.arg(&mp).arg(&xp).arg(&rows64).arg(&n64);
        let cfg = LaunchConfig {
            grid_dim: (n.div_ceil(32) as u32, rows.div_ceil(32) as u32, 1),
            block_dim: (32, 8, 1),
            shared_mem_bytes: 0,
        };
        // SAFETY: `msg` has rows·n entries; `x` has big·rows ≥ n·rows.
        unsafe { b.launch(cfg) }?;
    }
    let level =
        |levels: &[CudaSlice<u32>], hs: &[usize], len: usize, inverse: i32| -> Result<(), Error> {
            let f = dev.function("level_kernel")?;
            for (tw, h) in levels.iter().zip(hs) {
                let (tp, h64, len64) = (dev.ptr(tw), *h as u64, len as u64);
                let threads = (len / (2 * h)) * h.div_ceil(2) * rows;
                let mut b = dev.stream().launch_builder(&f);
                b.arg(&xp)
                    .arg(&tp)
                    .arg(&h64)
                    .arg(&rows64)
                    .arg(&len64)
                    .arg(&inverse);
                // SAFETY: `x` has len·rows entries in use; `tw` has h entries.
                unsafe { b.launch(dev.grid(threads)) }?;
            }
            Ok(())
        };
    let bitrev = |log: u32| -> Result<(), Error> {
        let f = dev.function("bitrev_kernel")?;
        let log = log as i32;
        let mut b = dev.stream().launch_builder(&f);
        b.arg(&xp).arg(&rows64).arg(&log);
        // SAFETY: `x` has 2^log·rows entries in use.
        unsafe { b.launch(dev.grid((1usize << log) * rows)) }?;
        Ok(())
    };
    let inv_h: Vec<usize> = inv.iter().map(Vec::len).collect();
    level(&inv_dev, &inv_h, n, 1)?;
    bitrev(log_n)?;
    {
        let f = dev.function("scale_kernel")?;
        let count = (n * rows) as u64;
        let mut b = dev.stream().launch_builder(&f);
        b.arg(&xp).arg(&scale).arg(&count);
        // SAFETY: `x` has n·rows entries in use.
        unsafe { b.launch(dev.grid(n * rows)) }?;
    }
    bitrev(log_big)?;
    let fwd_rev: Vec<CudaSlice<u32>> = fwd_dev.into_iter().rev().collect();
    let fwd_h: Vec<usize> = fwd.iter().rev().map(Vec::len).collect();
    level(&fwd_rev, &fwd_h, big, 0)?;
    dev.sync()?;
    let encode = start.elapsed();
    drop(msg);

    // Merkle: leaves, then each level up to the root.
    let start = Instant::now();
    let mut digests = dev.stream().alloc_zeros::<u32>(big * 8)?;
    {
        let f = dev.function("leaf_kernel")?;
        let (dp, lp, kp, sp, leaves) = (
            dev.ptr(&digests),
            dev.ptr(&leaf_prefix),
            dev.ptr(&key_dev),
            dev.ptr(&sblock_dev),
            big as u64,
        );
        let mut b = dev.stream().launch_builder(&f);
        b.arg(&xp)
            .arg(&rows64)
            .arg(&leaves)
            .arg(&lp)
            .arg(&kp)
            .arg(&sp)
            .arg(&slen)
            .arg(&dp);
        // SAFETY: `x` holds big·rows symbols; `digests` 8 words per leaf.
        unsafe { b.launch(dev.grid_with(big, 128)) }?;
    }
    let f = dev.function("node_kernel")?;
    let np = dev.ptr(&node_prefix);
    let (mut width, mut level_no) = (big, 1u32);
    while width > 1 {
        let parents = dev.stream().alloc_zeros::<u32>(width / 2 * 8)?;
        let (cp, pp, count) = (dev.ptr(&digests), dev.ptr(&parents), (width / 2) as u64);
        let mut b = dev.stream().launch_builder(&f);
        b.arg(&cp).arg(&pp).arg(&count).arg(&level_no).arg(&np);
        // SAFETY: `digests` has 2·count digests, `parents` count.
        unsafe { b.launch(dev.grid_with(width / 2, 128)) }?;
        digests = parents;
        width /= 2;
        level_no += 1;
    }
    let root_words = dev.stream().clone_dtoh(&digests)?;
    let merkle = start.elapsed();
    drop(x);
    let mut root = [0u8; 32];
    for (o, w) in root.chunks_mut(4).zip(root_words) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    Ok((
        root,
        Timing {
            upload,
            encode,
            merkle,
        },
    ))
}
