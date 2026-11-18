//! RFC-0010 A2. Circle twiddles and integer-only transforms for interleaved rows.
use crate::runtime::{Cuda, Error};
use cudarc::driver::{CudaSlice, LaunchConfig, PushKernelArg};
use stele_kernels::{Field, M31};

fn multiply(a: (M31, M31), b: (M31, M31)) -> (M31, M31) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

fn twiddles(log: u32, inverse: bool) -> Vec<u32> {
    let half = 1usize << (log - 1);
    let mut point = (M31::from_u64(1717986917), M31::from_u64(1288490189));
    for _ in log..30 {
        point = multiply(point, point);
    }
    let step = multiply(point, point);
    let mut table = vec![M31::ZERO; 2 * half - 1];
    for i in 0..half {
        table[i] = point.1;
        if i < half / 2 {
            table[half + i] = point.0;
        }
        point = multiply(point, step);
    }
    let mut offset = half;
    let mut width = half / 2;
    while width > 1 {
        for i in 0..width / 2 {
            let square = table[offset + i] * table[offset + i];
            table[offset + width + i] = square + square - M31::ONE;
        }
        offset += width;
        width /= 2;
    }
    if inverse {
        // All twiddles are nonzero in the canonical fixed domain (RFC-0010 A2).
        let mut prefixes = Vec::with_capacity(table.len());
        let mut product = M31::ONE;
        for &t in &table {
            prefixes.push(product);
            product = product * t;
        }
        let mut inv = product.pow(u64::from(M31::MODULUS) - 2);
        for (t, p) in table.iter_mut().zip(prefixes).rev() {
            let old = *t;
            *t = inv * p;
            inv = inv * old;
        }
    }
    table.into_iter().map(|t| t.as_u32()).collect()
}

fn bit_reverse(dev: &Cuda, data: &mut CudaSlice<u32>, rows: u64, log: u32) -> Result<(), Error> {
    let op = dev.kernel("bitrev_kernel")?;
    let count = (1usize << log) * rows as usize;
    let log = log as i32;
    let mut launch = dev.stream.launch_builder(&op);
    launch.arg(data).arg(&rows).arg(&log);
    // SAFETY: the in-place swaps address only the checked count interleaved symbols.
    unsafe { launch.launch(dev.grid(count)) }?;
    Ok(())
}

fn levels(
    dev: &Cuda,
    data: &mut CudaSlice<u32>,
    rows: u64,
    n: usize,
    inverse: bool,
) -> Result<(), Error> {
    let log = n.ilog2();
    let host = twiddles(log, inverse);
    let table = dev.complete_transfer(dev.stream.clone_htod(&host))?;
    let op = dev.kernel("level_kernel")?;
    for k in 0..log {
        let h = if inverse { n >> (k + 1) } else { 1usize << k };
        // Levels are laid out with widths n/2, n/4, ..., 1.
        let offset = n - 2 * h;
        let tw = table.slice(offset..offset + h);
        let count = n / (2 * h) * h.div_ceil(2) * rows as usize;
        let (half, length, sign) = (h as u64, n as u64, i32::from(inverse));
        let mut launch = dev.stream.launch_builder(&op);
        launch
            .arg(&mut *data)
            .arg(&tw)
            .arg(&half)
            .arg(&rows)
            .arg(&length)
            .arg(&sign);
        // SAFETY: each thread touches its disjoint row/quad in n*rows, reading h twiddles.
        unsafe { launch.launch(dev.grid(count)) }?;
    }
    Ok(())
}

pub(super) fn encode(
    dev: &Cuda,
    rows: usize,
    n: usize,
    message: &CudaSlice<u32>,
    out: &mut CudaSlice<u32>,
) -> Result<(), Error> {
    let rows64 = rows as u64;
    let cols64 = n as u64;
    let op = dev.kernel("transpose_kernel")?;
    let mut launch = dev.stream.launch_builder(&op);
    launch.arg(message).arg(&mut *out).arg(&rows64).arg(&cols64);
    let tiles = LaunchConfig {
        grid_dim: (
            n.div_ceil(32) as u32,
            rows.div_ceil(32).min(65_535) as u32,
            1,
        ),
        block_dim: (32, 8, 1),
        shared_mem_bytes: 0,
    };
    // SAFETY: the exact physical message and zero-filled fourfold output were size checked.
    unsafe { launch.launch(tiles) }?;
    levels(dev, out, rows64, n, true)?;
    bit_reverse(dev, out, rows64, n.ilog2())?;
    let scale = M31::from_u64(cols64)
        .pow(u64::from(M31::MODULUS) - 2)
        .as_u32();
    let count = cols64 * rows64;
    let op = dev.kernel("scale_kernel")?;
    let mut launch = dev.stream.launch_builder(&op);
    launch.arg(&mut *out).arg(&scale).arg(&count);
    // SAFETY: only the populated n*rows prefix of out is scaled.
    unsafe { launch.launch(dev.grid(count as usize)) }?;
    bit_reverse(dev, out, rows64, (4 * n).ilog2())?;
    levels(dev, out, rows64, 4 * n, false)
}
