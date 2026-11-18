//! RFC-0008 A7: selected tops and resident, root-first layer pairs for GKR.
use super::{build, Device, Error, LookupInputs, Prepared, Timing, K};
use crate::lookup::{element, words, Error as LookupError};
use cudarc::driver::{CudaSlice, CudaView};
use std::time::{Duration, Instant};

/// RFC-0014 A1. The current pool includes all live buffers for earlier stages.
fn start<'a>(
    dev: &'a Device,
    input: &LookupInputs<K>,
    only_top: bool,
    stage_input: impl FnOnce(&mut Prepared),
) -> Result<(Prepared, super::Tree<'a>, Timing), Error> {
    let since = Instant::now();
    let mut p = Prepared::new(input)?;
    stage_input(&mut p);
    let upload_bytes = 4 * (p.values.len() + p.selector.len());
    let peak = upload_bytes + 4 * (p.tree_words + 5 * p.top);
    dev.require_budget(peak)?;
    let stage = since.elapsed();
    let (tree, upload, build) = build(dev, &p, if only_top { p.top } else { 1 })?;
    let retained = 4 * p.tree_words;
    Ok((
        p,
        tree,
        Timing {
            stage,
            upload,
            tree: build,
            top: Duration::ZERO,
            download: Duration::ZERO,
            assemble: Duration::ZERO,
            upload_bytes,
            download_bytes: 0,
            buffer_peak_bytes: peak,
            retained_bytes: retained,
        },
    ))
}

/// First visit: the prover commits just the top p, q, h; flag every zero denominator.
pub fn top(dev: &Device, input: &LookupInputs<K>) -> Result<([Vec<K>; 3], Timing), Error> {
    run_top(dev, input, |_| {})
}

fn run_top(
    dev: &Device,
    input: &LookupInputs<K>,
    stage_input: impl FnOnce(&mut Prepared),
) -> Result<([Vec<K>; 3], Timing), Error> {
    let (p, tree, t) = start(dev, input, true, stage_input)?;
    finish_top(dev, p.top, tree, t)
}

pub(super) fn finish_top(
    dev: &Device,
    count: usize,
    tree: super::Tree<'_>,
    mut t: Timing,
) -> Result<([Vec<K>; 3], Timing), Error> {
    let since = Instant::now();
    tree.divide()?;
    dev.sync()?;
    t.top = since.elapsed();
    let since = Instant::now();
    let pairs = dev
        .stream()
        .clone_dtoh(&tree.pairs.slice(8 * (count - 1)..8 * (2 * count - 1)))?;
    let h = dev.stream().clone_dtoh(&tree.h)?;
    let flags = dev.stream().clone_dtoh(&tree.flags)?;
    dev.sync()?;
    t.download = since.elapsed();
    t.download_bytes = 4 * (pairs.len() + h.len() + flags.len());
    let since = Instant::now();
    if flags.iter().any(|f| *f > 1) {
        return Err(LookupError::Value.into());
    }
    if flags.contains(&1) {
        return Err(LookupError::DenominatorZero.into());
    }
    let mut top = [
        Vec::with_capacity(count),
        Vec::with_capacity(count),
        Vec::with_capacity(count),
    ];
    for (pair, ratio) in pairs.chunks_exact(8).zip(h.chunks_exact(4)) {
        top[0].push(element(&pair[..4])?);
        top[1].push(element(&pair[4..])?);
        top[2].push(element(ratio)?);
    }
    t.assemble = since.elapsed();
    t.retained_bytes = 0;
    Ok((top, t))
}

/// Rebuild: no division and no D2H. A layer view borrows this allocation.
pub fn resident<'a>(
    dev: &'a Device,
    id: usize,
    input: &LookupInputs<K>,
) -> Result<(Resident<'a>, Timing), Error> {
    run_resident(dev, id, input, |_| {})
}

fn run_resident<'a>(
    dev: &'a Device,
    id: usize,
    input: &LookupInputs<K>,
    stage_input: impl FnOnce(&mut Prepared),
) -> Result<(Resident<'a>, Timing), Error> {
    let (p, tree, t) = start(dev, input, false, stage_input)?;
    Ok((finish_resident(dev, id, p.leaves, tree), t))
}

pub(super) fn finish_resident<'a>(
    dev: &'a Device,
    id: usize,
    leaves: usize,
    tree: super::Tree<'a>,
) -> Resident<'a> {
    Resident {
        dev,
        id,
        leaves,
        pairs: tree.pairs,
    }
}

#[cfg(test)]
fn lift(p: &mut Prepared) {
    crate::lookup_cases::lazy(&mut p.values);
    crate::lookup_cases::lazy(&mut p.selector);
}

#[cfg(test)]
pub(super) fn top_raw(
    dev: &Device,
    input: &LookupInputs<K>,
) -> Result<([Vec<K>; 3], Timing), Error> {
    run_top(dev, input, lift)
}

#[cfg(test)]
pub(super) fn resident_raw<'a>(
    dev: &'a Device,
    id: usize,
    input: &LookupInputs<K>,
) -> Result<(Resident<'a>, Timing), Error> {
    run_resident(dev, id, input, lift)
}

pub struct Resident<'a> {
    dev: &'a Device,
    id: usize,
    leaves: usize,
    pairs: CudaSlice<u32>,
}

impl Resident<'_> {
    pub fn bytes(&self) -> usize {
        4 * self.pairs.len()
    }

    pub(crate) fn check(&self, dev: &Device, id: usize) -> Result<(), Error> {
        if id != self.id || !std::ptr::eq(dev, self.dev) {
            return Err(Error::Shape("lookup context"));
        }
        Ok(())
    }

    /// Level of the specified width at pair offsets [width-1,2*width-1).
    pub(crate) fn layer(
        &self,
        dev: &Device,
        id: usize,
        width: usize,
    ) -> Result<CudaView<'_, u32>, Error> {
        self.check(dev, id)?;
        if !width.is_power_of_two() || width > self.leaves {
            return Err(Error::Shape("lookup layer width"));
        }
        Ok(self.pairs.slice(8 * (width - 1)..8 * (2 * width - 1)))
    }

    /// Qualification only. Validate every pair in deterministic order, with
    /// bounded CPU scratch and explicit D2H; a production consumer reads a view.
    pub fn compare_all(&self, expected: &[Vec<[K; 2]>]) -> Result<usize, Error> {
        if expected.len() != 1 + self.leaves.ilog2() as usize {
            return Err(Error::Shape("lookup layer count"));
        }
        let mut copied = 0;
        for (k, layer) in expected.iter().enumerate() {
            let width = 1usize << k;
            if layer.len() != width {
                return Err(Error::Shape("lookup layer width"));
            }
            let view = self.layer(self.dev, self.id, width)?;
            const CHUNK: usize = 1 << 16;
            for (group, chunk) in layer.chunks(CHUNK).enumerate() {
                let begin = 8 * group * CHUNK;
                let out = self
                    .dev
                    .stream()
                    .clone_dtoh(&view.slice(begin..begin + 8 * chunk.len()))?;
                for (wanted, got) in chunk.iter().zip(out.chunks_exact(8)) {
                    if words(wanted[0]) != got[..4] || words(wanted[1]) != got[4..] {
                        return Err(Error::Value);
                    }
                }
                copied += 4 * out.len();
            }
        }
        Ok(copied)
    }
}
