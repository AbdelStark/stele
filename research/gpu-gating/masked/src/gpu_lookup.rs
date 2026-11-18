//! RFC-0008 A7 items 2/3: actual lookup leaves, every tree layer and top on CUDA.
use crate::gpu::{Device, Error};
use crate::lookup::Prepared;
use crate::K;
use cudarc::driver::{CudaSlice, PushKernelArg};
use std::time::{Duration, Instant};
use stele_reductions::zk::claims::bench::{LookupInputs, LookupTree};

#[path = "gpu_lookup_resident.rs"]
pub mod select;

#[cfg(test)]
#[path = "gpu_lookup_tests.rs"]
mod tests;

/// Operation wall times and exact explicit buffers, excluding CUDA infrastructure.
/// Callers must additionally charge production inputs(), constructor, cold context
/// and module setup, whole-process wall/RSS and observed device peak.
pub struct Timing {
    pub stage: Duration,
    pub upload: Duration,
    pub tree: Duration,
    pub top: Duration,
    pub download: Duration,
    pub assemble: Duration,
    pub upload_bytes: usize,
    pub download_bytes: usize,
    /// All input, retained tree, h and flag buffers coexist until this call returns.
    pub buffer_peak_bytes: usize,
    /// Tree plus h on device; p and q already occur in the tree.
    pub retained_bytes: usize,
}

struct Tree<'a> {
    dev: &'a Device,
    pairs: CudaSlice<u32>,
    h: CudaSlice<u32>,
    flags: CudaSlice<u32>,
}

impl<'a> Tree<'a> {
    fn new(dev: &'a Device, p: &Prepared) -> Result<Self, Error> {
        Ok(Self {
            dev,
            pairs: dev.stream().alloc_zeros(p.tree_words)?,
            h: dev.stream().alloc_zeros(4 * p.top)?,
            flags: dev.stream().alloc_zeros(p.top)?,
        })
    }

    fn leaf(
        &self,
        values: &CudaSlice<u32>,
        selector: &CudaSlice<u32>,
        p: &Prepared,
    ) -> Result<(), Error> {
        let f = self.dev.function("lookup_leaf")?;
        let (input, sel, out, n, width, mults) = (
            self.dev.ptr(values),
            self.dev.ptr(selector),
            self.dev.ptr(&self.pairs),
            p.n as u64,
            p.width as u64,
            p.mults as u64,
        );
        let mut b = self.dev.stream().launch_builder(&f);
        b.arg(&input)
            .arg(&sel)
            .arg(&out)
            .arg(&n)
            .arg(&width)
            .arg(&mults);
        // SAFETY: Prepared checks RFC-0008 A7 geometry; values and selectors have
        // exactly its lengths, pairs holds all 2*leaves-1 nodes; each x is disjoint.
        unsafe { b.launch(self.dev.grid(p.n)) }?;
        Ok(())
    }

    fn level(&self, count: usize) -> Result<(), Error> {
        let f = self.dev.function("lookup_level")?;
        let (out, n) = (self.dev.ptr(&self.pairs), count as u64);
        let mut b = self.dev.stream().launch_builder(&f);
        b.arg(&out).arg(&n);
        // SAFETY: count halves from leaves/2 to 1; both child and parent ranges
        // lie in pairs and are disjoint. One stream orders levels (RFC-0014 §1).
        unsafe { b.launch(self.dev.grid(count)) }?;
        Ok(())
    }

    fn divide(&self) -> Result<(), Error> {
        let f = self.dev.function("lookup_top")?;
        let (pairs, h, flags, count) = (
            self.dev.ptr(&self.pairs),
            self.dev.ptr(&self.h),
            self.dev.ptr(&self.flags),
            self.flags.len() as u64,
        );
        let mut b = self.dev.stream().launch_builder(&f);
        b.arg(&pairs).arg(&h).arg(&flags).arg(&count);
        // SAFETY: Prepared bounds top by leaves. One h and flag per top pair;
        // no atomic reduction and every output is canonical (RFC-0003 §1).
        unsafe { b.launch(self.dev.grid(self.flags.len())) }?;
        Ok(())
    }
}

/// Build the tree down to the lowest consumed layer, retaining the device pairs.
fn build<'a>(
    dev: &'a Device,
    p: &Prepared,
    lowest: usize,
) -> Result<(Tree<'a>, Duration, Duration), Error> {
    let start = Instant::now();
    let values = dev.stream().clone_htod(&p.values)?;
    let selector = dev.stream().clone_htod(&p.selector)?;
    let tree = Tree::new(dev, p)?;
    dev.sync()?;
    let upload = start.elapsed();
    let start = Instant::now();
    tree.leaf(&values, &selector, p)?;
    let mut width = p.leaves / 2;
    while width >= lowest {
        tree.level(width)?;
        width /= 2;
    }
    dev.sync()?;
    let tree_time = start.elapsed();
    Ok((tree, upload, tree_time))
}

/// Consume production-normalized inputs and return all canonical layers and p/q/h.
/// No proof, commitment, transcript or core backend calls this research operation.
pub fn prepare(dev: &Device, input: &LookupInputs<K>) -> Result<(LookupTree<K>, Timing), Error> {
    let start = Instant::now();
    let p = Prepared::new(input)?;
    let stage = start.elapsed();
    let (tree, upload, tree_time) = build(dev, &p, 1)?;
    let start = Instant::now();
    tree.divide()?;
    dev.sync()?;
    let top = start.elapsed();
    let start = Instant::now();
    let pairs = dev.stream().clone_dtoh(&tree.pairs)?;
    let h = dev.stream().clone_dtoh(&tree.h)?;
    let flags = dev.stream().clone_dtoh(&tree.flags)?;
    dev.sync()?;
    let download = start.elapsed();
    let start = Instant::now();
    let result = p.finish(&pairs, &h, &flags)?;
    let assemble = start.elapsed();
    let upload_bytes = 4 * (p.values.len() + p.selector.len());
    let download_bytes = 4 * (p.tree_words + 5 * p.top);
    Ok((
        result,
        Timing {
            stage,
            upload,
            tree: tree_time,
            top,
            download,
            assemble,
            upload_bytes,
            download_bytes,
            buffer_peak_bytes: upload_bytes + download_bytes,
            retained_bytes: 4 * (p.tree_words + 4 * p.top),
        },
    ))
}
