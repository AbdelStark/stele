//! RFC-0008 A7. Build leaf pairs directly from compact original input columns.
use super::{build_levels, select, Device, Error, Timing, Tree, K};
use crate::compact_lookup::{Input, Packed};
use cudarc::driver::PushKernelArg;
use std::time::{Duration, Instant};

fn build<'a>(
    dev: &'a Device,
    input: &Input<'_>,
    selected: bool,
    stage_inputs: impl FnOnce(&mut Packed),
) -> Result<(Tree<'a>, usize, usize, Timing), Error> {
    let now = Instant::now();
    let mut p = Packed::new(input).map_err(Error::Shape)?;
    stage_inputs(&mut p);
    let upload_bytes = p.upload_bytes();
    let retained_bytes = 4 * p.tree_words;
    let buffer_peak_bytes = upload_bytes + retained_bytes + 20 * p.top;
    dev.require_budget(buffer_peak_bytes)?;
    let stage = now.elapsed();
    let now = Instant::now();
    let fields = dev.stream().clone_htod(&p.fields)?;
    let members = dev.stream().clone_htod(&p.descriptors)?;
    let shifts = dev.stream().clone_htod(&p.shifts)?;
    let tree = Tree::sized(dev, p.tree_words, p.top)?;
    dev.sync()?;
    let upload = now.elapsed();
    let now = Instant::now();
    let f = dev.function("lookup_compact_leaf")?;
    let (fp, mp, sp, tp) = (
        dev.ptr(&fields),
        dev.ptr(&members),
        dev.ptr(&shifts),
        dev.ptr(&tree.pairs),
    );
    let n = p.n as u64;
    let mut kernel = dev.stream().launch_builder(&f);
    kernel
        .arg(&fp)
        .arg(&mp)
        .arg(&sp)
        .arg(&tp)
        .arg(&n)
        .arg(&p.width)
        .arg(&p.members)
        .arg(&p.valid)
        .arg(&p.mults);
    // SAFETY: Packed checks every field/projection extent and tree capacity before upload.
    // Thread x writes four disjoint canonical QM31 words at its two leaf positions.
    unsafe { kernel.launch(dev.grid(p.n)) }?;
    build_levels(&tree, p.leaves, if selected { p.top } else { 1 })?;
    let (leaves, top) = (p.leaves, p.top);
    drop((fields, members, shifts, p));
    dev.sync()?;
    let build = now.elapsed();
    Ok((
        tree,
        leaves,
        top,
        Timing {
            stage,
            upload,
            tree: build,
            top: Duration::ZERO,
            download: Duration::ZERO,
            assemble: Duration::ZERO,
            upload_bytes,
            download_bytes: 0,
            buffer_peak_bytes,
            retained_bytes,
        },
    ))
}

pub fn top(dev: &Device, input: &Input<'_>) -> Result<([Vec<K>; 3], Timing), Error> {
    let (tree, _, count, t) = build(dev, input, true, |_| {})?;
    select::finish_top(dev, count, tree, t)
}

pub fn resident<'a>(
    dev: &'a Device,
    id: usize,
    input: &Input<'_>,
) -> Result<(select::Resident<'a>, Timing), Error> {
    let (tree, leaves, _, t) = build(dev, input, false, |_| {})?;
    let owner = select::finish_resident(dev, id, leaves, tree);
    dev.sync()?;
    Ok((owner, t))
}
