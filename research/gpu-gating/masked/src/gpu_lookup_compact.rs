//! RFC-0008 A7. Build leaf pairs directly from compact original input columns.
use super::{build_levels, select, Device, Error, Timing, Tree, K};
use crate::compact_lookup::{Input, Packed};
use crate::gpu::OriginalMessage;
use cudarc::driver::PushKernelArg;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn build<'a>(
    dev: &'a Device,
    input: &Input<'_>,
    selected: bool,
    stage_inputs: impl FnOnce(&mut Packed),
) -> Result<(Tree<'a>, usize, usize, Timing), Error> {
    build_with(dev, input, selected, None, stage_inputs)
}

/// Original column descriptors in member-major order, preceded by multiplicity.
/// Each entry is [column index, source index, physical rows, physical columns, data start, length].
#[derive(Clone, Copy)]
pub struct OriginalViews<'a, 'd> {
    pub columns: &'a [[usize; 6]],
    pub owners: &'a BTreeMap<u64, OriginalMessage<'d>>,
}

fn build_with<'a>(
    dev: &'a Device,
    input: &Input<'_>,
    selected: bool,
    originals: Option<OriginalViews<'_, '_>>,
    stage_inputs: impl FnOnce(&mut Packed),
) -> Result<(Tree<'a>, usize, usize, Timing), Error> {
    let now = Instant::now();
    let mut view_words = Vec::new();
    let mut p = if let Some(originals) = originals {
        let mut lengths = Vec::with_capacity(originals.columns.len());
        for &[_, source, rows, columns, at, len] in originals.columns {
            let source =
                u64::try_from(source).map_err(|_| Error::Shape("original lookup source ID"))?;
            let owner = originals
                .owners
                .get(&source)
                .ok_or(Error::Shape("missing original lookup source"))?;
            let words = owner.words(dev, source, rows, columns)?;
            if rows < 2
                || columns < 2
                || !rows.is_power_of_two()
                || !columns.is_power_of_two()
                || !len.is_power_of_two()
                || at.checked_add(len).is_none_or(|end| end > words.len() / 4)
            {
                return Err(Error::Shape("original lookup data quadrant"));
            }
            lengths.push(len);
            view_words.extend([
                dev.ptr(words),
                at as u64,
                (columns / 2).trailing_zeros() as u64,
            ]);
        }
        Packed::from_sources(input, &lengths)
    } else {
        Packed::new(input)
    }
    .map_err(Error::Shape)?;
    stage_inputs(&mut p);
    let upload_bytes = p
        .upload_bytes()
        .checked_add(size_of_val(view_words.as_slice()))
        .ok_or(Error::Shape("original view descriptor bytes"))?;
    let retained_bytes = 4 * p.tree_words;
    let buffer_peak_bytes = upload_bytes + retained_bytes + 20 * p.top;
    dev.require_budget(buffer_peak_bytes)?;
    let stage = now.elapsed();
    let now = Instant::now();
    let fields = dev.stream().clone_htod(&p.fields)?;
    let members = dev.stream().clone_htod(&p.descriptors)?;
    let shifts = dev.stream().clone_htod(&p.shifts)?;
    let views = originals
        .map(|_| dev.stream().clone_htod(&view_words))
        .transpose()?;
    let tree = Tree::sized(dev, p.tree_words, p.top)?;
    dev.sync()?;
    let upload = now.elapsed();
    let now = Instant::now();
    let f = dev.function(if originals.is_some() {
        "lookup_original_leaf"
    } else {
        "lookup_compact_leaf"
    })?;
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
    let view_pointer = views.as_ref().map(|v| dev.ptr(v));
    if let Some(ref ptr) = view_pointer {
        kernel.arg(ptr);
    }
    // SAFETY: Each original owner is on this device, held through the sync below.
    // Its checked data-quadrant interval contains every gathered leg position.
    // Packed checks every field/projection extent and tree capacity before upload.
    // Thread x writes four disjoint canonical QM31 words at its two leaf positions.
    unsafe { kernel.launch(dev.grid(p.n)) }?;
    build_levels(&tree, p.leaves, if selected { p.top } else { 1 })?;
    let (leaves, top) = (p.leaves, p.top);
    drop((fields, members, shifts, views, view_words, p));
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

/// Select the committed top from the original immutable sources.
pub fn top_original(
    dev: &Device,
    input: &Input<'_>,
    originals: OriginalViews<'_, '_>,
) -> Result<([Vec<K>; 3], Timing), Error> {
    let (tree, _, count, t) = build_with(dev, input, true, Some(originals), |_| {})?;
    select::finish_top(dev, count, tree, t)
}

/// Keep the tree for GKR; the original messages continue to belong to their PCS owners.
pub fn resident_original<'a>(
    dev: &'a Device,
    id: usize,
    input: &Input<'_>,
    originals: OriginalViews<'_, '_>,
) -> Result<(select::Resident<'a>, Timing), Error> {
    let (tree, leaves, _, t) = build_with(dev, input, false, Some(originals), |_| {})?;
    let owner = select::finish_resident(dev, id, leaves, tree);
    dev.sync()?;
    Ok((owner, t))
}
