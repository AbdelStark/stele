//! RFC-0014 A3. Construct genuine RFC-0008 A7 factors from the checked host spans.
use crate::gkr::device_words;
use crate::gkr::{Factor, Table};
use crate::{Cuda, Error};
use cudarc::driver::{CudaSlice, DevicePtr, PushKernelArg};
use std::mem::size_of_val;
use stele_kernels::gkr::plan::{Op, Plan, Span, TablePlan};

pub(crate) fn pointer<T>(device: &Cuda, buffer: &CudaSlice<T>) -> u64 {
    buffer.device_ptr(&device.stream).0
}

fn storage(table: &TablePlan<'_>, len: usize) -> usize {
    match table.spans.as_slice() {
        [s] if !table.base
            && s.op == Op::Block
            && s.begin == 0
            && s.end == s.period
            && s.arg.is_power_of_two()
            && s.arg <= s.period
            && s.data.len() == 4 + 2 * s.arg as usize =>
        {
            s.arg as usize
        }
        _ => len,
    }
}

pub(crate) struct Budget {
    pub peak: usize,
    pub fold_extra: usize,
}
pub(crate) fn budget(p: &Plan<'_>, blocks: usize, indices: usize) -> Result<Budget, Error> {
    let table_bytes = |t: &TablePlan<'_>| storage(t, p.len) as u128 * if t.base { 4 } else { 16 };
    let mut live = 0u128;
    let mut peak = 0u128;
    for f in &p.factors {
        for table in std::iter::once(&f.values).chain(f.mask.as_ref().map(|m| &m.0)) {
            if f.mask.is_some() && storage(table, p.len) != p.len {
                return Err(Error::Geometry);
            }
            live += table_bytes(table);
            peak = peak.max(live);
            for s in &table.spans {
                // Layer chunks are copied straight into the final output allocation.
                peak = peak.max(live + 4 * (s.data.len() as u128 + s.shifts.len() as u128));
            }
        }
    }
    let terms = p.terms.len() as u128;
    live +=
        20 * p.factors.len() as u128 + 4 * (terms + 1 + indices.max(1) as u128) + 16 * terms.max(1);
    live += 16 * (p.degree as u128 + 1) * (blocks as u128 + 1);
    let installed = live;
    let mut fold = live;
    // Bind x before r. A disappearing mask survives through its joint fold, then drops.
    let promote = |t: &TablePlan<'_>, live: &mut u128, high: &mut u128| {
        if t.base {
            *high = (*high).max(*live + 8 * p.len as u128);
            *live += 4 * p.len as u128;
        }
    };
    for f in &p.factors {
        promote(&f.values, &mut live, &mut fold);
        if let Some((m, v)) = &f.mask {
            if *v == 0 {
                live -= table_bytes(m)
            } else {
                promote(m, &mut live, &mut fold)
            }
        }
    }
    Ok(Budget {
        peak: usize::try_from(peak.max(fold)).map_err(|_| Error::Budget)?,
        fold_extra: usize::try_from(fold - installed).map_err(|_| Error::Budget)?,
    })
}

#[derive(Default)]
pub(crate) struct Work {
    pub uploaded: u64,
    pub layer_bytes: u64,
    pub fields: u64,
    pub masks: u64,
}

fn layer(
    device: &Cuda,
    s: &Span<'_>,
    len: usize,
    output: &mut CudaSlice<u32>,
    work: &mut Work,
) -> Result<(), Error> {
    let values = s.layer.ok_or(Error::Geometry)?;
    let width = s.period as usize;
    if s.begin != 0
        || s.end != s.period
        || values.len() != 2 * width
        || s.arg >= 4
        || !len.is_multiple_of(width)
    {
        return Err(Error::Geometry);
    }
    // Select the original child/limb into a bounded canonical staging buffer. Replicate
    // the selected half using a device copy so each input field crosses PCIe only once.
    const CHUNK: usize = 1 << 16;
    let mut staging = Vec::with_capacity(4 * width.min(CHUNK));
    for start in (0..width).step_by(CHUNK) {
        let end = (start + CHUNK).min(width);
        staging.clear();
        for i in start..end {
            staging.extend(device_words(
                values[2 * i + s.arg as usize / 2][s.arg as usize % 2],
            ));
        }
        device.complete_transfer(
            device
                .stream
                .memcpy_htod(&staging, &mut output.slice_mut(4 * start..4 * end)),
        )?;
    }
    for start in (width..len).step_by(width) {
        let (first, mut later) = output.split_at_mut(4 * start);
        device
            .stream
            .memcpy_dtod(&first.slice(..4 * width), &mut later.slice_mut(..4 * width))?;
    }
    let bytes = 16 * width as u64;
    work.uploaded += bytes;
    work.layer_bytes += bytes;
    work.fields += bytes;
    Ok(())
}

fn table(device: &Cuda, t: TablePlan<'_>, len: usize, work: &mut Work) -> Result<Table, Error> {
    let count = storage(&t, len);
    let mut output = device
        .stream
        .alloc_zeros::<u32>(count * if t.base { 1 } else { 4 })?;
    let kernel = device.kernel("gkr_build_span")?;
    for s in t.spans {
        #[cfg(test)]
        let s = {
            let mut s = s;
            if crate::gkr_tests::RAW.get() {
                for w in &mut s.data {
                    *w += <stele_kernels::M31 as stele_kernels::Field>::MODULUS;
                }
                if matches!(s.op, Op::Constant | Op::GatherBase | Op::GatherExt) {
                    s.arg += <stele_kernels::M31 as stele_kernels::Field>::MODULUS;
                }
            }
            s
        };
        if s.op == Op::Layer {
            if t.base || count != len {
                return Err(Error::Geometry);
            }
            layer(device, &s, len, &mut output, work)?;
            continue;
        }
        let (period, begin, width) = if count < len {
            (count as u32, 0, count as u32)
        } else {
            (s.period, s.begin, s.end - s.begin)
        };
        let entries = (count / period as usize) * width as usize;
        let upload = |w: &[u32]| {
            if w.is_empty() {
                Ok(None)
            } else {
                device
                    .complete_transfer(device.stream.clone_htod(w))
                    .map(Some)
            }
        };
        let data = upload(&s.data)?;
        let shifts = upload(&s.shifts)?;
        work.fields += size_of_val(s.data.as_slice()) as u64;
        work.uploaded += (size_of_val(s.data.as_slice()) + size_of_val(s.shifts.as_slice())) as u64;
        let ptr = |b: &Option<CudaSlice<u32>>| b.as_ref().map_or(0, |b| pointer(device, b));
        let data_ptr = ptr(&data);
        let shifts_ptr = ptr(&shifts);
        let op = s.op as u32;
        let base = u32::from(t.base);
        let n = entries as u64;
        let shifts_len = s.shifts.len() as u32;
        let mut launch = device.stream.launch_builder(&kernel);
        launch
            .arg(&mut output)
            .arg(&base)
            .arg(&data_ptr)
            .arg(&shifts_ptr)
            .arg(&shifts_len)
            .arg(&op)
            .arg(&s.arg)
            .arg(&period)
            .arg(&begin)
            .arg(&width)
            .arg(&n);
        // SAFETY: Plan::new checks each indexed operand and destination span. An absent
        // operand is unused. Inputs, launch and frees are ordered on this single stream.
        unsafe { launch.launch(device.grid(entries)) }?;
    }
    Ok(Table {
        data: output,
        base: t.base,
    })
}

pub(crate) fn factors(
    device: &Cuda,
    p: Vec<stele_kernels::gkr::plan::FactorPlan<'_>>,
    len: usize,
    work: &mut Work,
) -> Result<Vec<Factor>, Error> {
    let mut factors = Vec::with_capacity(p.len());
    for f in p {
        let x = table(device, f.values, len, work)?;
        let old = work.fields;
        let mask = match f.mask {
            Some((m, v)) => Some((table(device, m, len, work)?, v)),
            None => None,
        };
        work.masks += work.fields - old;
        factors.push(Factor { x, mask });
    }
    Ok(factors)
}
