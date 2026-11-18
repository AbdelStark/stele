//! RFC-0014 A3. A proof-local compact GKR sumcheck. The host owns Fiat–Shamir.
use crate::device::{Phase, Session};
use crate::gkr_build::{budget, factors, pointer, Work};
use crate::packing::{canonical, words};
use crate::{Cuda, Error};
use cudarc::driver::{CudaSlice, LaunchConfig, PushKernelArg};
use stele_kernels::gkr::{
    plan::Plan, GkrBackend, GkrConstruction, RelationBackend, RelationConstruction,
};
use stele_kernels::QM31;

/// RFC-0003 §1 uses canonical inputs in the prover. The device differential also
/// supplies valid lazy limbs to every field operand, including launch arguments.
pub(crate) fn device_words(x: QM31) -> [u32; 4] {
    let limbs = words(x);
    #[cfg(test)]
    if crate::gkr_tests::RAW.get() {
        return limbs.map(|w| w + <stele_kernels::M31 as stele_kernels::Field>::MODULUS);
    }
    limbs
}

pub(crate) struct Table {
    pub data: CudaSlice<u32>,
    pub base: bool,
}
impl Table {
    fn period(&self, len: usize) -> Option<usize> {
        let physical = self.data.len() / 4;
        (!self.base && physical < len).then_some(physical)
    }
}
pub(crate) struct Factor {
    pub x: Table,
    pub mask: Option<(Table, usize)>,
}

#[derive(Clone, Copy)]
enum Family {
    Gkr,
    Relation,
}

/// Device owners and transition state of one selected GKR sumcheck.
pub struct Gkr<'s, 'd> {
    session: &'s Session<'d>,
    family: Family,
    factors: Vec<Factor>,
    len: usize,
    axis: usize,
    phase: Phase,
    nodes: usize,
    terms: u32,
    offsets: CudaSlice<u32>,
    indices: CudaSlice<u32>,
    coefficients: CudaSlice<[u32; 4]>,
    xs: CudaSlice<u64>,
    rs: CudaSlice<u64>,
    flags: CudaSlice<u32>,
    partials: CudaSlice<[u32; 4]>,
    out: CudaSlice<[u32; 4]>,
    fold_extra: usize,
}

impl<'d> Session<'d> {
    fn start_masked(&self, p: Plan<'_>, family: Family) -> Result<Gkr<'_, 'd>, Error> {
        let nodes = p.degree + 1;
        let terms = u32::try_from(p.terms.len()).map_err(|_| Error::Geometry)?;
        let n = p.factors.len();
        let mut offsets = Vec::with_capacity(p.terms.len() + 1);
        let mut indices = Vec::new();
        let mut coefficients = Vec::with_capacity(p.terms.len());
        offsets.push(0);
        for (c, term) in &p.terms {
            let offset = indices
                .len()
                .checked_add(term.len())
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(Error::Geometry)?;
            indices.extend_from_slice(term);
            offsets.push(offset);
            coefficients.push(device_words(*c));
        }
        if indices.is_empty() {
            indices.push(0)
        }
        let device = self.device;
        let blocks = device.grid(p.len / 2).grid_dim.0 as usize;
        let budget = budget(&p, blocks, indices.len())?;
        let _guard = device.allocation(budget.peak)?;
        let before = device.memory()?;
        let planned =
            (before.pool_used + budget.peak).max(before.pool_reserved) + before.outside_pool;
        let mut work = Work::default();
        let factors = factors(device, p.factors, p.len, &mut work)?;
        let stream = &device.stream;
        let state = Gkr {
            session: self,
            family,
            factors,
            len: p.len,
            axis: 0,
            phase: Phase::Round,
            nodes,
            terms,
            offsets: device.complete_transfer(stream.clone_htod(&offsets))?,
            indices: device.complete_transfer(stream.clone_htod(&indices))?,
            coefficients: device.complete_transfer(stream.clone_htod(&coefficients))?,
            xs: stream.alloc_zeros(n)?,
            rs: stream.alloc_zeros(n)?,
            flags: stream.alloc_zeros(n)?,
            partials: stream.alloc_zeros(blocks * nodes)?,
            out: stream.alloc_zeros(nodes)?,
            fold_extra: budget.fold_extra,
        };
        work.uploaded += (4 * (offsets.len() + indices.len()) + 16 * coefficients.len()) as u64;
        device.check_peak()?;
        let m = device.memory()?;
        self.record(|c| {
            c.uploaded_bytes += work.uploaded;
            match family {
                Family::Gkr => {
                    c.gkr_steps += 1;
                    c.gkr_expected_rounds += p.len.ilog2() as usize;
                    c.gkr_planned_peak_bytes = c.gkr_planned_peak_bytes.max(planned);
                    c.gkr_observed_peak_bytes =
                        c.gkr_observed_peak_bytes.max(m.outside_pool + m.pool_high);
                    c.gkr_uploaded_bytes += work.uploaded;
                    c.gkr_layer_source_bytes += work.layer_bytes;
                }
                Family::Relation => {
                    c.relation_steps += 1;
                    c.relation_expected_rounds += p.len.ilog2() as usize;
                    c.relation_planned_peak_bytes = c.relation_planned_peak_bytes.max(planned);
                    c.relation_observed_peak_bytes = c
                        .relation_observed_peak_bytes
                        .max(m.outside_pool + m.pool_high);
                    c.relation_uploaded_bytes += work.uploaded;
                    c.relation_value_bytes += work.fields - work.masks;
                    c.relation_mask_bytes += work.masks;
                }
            }
        });
        Ok(state)
    }
}

impl<'d> RelationBackend<QM31> for Session<'d> {
    fn relation_start<'s>(
        &'s self,
        input: &RelationConstruction<'_, QM31>,
    ) -> Result<Self::Gkr<'s>, Error> {
        self.start_masked(
            Plan::relation(input).map_err(|_| Error::Geometry)?,
            Family::Relation,
        )
    }
}

impl<'d> GkrBackend<QM31> for Session<'d> {
    type Gkr<'s>
        = Gkr<'s, 'd>
    where
        Self: 's;
    fn gkr_start<'s>(&'s self, input: &GkrConstruction<'_, QM31>) -> Result<Self::Gkr<'s>, Error> {
        let p = Plan::new(input).map_err(|_| Error::Geometry)?;
        self.start_masked(p, Family::Gkr)
    }
    fn gkr_round<'s>(s: &mut Self::Gkr<'s>) -> Result<Vec<QM31>, Error>
    where
        Self: 's,
    {
        if s.len < 2 || s.phase != Phase::Round {
            return Err(Error::Phase);
        }
        s.phase = Phase::Poisoned;
        let device = s.session.device;
        let stream = &device.stream;
        let mut xs = Vec::with_capacity(s.factors.len());
        let mut rs = Vec::with_capacity(s.factors.len());
        let mut flags = Vec::with_capacity(s.factors.len());
        for f in &s.factors {
            xs.push(pointer(device, &f.x.data));
            let r = f.mask.as_ref().filter(|(_, v)| *v == s.axis);
            rs.push(r.map_or(0, |(t, _)| pointer(device, &t.data)));
            let period = f.x.period(s.len).map_or(0, |p| (1 + p.ilog2()) << 3);
            flags.push(
                period | u32::from(f.x.base) | r.map_or(0, |(m, _)| 2 | (u32::from(m.base) << 2)),
            );
        }
        device.complete_transfer(stream.memcpy_htod(&xs, &mut s.xs))?;
        device.complete_transfer(stream.memcpy_htod(&rs, &mut s.rs))?;
        device.complete_transfer(stream.memcpy_htod(&flags, &mut s.flags))?;
        let half = (s.len / 2) as u64;
        let grid = device.grid(s.len / 2);
        let blocks = grid.grid_dim.0 as i32;
        let nodes = s.nodes as i32;
        let kernel = device.kernel("round_kernel")?;
        let mut b = stream.launch_builder(&kernel);
        b.arg(&s.xs)
            .arg(&s.rs)
            .arg(&s.flags)
            .arg(&s.offsets)
            .arg(&s.indices)
            .arg(&s.coefficients)
            .arg(&s.terms)
            .arg(&half)
            .arg(&nodes)
            .arg(&mut s.partials);
        // SAFETY: Plan validates all term indices. Every active mask covers both branches.
        // Repeated public factors carry their validated power-of-two physical period.
        unsafe { b.launch(grid) }?;
        let kernel = device.kernel("reduce_kernel")?;
        let mut b = stream.launch_builder(&kernel);
        b.arg(&s.partials).arg(&blocks).arg(&nodes).arg(&mut s.out);
        // SAFETY: the declared degree has at most 32 nodes, and the initial grid bounds later grids.
        unsafe {
            b.launch(LaunchConfig {
                grid_dim: (1, 1, 1),
                block_dim: (32, 1, 1),
                shared_mem_bytes: 0,
            })
        }?;
        let mut downloaded_nodes = vec![[0u32; 4]; s.nodes];
        device.complete_transfer(stream.memcpy_dtoh(&s.out, &mut downloaded_nodes))?;
        let result = downloaded_nodes
            .into_iter()
            .map(canonical)
            .collect::<Result<Vec<_>, _>>()?;
        let uploaded = 20 * xs.len() as u64;
        let downloaded = 16 * result.len() as u64;
        s.session.record(|c| {
            c.uploaded_bytes += uploaded;
            c.downloaded_bytes += downloaded;
            match s.family {
                Family::Gkr => {
                    c.gkr_rounds += 1;
                    c.gkr_uploaded_bytes += uploaded;
                    c.gkr_downloaded_bytes += downloaded;
                }
                Family::Relation => {
                    c.relation_rounds += 1;
                    c.relation_uploaded_bytes += uploaded;
                    c.relation_downloaded_bytes += downloaded;
                }
            }
        });
        s.phase = Phase::Fold;
        Ok(result)
    }
    fn gkr_fold<'s>(s: &mut Self::Gkr<'s>, c: QM31) -> Result<(), Error>
    where
        Self: 's,
    {
        if s.len < 2 || s.phase != Phase::Fold {
            return Err(Error::Phase);
        }
        s.phase = Phase::Poisoned;
        let device = s.session.device;
        let _guard = if s.axis == 0 {
            Some(device.allocation(s.fold_extra)?)
        } else {
            None
        };
        let half = s.len / 2;
        for f in &mut s.factors {
            if f.mask.as_ref().is_some_and(|(_, v)| *v == s.axis) {
                let (mask, _) = f.mask.take().ok_or(Error::Geometry)?;
                fold(device, &mut f.x, Some(&mask), half, c)?;
            } else {
                fold(device, &mut f.x, None, half, c)?;
                if let Some((m, _)) = &mut f.mask {
                    fold(device, m, None, half, c)?
                }
            }
        }
        device.check_peak()?;
        let m = device.memory()?;
        s.session.record(|counts| match s.family {
            Family::Gkr => {
                counts.gkr_folds += 1;
                counts.gkr_observed_peak_bytes = counts
                    .gkr_observed_peak_bytes
                    .max(m.outside_pool + m.pool_high);
            }
            Family::Relation => {
                counts.relation_folds += 1;
                counts.relation_observed_peak_bytes = counts
                    .relation_observed_peak_bytes
                    .max(m.outside_pool + m.pool_high);
            }
        });
        s.len = half;
        s.axis += 1;
        s.phase = Phase::Round;
        Ok(())
    }
    fn gkr_finals<'s>(s: &Self::Gkr<'s>) -> Result<Vec<QM31>, Error>
    where
        Self: 's,
    {
        if s.len != 1 || s.phase != Phase::Round {
            return Err(Error::Phase);
        }
        let mut result = Vec::with_capacity(s.factors.len());
        let mut bytes = 0;
        for f in &s.factors {
            if f.mask.is_some() {
                return Err(Error::Geometry);
            }
            let n = if f.x.base { 1 } else { 4 };
            let mut raw = [0u32; 4];
            let device = s.session.device;
            device.complete_transfer(
                device
                    .stream
                    .memcpy_dtoh(&f.x.data.slice(..n), &mut raw[..n]),
            )?;
            result.push(if f.x.base {
                canonical([raw[0], 0, 0, 0])?
            } else {
                canonical(raw)?
            });
            bytes += 4 * n as u64;
        }
        s.session.record(|c| {
            c.downloaded_bytes += bytes;
            match s.family {
                Family::Gkr => {
                    c.gkr_finals += 1;
                    c.gkr_downloaded_bytes += bytes;
                }
                Family::Relation => {
                    c.relation_finals += 1;
                    c.relation_downloaded_bytes += bytes;
                }
            }
        });
        Ok(result)
    }
}

fn fold(
    device: &Cuda,
    x: &mut Table,
    mask: Option<&Table>,
    half: usize,
    c: QM31,
) -> Result<(), Error> {
    if x.period(2 * half).is_some() {
        return if mask.is_none() {
            Ok(())
        } else {
            Err(Error::Geometry)
        };
    }
    let stream = &device.stream;
    let out = if x.base {
        Some(stream.alloc_zeros::<u32>(4 * half)?)
    } else {
        None
    };
    let src = pointer(device, &x.data);
    let dst = out.as_ref().map_or(src, |b| pointer(device, b));
    let xb = i32::from(x.base);
    let rb = i32::from(mask.is_some_and(|m| m.base));
    let rp = mask.map_or(0, |m| pointer(device, &m.data));
    let len = half as u64;
    let kernel = device.kernel(if mask.is_some() {
        "fold_mask"
    } else if x.base {
        "fold_base"
    } else {
        "fold_ext"
    })?;
    let mut b = stream.launch_builder(&kernel);
    if mask.is_some() {
        b.arg(&dst).arg(&src).arg(&xb).arg(&rp).arg(&rb);
    } else if x.base {
        b.arg(&src).arg(&dst);
    } else {
        b.arg(&src);
    }
    b.arg(&len);
    let ch = device_words(c);
    let kap = device_words(c * (QM31::ONE - c));
    for limb in &ch {
        b.arg(limb);
    }
    if mask.is_some() {
        for limb in &kap {
            b.arg(limb);
        }
    }
    // SAFETY: both input tables have 2*half entries. Each thread writes one distinct
    // output and in-place extension interpolation reads both of its own sources first.
    unsafe { b.launch(device.grid(half)) }?;
    if let Some(promoted) = out {
        x.data = promoted;
        x.base = false
    }
    Ok(())
}
