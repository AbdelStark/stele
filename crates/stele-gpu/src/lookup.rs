//! RFC-0014 A6. Read original owners and retain one lookup's internal [p,q] layers.
use crate::device::{Original, Session};
use crate::gkr::{Family, Gkr};
use crate::gkr_build::pointer;
use crate::packing::{canonical, words};
use crate::Error;
use cudarc::driver::{CudaSlice, PushKernelArg};
use stele_kernels::gkr::{plan::Plan, GkrConstruction};
use stele_kernels::lookup::{Column, Input, Key, LookupBackend, Visit};
use stele_kernels::{Field, M31, QM31 as K};

fn word(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::Geometry)
}

struct Packed {
    ptrs: Vec<u64>,
    desc: Vec<u32>,
    axes: Vec<u32>,
    fields: Vec<u32>,
}

impl Packed {
    fn new(
        session: &Session<'_>,
        input: &Input<'_>,
        owners: &[&Original<'_, '_>],
    ) -> Result<Self, Error> {
        input.check().map_err(|_| Error::Geometry)?;
        let mut ptrs = vec![0; owners.len()];
        let mut column = |c: Column| -> Result<[u32; 3], Error> {
            let owner = owners.get(c.owner).ok_or(Error::Source)?;
            ptrs[c.owner] = pointer(session.device, owner.checked_words(session, c.geometry)?);
            Ok([
                word(c.owner)?,
                word(c.offset)?,
                (c.geometry.columns / 2).ilog2(),
            ])
        };
        let mut desc = Vec::from(column(input.multiplicity)?);
        desc.extend([
            word(input.multiplicity.len)?,
            word(input.members[0].tuple.len())?,
            word(input.members.len())?,
            word(input.valid)?,
        ]);
        let mut fields = Vec::from(words(input.key.alpha));
        fields.extend(words(input.key.beta));
        for row in &input.table[..input.valid] {
            fields.extend(row.iter().map(|&v| M31::from_i64(v).as_u32()));
        }
        let mut axes = Vec::new();
        let mut projection = |coords: &[usize]| -> Result<[u32; 2], Error> {
            let at = word(axes.len())?;
            for &q in coords {
                axes.push(word(input.key.variables - 1 - q)?);
            }
            Ok([at, word(coords.len())?])
        };
        for m in input.members {
            desc.extend([word(m.range.start)?, word(m.range.end)?]);
            if let Some((values, coords)) = m.selector {
                desc.push(word(fields.len())?);
                fields.extend(values.iter().map(|&v| M31::from_i64(v).as_u32()));
                desc.extend(projection(coords)?);
            } else {
                desc.extend([u32::MAX, 0, 0])
            }
            for l in &m.tuple {
                desc.extend(column(l.column)?);
                desc.extend(projection(l.coordinates)?);
                let shift = M31::from_i64(l.shift).as_u32();
                #[cfg(test)]
                let shift = if crate::gkr_tests::RAW.get() {
                    shift + M31::MODULUS
                } else {
                    shift
                };
                desc.push(shift);
            }
        }
        #[cfg(test)]
        if crate::gkr_tests::RAW.get() {
            fields.iter_mut().for_each(|v| *v += M31::MODULUS);
        }
        word(fields.len())?;
        word(axes.len())?;
        if axes.is_empty() {
            axes.push(0)
        }
        Ok(Self {
            ptrs,
            desc,
            axes,
            fields,
        })
    }
    fn bytes(&self) -> usize {
        8 * self.ptrs.len() + 4 * (self.desc.len() + self.axes.len() + self.fields.len())
    }
}

pub struct Tree<'s, 'd> {
    pub(crate) key: Key,
    session: &'s Session<'d>,
    pub(crate) pairs: CudaSlice<u32>,
}

impl<'d> Session<'d> {
    fn build_lookup(
        &self,
        input: &Input<'_>,
        owners: &[&Original<'_, '_>],
        top: bool,
    ) -> Result<Tree<'_, 'd>, Error> {
        let p = Packed::new(self, input, owners)?;
        let n = 1usize << input.key.variables;
        let words = 8 * (2 * n - 1);
        let target = if top { 1 << input.key.top_variables } else { 1 };
        let dev = self.device;
        let extra = 4 * words + p.bytes();
        let _guard = dev.allocation(extra)?;
        let before = dev.memory()?;
        let planned = (before.pool_used + extra).max(before.pool_reserved) + before.outside_pool;
        let stream = &dev.stream;
        let ptrs = dev.complete_transfer(stream.clone_htod(&p.ptrs))?;
        let desc = dev.complete_transfer(stream.clone_htod(&p.desc))?;
        let axes = dev.complete_transfer(stream.clone_htod(&p.axes))?;
        let fields = dev.complete_transfer(stream.clone_htod(&p.fields))?;
        let mut pairs = stream.alloc_zeros(words)?;
        let first = dev.kernel("lookup_first")?;
        let rows = n as u64;
        let mut launch = stream.launch_builder(&first);
        launch
            .arg(&ptrs)
            .arg(&desc)
            .arg(&axes)
            .arg(&fields)
            .arg(&mut pairs)
            .arg(&rows);
        // SAFETY: Packed validated the source sessions, physical quadrant, member ranges,
        // coordinate widths and row-major table extent. Each row writes one disjoint pair.
        unsafe { launch.launch(dev.grid(n)) }?;
        let parent = dev.kernel("lookup_parents")?;
        let mut width = n;
        while width > target {
            width /= 2;
            let w = width as u64;
            let mut launch = stream.launch_builder(&parent);
            launch.arg(&mut pairs).arg(&w);
            // SAFETY: parents occupy width-1..2*width-1; their two children are in
            // the disjoint following level. The same stream orders successive levels.
            unsafe { launch.launch(dev.grid(width)) }?;
        }
        stream.synchronize()?;
        dev.check_peak()?;
        let peak = dev.memory()?;
        self.record(|c| {
            if top {
                c.lookup_tops += 1
            } else {
                c.lookup_rebuilds += 1;
            }
            c.lookup_uploaded_bytes += p.bytes() as u64;
            c.uploaded_bytes += p.bytes() as u64;
            c.lookup_planned_peak_bytes = c.lookup_planned_peak_bytes.max(planned);
            c.lookup_observed_peak_bytes = c
                .lookup_observed_peak_bytes
                .max(peak.outside_pool + peak.pool_high);
        });
        Ok(Tree {
            session: self,
            key: input.key,
            pairs,
        })
    }
}

impl<'d> LookupBackend for Session<'d> {
    type Tree<'s>
        = Tree<'s, 'd>
    where
        Self: 's;
    fn lookup_top(
        &self,
        input: &Input<'_>,
        owners: &[&Original<'_, 'd>],
    ) -> Result<Vec<[K; 2]>, Error> {
        let tree = self.build_lookup(input, owners, true)?;
        let width = 1usize << input.key.top_variables;
        let raw = self.device.complete_transfer(
            self.device
                .stream
                .clone_dtoh(&tree.pairs.slice(8 * (width - 1)..8 * (2 * width - 1))),
        )?;
        let mut result = Vec::with_capacity(width);
        for pair in raw.chunks_exact(8) {
            result.push([
                canonical(pair[..4].try_into().map_err(|_| Error::Geometry)?)?,
                canonical(pair[4..].try_into().map_err(|_| Error::Geometry)?)?,
            ]);
        }
        self.record(|c| {
            c.lookup_downloaded_bytes += (4 * raw.len()) as u64;
            c.downloaded_bytes += (4 * raw.len()) as u64;
        });
        Ok(result)
    }
    fn lookup_tree<'s>(
        &'s self,
        input: &Input<'_>,
        owners: &[&Original<'_, 'd>],
    ) -> Result<Tree<'s, 'd>, Error> {
        self.build_lookup(input, owners, false)
    }
    fn lookup_gkr<'s>(
        &'s self,
        key: Key,
        visit: Visit<'_, Tree<'_, 'd>>,
        input: &GkrConstruction<'_, K>,
    ) -> Result<Gkr<'s, 'd>, Error> {
        let tree = visit.tree();
        let level = input
            .layer_variables
            .checked_add(1)
            .ok_or(Error::Geometry)?;
        if !std::ptr::eq(self, tree.session)
            || tree.key != key
            || level > key.variables
            || level <= key.top_variables
            || matches!(visit, Visit::Last(_)) != (level == key.variables)
        {
            return Err(Error::Source);
        }
        let p = Plan::retained(input, level, None).map_err(|_| Error::Geometry)?;
        let released = if matches!(visit, Visit::Last(_)) {
            4 * tree.pairs.len()
        } else {
            0
        };
        let state = self.start_masked(p, Family::Gkr, Some(&tree.pairs), released)?;
        self.device.stream.synchronize()?;
        self.record(|c| {
            c.lookup_child_views += 4;
            c.lookup_child_released += usize::from(released != 0);
        });
        Ok(state)
    }
}
