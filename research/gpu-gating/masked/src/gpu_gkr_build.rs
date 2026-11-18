//! RFC-0008 A7 and RFC-0014 §5: construct compact summand tables on the device.
use super::{Buf, Device, DeviceMasked, Error, Factor, PushKernelArg};
use crate::gkr_build::{Op, Plan, TablePlan};
use crate::gpu_lookup::select::Resident;
use crate::{round::Terms, Field, K, M31};
use cudarc::driver::DevicePtr;
use stele_reductions::zk::claims::bench::GkrConstruction;

/// Actual explicit H2D copies. CUDA launch parameters, allocations and device
/// zero initialization are excluded; the resident summand reports its own size.
#[derive(Default)]
pub struct ConstructionWork {
    /// Field-word input buffers, including copies used by more than one span.
    pub input_bytes: usize,
    /// Coordinate shifts plus the summand's term offsets, indices and coefficients.
    pub descriptor_bytes: usize,
    /// Conservative explicit allocation peak for this step, including promotion.
    pub peak_bytes: usize,
    /// Child-layer views consumed and their addressable bytes across all factors.
    pub layer_views: usize,
    pub layer_bytes: usize,
}

fn charge(total: &mut usize, bytes: usize) -> Result<(), Error> {
    *total = total
        .checked_add(bytes)
        .ok_or(Error::Shape("GKR upload size"))?;
    Ok(())
}

impl Device {
    /// Construct an observed GKR step from its original columns, blocks and layers.
    pub fn build_gkr(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.build_gkr_plan(Plan::new(input).map_err(Error::Shape)?, false, None)
    }

    #[cfg(test)]
    pub(super) fn build_gkr_raw(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.build_gkr_plan(Plan::new(input).map_err(Error::Shape)?, true, None)
    }

    /// Actual CUDA allocator counters, including its retained pages, on the current device.
    pub fn memory_sample(&self) -> Result<MemorySample, Error> {
        use cudarc::driver::{result, sys::CUmemPool_attribute as Attr};
        if !self.ctx.has_async_alloc() {
            return Err(Error::Shape("CUDA memory pool required"));
        }
        self.ctx.bind_to_thread()?;
        let (free, total) = self.ctx.mem_get_info()?;
        // SAFETY: the live context owns this CUDA device and its current allocation pool.
        let pool = unsafe { result::device::get_mem_pool(self.ctx.cu_device()) }?;
        let read = |attr| {
            let mut bytes = 0u64;
            // SAFETY: the four memory counters below have CUDA's cuuint64_t result type.
            unsafe {
                result::mem_pool::get_attribute(pool, attr, core::ptr::from_mut(&mut bytes).cast())
            }?;
            usize::try_from(bytes).map_err(|_| Error::Shape("CUDA pool byte count"))
        };
        Ok(MemorySample {
            total,
            free,
            reserved: read(Attr::CU_MEMPOOL_ATTR_RESERVED_MEM_CURRENT)?,
            used: read(Attr::CU_MEMPOOL_ATTR_USED_MEM_CURRENT)?,
            reserved_high: read(Attr::CU_MEMPOOL_ATTR_RESERVED_MEM_HIGH)?,
            used_high: read(Attr::CU_MEMPOOL_ATTR_USED_MEM_HIGH)?,
        })
    }

    /// Apply the RFC-0014 A1 budget before any device allocation for this GKR step.
    pub fn build_gkr_bounded(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.bounded_gkr(input, None)
    }

    /// Build this step with child values borrowed from the matching rebuilt device tree.
    pub fn build_gkr_resident(
        &self,
        input: &GkrConstruction<'_, K>,
        id: usize,
        tree: &Resident<'_>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        tree.check(self, id)?;
        self.bounded_gkr(input, Some((id, tree)))
    }

    fn bounded_gkr(
        &self,
        input: &GkrConstruction<'_, K>,
        resident: Option<(usize, &Resident<'_>)>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let plan = Plan::with_layers(input, resident.is_some()).map_err(Error::Shape)?;
        let peak = plan
            .peak_bytes(self.grid(plan.len / 2).grid_dim.0 as usize)
            .map_err(Error::Shape)?;
        self.require_budget(peak)?;
        let (state, mut work) = self.build_gkr_plan(plan, false, resident)?;
        work.peak_bytes = peak;
        Ok((state, work))
    }

    pub(crate) fn require_budget(&self, peak: usize) -> Result<(), Error> {
        let sample = self.memory_sample()?;
        let outside_pool = (sample.total - sample.free).saturating_sub(sample.reserved);
        let available =
            (sample.total / 5 * 2).saturating_sub(outside_pool.saturating_add(sample.used));
        if peak > available {
            return Err(Error::Budget {
                required: peak,
                available,
            });
        }
        Ok(())
    }

    fn build_gkr_plan(
        &self,
        plan: Plan,
        raw: bool,
        resident: Option<(usize, &Resident<'_>)>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let nodes = plan
            .degree
            .checked_add(1)
            .ok_or(Error::Shape("GKR degree"))?;
        let terms = Terms::new(plan.factors.len(), &plan.terms, nodes).map_err(Error::Shape)?;
        let mut work = ConstructionWork::default();
        let mut factors = Vec::with_capacity(plan.factors.len());
        for factor in plan.factors {
            let x = self.gkr_table(factor.values, plan.len, raw, resident, &mut work)?;
            let (r, v) = match factor.mask {
                Some((mask, v)) => (
                    Some(self.gkr_table(mask, plan.len, raw, resident, &mut work)?),
                    Some(v),
                ),
                None => (None, None),
            };
            factors.push(Factor { x, r, v });
        }
        let state = self.summand(factors, &plan.terms, terms, nodes, plan.len)?;
        charge(&mut work.descriptor_bytes, state.descriptor_upload_bytes())?;
        self.sync()?;
        Ok((state, work))
    }

    fn gkr_table(
        &self,
        table: TablePlan,
        len: usize,
        raw: bool,
        resident: Option<(usize, &Resident<'_>)>,
        work: &mut ConstructionWork,
    ) -> Result<Buf, Error> {
        let words = len
            .checked_mul(if table.base { 1 } else { 4 })
            .filter(|n| *n <= isize::MAX as usize / 4)
            .ok_or(Error::Shape("GKR table size"))?;
        // Positions outside every member are zero in both value and mask tables.
        let out = self.stream.alloc_zeros::<u32>(words)?;
        let kernel = self.function("gkr_build_span")?;
        let dst = self.ptr(&out);
        let base = u32::from(table.base);
        for mut span in table.spans {
            let width = span
                .end
                .checked_sub(span.begin)
                .ok_or(Error::Shape("GKR span"))?;
            if span.period == 0
                || span.end > span.period
                || !len.is_multiple_of(span.period as usize)
            {
                return Err(Error::Shape("GKR span"));
            }
            if width == 0 {
                continue;
            }
            let count = (len / span.period as usize) * width as usize;
            let shift_count =
                u32::try_from(span.shifts.len()).map_err(|_| Error::Shape("GKR shifts"))?;
            // The lazy-input test lifts field limbs only. Periods, shift counts
            // and source indices retain their ordinary integer representation.
            if raw {
                for word in &mut span.data {
                    *word += M31::MODULUS;
                }
                if matches!(span.op, Op::Constant | Op::GatherBase | Op::GatherExt) {
                    span.arg += M31::MODULUS;
                }
            }
            let upload = |words: &[u32]| {
                if words.is_empty() {
                    Ok(None)
                } else {
                    self.stream.clone_htod(words).map(Some)
                }
            };
            let data = upload(&span.data)?;
            let shifts = upload(&span.shifts)?;
            charge(
                &mut work.input_bytes,
                std::mem::size_of_val(span.data.as_slice()),
            )?;
            charge(
                &mut work.descriptor_bytes,
                std::mem::size_of_val(span.shifts.as_slice()),
            )?;
            let layer = match (span.op, resident) {
                (Op::Layer, Some((id, tree))) => {
                    Some(tree.layer(self, id, 2 * span.period as usize)?)
                }
                _ => None,
            };
            let data_ptr = match &layer {
                Some(view) => {
                    charge(&mut work.layer_views, 1)?;
                    charge(&mut work.layer_bytes, 4 * view.len())?;
                    view.device_ptr(&self.stream).0
                }
                None => data.as_ref().map_or(0, |d| self.ptr(d)),
            };
            let shifts_ptr = shifts.as_ref().map_or(0, |d| self.ptr(d));
            let op = span.op as u32;
            let entries = count as u64;
            let mut b = self.stream.launch_builder(&kernel);
            b.arg(&dst)
                .arg(&base)
                .arg(&data_ptr)
                .arg(&shifts_ptr)
                .arg(&shift_count)
                .arg(&op)
                .arg(&span.arg)
                .arg(&span.period)
                .arg(&span.begin)
                .arg(&width)
                .arg(&entries);
            // SAFETY: Plan::new checks each RFC-0008 A7 operation's source extent
            // and coordinates. Each repeated span fits the allocated output; a
            // null operand is never read. A resident layer view has exactly two
            // QM31s per child pair and its owner lives through the final sync.
            // Upload, kernel and free share one stream.
            unsafe { b.launch(self.grid(count)) }?;
        }
        Ok(if table.base {
            Buf::Base(out)
        } else {
            Buf::Ext(out)
        })
    }
}

/// Device-wide availability and current process pool high-water marks (bytes).
pub struct MemorySample {
    pub total: usize,
    pub free: usize,
    pub reserved: usize,
    pub used: usize,
    pub reserved_high: usize,
    pub used_high: usize,
}
