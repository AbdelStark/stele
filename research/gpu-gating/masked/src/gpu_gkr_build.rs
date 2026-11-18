//! RFC-0008 A7 and RFC-0014 §5: construct compact summand tables on the device.
use super::{Buf, Device, DeviceMasked, Error, Factor, OriginalMessage, PushKernelArg};
use crate::gkr::ColumnOrigin;
use crate::gkr_build::{InputKind, Op, Plan, TablePlan};
use crate::gpu_lookup::select::Resident;
use crate::{round::Terms, Field, K, M31};
use cudarc::driver::DevicePtr;
use std::collections::BTreeMap;
use stele_reductions::zk::claims::bench::GkrConstruction;

/// Actual explicit H2D copies. CUDA launch parameters, allocations and device
/// zero initialization are excluded; the resident summand reports its own size.
#[derive(Default)]
pub struct ConstructionWork {
    /// Field-word input buffers, including copies used by more than one span.
    pub input_bytes: usize,
    /// Disjoint uses of the field words copied for this construction.
    pub equality_bytes: usize,
    pub block_challenge_bytes: usize,
    pub block_mask_bytes: usize,
    pub column_bytes: usize,
    pub mask_bytes: usize,
    pub layer_upload_bytes: usize,
    pub public_challenge_bytes: usize,
    pub public_table_bytes: usize,
    pub selector_bytes: usize,
    /// Explicit coordinate shift arrays and term arrays.
    pub coordinate_bytes: usize,
    pub term_bytes: usize,
    /// Original-column views and addressable bytes across spans, including repeated uses.
    pub original_views: usize,
    pub mask_views: usize,
    pub mask_view_bytes: usize,
    pub block_views: usize,
    pub block_view_bytes: usize,
    pub original_bytes: usize,
    /// Coordinate shifts plus the summand's term offsets, indices and coefficients.
    pub descriptor_bytes: usize,
    /// Conservative explicit allocation peak for this step, including promotion.
    pub peak_bytes: usize,
    /// Construction and first-fold peaks of the GKR state, excluding its parent tree.
    pub construction_bytes: usize,
    pub fold_bytes: usize,
    /// Device tree freed between synchronized factor copies and the first fold.
    pub released_bytes: usize,
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

impl ConstructionWork {
    fn input(&mut self, kind: InputKind, bytes: usize) -> Result<(), Error> {
        charge(&mut self.input_bytes, bytes)?;
        // Empty spans and launch immediates perform no explicit host-to-device copy.
        if bytes == 0 {
            return Ok(());
        }
        let bucket = match kind {
            InputKind::Equality => &mut self.equality_bytes,
            InputKind::Column => &mut self.column_bytes,
            InputKind::Mask => &mut self.mask_bytes,
            InputKind::Layer => &mut self.layer_upload_bytes,
            InputKind::Selector => &mut self.selector_bytes,
            InputKind::Block => {
                let challenge = 4 * std::mem::size_of::<u32>();
                charge(&mut self.block_challenge_bytes, challenge)?;
                return charge(
                    &mut self.block_mask_bytes,
                    bytes
                        .checked_sub(challenge)
                        .ok_or(Error::Shape("GKR block challenge"))?,
                );
            }
            InputKind::Public => {
                let challenges = 8 * std::mem::size_of::<u32>();
                charge(&mut self.public_challenge_bytes, challenges)?;
                return charge(
                    &mut self.public_table_bytes,
                    bytes
                        .checked_sub(challenges)
                        .ok_or(Error::Shape("GKR public challenges"))?,
                );
            }
        };
        charge(bucket, bytes)
    }
}

type OriginalOwners<'d> = BTreeMap<u64, OriginalMessage<'d>>;

/// Physical child lifetime on a GKR step. A host child is used by the seeded
/// reference campaign. Real non-leaf steps take the checked device tree.
pub enum PrivateChild<'a, 'd> {
    Host,
    Borrowed(usize, &'a Resident<'d>),
    Last(usize, Resident<'d>),
}

#[derive(Clone, Copy, Default)]
struct Inputs<'a, 'd> {
    tree: Option<(usize, &'a Resident<'d>)>,
    originals: Option<&'a OriginalOwners<'d>>,
}

impl Device {
    /// Construct an observed GKR step from its original columns, blocks and layers.
    pub fn build_gkr(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.build_gkr_plan(
            Plan::new(input).map_err(Error::Shape)?,
            false,
            Inputs::default(),
        )
    }

    #[cfg(test)]
    pub(super) fn build_gkr_raw(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.bounded_gkr(input, None, true)
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
        self.bounded_gkr(input, None, false)
    }

    /// Borrow certified original base columns for a leaf. The caller binds each
    /// plan-derived descriptor to its source root in the same proof registry.
    pub fn build_gkr_original(
        &self,
        input: &GkrConstruction<'_, K>,
        origins: &[ColumnOrigin],
        owners: &BTreeMap<u64, OriginalMessage<'_>>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let plan = Plan::with_originals(input, origins).map_err(Error::Shape)?;
        self.bounded_plan(
            plan,
            false,
            Inputs {
                tree: None,
                originals: Some(owners),
            },
        )
    }

    #[cfg(test)]
    pub fn build_gkr_original_raw(
        &self,
        input: &GkrConstruction<'_, K>,
        origins: &[ColumnOrigin],
        owners: &BTreeMap<u64, OriginalMessage<'_>>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.bounded_plan(
            Plan::with_originals(input, origins).map_err(Error::Shape)?,
            true,
            Inputs {
                tree: None,
                originals: Some(owners),
            },
        )
    }

    /// Construct on the original source windows while preserving the final-child
    /// handoff and its two synchronized memory budgets.
    pub fn build_gkr_private(
        &self,
        input: &GkrConstruction<'_, K>,
        columns: Option<&[ColumnOrigin]>,
        private: &[Vec<[usize; 6]>],
        owners: &BTreeMap<u64, OriginalMessage<'_>>,
        child: PrivateChild<'_, '_>,
        raw: bool,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let plan = match columns {
            Some(columns) => {
                if !matches!(child, PrivateChild::Host) {
                    return Err(Error::Shape("GKR leaf with child owner"));
                }
                Plan::with_originals(input, columns)
            }
            None => Plan::with_layers(input, !matches!(child, PrivateChild::Host)),
        }
        .and_then(|p| p.original_masks(private))
        .map_err(Error::Shape)?;
        let originals = Some(owners);
        let tree = match child {
            PrivateChild::Host => None,
            PrivateChild::Borrowed(id, tree) => {
                tree.check(self, id)?;
                Some((id, tree))
            }
            PrivateChild::Last(id, tree) => {
                return self.last_plan(plan, input.layer_variables, id, tree, originals, raw);
            }
        };
        self.bounded_plan(plan, raw, Inputs { tree, originals })
    }

    /// Build this step with child values borrowed from the matching rebuilt device tree.
    pub fn build_gkr_resident(
        &self,
        input: &GkrConstruction<'_, K>,
        id: usize,
        tree: &Resident<'_>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        tree.check(self, id)?;
        self.bounded_gkr(input, Some((id, tree)), false)
    }

    /// Transfer the final child owner after the last consumer has copied its
    /// values into the factor tables. The owning reference enforces release
    /// before any round can promote a mask. The two budgets cover each lifetime.
    pub fn build_gkr_last_child(
        &self,
        input: &GkrConstruction<'_, K>,
        id: usize,
        tree: Resident<'_>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let plan = Plan::with_layers(input, true).map_err(Error::Shape)?;
        self.last_plan(plan, input.layer_variables, id, tree, None, false)
    }

    fn last_plan(
        &self,
        plan: Plan,
        layer_variables: usize,
        id: usize,
        tree: Resident<'_>,
        originals: Option<&OriginalOwners<'_>>,
        raw: bool,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        tree.check(self, id)?;
        if !tree.is_last_child(layer_variables) {
            return Err(Error::Shape("not the final lookup child"));
        }
        let peak = plan
            .peak(self.grid(plan.len / 2).grid_dim.0 as usize)
            .map_err(Error::Shape)?;
        self.require_budget(
            peak.construction
                .max(peak.fold.saturating_sub(tree.bytes())),
        )?;
        let (state, mut work) = self.build_gkr_plan(
            plan,
            raw,
            Inputs {
                tree: Some((id, &tree)),
                originals,
            },
        )?;
        if work.layer_views == 0 {
            return Err(Error::Shape("unused final lookup child"));
        }
        // build_gkr_plan synchronized after copying every child on this stream.
        work.released_bytes = tree.bytes();
        drop(tree);
        self.sync()?;
        // Point-in-time driver counters now cover the constructed state; only
        // first-fold overlap beyond that resident state requires additional room.
        self.require_budget(peak.fold.saturating_sub(state.device_buffer_bytes()))?;
        work.construction_bytes = peak.construction;
        work.fold_bytes = peak.fold;
        work.peak_bytes = peak.construction.max(peak.fold);
        Ok((state, work))
    }

    fn bounded_gkr(
        &self,
        input: &GkrConstruction<'_, K>,
        resident: Option<(usize, &Resident<'_>)>,
        raw: bool,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let plan = Plan::with_layers(input, resident.is_some()).map_err(Error::Shape)?;
        self.bounded_plan(
            plan,
            raw,
            Inputs {
                tree: resident,
                originals: None,
            },
        )
    }

    fn bounded_plan(
        &self,
        plan: Plan,
        raw: bool,
        inputs: Inputs<'_, '_>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let peak = plan
            .peak(self.grid(plan.len / 2).grid_dim.0 as usize)
            .map_err(Error::Shape)?;
        self.require_budget(peak.construction.max(peak.fold))?;
        let (state, mut work) = self.build_gkr_plan(plan, raw, inputs)?;
        work.construction_bytes = peak.construction;
        work.fold_bytes = peak.fold;
        work.peak_bytes = peak.construction.max(peak.fold);
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
        inputs: Inputs<'_, '_>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let nodes = plan
            .degree
            .checked_add(1)
            .ok_or(Error::Shape("GKR degree"))?;
        let terms = Terms::new(plan.factors.len(), &plan.terms, nodes).map_err(Error::Shape)?;
        let mut work = ConstructionWork::default();
        let mut factors = Vec::with_capacity(plan.factors.len());
        for factor in plan.factors {
            let x = self.gkr_table(factor.values, plan.len, raw, inputs, &mut work)?;
            let (r, v) = match factor.mask {
                Some((mask, v)) => (
                    Some(self.gkr_table(mask, plan.len, raw, inputs, &mut work)?),
                    Some(v),
                ),
                None => (None, None),
            };
            factors.push(Factor { x, r, v });
        }
        let state = self.summand(factors, &plan.terms, terms, nodes, plan.len)?;
        work.term_bytes = state.descriptor_upload_bytes();
        charge(&mut work.descriptor_bytes, work.term_bytes)?;
        self.sync()?;
        Ok((state, work))
    }

    fn gkr_table(
        &self,
        table: TablePlan,
        len: usize,
        raw: bool,
        inputs: Inputs<'_, '_>,
        work: &mut ConstructionWork,
    ) -> Result<Buf, Error> {
        let physical = table.storage_len(len);
        let cyclic = physical < len;
        let len = physical;
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
            if cyclic {
                span.period = span.arg;
                span.end = span.arg;
            }
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
                if matches!(
                    span.op,
                    Op::Constant | Op::GatherBase | Op::GatherExt | Op::OriginalBase
                ) {
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
            work.input(span.kind, std::mem::size_of_val(span.data.as_slice()))?;
            charge(
                &mut work.coordinate_bytes,
                std::mem::size_of_val(span.shifts.as_slice()),
            )?;
            charge(
                &mut work.descriptor_bytes,
                std::mem::size_of_val(span.shifts.as_slice()),
            )?;
            let layer = match (span.op, inputs.tree) {
                (Op::Layer, Some((id, tree))) => {
                    Some(tree.layer(self, id, 2 * span.period as usize)?)
                }
                _ => None,
            };
            let mut original_at = 0u64;
            let mut row_shift = 0u32;
            let mut original_ptr = 0u64;
            let data_ptr = match (span.op, &layer) {
                (Op::OriginalBase | Op::OriginalBlock, _) => {
                    let [_, source, rows, columns, at, entries] = span
                        .original
                        .ok_or(Error::Shape("missing GKR original descriptor"))?;
                    let cells = rows
                        .checked_mul(columns)
                        .ok_or(Error::Shape("GKR original extent"))?;
                    let block = matches!(span.op, Op::OriginalBlock);
                    let shape = if block {
                        span.arg.is_power_of_two()
                            && 2 * span.arg as usize == entries
                            && span.data.len() == 4
                            && shift_count == 0
                    } else {
                        1usize.checked_shl(shift_count) == Some(entries) && data.is_none()
                    };
                    if !shape
                        || !rows.is_power_of_two()
                        || !columns.is_power_of_two()
                        || rows < 2
                        || columns < 2
                        || at.checked_add(entries).is_none_or(|end| end > cells / 4)
                    {
                        return Err(Error::Shape("GKR original gather"));
                    }
                    let id = u64::try_from(source)
                        .map_err(|_| Error::Shape("GKR original source id"))?;
                    let owner = inputs
                        .originals
                        .and_then(|owners| owners.get(&id))
                        .ok_or(Error::Shape("missing GKR original owner"))?;
                    let words = owner.words(self, id, rows, columns)?;
                    original_at =
                        u64::try_from(at).map_err(|_| Error::Shape("GKR original offset"))?;
                    row_shift = (columns / 2).ilog2();
                    match (span.op, span.kind) {
                        (Op::OriginalBlock, InputKind::Block) => {
                            charge(&mut work.block_views, 1)?;
                            charge(&mut work.block_view_bytes, 4 * entries)?;
                            original_ptr = self.ptr(words);
                            self.ptr(data.as_ref().ok_or(Error::Shape("GKR block challenge"))?)
                        }
                        (Op::OriginalBase, InputKind::Mask) => {
                            charge(&mut work.mask_views, 1)?;
                            charge(&mut work.mask_view_bytes, 4 * entries)?;
                            self.ptr(words)
                        }
                        (Op::OriginalBase, InputKind::Column) => {
                            charge(&mut work.original_views, 1)?;
                            charge(&mut work.original_bytes, 4 * entries)?;
                            self.ptr(words)
                        }
                        _ => return Err(Error::Shape("GKR original input kind")),
                    }
                }
                (_, Some(view)) => {
                    charge(&mut work.layer_views, 1)?;
                    charge(&mut work.layer_bytes, 4 * view.len())?;
                    view.device_ptr(&self.stream).0
                }
                (_, None) => data.as_ref().map_or(0, |d| self.ptr(d)),
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
                .arg(&entries)
                .arg(&original_at)
                .arg(&row_shift)
                .arg(&original_ptr);
            // SAFETY: Plan::new checks each RFC-0008 A7 operation's source extent
            // and coordinates. Each repeated span fits the allocated output; a
            // null operand is never read. A resident layer view has exactly two
            // QM31s per child pair and its owner lives through the final sync.
            // Original view bounds cover every selected row in the data quadrant;
            // its immutable owner is borrowed through the final synchronization.
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
