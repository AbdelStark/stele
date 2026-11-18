//! RFC-0008 A7 and RFC-0014 §5: construct compact summand tables on the device.
use super::{Buf, Device, DeviceMasked, Error, Factor, PushKernelArg};
use crate::gkr_build::{Op, Plan, TablePlan};
use crate::{round::Terms, Field, K, M31};
use stele_reductions::zk::claims::bench::GkrConstruction;

/// Actual explicit H2D copies. CUDA launch parameters, allocations and device
/// zero initialization are excluded; the resident summand reports its own size.
#[derive(Default)]
pub struct ConstructionWork {
    /// Field-word input buffers, including copies used by more than one span.
    pub input_bytes: usize,
    /// Coordinate shifts plus the summand's term offsets, indices and coefficients.
    pub descriptor_bytes: usize,
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
        self.build_gkr_plan(Plan::new(input).map_err(Error::Shape)?, false)
    }

    #[cfg(test)]
    pub(super) fn build_gkr_raw(
        &self,
        input: &GkrConstruction<'_, K>,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        self.build_gkr_plan(Plan::new(input).map_err(Error::Shape)?, true)
    }

    fn build_gkr_plan(
        &self,
        plan: Plan,
        raw: bool,
    ) -> Result<(DeviceMasked<'_>, ConstructionWork), Error> {
        let nodes = plan
            .degree
            .checked_add(1)
            .ok_or(Error::Shape("GKR degree"))?;
        let terms = Terms::new(plan.factors.len(), &plan.terms, nodes).map_err(Error::Shape)?;
        let mut work = ConstructionWork::default();
        let mut factors = Vec::with_capacity(plan.factors.len());
        for factor in plan.factors {
            let x = self.gkr_table(factor.values, plan.len, raw, &mut work)?;
            let (r, v) = match factor.mask {
                Some((mask, v)) => (
                    Some(self.gkr_table(mask, plan.len, raw, &mut work)?),
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
            let data_ptr = data.as_ref().map_or(0, |d| self.ptr(d));
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
            // null operand is never read. Upload, kernel and free share one stream.
            unsafe { b.launch(self.grid(count)) }?;
        }
        Ok(if table.base {
            Buf::Base(out)
        } else {
            Buf::Ext(out)
        })
    }
}
