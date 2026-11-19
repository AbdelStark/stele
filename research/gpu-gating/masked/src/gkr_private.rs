//! RFC-0013 A5 / RFC-0008 A7: bind each private mask window to its actual factor span.
use super::{Op, Plan, Span};

impl Plan {
    /// Each range is (destination start, source id, physical rows, columns,
    /// logical data position, limb count). Compact member order can differ
    /// from the writer's sorted, disjoint destination order.
    pub(crate) fn original_masks(
        mut self,
        windows: &[Vec<[usize; 6]>],
    ) -> Result<Self, &'static str> {
        if windows.len() != self.factors.len() {
            return Err("GKR private mask factor count");
        }
        for (factor, origins) in self.factors.iter_mut().zip(windows) {
            if let [span] = &mut factor.values.spans[..] {
                if matches!(span.op, Op::Block) {
                    let [origin] = origins.as_slice() else {
                        return Err("GKR private interpolation window");
                    };
                    if factor.mask.is_some() || span.data.len() != 4 + 2 * span.arg as usize {
                        return Err("GKR private interpolation payload");
                    }
                    bind(span, *origin, 2 * span.arg as usize)?;
                    span.op = Op::OriginalBlock;
                    // The line challenge is drawn after commitment. Both mask halves
                    // remain on the original owner and are read by address.
                    span.data.truncate(4);
                    continue;
                }
            }
            let Some((mask, _)) = &mut factor.mask else {
                if !origins.is_empty() {
                    return Err("unexpected GKR private mask window");
                }
                continue;
            };
            if mask.spans.len() != origins.len() {
                return Err("GKR private mask member count");
            }
            let mut ordered = origins.to_vec();
            ordered.sort_unstable_by_key(|origin| origin[0]);
            for (span, origin) in mask.spans.iter_mut().zip(ordered) {
                let entries = span.data.len();
                if !matches!(span.op, Op::GatherBase) || entries == 0 {
                    return Err("GKR private mask gather");
                }
                bind(span, origin, entries)?;
                span.op = Op::OriginalBase;
                span.data = Vec::new();
            }
        }
        Ok(self)
    }
}

fn bind(span: &mut Span, origin: [usize; 6], entries: usize) -> Result<(), &'static str> {
    let [begin, _, rows, columns, at, count] = origin;
    let cells = rows
        .checked_mul(columns)
        .ok_or("GKR private source extent")?;
    if begin != span.begin as usize
        || !entries.is_power_of_two()
        || entries != count
        || !rows.is_power_of_two()
        || !columns.is_power_of_two()
        || rows < 2
        || columns < 2
        || at.checked_add(entries).is_none_or(|end| end > cells / 4)
    {
        return Err("GKR private source window");
    }
    span.original = Some(origin);
    Ok(())
}
#[cfg(test)]
#[path = "gkr_private_tests.rs"]
mod tests;
