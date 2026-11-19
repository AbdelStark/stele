//! RFC-0013 A5. One original base column occupies [at, first_block) in the data quadrant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub index: usize,
    pub source: usize,
    /// Physical dimensions of the entire hiding message, including masks.
    pub rows: usize,
    pub columns: usize,
    pub at: usize,
    pub len: usize,
}

impl Column {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: usize,
        source: usize,
        rows: usize,
        columns: usize,
        at: usize,
        first_block: usize,
        len: usize,
        limbs: usize,
    ) -> Option<Self> {
        let cells = rows.checked_mul(columns)?;
        if !rows.is_power_of_two()
            || !columns.is_power_of_two()
            || rows < 2
            || columns < 2
            || !len.is_power_of_two()
            || limbs != 1
            || at.checked_add(len)? != first_block
            || first_block > cells / 4
        {
            return None;
        }
        Some(Self {
            index,
            source,
            rows,
            columns,
            at,
            len,
        })
    }

    pub fn descriptor(self) -> [usize;6] { [self.index, self.source, self.rows, self.columns, self.at, self.len] }

    pub fn physical(self, p: usize) -> Option<usize> {
        if p >= self.len {
            return None;
        }
        let x = self.at.checked_add(p)?;
        let width = self.columns / 2;
        (x / width)
            .checked_mul(self.columns)?
            .checked_add(x % width)
    }
}

#[cfg(test)]
#[path = "t32_alias_tests.rs"]
mod tests;
