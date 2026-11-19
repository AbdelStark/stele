// RFC-0013 A5. Same source, block ordinal and logical data quadrant as Plan::block.
impl<K: ChallengeField + CodeField> Plan<K> {
    fn occurrence_mask_origin(&self, o: &Occurrence, begin: usize) -> Result<[usize; 6], Error> {
        let c = self.columns.get(o.column).ok_or(Error::Statement)?;
        let layout = self.layouts.get(c.source).ok_or(Error::Statement)?;
        let &(_, blocks) = layout
            .offsets
            .get(slot(self, o.column))
            .ok_or(Error::Statement)?;
        let dim = dim::<K>();
        let start = o
            .block
            .checked_mul(dim)
            .and_then(|n| blocks.checked_add(n))
            .ok_or(Error::Statement)?;
        Ok([
            begin,
            c.source,
            2usize << layout.ell,
            2usize << layout.m,
            start,
            dim,
        ])
    }

    fn shared_mask_origin(&self, index: usize, side: Option<usize>) -> Result<[usize; 6], Error> {
        let d = dim::<K>();
        let size = 4 * d;
        if index >= self.blocks || side.is_some_and(|i| i > 1) {
            return Err(Error::Statement);
        }
        let len = if side.is_some() { size / 2 } else { size };
        let offset = d
            .checked_mul(self.stride)
            .and_then(|n| index.checked_mul(size).and_then(|i| n.checked_add(i)))
            .and_then(|n| n.checked_add(side.unwrap_or(0) * len))
            .ok_or(Error::Statement)?;
        Ok([
            0,
            self.layouts.len(),
            2usize << self.shared.0,
            2usize << self.shared.1,
            offset,
            len,
        ])
    }
}
