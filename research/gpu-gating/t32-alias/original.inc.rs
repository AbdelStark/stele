// RFC-0013 A5. Follow the same ordered per-source layout entries used by source_message.
impl<K: ChallengeField + CodeField> Plan<K> {
    fn lookup_columns(&self, original: &[Vec<M31>]) -> Result<Vec<t32_alias::Column>, Error> {
        let mut slots = vec![0; self.layouts.len()];
        let mut result = Vec::with_capacity(original.len());
        for (index, values) in original.iter().enumerate() {
            let c = self.columns.get(index).ok_or(Error::Statement)?;
            let layout = self.layouts.get(c.source).ok_or(Error::Statement)?;
            let slot = &mut slots[c.source];
            let &(at, blocks) = layout.offsets.get(*slot).ok_or(Error::Statement)?;
            *slot += 1;
            let len = 1usize.checked_shl(c.log_len).ok_or(Error::Statement)?;
            if len != values.len() || c.source >= self.early() { return Err(Error::Statement); }
            result.push(t32_alias::Column::new(index, c.source, 2usize << layout.ell,
                2usize << layout.m, at, blocks, len, c.limbs).ok_or(Error::Statement)?);
        }
        Ok(result)
    }
}

#[path = "t32_alias.rs"]
pub mod t32_alias;
