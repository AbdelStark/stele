// Validate each distinct referenced source/column at every logical input position.
// Column IDs are selected by the plan before looking at any witness value.
{
    extern crate std;
    let start = std::time::Instant::now();
    let projected = plan.lookup_columns(columns)?;
    std::eprintln!("alias_layout columns={} sources={} ns={}", projected.len(), prepared.len(), start.elapsed().as_nanos());
    for (id, lookup) in plan.lookups.iter().enumerate() {
        let start = std::time::Instant::now();
        let mut unique = alloc::collections::BTreeSet::new();
        let mut legs = 0usize;
        let mut source_mask = 0u64;
        let mut cells = 0usize;
        let mut straddling = 0usize;
        for index in lookup.original_columns() {
            legs += 1;
            if !unique.insert(index) { continue; }
            let col = *projected.get(index).ok_or(Error::Statement)?;
            let owner = prepared.get(col.source).ok_or(Error::Statement)?;
            let src = owner.source();
            let message = owner.message();
            let original = &columns[index];
            let descriptor = src.bytes();
            if col.index != index || !src.is_hiding() || src.rows() != col.rows ||
                src.columns() != col.columns || message.len() != col.rows * col.columns ||
                descriptor[25..33] != plan.source_id(col.source).to_le_bytes() {
                return Err(Error::Statement);
            }
            let width = col.columns / 2;
            straddling += usize::from(col.at / width != (col.at + col.len - 1) / width);
            source_mask |= 1u64.checked_shl(u32::try_from(col.source).map_err(|_| Error::Statement)?)
                .ok_or(Error::Statement)?;
            for (j, &expected) in original.iter().enumerate() {
                let pos = col.physical(j).ok_or(Error::Statement)?;
                if message.get(pos) != Some(&expected) { return Err(Error::Statement); }
            }
            cells += col.len;
        }
        std::eprintln!("alias_lookup id={id} legs={legs} unique={} source_mask={source_mask} straddling={straddling} cells={cells} checked_bytes={} ns={}",
            unique.len(), cells*4, start.elapsed().as_nanos());
    }
}
