//! RFC-0025 source §§2–4: complete shard, selection, metadata and raw-alias joins.
use super::{Budget, Error, SourceIndex, SourcePackage};

pub(super) fn complete<E>(
    p: &mut SourcePackage<'_>,
    index: Option<&SourceIndex<'_>>,
    total: u64,
    budget: &mut Budget,
    read_at: &mut impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
) -> Result<(), Error> {
    p.tensors
        .sort_unstable_by(|a, b| a.tensor.name().cmp(b.tensor.name()));
    if p.tensors
        .windows(2)
        .any(|pair| pair[0].tensor.name() == pair[1].tensor.name())
    {
        return Err(Error::SourceDuplicate);
    }
    if let Some(index) = index {
        shards(p, index, total, budget)?;
    }
    let count = p
        .map
        .entries()
        .len()
        .checked_add(p.map.ignored().len())
        .and_then(|n| n.checked_add(usize::from(p.map.alias_name().is_some())))
        .ok_or(Error::Capacity)?;
    let mut expected = budget.vector(count)?;
    expected.extend(
        p.map
            .entries()
            .iter()
            .map(|e| e.name())
            .chain(p.map.ignored().iter().copied())
            .chain(p.map.alias_name()),
    );
    expected.sort_unstable();
    expected.dedup();
    if expected.len() != p.tensors.len()
        || expected
            .iter()
            .zip(&p.tensors)
            .any(|(name, t)| *name != t.tensor.name())
    {
        return Err(Error::SourceSelection);
    }
    let mut physical = budget.vector(p.map.entries().len())?;
    for entry in p.map.entries() {
        let at = p.tensor_index(entry.name())?;
        let tensor = &p.tensors[at].tensor;
        let dtype = match entry.dtype() {
            1 => "F16",
            2 => "BF16",
            3 => "F32",
            4 => "F64",
            _ => return Err(Error::SourceDtype),
        };
        if tensor.dtype() != dtype {
            return Err(Error::SourceDtype);
        }
        if !entry
            .dimensions()
            .iter()
            .copied()
            .map(u64::from)
            .eq(tensor.dimensions().iter().copied())
            || entry.byte_length() != tensor.length()
        {
            return Err(Error::SourceShape);
        }
        physical.push(at);
    }
    if let Some(name) = p.map.alias_name() {
        let token = *physical.first().ok_or(Error::SourceAlias)?;
        let alias = p.tensor_index(name)?;
        let left = &p.tensors[token].tensor;
        let right = &p.tensors[alias].tensor;
        if left.dtype() != right.dtype()
            || left.dimensions() != right.dimensions()
            || left.length() != right.length()
        {
            return Err(Error::SourceAlias);
        }
        let left = p.view(token);
        let right = p.view(alias);
        let mut position = 0u64;
        while position < left.length() {
            let a = left.chunk(position, &mut *read_at)?;
            let b = right.chunk(position, &mut *read_at)?;
            let n = a.as_bytes().len().min(b.as_bytes().len());
            if a.as_bytes()[..n] != b.as_bytes()[..n] {
                return Err(Error::SourceAlias);
            }
            position = position.checked_add(n as u64).ok_or(Error::SourceOffset)?;
        }
    }
    p.physical = physical;
    Ok(())
}
fn shards(
    p: &SourcePackage<'_>,
    index: &SourceIndex<'_>,
    total: u64,
    budget: &mut Budget,
) -> Result<(), Error> {
    if index.entries().len() != p.tensors.len() {
        return Err(Error::SourceShard);
    }
    let mut seen = budget.bytes(p.files.len())?;
    for (entry, route) in index.entries().iter().zip(&p.tensors) {
        // Both lists have unique exact names in sorted order. This checks every
        // actual tensor, including ignored buffers, in its exact assigned shard.
        if entry.name() != route.tensor.name()
            || entry.file_name() != p.files[route.file].file().name()
        {
            return Err(Error::SourceShard);
        }
        seen[route.file] = 1;
    }
    for file in p.source.files() {
        if seen[p.file_index(file.name())?] != 1 {
            return Err(Error::SourceShard);
        }
    }
    if index.total_size() != total {
        return Err(Error::SourceTotalSize);
    }
    Ok(())
}
