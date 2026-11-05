//! RFC-0025 source §§1–4: complete original-file package before any source views.
use super::{
    json::Budget, snapshot::CHUNK, Assets, Error, Source, SourceContainer, SourceFile, SourceIndex,
    SourceSnapshot, SourceTensor,
};
use crate::model::SourceMap;
use alloc::vec::Vec;
mod bind;
mod view;
pub use view::{SourceSlice, SourceView};

/// Complete original files and source-map joins, retaining checked snapshots.
/// Publisher authority, expected adapter completeness, SourceConfig semantics,
/// exact conversion and proof admission remain separate required consumers.
/// ```compile_fail
/// fn change(p: &mut stele_cqis::model::SourcePackage<'_>) { p.physical.clear(); }
/// ```
pub struct SourcePackage<'a> {
    map: &'a SourceMap<'a>,
    source: &'a Source<'a>,
    assets: &'a Assets<'a>,
    files: Vec<SourceSnapshot<'a>>,
    tensors: Vec<RoutedTensor>,
    physical: Vec<usize>,
}
struct RoutedTensor {
    file: usize,
    tensor: SourceTensor,
}

impl<'a> SourcePackage<'a> {
    /// Validate the exact joint supplied label set and hash every complete file
    /// before parsing all containers/index and checking selection and raw aliases.
    /// Labels are passed to the caller's reader; they authorize no filesystem access.
    ///
    /// Snapshot budget counts all retained chunk digests. One shared metadata
    /// budget conservatively charges file/route vectors, parsed metadata and
    /// temporary original headers/index bytes before allocation. Allocator overhead
    /// and at most two 65536-byte read buffers are separate. No partial package or
    /// tensor view escapes failure; every consuming read revalidates original bytes.
    pub fn read_from<E>(
        map: &'a SourceMap<'a>,
        source: &'a Source<'a>,
        assets: &'a Assets<'a>,
        supplied_names: &[&str],
        max_snapshot_bytes: usize,
        max_metadata_bytes: usize,
        mut read_at: impl FnMut(&str, u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let mut budget = Budget::new(max_metadata_bytes);
        let expected = preflight(
            source,
            assets,
            supplied_names,
            max_snapshot_bytes,
            &mut budget,
        )?;
        let mut files = budget.vector(expected.len())?;
        for file in expected {
            let mut position = 0u64;
            let snapshot = SourceSnapshot::read_from(file, max_snapshot_bytes, |out| {
                let n = read_at(file.name(), position, out).map_err(|_| Error::Read)?;
                position = position.checked_add(n as u64).ok_or(Error::Read)?;
                Ok::<_, Error>(n)
            })?;
            files.push(snapshot);
        }
        let mut package = Self {
            map,
            source,
            assets,
            files,
            tensors: Vec::new(),
            physical: Vec::new(),
        };
        let index = if let Some(file) = source.index() {
            let at = package.file_index(file.name())?;
            Some(SourceIndex::read_with_budget(
                &package.files[at],
                &mut budget,
                |offset, out| read_at(file.name(), offset, out),
            )?)
        } else {
            None
        };
        let mut total = 0u64;
        for file in source.files() {
            let at = package.file_index(file.name())?;
            let container = SourceContainer::read_with_budget(
                &package.files[at],
                &mut budget,
                |offset, out| read_at(file.name(), offset, out),
            )?;
            total = total
                .checked_add(container.payload_length())
                .ok_or(Error::FileLength)?;
            for tensor in container.into_tensors() {
                budget.push(&mut package.tensors, RoutedTensor { file: at, tensor })?;
            }
        }
        bind::complete(
            &mut package,
            index.as_ref(),
            total,
            &mut budget,
            &mut read_at,
        )?;
        Ok(package)
    }
    /// Complete checked physical source map used for this package.
    pub fn source_map(&self) -> &SourceMap<'a> {
        self.map
    }
    /// Original canonical source declaration; authority remains external.
    pub fn source(&self) -> &Source<'a> {
        self.source
    }
    /// Exact auxiliary roles whose original files were completely hashed.
    pub fn assets(&self) -> &Assets<'a> {
        self.assets
    }
    /// Raw original source for a physical ordinal. Fused sources retain their
    /// full original extent; the Map's exact transform is applied by conversion.
    pub fn tensor(&self, ordinal: u16) -> Option<SourceView<'_, 'a>> {
        self.physical
            .get(usize::from(ordinal))
            .map(|&index| self.view(index))
    }
    /// Checked original config/tokenizer/generation bytes, only for declared roles.
    pub fn asset(&self, name: &str) -> Option<SourceView<'_, 'a>> {
        let declared = self.assets.config().name() == name
            || self.assets.generation().is_some_and(|f| f.name() == name)
            || self
                .assets
                .tokenizers()
                .binary_search_by(|f| f.name().cmp(name))
                .is_ok();
        if !declared {
            return None;
        }
        let snapshot = self.files.get(self.file_index(name).ok()?)?;
        Some(SourceView::new(snapshot, 0, snapshot.file().length()))
    }
    fn file_index(&self, name: &str) -> Result<usize, Error> {
        self.files
            .binary_search_by(|f| f.file().name().cmp(name))
            .map_err(|_| Error::FileSet)
    }
    fn tensor_index(&self, name: &str) -> Result<usize, Error> {
        self.tensors
            .binary_search_by(|t| t.tensor.name().cmp(name))
            .map_err(|_| Error::SourceSelection)
    }
    fn view(&self, index: usize) -> SourceView<'_, 'a> {
        let route = &self.tensors[index];
        SourceView::new(
            &self.files[route.file],
            route.tensor.offset(),
            route.tensor.length(),
        )
    }
}

fn preflight<'a>(
    source: &Source<'a>,
    assets: &Assets<'a>,
    supplied: &[&str],
    max_snapshots: usize,
    budget: &mut Budget,
) -> Result<Vec<SourceFile<'a>>, Error> {
    source
        .total_length()
        .checked_add(assets.total_length())
        .ok_or(Error::FileLength)?;
    let count = source
        .files()
        .len()
        .checked_add(usize::from(source.index().is_some()))
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(assets.tokenizers().len()))
        .and_then(|n| n.checked_add(usize::from(assets.generation().is_some())))
        .ok_or(Error::Capacity)?;
    if supplied.len() != count {
        return Err(Error::FileSet);
    }
    let mut expected: Vec<SourceFile<'a>> = budget.vector(count)?;
    expected.extend(
        source
            .files()
            .iter()
            .chain(source.index())
            .chain(core::iter::once(assets.config()))
            .chain(assets.tokenizers())
            .chain(assets.generation())
            .copied(),
    );
    expected.sort_unstable_by(|a, b| a.name().cmp(b.name()));
    if expected.windows(2).any(|p| p[0].name() == p[1].name()) {
        return Err(Error::FileSet);
    }
    let mut names = budget.vector(supplied.len())?;
    names.extend_from_slice(supplied);
    names.sort_unstable();
    if expected
        .iter()
        .zip(names)
        .any(|(file, name)| file.name() != name)
    {
        return Err(Error::FileSet);
    }
    let mut bytes = 0usize;
    for file in &expected {
        let count = usize::try_from(file.length().div_ceil(CHUNK)).map_err(|_| Error::Capacity)?;
        bytes = bytes
            .checked_add(count.checked_mul(32).ok_or(Error::Capacity)?)
            .ok_or(Error::Capacity)?;
    }
    if bytes > max_snapshots {
        return Err(Error::Capacity);
    }
    Ok(expected)
}
