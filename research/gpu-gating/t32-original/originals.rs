//! RFC-0013 A5/A6. A single proof owns source identities from certificate through opening.
use crate::{gpu::OriginalMessage, K};
use std::{collections::BTreeMap, sync::{Mutex, MutexGuard}};
use stele_reductions::stele_pcs::Source;

pub(super) struct Registry {
    pub owners: BTreeMap<u64, OriginalMessage<'static>>,
    pub roots: BTreeMap<u64, [u8; 32]>,
}
static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    owners: BTreeMap::new(),
    roots: BTreeMap::new(),
});
pub(super) fn lock() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().expect("source owner registry")
}
pub(crate) fn with_originals<T>(visit: impl FnOnce(&BTreeMap<u64, OriginalMessage<'static>>) -> T) -> T {
    visit(&lock().owners)
}
pub(super) fn with_source<T>(source: &Source<K>, visit: impl FnOnce(&OriginalMessage<'static>) -> T) -> T {
    let registry = lock();
    let id = source.descriptor().id;
    assert_eq!(registry.roots.get(&id), Some(&source.root()), "ordinary batch source root");
    visit(registry.owners.get(&id).expect("ordinary batch source owner"))
}
