//! RFC-0008 A7. Borrow true CPU lookup inputs and release the device tree before the leaf.
extern crate std;
use super::bench::LookupInputs;
use alloc::vec::Vec;
use std::{any::Any, sync::OnceLock, time::Duration};
use stele_field::QM31;
use stele_hash::ChallengeField;
pub enum Event<'a> {
    Lookup {
        id: usize,
        input: &'a LookupInputs<QM31>,
        layers: &'a [Vec<[QM31; 2]>],
        top: Option<[&'a Vec<QM31>; 3]>,
        normalize: Duration,
    },
    Release(usize),
}
pub static OBSERVER: OnceLock<fn(Event<'_>)> = OnceLock::new();
fn field<T: 'static>(x: &dyn Any) -> &T {
    x.downcast_ref().expect("required QM31 lookup")
}
pub(super) fn lookup<K: ChallengeField>(
    id: usize,
    input: &LookupInputs<K>,
    layers: &Vec<Vec<[K; 2]>>,
    top: Option<[&Vec<K>; 3]>,
    normalize: Duration,
) {
    OBSERVER.get().expect("required resident observer")(Event::Lookup {
        id,
        input: field(input),
        layers: field::<Vec<Vec<[QM31; 2]>>>(layers),
        top: top.map(|set| set.map(|v| field(v))),
        normalize,
    });
}
pub(super) fn release(id: usize) {
    OBSERVER.get().expect("required resident observer")(Event::Release(id));
}
