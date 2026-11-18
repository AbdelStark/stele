//! RFC-0008 A7: store only CPU round/compact results within a single observed GKR step.
extern crate std;
use super::{bench::GkrCase, Error};
use alloc::vec::Vec;
use std::{cell::RefCell, sync::OnceLock, time::Duration};
use stele_field::{Serialize, QM31};
use stele_hash::ChallengeField;

pub type Observer = fn(&GkrCase<'_, QM31>, Record) -> Result<(), Error>;
pub static OBSERVER: OnceLock<Observer> = OnceLock::new();
#[derive(Default)]
pub struct Record {
    pub factors: Duration,
    pub arithmetic: Duration,
    pub rounds_wall: Duration,
    pub polynomials: Vec<Vec<QM31>>,
    pub points: Vec<QM31>,
    pub compact: Option<Vec<QM31>>,
}
std::thread_local! { static STEP: RefCell<Option<Record>> = const { RefCell::new(None) }; }

fn element<K: ChallengeField>(value: K) -> QM31 {
    QM31::from_le_bytes(
        value
            .to_le_bytes()
            .as_ref()
            .try_into()
            .expect("QM31 field width"),
    )
    .expect("canonical CPU field value")
}
pub(super) fn begin(factors: Duration) {
    STEP.with_borrow_mut(|s| {
        assert!(s
            .replace(Record {
                factors,
                ..Record::default()
            })
            .is_none())
    });
}
pub(super) fn round<K: ChallengeField>(values: &[K], elapsed: Duration) {
    STEP.with_borrow_mut(|slot| {
        if let Some(s) = slot {
            s.arithmetic += elapsed;
            s.polynomials
                .push(values.iter().copied().map(element).collect());
        }
    });
}
pub(super) fn fold<K: ChallengeField>(point: K, elapsed: Duration) {
    STEP.with_borrow_mut(|slot| {
        if let Some(s) = slot {
            s.arithmetic += elapsed;
            s.points.push(element(point));
        }
    });
}
pub(super) fn finals<K: ChallengeField>(values: &[K]) {
    STEP.with_borrow_mut(|slot| {
        if let Some(s) = slot {
            assert!(s
                .compact
                .replace(values.iter().copied().map(element).collect())
                .is_none());
        }
    });
}
pub(super) fn end(elapsed: Duration) {
    STEP.with_borrow_mut(|slot| slot.as_mut().expect("GKR start").rounds_wall = elapsed);
}
pub fn observe(case: &GkrCase<'_, QM31>) -> Result<(), Error> {
    let record = STEP.with_borrow_mut(|slot| slot.take().expect("one complete GKR step"));
    OBSERVER.get().expect("required GKR observer")(case, record)
}
