//! RFC-0008 A7 / RFC-0013 A5. CPU values alone enter the measured proof.
extern crate std;
use super::{bench::LookupInputs, Claim};
use alloc::vec::Vec;
use std::{
    any::Any,
    sync::OnceLock,
    time::{Duration, Instant},
};
use stele_field::{M31, QM31};
use stele_hash::ChallengeField;
use stele_pcs::PreparedSource;
use stele_sumcheck::{Dense, Error, Instance, Summand};

pub enum Event<'a> {
    Lookup {
        id: usize,
        input: &'a LookupInputs<QM31>,
        layers: &'a [Vec<[QM31; 2]>],
        top: Option<[&'a Vec<QM31>; 3]>,
        normalize: Duration,
    },
    Batch {
        id: u64,
        descriptor: &'a [u8],
        message: &'a [M31],
        claims: &'a [Claim<QM31>],
        gammas: &'a [QM31],
    },
    Round {
        values: &'a [QM31],
        cpu: Duration,
    },
    Fold {
        challenge: QM31,
        cpu: Duration,
    },
    Finals {
        values: &'a [QM31],
        cpu: Duration,
    },
}
pub static OBSERVER: OnceLock<fn(Event<'_>)> = OnceLock::new();

fn send(event: Event<'_>) {
    OBSERVER.get().expect("required T32 observer")(event);
}
fn as_type<T: 'static>(value: &dyn Any) -> &T {
    value.downcast_ref().expect("required T32 QM31 field")
}

pub(super) fn lookup<K: ChallengeField>(
    id: usize,
    input: &LookupInputs<K>,
    layers: &Vec<Vec<[K; 2]>>,
    top: Option<[&Vec<K>; 3]>,
    normalize: Duration,
) {
    send(Event::Lookup {
        id,
        input: as_type(input),
        layers: as_type::<Vec<Vec<[QM31; 2]>>>(layers),
        top: top.map(|v| v.map(|x| as_type(x))),
        normalize,
    });
}

pub(super) fn batch<K: ChallengeField>(
    id: u64,
    source: &PreparedSource<'_, K>,
    claims: &Vec<Claim<K>>,
    gammas: &Vec<K>,
) {
    send(Event::Batch {
        id,
        descriptor: &source.source().bytes(),
        message: source.message(),
        claims: as_type::<Vec<Claim<QM31>>>(claims),
        gammas: as_type::<Vec<QM31>>(gammas),
    });
}

pub(super) struct Measured<K>(pub Dense<K>);

impl<K: ChallengeField + Eq> Summand<K> for Measured<K> {
    fn shape(&self) -> (u32, usize) {
        self.0.shape()
    }
    fn validate_instance(&self, i: &Instance<K>) -> Result<(), Error> {
        self.0.validate_instance(i)
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        let start = Instant::now();
        let values = self.0.round(i)?;
        let cpu = start.elapsed();
        send(Event::Round {
            values: as_type::<Vec<QM31>>(&values),
            cpu,
        });
        Ok(values)
    }
    fn fold(&mut self, point: K) -> Result<(), Error> {
        let start = Instant::now();
        self.0.fold(point)?;
        let cpu = start.elapsed();
        send(Event::Fold {
            challenge: *as_type(&point),
            cpu,
        });
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        let start = Instant::now();
        let values = self.0.final_values()?;
        let cpu = start.elapsed();
        send(Event::Finals {
            values: as_type::<Vec<QM31>>(&values),
            cpu,
        });
        Ok(values)
    }
}
