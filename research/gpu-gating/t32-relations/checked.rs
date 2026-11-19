//! RFC-0013 A4/A5. The ordinary protocol consumes independent device outputs after parity checks.
extern crate std;
use super::{bench::Masked, Occurrences};
use alloc::{boxed::Box, vec::Vec};
use core::{any::Any, cell::Cell};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use stele_field::QM31;
use stele_hash::ChallengeField;
use stele_sumcheck::{Error, Instance, Summand};

pub struct Backend {
    pub begin: fn(usize),
    pub build: fn(usize, &Masked<QM31>, Duration),
    pub round: fn(usize) -> Vec<QM31>,
    pub fold: fn(usize, QM31),
    pub finals: fn(usize) -> Vec<QM31>,
    pub finish: fn(usize, Duration),
    pub end: fn(usize),
}
pub static BACKEND: OnceLock<Backend> = OnceLock::new();
pub(super) fn backend() -> &'static Backend {
    BACKEND.get().expect("required masked relation H100")
}

pub(super) struct Checked<K> {
    reference: Occurrences<K>,
    id: usize,
    cpu: Cell<Duration>,
}
impl<K: ChallengeField + Eq> Checked<K> {
    pub(super) fn new(id: usize, source: Occurrences<K>, host: Duration) -> Self {
        let reference = Masked(source);
        let actual = (&reference as &dyn Any)
            .downcast_ref()
            .expect("required QM31 occurrence tables");
        (backend().build)(id, actual, host);
        Self {
            reference: reference.0,
            id,
            cpu: Cell::new(Duration::ZERO),
        }
    }
    fn compare(&self, received: Vec<QM31>, expected: Vec<K>) -> Result<Vec<K>, Error> {
        // Return ownership of the device output to the ordinary Fiat–Shamir engine.
        let result = (Box::new(received) as Box<dyn Any>)
            .downcast::<Vec<K>>()
            .map_err(|_| Error::Source)?;
        if *result != expected {
            return Err(Error::Source);
        }
        Ok(*result)
    }
}
impl<K: ChallengeField + Eq> Summand<K> for Checked<K> {
    fn shape(&self) -> (u32, usize) {
        self.reference.shape()
    }
    fn validate_instance(&self, i: &Instance<K>) -> Result<(), Error> {
        self.reference.validate_instance(i)
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        let received = (backend().round)(self.id);
        let start = Instant::now();
        let expected = self.reference.round(i)?;
        self.cpu.set(self.cpu.get() + start.elapsed());
        self.compare(received, expected)
    }
    fn fold(&mut self, point: K) -> Result<(), Error> {
        (backend().fold)(
            self.id,
            *(&point as &dyn Any).downcast_ref().ok_or(Error::Source)?,
        );
        let start = Instant::now();
        self.reference.fold(point)?;
        self.cpu.set(self.cpu.get() + start.elapsed());
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        let received = (backend().finals)(self.id);
        let start = Instant::now();
        let expected = self.reference.final_values()?;
        let cpu = self.cpu.get() + start.elapsed();
        let result = self.compare(received, expected)?;
        (backend().finish)(self.id, cpu);
        Ok(result)
    }
}
