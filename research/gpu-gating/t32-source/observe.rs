//! RFC-0010 A9 and A15. Observe only bytes already emitted by the CPU proof producer.
use crate::{PreparedSource, ProofKind};
use std::{sync::OnceLock, time::Instant};
use stele_field::M31;
use stele_hash::{merkle::Digest, ChallengeField};

pub fn now() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .expect("clock overflow")
}

pub struct Visit<'a> {
    pub id: u64,
    pub rows: usize,
    pub cols: usize,
    pub opening: bool,
    pub seed: &'a [u8; 32],
    pub root: Digest,
    pub code: &'a [u8],
    pub message: &'a [M31],
    pub indices: &'a [u64],
    pub responses: &'a [u8],
    pub cpu_start: u64,
    pub cpu_stop: u64,
}
pub static OBSERVER: OnceLock<fn(Visit<'_>)> = OnceLock::new();

impl<K: ChallengeField> PreparedSource<'_, K> {
    pub(crate) fn observe_responses(&self, kind: ProofKind, indices: &[u64], responses: &[u8]) {
        let source = self.source();
        let Some((seed, cpu_start, cpu_stop)) = self.observed_preparation.as_ref() else {
            return;
        };
        assert_eq!(indices.len(), usize::from(source.queries(kind)));
        OBSERVER.get().expect("source observer installed")(Visit {
            id: source.descriptor().id,
            rows: source.rows(),
            cols: source.columns(),
            opening: kind == ProofKind::Opening,
            seed,
            root: source.root(),
            code: source.code_id(),
            message: self.message(),
            indices,
            responses,
            cpu_start: *cpu_start,
            cpu_stop: *cpu_stop,
        });
    }
}
