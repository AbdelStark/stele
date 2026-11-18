//! RFC-0014 §5. No field data leave the CPU arithmetic path.
use super::std::{cell::Cell, time::Instant};

#[derive(Clone, Copy, Default)]
struct Counts {
    tables: u128,
    arithmetic: u128,
    calls: u32,
}
super::std::thread_local! { static STEP: Cell<Option<Counts>> = const { Cell::new(None) }; }

pub(super) fn begin() {
    STEP.with(|s| assert!(s.replace(Some(Counts::default())).is_none()));
}

pub(super) fn table(start: Instant) {
    let elapsed = start.elapsed().as_nanos();
    STEP.with(|s| {
        let mut counts = s.get().expect("lookup factor outside a GKR step");
        counts.tables += elapsed;
        s.set(Some(counts));
    });
}

pub(super) struct Round(Option<Instant>);
impl Round {
    pub(super) fn start() -> Self {
        Self(STEP.with(|s| s.get().map(|_| Instant::now())))
    }
}
impl Drop for Round {
    fn drop(&mut self) {
        if let Some(start) = self.0 {
            let elapsed = start.elapsed().as_nanos();
            STEP.with(|s| {
                let mut counts = s.get().expect("GKR arithmetic outside step");
                counts.arithmetic += elapsed;
                counts.calls += 1;
                s.set(Some(counts));
            });
        }
    }
}

pub(super) fn end(step: usize, lookup: usize, n: u32, map: bool, factors: u128, rounds: u128) {
    let count = STEP.with(Cell::take).expect("GKR step");
    assert!(count.calls == 2 * n && count.tables <= factors && count.arithmetic <= rounds);
    super::std::eprintln!(
        "mac_gkr step={step} lookup={lookup} vars={n} compact={} factor_ns={factors} table_ns={} rounds_ns={rounds} arithmetic_ns={} calls={}",
        u8::from(map), count.tables, count.arithmetic, count.calls
    );
}
