//! Prover-side work splitting for dense strategies (RFC-0006 A1 prover only).
//!
//! Every split is over exact field additions or independent fold slots, so results,
//! transcripts and proof bytes are identical to the sequential loops. Without the
//! `std` feature everything runs on the calling thread.
use crate::Error;
use alloc::vec::Vec;
use stele_hash::ChallengeField;

/// Below this many columns the thread start-up costs more than it saves.
#[cfg(feature = "std")]
const MIN_CHUNK: usize = 1 << 8;

#[cfg(feature = "std")]
fn threads(len: usize) -> usize {
    let available = std::thread::available_parallelism().map_or(1, |n| n.get());
    available.min(len / MIN_CHUNK).max(1)
}

/// `out = Σ_chunks partial(chunk)` over `0..len`, each chunk filling a fresh `out`.
pub(crate) fn sum_ranges<K: ChallengeField>(
    len: usize,
    out: &mut [K],
    partial: impl Fn(core::ops::Range<usize>, &mut [K]) -> Result<(), Error> + Sync,
) -> Result<(), Error> {
    #[cfg(feature = "std")]
    {
        let n = threads(len);
        if n > 1 {
            let step = len.div_ceil(n);
            let mut parts: Vec<Vec<K>> = Vec::new();
            parts.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
            for _ in 0..n {
                let mut part = Vec::new();
                part.try_reserve_exact(out.len())
                    .map_err(|_| Error::Capacity)?;
                part.resize(out.len(), K::from_i64(0));
                parts.push(part);
            }
            let partial = &partial;
            std::thread::scope(|scope| {
                let handles: Vec<_> = parts
                    .iter_mut()
                    .enumerate()
                    .map(|(t, part)| {
                        let range = t * step..((t + 1) * step).min(len);
                        scope.spawn(move || partial(range, part))
                    })
                    .collect();
                // Join in chunk order; a worker panic re-raises here, an error returns.
                handles
                    .into_iter()
                    .try_for_each(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            })?;
            out.fill(K::from_i64(0));
            for part in &parts {
                for (o, v) in out.iter_mut().zip(part) {
                    *o = *o + *v;
                }
            }
            return Ok(());
        }
    }
    partial(0..len, out)
}

/// Fix the leading coordinate: `t[j] += r·(t[j + half] − t[j])`, then halve.
pub(crate) fn fold<K: ChallengeField>(table: &mut Vec<K>, challenge: K) {
    let half = table.len() / 2;
    {
        let (low, high) = table.split_at_mut(half);
        let apply = |low: &mut [K], high: &[K]| {
            for (a, b) in low.iter_mut().zip(high) {
                *a = *a + challenge * (*b - *a);
            }
        };
        #[cfg(feature = "std")]
        {
            let n = threads(half);
            if n > 1 {
                let step = half.div_ceil(n);
                std::thread::scope(|scope| {
                    for (a, b) in low.chunks_mut(step).zip(high.chunks(step)) {
                        scope.spawn(move || apply(a, b));
                    }
                });
            } else {
                apply(low, high);
            }
        }
        #[cfg(not(feature = "std"))]
        apply(low, high);
    }
    table.truncate(half);
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    #[test]
    fn matches_reference_split_sums_and_folds() {
        // Large enough to split across threads under `std`; identical to the loops.
        let len = 1usize << 14;
        let table: Vec<QM31> = (0..2 * len as i64)
            .map(|i| QM31::from_i64(i * i - 7))
            .collect();
        let mut out = [QM31::from_i64(0); 2];
        sum_ranges(len, &mut out, |range, out| {
            for i in range {
                out[0] = out[0] + table[i];
                out[1] = out[1] + table[i] * table[i + len];
            }
            Ok(())
        })
        .expect("sum");
        let mut expected = [QM31::from_i64(0); 2];
        for i in 0..len {
            expected[0] = expected[0] + table[i];
            expected[1] = expected[1] + table[i] * table[i + len];
        }
        assert_eq!(out, expected);
        let r = QM31::from_i64(123_456_789);
        let mut folded = table.clone();
        fold(&mut folded, r);
        let naive: Vec<QM31> = (0..len)
            .map(|j| table[j] + r * (table[j + len] - table[j]))
            .collect();
        assert_eq!(folded, naive);
    }
}
