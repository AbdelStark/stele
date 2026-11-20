//! Prover-side work splitting for dense strategies (RFC-0006 A1 prover only).
//!
//! Every split is over exact field additions or independent, disjoint output slots,
//! so results, transcripts and proof bytes are identical to the sequential loops.
//! With the `std` feature the work runs on rayon's global pool (no per-round thread
//! spawns); without it everything runs on the calling thread. Worker panics propagate
//! to the caller.
use crate::Error;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use rayon::prelude::*;
use stele_hash::ChallengeField;

/// Prover stage timing (task E16-22): with `std` and the environment variable
/// `STELE_STAGE_TIMES` set, each [`Laps::lap`] prints `stage <name> <ms>` (the wall time
/// since the previous lap) to stderr. Otherwise it does nothing. It never touches a
/// transcript, a value or a byte.
pub struct Laps {
    #[cfg(feature = "std")]
    last: Option<std::time::Instant>,
}

impl Laps {
    /// Start timing if `STELE_STAGE_TIMES` is set.
    pub fn start() -> Self {
        Self {
            #[cfg(feature = "std")]
            last: std::env::var_os("STELE_STAGE_TIMES").map(|_| std::time::Instant::now()),
        }
    }
    /// Report the stage that just ended and start the next.
    pub fn lap(&mut self, _name: &str) {
        #[cfg(feature = "std")]
        if let Some(last) = &mut self.last {
            std::eprintln!("stage {_name} {}", last.elapsed().as_millis());
            *last = std::time::Instant::now();
        }
    }
}

/// Below this many items a split costs more than it saves.
#[cfg(feature = "std")]
const MIN_CHUNK: usize = 1 << 8;

/// Pieces per pool thread: a slow or busy core takes fewer of them (work stealing).
#[cfg(feature = "std")]
const PIECES: usize = 4;

#[cfg(feature = "std")]
fn chunks(len: usize) -> usize {
    (PIECES * rayon::current_num_threads())
        .min(len / MIN_CHUNK)
        .max(1)
}

/// `out = Σ_chunks partial(chunk)` over `0..len`, each chunk filling a fresh `out`;
/// partial results are added in chunk order.
pub fn sum_ranges<K: ChallengeField>(
    len: usize,
    out: &mut [K],
    partial: impl Fn(core::ops::Range<usize>, &mut [K]) -> Result<(), Error> + Sync,
) -> Result<(), Error> {
    sum_ranges_weighted(len, 1, out, partial)
}

/// [`sum_ranges`] for items that each cost about `cost` dense-round items, so a short
/// range of heavy items still splits (E16-24: masked rounds with many terms).
pub fn sum_ranges_weighted<K: ChallengeField>(
    len: usize,
    cost: usize,
    out: &mut [K],
    partial: impl Fn(core::ops::Range<usize>, &mut [K]) -> Result<(), Error> + Sync,
) -> Result<(), Error> {
    #[cfg(not(feature = "std"))]
    let _ = cost;
    #[cfg(feature = "std")]
    {
        let n = chunks(len.saturating_mul(cost.max(1))).min(len.max(1));
        if n > 1 {
            let step = len.div_ceil(n);
            let width = out.len();
            let parts: Vec<Vec<K>> = (0..n)
                .into_par_iter()
                .map(|t| {
                    let mut part = Vec::new();
                    part.try_reserve_exact(width).map_err(|_| Error::Capacity)?;
                    part.resize(width, K::from_i64(0));
                    partial(t * step..((t + 1) * step).min(len), &mut part)?;
                    Ok(part)
                })
                .collect::<Result<_, Error>>()?;
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

/// Fill `out` chunk by chunk: `fill(start, chunk)` writes `out[start..start + len]`.
/// Chunks are disjoint, so the result does not depend on the split.
pub fn for_each_chunk<T: Send>(out: &mut [T], fill: impl Fn(usize, &mut [T]) + Sync) {
    for_each_chunk_weighted(out, 1, fill)
}

/// [`for_each_chunk`] for items that each cost about `cost` table entries, so a short
/// run of heavy items still splits (E16-24: many small sumcheck factors).
pub fn for_each_chunk_weighted<T: Send>(
    out: &mut [T],
    cost: usize,
    fill: impl Fn(usize, &mut [T]) + Sync,
) {
    #[cfg(not(feature = "std"))]
    let _ = cost;
    #[cfg(feature = "std")]
    {
        let n = chunks(out.len().saturating_mul(cost.max(1))).min(out.len().max(1));
        if n > 1 {
            let step = out.len().div_ceil(n);
            out.par_chunks_mut(step)
                .enumerate()
                .for_each(|(t, chunk)| fill(t * step, chunk));
            return;
        }
    }
    fill(0, out);
}

/// `(0..len).map(f)` in index order, each item one task on the pool. For a few large,
/// independent items, which `for_each_chunk` (runs of at least `MIN_CHUNK`) never splits.
pub fn map<T: Send>(len: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
    #[cfg(feature = "std")]
    if len > 1 {
        return (0..len).into_par_iter().map(f).collect();
    }
    (0..len).map(f).collect()
}

/// `(a(), b())`, the two run concurrently on the pool.
pub fn join<A: Send, B: Send>(
    a: impl FnOnce() -> A + Send,
    b: impl FnOnce() -> B + Send,
) -> (A, B) {
    #[cfg(feature = "std")]
    return rayon::join(a, b);
    #[cfg(not(feature = "std"))]
    (a(), b())
}

/// `gate()` beside `work()`, with `gate` deciding: its error is returned even if `work`
/// panicked, so work on an input the gate rejects never decides the outcome. When the
/// gate passes, a panic in `work` propagates. Without `std`, `gate` runs first and
/// `work` only after it passes.
pub fn gated<E: Send, B: Send>(
    gate: impl FnOnce() -> Result<(), E> + Send,
    work: impl FnOnce() -> B + Send,
) -> Result<B, E> {
    #[cfg(feature = "std")]
    {
        extern crate std;
        use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
        let (verdict, result) = rayon::join(gate, || catch_unwind(AssertUnwindSafe(work)));
        verdict?;
        Ok(result.unwrap_or_else(|panic| resume_unwind(panic)))
    }
    #[cfg(not(feature = "std"))]
    {
        gate()?;
        Ok(work())
    }
}

/// `stele_poly::eq_table(point)`, split into blocks: entry `(hi << r) | lo` is
/// `eq(point[..k], hi) · eq(point[k..], lo)`. Field products are exact, so every
/// entry equals the sequential table's.
pub fn eq_table<K: ChallengeField>(point: &[K]) -> Result<Vec<K>, Error> {
    #[cfg(feature = "std")]
    {
        let k = chunks(1usize.checked_shl(point.len() as u32).unwrap_or(0))
            .next_power_of_two()
            .trailing_zeros() as usize;
        if k > 0 && k <= point.len() {
            let high = stele_poly::eq_table(&point[..k]).map_err(|_| Error::Capacity)?;
            let low = stele_poly::eq_table(&point[k..]).map_err(|_| Error::Capacity)?;
            let mut out = Vec::new();
            out.try_reserve_exact(high.len() * low.len())
                .map_err(|_| Error::Capacity)?;
            out.resize(high.len() * low.len(), K::from_i64(0));
            out.par_chunks_mut(low.len())
                .zip(high.par_iter())
                .for_each(|(block, h)| {
                    for (o, l) in block.iter_mut().zip(&low) {
                        *o = *h * *l;
                    }
                });
            return Ok(out);
        }
    }
    stele_poly::eq_table(point).map_err(|_| Error::Capacity)
}

/// Fix the leading coordinate: `t[j] += r·(t[j + half] − t[j])`, then halve.
/// `table.len()` must be a power of two (a dense MLE table).
pub fn fold<K: ChallengeField>(table: &mut Vec<K>, challenge: K) {
    debug_assert!(table.len().is_power_of_two());
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
            let n = chunks(half);
            if n > 1 {
                let step = half.div_ceil(n);
                low.par_chunks_mut(step)
                    .zip(high.par_chunks(step))
                    .for_each(|(a, b)| apply(a, b));
            } else {
                apply(low, high);
            }
        }
        #[cfg(not(feature = "std"))]
        apply(low, high);
    }
    table.truncate(half);
}

/// Fold a base-field M31 table into a half-sized extension-field table (RFC-0006 A5, E20-01):
/// `out[j] = from_m31(t[j]) + challenge · (t[j + half] − t[j])`.
/// `table.len()` must be a power of two and at least 2.
pub fn fold_base<K: ChallengeField>(
    table: &[stele_field::M31],
    challenge: K,
) -> Result<Vec<K>, Error> {
    if !table.len().is_power_of_two() || table.len() < 2 {
        return Err(Error::PublicShape);
    }
    let half = table.len() / 2;
    let one = K::from_i64(1);
    let mut out = Vec::new();
    out.try_reserve_exact(half).map_err(|_| Error::Capacity)?;
    out.resize(half, K::from_i64(0));
    let (low, high) = table.split_at(half);
    for_each_chunk(&mut out, |start, chunk| {
        for (o, (&a, &b)) in chunk
            .iter_mut()
            .zip(low[start..].iter().zip(&high[start..]))
        {
            *o = one.mul_m31(a) + challenge.mul_m31(b - a);
        }
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    #[test]
    fn matches_reference_split_sums_and_folds() {
        // Large enough to split under `std`; identical to the loops.
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
        let mut filled = alloc::vec![0usize; len];
        for_each_chunk(&mut filled, |start, chunk| {
            for (j, v) in chunk.iter_mut().enumerate() {
                *v = (start + j) * 3;
            }
        });
        assert!(filled.iter().enumerate().all(|(j, v)| *v == 3 * j));
    }

    #[test]
    #[cfg(feature = "std")]
    #[should_panic(expected = "worker")]
    fn propagates_worker_panics() {
        let mut out = alloc::vec![0u8; 1 << 14];
        // Every chunk starts below the length, so every worker panics.
        for_each_chunk(&mut out, |start, _| assert!(start >= 1 << 14, "worker"));
    }

    #[test]
    fn rejects_by_gate_even_when_work_panics() {
        let result: Result<(), u8> = gated(
            || Err(7),
            || assert!(core::hint::black_box(false), "work on a rejected input"),
        );
        assert_eq!(result, Err(7));
        assert_eq!(gated(|| Ok::<(), u8>(()), || 5), Ok(5));
        assert_eq!(map(3, |i| i * i), alloc::vec![0, 1, 4]);
    }

    #[test]
    #[should_panic(expected = "work")]
    fn rejects_silent_loss_of_a_work_panic_after_a_passing_gate() {
        let _ = gated(
            || Ok::<(), u8>(()),
            || assert!(core::hint::black_box(false), "work"),
        );
    }

    #[test]
    fn matches_reference_base_first_round_zerocheck_and_claim_batch() {
        use crate::{claim_batch::Batch, zerocheck::Zerocheck, Instance, Term};
        use alloc::vec;
        use stele_field::M31;
        use stele_hash::Transcript;

        // 1. fold_base vs fold parity.
        let m31_tbl: Vec<M31> = (0..1usize << 10)
            .map(|i| M31::from_i64(i as i64 * 17 - 300))
            .collect();
        let mut k_tbl: Vec<QM31> = m31_tbl
            .iter()
            .map(|&v| QM31::from_i64(i64::from(v.as_u32())))
            .collect();
        let ch = QM31::from_i64(13) + QM31::from_i64(5);
        let fb = fold_base(&m31_tbl, ch).expect("fold_base");
        fold(&mut k_tbl, ch);
        assert_eq!(fb, k_tbl);

        // 2. ClaimBatch::prove_base_with_point vs prove_with_point (num_vars = 0, 1, 9).
        for nv in [0u32, 1, 9] {
            let n = 1usize << nv;
            let raw: Vec<M31> = (0..n).map(|i| M31::from_i64(i as i64 * 7 - 11)).collect();
            let k_raw: Vec<QM31> = raw
                .iter()
                .map(|&v| QM31::from_i64(i64::from(v.as_u32())))
                .collect();
            let p1: Vec<QM31> = (0..nv).map(|i| QM31::from_i64(i as i64 + 2)).collect();
            let p2: Vec<QM31> = (0..nv).map(|i| QM31::from_i64(i as i64 + 5)).collect();
            let eval = |pt: &[QM31]| {
                let eq = stele_poly::eq_table(pt).expect("eq");
                k_raw
                    .iter()
                    .zip(eq)
                    .fold(QM31::from_i64(0), |s, (a, b)| s + *a * b)
            };
            let claims = vec![(p1.clone(), eval(&p1)), (p2.clone(), eval(&p2))];
            let batch = Batch {
                id: 77,
                tensor: 3,
                num_vars: nv,
                claims: &claims,
            };
            let mut t_ref = Transcript::new(b"e20-01/batch").expect("t");
            let mut t_base = Transcript::new(b"e20-01/batch").expect("t");
            let ref_res = batch.prove_with_point(k_raw, &mut t_ref).expect("ref");
            let base_res = batch
                .prove_base_with_point(&raw, &mut t_base)
                .expect("base");
            assert_eq!(base_res, ref_res, "batch nv={nv}");
        }

        // 3. Zerocheck::prove_base_with_point vs prove_with_point (skip = 0 and 2, nv = 0, 1, 6, 9).
        for (nv, skip) in [(0u32, 0u8), (1, 0), (6, 0), (6, 2), (9, 0)] {
            let n = 1usize << nv;
            let a: Vec<M31> = (0..n).map(|i| M31::from_i64(i as i64 * 3 - 5)).collect();
            let b: Vec<M31> = (0..n).map(|i| M31::from_i64(i as i64 * 5 + 7)).collect();
            let c: Vec<M31> = a
                .iter()
                .zip(&b)
                .map(|(&x, &y)| x * x * y + M31::from_i64(2) * x - M31::from_i64(3))
                .collect();
            let base_tables = vec![a, b, c];
            let k_tables: Vec<Vec<QM31>> = base_tables
                .iter()
                .map(|t| {
                    t.iter()
                        .map(|&v| QM31::from_i64(i64::from(v.as_u32())))
                        .collect()
                })
                .collect();
            let inst = Instance {
                id: 88,
                num_vars: nv,
                inputs: vec![0, 1, 2],
                terms: vec![
                    Term {
                        coefficient: QM31::from_i64(1),
                        factors: vec![0, 0, 1],
                    },
                    Term {
                        coefficient: QM31::from_i64(2),
                        factors: vec![0],
                    },
                    Term {
                        coefficient: QM31::from_i64(-3),
                        factors: vec![],
                    },
                    Term {
                        coefficient: QM31::from_i64(-1),
                        factors: vec![2],
                    },
                ],
                claimed_sum: QM31::from_i64(0),
            };
            let zc = Zerocheck {
                instance: &inst,
                skip,
            };
            let mut t_ref = Transcript::new(b"e20-01/zc").expect("t");
            let mut t_base = Transcript::new(b"e20-01/zc").expect("t");
            let ref_res = zc.prove_with_point(&k_tables, &mut t_ref).expect("ref");
            let base_res = zc
                .prove_base_with_point(&base_tables, &mut t_base)
                .expect("base");
            assert_eq!(base_res, ref_res, "zc nv={nv} skip={skip}");
        }
    }
}
