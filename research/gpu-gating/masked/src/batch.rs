//! RFC-0013 A5 item 5: pack claim weights in their original order. A run maps
//! consecutive weights of one claim to consecutive positions within one tile.
use crate::{lookup::words, Field, K, M31};
use stele_reductions::stele_pcs::Source;
use stele_reductions::zk::claims::Claim;

use std::time::{Duration, Instant};

pub(crate) const TILE: usize = 128;

pub(crate) struct Prepared {
    pub message: Vec<u32>,
    pub weights: Vec<[u32; 4]>,
    pub gammas: Vec<[u32; 4]>,
    /// [destination begin, exclusive end, first packed weight, claim index].
    pub runs: Vec<[u64; 4]>,
    /// Each tile owns a stable interval of runs.
    pub offsets: Vec<u64>,
    pub columns: usize,
    pub len: usize,
    pub claimed_sum: K,
    pub schedule_checks: u64,
    pub index_time: std::time::Duration,
    upload_bytes: usize,
}

/// Visit original claims and their consecutive position ranges, splitting at a
/// tile boundary, gap, reversal or repeated position. Every position, including
/// a zero-weight or zero-coefficient occurrence, must be in the data face.
fn visit_runs(
    claims: &[Claim<K>],
    half: usize,
    mut visit: impl FnMut(usize, usize, &[(usize, K)]),
) -> Option<()> {
    for (claim, c) in claims.iter().enumerate() {
        let mut remaining = c.weights.as_slice();
        while let Some(&(start, _)) = remaining.first() {
            if start >= half {
                return None;
            }
            let limit = remaining.len().min(TILE - start % TILE).min(half - start);
            let count = 1 + remaining[1..limit]
                .iter()
                .enumerate()
                .take_while(|(i, (position, _))| *position == start + 1 + *i)
                .count();
            let (entries, tail) = remaining.split_at(count);
            visit(claim, start, entries);
            remaining = tail;
        }
    }
    Some(())
}

impl Prepared {
    pub fn new(
        source: &Source<K>,
        message: &[M31],
        claims: &[Claim<K>],
        gammas: &[K],
    ) -> Option<Self> {
        pack::<false>(source, message, claims, gammas).map(|(p, _)| p)
    }

    /// Compare every H2D word and every scalar used by the batch construction.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.columns == other.columns
            && self.len == other.len
            && self.schedule_checks == other.schedule_checks
            && self.upload_bytes == other.upload_bytes
            && self.claimed_sum == other.claimed_sum
            && self.message == other.message
            && self.weights == other.weights
            && self.gammas == other.gammas
            && self.runs == other.runs
            && self.offsets == other.offsets
    }

    pub fn upload_bytes(&self) -> usize {
        self.upload_bytes
    }

    /// Explicit host vector capacities kept while CUDA constructs the tables.
    pub fn host_buffer_bytes(&self) -> usize {
        self.message.capacity() * 4
            + (self.weights.capacity() + self.gammas.capacity()) * 16
            + self.runs.capacity() * 32
            + self.offsets.capacity() * 8
    }
}

#[derive(Default)]
pub(crate) struct PackTimes {
    pub split: Duration,
    pub alloc: Duration,
    pub weights: Duration,
    pub runs: Duration,
    pub message: Duration,
    pub scratch: usize,
}

pub(crate) fn pack<const PARALLEL: bool>(
    source: &Source<K>,
    message: &[M31],
    claims: &[Claim<K>],
    gammas: &[K],
) -> Option<(Prepared, PackTimes)> {
    pack_with_message::<PARALLEL>(source, Some(message), claims, gammas)
}

/// An absent host message means the caller supplies the checked device original.
pub(crate) fn pack_with_message<const PARALLEL: bool>(
    source: &Source<K>,
    original: Option<&[M31]>,
    claims: &[Claim<K>],
    gammas: &[K],
) -> Option<(Prepared, PackTimes)> {
    let columns = source.columns() / 2;
    let len = source.rows().checked_mul(columns)?;
    let half = len / 2;
    let expected_words = len.checked_mul(2)?;
    if !source.is_hiding()
        || original.is_some_and(|s| s.len() != expected_words)
        || claims.len() != gammas.len()
    {
        return None;
    }
    let message = original.unwrap_or(&[]);
    let index_start = std::time::Instant::now();
    let count = claims
        .iter()
        .try_fold(0usize, |n, c| n.checked_add(c.weights.len()))?;
    let mut offsets = vec![0u64; half.div_ceil(TILE) + 1];
    visit_runs(claims, half, |_, start, _| offsets[start / TILE + 1] += 1)?;
    let mut schedule_checks = 0u64;
    for i in 0..offsets.len() - 1 {
        let width = TILE.min(half - i * TILE) as u64;
        schedule_checks = schedule_checks.checked_add(width.checked_mul(offsets[i + 1])?)?;
        offsets[i + 1] += offsets[i];
    }
    let run_count = usize::try_from(*offsets.last()?).ok()?;
    // Empty CUDA inputs retain a single zero element; the offsets reference no sentinel run.
    let upload_bytes = message
        .len()
        .checked_mul(4)?
        .checked_add(count.max(1).checked_mul(16)?)?
        .checked_add(claims.len().max(1).checked_mul(16)?)?
        .checked_add(run_count.max(1).checked_mul(32)?)?
        .checked_add(offsets.len().checked_mul(8)?)?;
    if upload_bytes.checked_add(len.checked_mul(20)?)? > isize::MAX as usize {
        return None;
    }
    let index_time = index_start.elapsed();
    let mut timing = PackTimes::default();
    let split = Instant::now();
    let mut starts = Vec::new();
    if PARALLEL {
        starts.reserve_exact(claims.len() + 1);
        let mut end = 0;
        for claim in claims {
            starts.push(end);
            end += claim.weights.len(); // count was already checked
        }
        starts.push(end);
    }
    timing.split = split.elapsed();
    timing.scratch = starts.capacity() * size_of::<usize>();
    let alloc = Instant::now();
    let mut weights = if PARALLEL {
        vec![[0; 4]; count.max(1)]
    } else {
        Vec::with_capacity(count.max(1))
    };
    let mut runs = vec![[0; 4]; run_count.max(1)];
    let mut packed_message = if PARALLEL {
        vec![0; message.len()]
    } else {
        Vec::new()
    };
    timing.alloc = alloc.elapsed();
    if PARALLEL {
        let start = Instant::now();
        stele_reductions::parallel::for_each_chunk(&mut weights[..count], |begin, mut out| {
            // The final sentinel and duplicate starts make empty claims harmless.
            if out.is_empty() {
                return;
            }
            let mut c = starts.partition_point(|p| *p <= begin) - 1;
            let mut skip = begin - starts[c];
            while !out.is_empty() {
                let input = &claims[c].weights[skip..];
                let n = out.len().min(input.len());
                let (part, rest) = out.split_at_mut(n);
                for (dst, (_, crate::QM31(crate::CM31(a, b), crate::CM31(c, d)))) in
                    part.iter_mut().zip(input)
                {
                    *dst = [a.as_u32(), b.as_u32(), c.as_u32(), d.as_u32()];
                }
                out = rest;
                skip = 0;
                c += 1;
            }
        });
        timing.weights = start.elapsed();
    }
    drop(starts);
    let write_runs = Instant::now();
    let mut packed_cursor = 0;
    visit_runs(claims, half, |claim, start, entries| {
        let cursor = &mut offsets[start / TILE];
        runs[*cursor as usize] = [
            start as u64,
            (start + entries.len()) as u64,
            if PARALLEL {
                packed_cursor
            } else {
                weights.len()
            } as u64,
            claim as u64,
        ];
        *cursor += 1;
        if PARALLEL {
            packed_cursor += entries.len();
        } else {
            weights.extend(entries.iter().map(|(_, w)| words(*w)));
        }
    })?;
    // All cursors now point to tile ends. Recover starts without a second
    // tile-sized allocation. The previous final sentinel is discarded.
    offsets.rotate_right(1);
    offsets[0] = 0;
    if weights.is_empty() {
        weights.push([0; 4]);
    }
    timing.runs = write_runs.elapsed();
    let write_message = Instant::now();
    if PARALLEL {
        stele_reductions::parallel::for_each_chunk(&mut packed_message, |begin, out| {
            for (dst, x) in out.iter_mut().zip(&message[begin..]) {
                *dst = x.as_u32();
            }
        });
    } else {
        packed_message = message.iter().map(|x| x.as_u32()).collect();
    }
    timing.message = write_message.elapsed();
    let mut gamma_words: Vec<_> = gammas.iter().copied().map(words).collect();
    if gamma_words.is_empty() {
        gamma_words.push([0; 4]);
    }
    Some((
        Prepared {
            message: packed_message,
            weights,
            gammas: gamma_words,
            runs,
            offsets,
            columns,
            len,
            schedule_checks,
            index_time,
            upload_bytes,
            claimed_sum: claims
                .iter()
                .zip(gammas)
                .fold(K::from_i64(0), |sum, (c, g)| sum + *g * c.value),
        },
        timing,
    ))
}
