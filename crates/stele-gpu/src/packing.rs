//! RFC-0013 A5 item 5. Ordered contributions to the data half of the weight table.
use super::runtime::Error;
use stele_kernels::{Field, WeightedClaim, CM31, M31, QM31};

pub(crate) const TILE: usize = 128;
pub(crate) fn words(QM31(CM31(a, b), CM31(c, d)): QM31) -> [u32; 4] {
    [a.as_u32(), b.as_u32(), c.as_u32(), d.as_u32()]
}
pub(crate) fn canonical([a, b, c, d]: [u32; 4]) -> Result<QM31, Error> {
    let base = |x| M31::from_canonical(x).ok_or(Error::Noncanonical);
    Ok(QM31(CM31(base(a)?, base(b)?), CM31(base(c)?, base(d)?)))
}

pub(crate) struct Packed {
    pub weights: Vec<[u32; 4]>,
    pub gammas: Vec<[u32; 4]>,
    pub runs: Vec<[u64; 4]>,
    pub offsets: Vec<u64>,
    pub sum: QM31,
}
fn runs(
    claims: &[WeightedClaim<'_, QM31>],
    half: usize,
    mut visit: impl FnMut(usize, usize, &[(usize, QM31)]),
) -> Result<(), Error> {
    for (claim, c) in claims.iter().enumerate() {
        let mut remaining = c.weights;
        while let Some(&(start, _)) = remaining.first() {
            if start >= half {
                return Err(Error::Geometry);
            }
            let limit = remaining.len().min(TILE - start % TILE).min(half - start);
            let count = 1 + remaining[1..limit]
                .iter()
                .enumerate()
                .take_while(|(i, (p, _))| *p == start + 1 + *i)
                .count();
            let (entries, tail) = remaining.split_at(count);
            visit(claim, start, entries);
            remaining = tail;
        }
    }
    Ok(())
}

impl Packed {
    pub fn new(claims: &[WeightedClaim<'_, QM31>], half: usize) -> Result<Self, Error> {
        let count = claims
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.weights.len()))
            .ok_or(Error::Budget)?;
        let mut offsets = vec![0u64; half.div_ceil(TILE) + 1];
        runs(claims, half, |_, start, _| offsets[start / TILE + 1] += 1)?;
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let mut weights = Vec::new();
        weights
            .try_reserve_exact(count.max(1))
            .map_err(|_| Error::Budget)?;
        let mut packed_runs =
            vec![[0u64; 4]; (*offsets.last().ok_or(Error::Geometry)? as usize).max(1)];
        runs(claims, half, |claim, start, entries| {
            let cursor = &mut offsets[start / TILE];
            packed_runs[*cursor as usize] = [
                start as u64,
                (start + entries.len()) as u64,
                weights.len() as u64,
                claim as u64,
            ];
            *cursor += 1;
            weights.extend(entries.iter().map(|(_, w)| words(*w)));
        })?;
        // The per-tile insertion cursors now point to the end of each tile's range.
        offsets.rotate_right(1);
        offsets[0] = 0;
        if weights.is_empty() {
            weights.push([0; 4]);
        }
        let mut gammas: Vec<_> = claims.iter().map(|c| words(c.gamma)).collect();
        if gammas.is_empty() {
            gammas.push([0; 4]);
        }
        let sum = claims
            .iter()
            .fold(QM31::from_i64(0), |s, c| s + c.gamma * c.value);
        Ok(Self {
            weights,
            gammas,
            runs: packed_runs,
            offsets,
            sum,
        })
    }
    pub fn upload_bytes(&self) -> Result<usize, Error> {
        [
            self.weights.len().checked_mul(16),
            self.gammas.len().checked_mul(16),
            self.runs.len().checked_mul(32),
            self.offsets.len().checked_mul(8),
        ]
        .into_iter()
        .try_fold(0usize, |a, b| a.checked_add(b?))
        .ok_or(Error::Budget)
    }
}
