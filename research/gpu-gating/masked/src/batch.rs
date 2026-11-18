//! RFC-0013 A5 item 5: stage a prepared hiding source and ordered claim weights.
//! Research inputs are committed message values and claims, not new commitments.
use crate::{lookup::words, Field, K, M31};
use stele_reductions::stele_pcs::Source;
use stele_reductions::zk::claims::Claim;

pub(crate) struct Prepared {
    pub message: Vec<u32>,
    /// One (weight, gamma) pair per occurrence, grouped stably by data position.
    pub pairs: Vec<u32>,
    pub offsets: Vec<u64>,
    pub columns: usize,
    pub len: usize,
    pub claimed_sum: K,
}

impl Prepared {
    pub fn new(
        source: &Source<K>,
        message: &[M31],
        claims: &[Claim<K>],
        gammas: &[K],
    ) -> Option<Self> {
        let columns = source.columns() / 2;
        let len = source.rows().checked_mul(columns)?;
        let half = len / 2;
        if !source.is_hiding()
            || message.len() != len.checked_mul(2)?
            || claims.len() != gammas.len()
        {
            return None;
        }
        let count = claims
            .iter()
            .try_fold(0usize, |sum, c| sum.checked_add(c.weights.len()))?;
        let pair_words = count.checked_mul(8)?.max(8); // A nonempty CUDA allocation even for no claims.
        let bytes = message
            .len()
            .checked_mul(4)?
            .checked_add(pair_words.checked_mul(4)?)?
            .checked_add(half.checked_add(1)?.checked_mul(8)?)?
            .checked_add(len.checked_mul(20)?)?;
        if bytes > isize::MAX as usize
            || claims
                .iter()
                .flat_map(|c| &c.weights)
                .any(|(p, _)| *p >= half)
        {
            return None;
        }
        let mut offsets = vec![0u64; half + 1];
        for (position, _) in claims.iter().flat_map(|c| &c.weights) {
            offsets[position + 1] += 1;
        }
        for i in 0..half {
            offsets[i + 1] += offsets[i];
        }
        let mut cursor = offsets[..half].to_vec();
        let mut pairs = vec![0; pair_words];
        for (claim, gamma) in claims.iter().zip(gammas) {
            for (position, weight) in &claim.weights {
                let at = 8 * cursor[*position] as usize;
                pairs[at..at + 4].copy_from_slice(&words(*weight));
                pairs[at + 4..at + 8].copy_from_slice(&words(*gamma));
                cursor[*position] += 1;
            }
        }
        Some(Self {
            message: message.iter().map(|x| x.as_u32()).collect(),
            pairs,
            offsets,
            columns,
            len,
            claimed_sum: claims
                .iter()
                .zip(gammas)
                .fold(K::from_i64(0), |sum, (c, g)| sum + *g * c.value),
        })
    }

    pub fn upload_bytes(&self) -> usize {
        4 * (self.message.len() + self.pairs.len()) + 8 * self.offsets.len()
    }
}
