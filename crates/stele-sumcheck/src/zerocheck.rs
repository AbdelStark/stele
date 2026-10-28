//! Static zerocheck descriptor and proof data, RFC-0006 A3; protocol consumer pending.
use crate::{
    batch::{field_degree, Claim},
    reserve, Error, Instance, ScRecord,
};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
/// Logical A3 proof; all lengths come from the verifier's descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// Outside-node values Q(s)..Q(D); empty when k=0 or degree=1.
    pub skip_values: Vec<K>,
    /// Tail rows, each with degree+1 evaluations.
    pub rounds: Vec<Vec<K>>,
    /// Input-major, then ascending Boolean prefix; no claimed points.
    pub final_values: Vec<K>,
}
/// Conditional reduction: no statement acceptance until every claim is consumed.
#[must_use = "discharge every original tensor slice claim"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// All original MLE claims, including unused or zero-weight slices.
    pub claims: Vec<Claim<K>>,
    /// SC phases 0 (weights), 1 (skip), 2 (tail), in that fixed order.
    pub sc: [ScRecord; 3],
}
/// Verifier-owned row-zero relation, not merely a zero Boolean sum.
pub struct Zerocheck<'a, K> {
    /// Reuses A1's ordered polynomial/ids; claimed_sum must be zero and is not encoded.
    pub instance: &'a Instance<K>,
    /// Plan-fixed leading coordinates to skip, 0..=min(m,4).
    pub skip: u8,
}
impl<K: ChallengeField + Eq> Zerocheck<'_, K> {
    fn shape(&self) -> Result<(usize, usize, u32, usize), Error> {
        let degree = self
            .instance
            .validate()
            .map_err(|_| Error::InvalidZerocheck)?;
        if self.skip > 4
            || u32::from(self.skip) > self.instance.num_vars
            || (degree == 0 && self.skip != 0)
            || self.instance.claimed_sum != K::from_i64(0)
        {
            return Err(Error::InvalidZerocheck);
        }
        let s = 1usize << self.skip;
        Ok((
            degree,
            s,
            self.instance.num_vars - u32::from(self.skip),
            degree.saturating_sub(1) * (s - 1),
        ))
    }
    /// Canonical A3 descriptor; no A1 claimed-sum suffix.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.shape()?;
        let mut out = self.instance.encode()?;
        out.truncate(out.len() - usize::from(field_degree::<K>()) * 4);
        reserve(&mut out, 1)?;
        // A3 inserts k after version, field, id and m: 1+1+8+4 bytes.
        out.insert(14, self.skip);
        Ok(out)
    }
}
