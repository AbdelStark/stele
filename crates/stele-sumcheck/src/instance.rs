//! Verifier-owned polynomial and canonical descriptor, RFC-0006 A1.
use crate::{put, reserve, Error};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
/// One ordered product, including repeated factors and empty constant products.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term<K> {
    /// Field coefficient; zero does not reduce the conservative degree bound.
    pub coefficient: K,
    /// Input ordinals, at most four, in plan order.
    pub factors: Vec<u32>,
}
/// Verifier-owned instance; validate at every protocol entry, never trust proof metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance<K> {
    /// Plan instance identity, unique in the surrounding plan.
    pub id: u64,
    /// Common input hypercube dimension.
    pub num_vars: u32,
    /// Ordered distinct tensor identities.
    pub inputs: Vec<u64>,
    /// Ordered polynomial terms; empty means zero.
    pub terms: Vec<Term<K>>,
    /// Claimed Boolean-hypercube sum of P.
    pub claimed_sum: K,
}
impl<K: ChallengeField> Instance<K> {
    pub(crate) fn validate(&self) -> Result<usize, Error> {
        if u32::try_from(self.inputs.len()).is_err()
            || u32::try_from(self.terms.len()).is_err()
            || self
                .inputs
                .iter()
                .enumerate()
                .any(|(n, id)| self.inputs[..n].contains(id))
            || self.terms.iter().any(|t| {
                t.factors.len() > 4 || t.factors.iter().any(|i| *i as usize >= self.inputs.len())
            })
        {
            return Err(Error::InvalidInstance);
        }
        Ok(self
            .terms
            .iter()
            .map(|t| t.factors.len())
            .max()
            .unwrap_or(0))
    }
    pub(crate) fn evaluate(&self, values: &[K]) -> K {
        self.evaluate_with(|i| values[i as usize])
    }
    pub(crate) fn evaluate_with(&self, mut value: impl FnMut(u32) -> K) -> K {
        self.terms.iter().fold(K::from_i64(0), |sum, term| {
            sum + term
                .factors
                .iter()
                .fold(term.coefficient, |product, i| product * value(*i))
        })
    }
    /// Checked canonical A1 payload length, RFC-0006 A1/A6.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        self.validate()?;
        let k = 4 * K::DEGREE;
        let mut size = self
            .inputs
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(23 + k))
            .ok_or(Error::Capacity)?;
        for term in &self.terms {
            size = size
                .checked_add(k + 1 + 4 * term.factors.len())
                .ok_or(Error::Capacity)?;
        }
        Ok(size)
    }
    /// Write the canonical payload prefix without allocation; validation precedes writes.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        if out.len() < size {
            return Err(Error::Capacity);
        }
        let degree = self.validate()?;
        let mut cursor = 0;
        put(
            out,
            &mut cursor,
            &[1, (self.claimed_sum.to_le_bytes().as_ref().len() / 4) as u8],
        )?;
        put(out, &mut cursor, &self.id.to_le_bytes())?;
        put(out, &mut cursor, &self.num_vars.to_le_bytes())?;
        put(out, &mut cursor, &[degree as u8])?;
        put(out, &mut cursor, &(self.inputs.len() as u32).to_le_bytes())?;
        put(out, &mut cursor, &(self.terms.len() as u32).to_le_bytes())?;
        for id in &self.inputs {
            put(out, &mut cursor, &id.to_le_bytes())?;
        }
        for term in &self.terms {
            put(out, &mut cursor, term.coefficient.to_le_bytes().as_ref())?;
            put(out, &mut cursor, &[term.factors.len() as u8])?;
            for factor in &term.factors {
                put(out, &mut cursor, &factor.to_le_bytes())?;
            }
        }
        put(out, &mut cursor, self.claimed_sum.to_le_bytes().as_ref())?;
        Ok(cursor)
    }
    /// Exact A1 payload; all lengths and ordinals are checked before serialization.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let size = self.encoded_len()?;
        let mut out = Vec::new();
        reserve(&mut out, size)?;
        out.resize(size, 0);
        self.encode_into(&mut out)?;
        Ok(out)
    }
}
