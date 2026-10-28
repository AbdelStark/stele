//! Verifier-owned polynomial and canonical descriptor, RFC-0006 A1.
use crate::{append, Error};
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
        self.terms.iter().fold(K::from_i64(0), |sum, term| {
            sum + term
                .factors
                .iter()
                .fold(term.coefficient, |product, i| product * values[*i as usize])
        })
    }
    /// Exact A1 payload; all lengths and ordinals are checked before serialization.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let degree = self.validate()?;
        let mut out = Vec::new();
        append(
            &mut out,
            &[1, (self.claimed_sum.to_le_bytes().as_ref().len() / 4) as u8],
        )?;
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &self.num_vars.to_le_bytes())?;
        append(&mut out, &[degree as u8])?;
        append(&mut out, &(self.inputs.len() as u32).to_le_bytes())?;
        append(&mut out, &(self.terms.len() as u32).to_le_bytes())?;
        for id in &self.inputs {
            append(&mut out, &id.to_le_bytes())?;
        }
        for term in &self.terms {
            append(&mut out, term.coefficient.to_le_bytes().as_ref())?;
            append(&mut out, &[term.factors.len() as u8])?;
            for factor in &term.factors {
                append(&mut out, &factor.to_le_bytes())?;
            }
        }
        append(&mut out, self.claimed_sum.to_le_bytes().as_ref())?;
        Ok(out)
    }
}
