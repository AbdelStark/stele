//! RFC-0008 A7 items 2/3: production lookup reference for E16-40c qualification.
//! Available only with `bench`; no prover or verifier calls this adapter.
use super::{LookupPlan, Statement};
use alloc::vec::Vec;
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_pcs::CodeField;

/// A validated lookup with the same field-valued columns as the ordinary prover.
/// Construction is host setup, separate from either measured operation below.
pub struct LookupCase<K> {
    plan: LookupPlan,
    data: Vec<Vec<K>>,
}

/// Production-normalized inputs to the leaf, level and top computations.
/// Building these inputs is real host work and must be charged to a device path.
/// These are witness values for a benchmark caller, never public proof metadata.
pub struct LookupInputs<K> {
    /// Shifted tuple entries, one vector per coordinate over the lookup half.
    pub tuples: Vec<Vec<K>>,
    /// Public table denominators over the same domain; padding is one.
    pub table: Vec<K>,
    /// Concatenated public 0/1 selector; zero off the members.
    pub selector: Vec<i64>,
    /// Multiplicities over the original table domain; missing positions are zero.
    pub multiplicity: Vec<K>,
    /// Compression coefficients `1, beta, beta^2, ...`, in tuple order.
    pub powers: Vec<K>,
    /// The supplied denominator challenge value.
    pub alpha: K,
    /// Committed top layer exponent `c_D + 1`.
    pub top_variables: usize,
}

/// Actual production tree and committed top values, before masking/commitment.
pub struct LookupTree<K> {
    /// Root first: layer `k` contains `2^k` numerator/denominator pairs.
    pub layers: Vec<Vec<[K; 2]>>,
    /// The top's `p`, `q`, and `h = p/q`, in that order.
    pub top: [Vec<K>; 3],
}

impl<K: ChallengeField + CodeField> LookupCase<K> {
    /// Validate the complete statement and assigned lengths before selecting one
    /// lookup. Input columns are canonical M31, as in the production prover.
    pub fn new(
        statement: &Statement<K>,
        columns: &[Vec<M31>],
        lookup: usize,
    ) -> Result<Self, super::Error> {
        let plan = super::super::plan(statement)?;
        if columns.len() != statement.columns.len()
            || columns
                .iter()
                .zip(&statement.columns)
                .any(|(c, x)| c.len() != 1usize << x.log_len)
        {
            return Err(super::Error::Statement);
        }
        let plan = plan
            .lookups
            .into_iter()
            .nth(lookup)
            .ok_or(super::Error::Statement)?;
        let data = columns
            .iter()
            .map(|c| c.iter().map(|x| super::element::<K>(*x)).collect())
            .collect();
        Ok(Self { plan, data })
    }

    /// Normalize selectors, shifts, padding and compression with the production
    /// helpers. `beta`/`alpha` are synthetic benchmark inputs, not proof challenges.
    pub fn inputs(&self, beta: K, alpha: K) -> LookupInputs<K> {
        LookupInputs {
            tuples: super::tuple(&self.plan, &self.data),
            table: super::table(&self.plan, beta, alpha),
            selector: self.plan.selector(),
            multiplicity: self.data[self.plan.multiplicity].clone(),
            powers: super::powers(beta, self.plan.c),
            alpha,
            top_variables: self.plan.k0,
        }
    }

    /// Run the actual CPU tree/top construction, including its input preparation
    /// and top inversions. A zero top denominator returns `DenominatorZero`.
    pub fn reference(&self, beta: K, alpha: K) -> Result<LookupTree<K>, super::Error> {
        let layers = super::tree(&self.plan, &self.data, beta, alpha);
        let top = super::top(&self.plan, &layers)?;
        Ok(LookupTree { layers, top })
    }
}
