//! Conditional selected product and original columns, RFC-0008 A3 / RFC-0012 A9.
//! c_sc/T_misc: dense A1 copies and linear equality tables; no intermediate commitment.
use super::super::{
    reserve,
    tree::{prove_dense, prove_mixed},
    work, Reduction, Work,
};
use super::{Error, LeafDescriptor};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};
use stele_sumcheck::{DenseTable, Instance, Proof, ScRecord, Term, M31};

/// Conditional original-column obligations in the selected-product leaf phase.
#[must_use = "every original column requires a real reduction or opening consumer"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafReduction<K> {
    /// Outer tree scope; this type identifies the leaf phase separately from levels.
    pub tree_id: u64,
    /// Shared verifier-derived point, never supplied by proof metadata.
    pub point: Vec<K>,
    /// Every original column, including those with zero coefficient.
    pub claims: Vec<(u64, K)>,
    /// Actual leaf A1 record, numerator 3m over the indicated field.
    pub sc: ScRecord,
}
#[derive(Clone, Copy)]
enum Selector<'a, K> {
    Ext(&'a [K]),
    Base(&'a [M31]),
}
impl<K> Selector<'_, K> {
    fn len(&self) -> usize {
        match self {
            Self::Ext(s) => s.len(),
            Self::Base(s) => s.len(),
        }
    }
}
/// Fixed public selector and incoming fraction claims; construction is not acceptance.
/// The caller must discharge the incoming claims through their actual tree reduction.
pub struct SelectedProduct<'a, K: ChallengeField> {
    descriptor: LeafDescriptor<'a, K>,
    point: &'a [K],
    values: [K; 2],
    sigma: Selector<'a, K>,
    alpha: K,
    beta: K,
}
fn owned<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
fn mle<K: ChallengeField>(values: &[K], point: &[K]) -> Result<K, Error> {
    if !values.len().is_power_of_two() || values.len().trailing_zeros() as usize != point.len() {
        return Err(Error::SourceShape);
    }
    let weights = stele_sumcheck::parallel::eq_table(point)?;
    // Exact field sums: any split of the dot product is identical.
    let mut sum = [K::from_i64(0)];
    stele_sumcheck::parallel::sum_ranges(values.len(), &mut sum, |range, out| {
        for j in range {
            out[0] = out[0] + values[j] * weights[j];
        }
        Ok(())
    })?;
    Ok(sum[0])
}
fn mle_base<K: ChallengeField>(values: &[M31], point: &[K]) -> Result<K, Error> {
    if !values.len().is_power_of_two() || values.len().trailing_zeros() as usize != point.len() {
        return Err(Error::SourceShape);
    }
    let weights = stele_sumcheck::parallel::eq_table(point)?;
    let mut sum = [K::from_i64(0)];
    stele_sumcheck::parallel::sum_ranges(values.len(), &mut sum, |range, out| {
        for j in range {
            out[0] = out[0] + weights[j].mul_m31(values[j]);
        }
        Ok(())
    })?;
    Ok(sum[0])
}
impl<'a, K: ChallengeField + Eq> SelectedProduct<'a, K> {
    /// Validate shapes, Boolean selector and p=sigma_tilde(r) before any absorption.
    pub fn new(
        descriptor: LeafDescriptor<'a, K>,
        original: &'a Reduction<K>,
        sigma: &'a [K],
        alpha: K,
        beta: K,
    ) -> Result<Self, Error> {
        if original.point.len() != descriptor.tree.m as usize
            || original.claims.map(|c| c.0) != descriptor.tree.leaves
            || !sigma.len().is_power_of_two()
            || sigma.len().trailing_zeros() != descriptor.tree.m
        {
            return Err(Error::SourceShape);
        }
        if sigma
            .iter()
            .any(|s| *s != K::from_i64(0) && *s != K::from_i64(1))
        {
            return Err(Error::Selector);
        }
        let values = original.claims.map(|c| c.1);
        if values[0] != mle(sigma, &original.point)? {
            return Err(Error::SelectorMismatch);
        }
        Ok(Self {
            descriptor,
            point: &original.point,
            values,
            sigma: Selector::Ext(sigma),
            alpha,
            beta,
        })
    }
    /// Base-field selector variant of [`Self::new`] (task E20-02): avoids allocating a
    /// full-sized extension-field selector copy.
    pub fn new_base(
        descriptor: LeafDescriptor<'a, K>,
        original: &'a Reduction<K>,
        sigma: &'a [M31],
        alpha: K,
        beta: K,
    ) -> Result<Self, Error> {
        if original.point.len() != descriptor.tree.m as usize
            || original.claims.map(|c| c.0) != descriptor.tree.leaves
            || !sigma.len().is_power_of_two()
            || sigma.len().trailing_zeros() != descriptor.tree.m
        {
            return Err(Error::SourceShape);
        }
        if sigma.iter().any(|&s| s != M31::ZERO && s != M31::ONE) {
            return Err(Error::Selector);
        }
        let values = original.claims.map(|c| c.1);
        if values[0] != mle_base(sigma, &original.point)? {
            return Err(Error::SelectorMismatch);
        }
        Ok(Self {
            descriptor,
            point: &original.point,
            values,
            sigma: Selector::Base(sigma),
            alpha,
            beta,
        })
    }
    fn sources(&self, xs: &[Vec<K>]) -> Result<(), Error> {
        if xs.len() != self.descriptor.sources.len()
            || xs.iter().any(|x| x.len() != self.sigma.len())
        {
            return Err(Error::SourceShape);
        }
        Ok(())
    }
    fn sources_base(&self, xs: &[Vec<M31>]) -> Result<(), Error> {
        if xs.len() != self.descriptor.sources.len()
            || xs.iter().any(|x| x.len() != self.sigma.len())
        {
            return Err(Error::SourceShape);
        }
        Ok(())
    }
    fn instance(&self) -> Result<Instance<K>, Error> {
        let mut inputs = Vec::new();
        reserve(&mut inputs, self.descriptor.sources.len() + 2)?;
        inputs.extend_from_slice(&[0, 1]);
        inputs.extend_from_slice(self.descriptor.sources);
        let mut terms = Vec::new();
        reserve(&mut terms, self.descriptor.sources.len())?;
        let mut power = K::from_i64(1);
        for j in 0..self.descriptor.sources.len() {
            terms.push(Term {
                coefficient: power,
                factors: owned(&[0, 1, j as u32 + 2])?,
            });
            power = power * self.beta;
        }
        Ok(Instance {
            id: self.descriptor.tree.id,
            num_vars: self.descriptor.tree.m,
            inputs,
            terms,
            claimed_sum: K::from_i64(1) + (self.alpha - K::from_i64(1)) * self.values[0]
                - self.values[1],
        })
    }
    fn bind(&self, t: &mut Transcript<K>) -> Result<(), Error> {
        let mut bytes = self.descriptor.tree.encode()?;
        let size = self
            .descriptor
            .sources
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(4 + 4 * K::DEGREE * (self.point.len() + 4)))
            .ok_or(Error::Capacity)?;
        reserve(&mut bytes, size)?;
        bytes.extend_from_slice(&(self.descriptor.sources.len() as u32).to_le_bytes());
        for id in self.descriptor.sources {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        for v in [self.alpha, self.beta]
            .iter()
            .chain(self.point)
            .chain(&self.values)
        {
            bytes.extend_from_slice(v.to_le_bytes().as_ref());
        }
        t.absorb(AbsorbLabel::FractionLeaf, &bytes)?;
        Ok(())
    }
    fn finish(&self, point: Vec<K>, finals: &[K], sc: ScRecord) -> Result<LeafReduction<K>, Error> {
        if finals[0]
            != stele_poly::eq_evaluate(self.point, &point).map_err(|_| Error::SourceShape)?
        {
            return Err(Error::CoefficientMismatch);
        }
        let sigma_at = match self.sigma {
            Selector::Ext(s) => mle(s, &point)?,
            Selector::Base(s) => mle_base(s, &point)?,
        };
        if finals[1] != sigma_at {
            return Err(Error::SelectorMismatch);
        }
        let mut claims = Vec::new();
        reserve(&mut claims, self.descriptor.sources.len())?;
        claims.extend(
            self.descriptor
                .sources
                .iter()
                .copied()
                .zip(finals[2..].iter().copied()),
        );
        Ok(LeafReduction {
            tree_id: self.descriptor.tree.id,
            point,
            claims,
            sc,
        })
    }
    /// Prove the selected Boolean product directly from base-field `xs` (task E20-02):
    /// keeps `sigma` and `xs` in `M31` during round 0 via `Dense::new_mixed`. Proof bytes
    /// are bit-identical to [`Self::prove`].
    pub fn prove_base(
        &self,
        xs: &[Vec<M31>],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, LeafReduction<K>), Error> {
        self.sources_base(xs)?;
        let i = self.instance()?;
        let mut tables = Vec::new();
        reserve(&mut tables, xs.len() + 2)?;
        tables.push(DenseTable::Ext(stele_sumcheck::parallel::eq_table(
            self.point,
        )?));
        match self.sigma {
            Selector::Base(s) => tables.push(DenseTable::Base(owned(s)?)),
            Selector::Ext(s) => tables.push(DenseTable::Ext(owned(s)?)),
        }
        for x in xs {
            tables.push(DenseTable::Base(owned(x)?));
        }
        self.bind(t)?;
        let (proof, point) = prove_mixed(&i, tables, t)?;
        let result = self.finish(
            point,
            &proof.final_values,
            ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            },
        )?;
        Ok((proof, result))
    }
    /// Prove the selected Boolean product; returned original claims remain obligations.
    pub fn prove(
        &self,
        xs: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, LeafReduction<K>), Error> {
        self.prove_measured(xs, t)
            .map(|(proof, reduction, _)| (proof, reduction))
    }
    /// The same selected-product execution with actual boundary capacities (A5 §6).
    /// Work carries no authority and adds no challenge, replay or source consumer.
    pub fn prove_measured(
        &self,
        xs: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, LeafReduction<K>, Work), Error> {
        self.sources(xs)?;
        let i = self.instance()?;
        let mut tables = Vec::new();
        reserve(&mut tables, xs.len() + 2)?;
        tables.push(stele_sumcheck::parallel::eq_table(self.point)?);
        let sigma_ext = match self.sigma {
            Selector::Ext(s) => owned(s)?,
            Selector::Base(s) => {
                let one = K::from_i64(1);
                let mut out = Vec::new();
                reserve(&mut out, s.len())?;
                out.extend(s.iter().map(|&v| one.mul_m31(v)));
                out
            }
        };
        tables.push(sigma_ext);
        for x in xs {
            tables.push(owned(x)?);
        }
        self.bind(t)?;
        let (proof, point, dense) = prove_dense(&i, tables, t)?;
        let mut work = Work::default();
        work.observe(0, dense.tables, 0, dense.point)?;
        work.observe(0, 0, work::proof(&proof)?, work::bytes(&point)?)?;
        let result = self.finish(
            point,
            &proof.final_values,
            ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            },
        )?;
        Ok((proof, result, work))
    }
    /// Verify the conditional relation and exact Eq/selector finals; retain all columns.
    pub fn verify(
        &self,
        proof: &Proof<K>,
        t: &mut Transcript<K>,
    ) -> Result<LeafReduction<K>, Error> {
        self.descriptor.validate(proof)?;
        let i = self.instance()?;
        self.bind(t)?;
        let reduced = stele_sumcheck::verify(&i, proof, t)?;
        self.finish(reduced.point, &proof.final_values, reduced.sc)
    }
    /// Discharge every returned column against the original fixed public arrays.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        xs: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<LeafReduction<K>, Error> {
        self.sources(xs)?;
        let result = self.verify(proof, t)?;
        let weights = stele_poly::eq_table(&result.point).map_err(|_| Error::Capacity)?;
        for (x, (_, expected)) in xs.iter().zip(&result.claims) {
            let actual = x
                .iter()
                .zip(&weights)
                .fold(K::from_i64(0), |s, (v, w)| s + *v * *w);
            if actual != *expected {
                return Err(Error::SourceMismatch);
            }
        }
        Ok(result)
    }
}
