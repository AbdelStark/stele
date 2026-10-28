//! Conditional selected product and original columns, RFC-0008 A3 / RFC-0012 A9.
//! c_sc/T_misc: dense A1 copies and linear equality tables; no intermediate commitment.
use super::super::{reserve, tree::prove_dense, Reduction};
use super::{Error, LeafDescriptor};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};
use stele_sumcheck::{Instance, Proof, ScRecord, Term};

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
/// Fixed public selector and incoming fraction claims; construction is not acceptance.
/// The caller must discharge the incoming claims through their actual tree reduction.
pub struct SelectedProduct<'a, K: ChallengeField> {
    descriptor: LeafDescriptor<'a, K>,
    point: &'a [K],
    values: [K; 2],
    sigma: &'a [K],
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
    let weights = stele_poly::eq_table(point).map_err(|_| Error::Capacity)?;
    Ok(values
        .iter()
        .zip(weights)
        .fold(K::from_i64(0), |s, (v, w)| s + *v * w))
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
            sigma,
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
        if finals[1] != mle(self.sigma, &point)? {
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
    /// Prove the selected Boolean product; returned original claims remain obligations.
    pub fn prove(
        &self,
        xs: &[Vec<K>],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, LeafReduction<K>), Error> {
        self.sources(xs)?;
        let i = self.instance()?;
        let mut tables = Vec::new();
        reserve(&mut tables, xs.len() + 2)?;
        tables.push(stele_poly::eq_table(self.point).map_err(|_| Error::Capacity)?);
        tables.push(owned(self.sigma)?);
        for x in xs {
            tables.push(owned(x)?);
        }
        self.bind(t)?;
        let (proof, point) = prove_dense(&i, tables, t)?;
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
