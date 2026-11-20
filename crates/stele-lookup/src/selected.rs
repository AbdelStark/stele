//! Conditional selected product and original columns, RFC-0008 A3 / RFC-0012 A9.
//! c_sc/T_misc: dense A1 copies and linear equality tables; no intermediate commitment.
use super::super::{
    reserve,
    tree::{eq_line, factored_message, halve_suffix, prove_dense},
    work, Reduction, Work,
};
use super::{Error, LeafDescriptor};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};
use stele_sumcheck::{Instance, Proof, ScRecord, Summand, Term, M31};

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
/// A1 strategy for the selected product `eq · σ · Σ_j β^j x_j` over base-field originals,
/// with `eq(r, ·)` factored as in the tree layers: three sums over the suffix table give
/// each round's four values. The originals stay in the base field through the first round.
/// Messages equal the dense strategy's.
struct SelectedSummand<'a, K> {
    /// `σ` and the original columns, until the first fold.
    base: Option<(&'a [M31], &'a [Vec<M31>])>,
    /// `σ` then the original columns over the unbound coordinates, after the first fold.
    tables: Vec<Vec<K>>,
    /// `β^j`.
    powers: Vec<K>,
    /// The unbound coordinates of the claim point, leading first.
    r: &'a [K],
    /// `eq` of the bound coordinates.
    scale: K,
    /// `eq(r[1..], ·)`.
    suffix: Vec<K>,
    point: &'a mut Vec<K>,
}
impl<K: ChallengeField + Eq> Summand<K> for SelectedSummand<'_, K> {
    fn shape(&self) -> (u32, usize) {
        (self.r.len() as u32, self.powers.len() + 2)
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        let r0 = *self.r.first().ok_or(stele_sumcheck::Error::PublicShape)?;
        let half = self.suffix.len();
        let mut sums = [K::from_i64(0); 3];
        if let Some((sigma, xs)) = self.base {
            if sigma.len() != 2 * half {
                return Err(stele_sumcheck::Error::PublicShape);
            }
            // `σ · Σ_j β^j x_j` at 0, at 1 and its leading coefficient, per position.
            let single = xs.len() == 1;
            stele_sumcheck::parallel::sum_ranges(half, &mut sums, |range, out| {
                for x in range {
                    let y = x + half;
                    let e = self.suffix[x];
                    let (sa, sb) = (sigma[x], sigma[y]);
                    if single {
                        let (va, vb) = (xs[0][x], xs[0][y]);
                        out[0] = out[0] + e.mul_m31(sa * va);
                        out[1] = out[1] + e.mul_m31(sb * vb);
                        out[2] = out[2] + e.mul_m31((sb - sa) * (vb - va));
                    } else {
                        let (mut va, mut vb) = (K::from_i64(0), K::from_i64(0));
                        for (power, column) in self.powers.iter().zip(xs) {
                            va = va + power.mul_m31(column[x]);
                            vb = vb + power.mul_m31(column[y]);
                        }
                        out[0] = out[0] + e * va.mul_m31(sa);
                        out[1] = out[1] + e * vb.mul_m31(sb);
                        out[2] = out[2] + e * (vb - va).mul_m31(sb - sa);
                    }
                }
                Ok(())
            })?;
        } else {
            let (sigma, xs) = self
                .tables
                .split_first()
                .ok_or(stele_sumcheck::Error::PublicShape)?;
            if sigma.len() != 2 * half {
                return Err(stele_sumcheck::Error::PublicShape);
            }
            stele_sumcheck::parallel::sum_ranges(half, &mut sums, |range, out| {
                for x in range {
                    let y = x + half;
                    let (mut va, mut vb) = (xs[0][x], xs[0][y]);
                    for (power, column) in self.powers.iter().zip(xs).skip(1) {
                        va = va + *power * column[x];
                        vb = vb + *power * column[y];
                    }
                    let e = self.suffix[x];
                    let (sa, sb) = (sigma[x], sigma[y]);
                    out[0] = out[0] + e * (sa * va);
                    out[1] = out[1] + e * (sb * vb);
                    out[2] = out[2] + e * ((sb - sa) * (vb - va));
                }
                Ok(())
            })?;
        }
        factored_message(self.scale, r0, sums)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        let (&r0, rest) = self
            .r
            .split_first()
            .ok_or(stele_sumcheck::Error::PublicShape)?;
        if let Some((sigma, xs)) = self.base.take() {
            self.tables
                .try_reserve_exact(xs.len() + 1)
                .map_err(|_| stele_sumcheck::Error::Capacity)?;
            self.tables
                .push(stele_sumcheck::parallel::fold_base(sigma, challenge)?);
            for column in xs {
                self.tables
                    .push(stele_sumcheck::parallel::fold_base(column, challenge)?);
            }
        } else {
            for table in &mut self.tables {
                stele_sumcheck::parallel::fold(table, challenge);
            }
        }
        self.scale = self.scale * eq_line(r0, challenge);
        halve_suffix(&mut self.suffix);
        self.r = rest;
        self.point
            .try_reserve(1)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        self.point.push(challenge);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if !self.r.is_empty() {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(self.powers.len() + 2)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        out.push(self.scale);
        match self.base {
            // No round ran: the originals are single values.
            Some((sigma, xs)) => {
                let one = K::from_i64(1);
                out.push(one.mul_m31(sigma[0]));
                out.extend(xs.iter().map(|column| one.mul_m31(column[0])));
            }
            None => out.extend(self.tables.iter().map(|table| table[0])),
        }
        Ok(out)
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
        let Selector::Base(sigma) = self.sigma else {
            // An extension selector has no base-field round: the reference rounds.
            let mut ext = Vec::new();
            reserve(&mut ext, xs.len())?;
            for x in xs {
                let mut column = Vec::new();
                reserve(&mut column, x.len())?;
                column.extend(x.iter().map(|v| K::from_i64(1).mul_m31(*v)));
                ext.push(column);
            }
            return self.prove(&ext, t);
        };
        let mut powers = Vec::new();
        reserve(&mut powers, xs.len())?;
        powers.extend(i.terms.iter().map(|term| term.coefficient));
        self.bind(t)?;
        let mut point = Vec::new();
        reserve(&mut point, self.point.len())?;
        let strategy = SelectedSummand {
            base: Some((sigma, xs)),
            tables: Vec::new(),
            powers,
            r: self.point,
            scale: K::from_i64(1),
            suffix: stele_sumcheck::parallel::eq_table(self.point.get(1..).unwrap_or(&[]))?,
            point: &mut point,
        };
        let proof = stele_sumcheck::prove(&i, strategy, t)?;
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
