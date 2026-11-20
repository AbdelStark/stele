//! Conditional fraction tree and original public consumer, RFC-0008 A3.
//! c_sc/T_misc: linear tree/equality work; retained tree has 2N-1 pairs, plus
//! dense A1 copies, source, proof and coefficients. No intermediate commitment.
use super::{reserve, work, Descriptor, Error, Proof, Work};
use alloc::vec;
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{Dense, Instance, ScRecord, Summand, Term, M31};

/// Conditional tree losses over p^field_degree, excluding source/PCS/FS errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accounting {
    /// Outer scope; A1 ids below are local root-to-leaf levels, never global ids.
    pub tree_id: u64,
    /// Canonical challenge-field degree.
    pub field_degree: u8,
    /// Actual Gamma draws, each contributing one to the RLC numerator.
    pub gamma: u64,
    /// Actual Fold draws, each contributing one to the RLC numerator.
    pub fold: u64,
    /// Tree phase A1 records, in level order (including the scalar level).
    pub layers: Vec<ScRecord>,
}
/// Two original evaluations; neither this result nor the root equation is membership.
#[must_use = "both original leaf claims require an actual reduction or opening consumer"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// Shared verifier-derived MSB-first point.
    pub point: Vec<K>,
    /// Ordered original numerator and denominator identities and values.
    pub claims: [(u64, K); 2],
    /// Scoped, complete conditional tree losses.
    pub accounting: Accounting,
}
fn owned<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    reserve(&mut out, values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
fn source<K: ChallengeField>(d: &Descriptor<K>, leaves: &[[K; 2]]) -> Result<(), Error> {
    if !leaves.len().is_power_of_two() || leaves.len().trailing_zeros() != d.m {
        return Err(Error::SourceShape);
    }
    Ok(())
}
fn accounting<K: ChallengeField>(d: &Descriptor<K>) -> Result<Accounting, Error> {
    let mut layers = Vec::new();
    reserve(&mut layers, d.m as usize)?;
    Ok(Accounting {
        tree_id: d.id,
        field_degree: K::DEGREE as u8,
        gamma: 0,
        fold: 0,
        layers,
    })
}
fn weights<K: ChallengeField>(d: &Descriptor<K>, k: usize) -> [K; 2] {
    let one = K::from_i64(1);
    d.theta.get(k).map_or([one, one], |t| [one - *t, *t])
}
fn bind<K: ChallengeField>(
    d: &Descriptor<K>,
    root: [K; 2],
    t: &mut Transcript<K>,
) -> Result<(), Error> {
    let mut bytes = d.encode()?;
    reserve(&mut bytes, 8 * K::DEGREE)?;
    for v in root {
        bytes.extend_from_slice(v.to_le_bytes().as_ref());
    }
    t.absorb(AbsorbLabel::Fraction, &bytes)?;
    Ok(())
}
fn layer<K: ChallengeField>(
    d: &Descriptor<K>,
    r: &[K],
    values: [K; 2],
    t: &mut Transcript<K>,
    a: &mut Accounting,
) -> Result<Instance<K>, Error> {
    let k = r.len();
    let mut fields = owned(r)?;
    reserve(&mut fields, 2)?;
    fields.extend_from_slice(&values);
    t.absorb(
        AbsorbLabel::FractionLayer,
        &stele_sumcheck::message_bytes(d.id, k as u32, &fields)?,
    )?;
    let gamma = t.challenge(ChallengeLabel::FractionGamma)?;
    a.gamma += 1;
    let [left, right] = weights(d, k);
    let mut terms = Vec::new();
    reserve(&mut terms, 3)?;
    for (coefficient, factors) in [(left, [0, 3, 4]), (right, [2, 1, 4]), (gamma, [1, 3, 4])] {
        terms.push(Term {
            coefficient,
            factors: owned(&factors)?,
        });
    }
    Ok(Instance {
        id: k as u64,
        num_vars: k as u32,
        inputs: owned(&[0, 1, 2, 3, 4])?,
        terms,
        claimed_sum: values[0] + gamma * values[1],
    })
}
fn advance<K: ChallengeField + Eq>(
    r: &[K],
    mut point: Vec<K>,
    finals: &[K],
    t: &mut Transcript<K>,
    a: &mut Accounting,
) -> Result<(Vec<K>, [K; 2]), Error> {
    if finals[4] != stele_poly::eq_evaluate(r, &point).map_err(|_| Error::SourceShape)? {
        return Err(Error::CoefficientMismatch);
    }
    reserve(&mut point, 1)?;
    // A3: all five A1 finals are already absorbed, and Eq was consumed exactly.
    let tau = t.challenge(ChallengeLabel::FractionFold)?;
    a.fold += 1;
    point.push(tau);
    Ok((
        point,
        [
            finals[0] + tau * (finals[2] - finals[0]),
            finals[1] + tau * (finals[3] - finals[1]),
        ],
    ))
}
fn result<K: ChallengeField>(
    d: &Descriptor<K>,
    point: Vec<K>,
    values: [K; 2],
    accounting: Accounting,
) -> Reduction<K> {
    Reduction {
        point,
        claims: [(d.leaves[0], values[0]), (d.leaves[1], values[1])],
        accounting,
    }
}
// A1 strategy observer records only challenges supplied by the actual engine.
// No transcript cloning, extra challenge, RNG or state import is used.
struct Capture<'a, K> {
    dense: Dense<K>,
    point: &'a mut Vec<K>,
}
impl<K: ChallengeField> Summand<K> for Capture<'_, K> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.round(i)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        self.dense.fold(r)?;
        self.point
            .try_reserve(1)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        self.point.push(r);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.final_values()
    }
}
// Shared A1 strategy observation, without transcript replay or additional draws.
pub(super) fn prove_dense<K: ChallengeField + Eq>(
    i: &Instance<K>,
    tables: Vec<Vec<K>>,
    t: &mut Transcript<K>,
) -> Result<(stele_sumcheck::Proof<K>, Vec<K>, work::DenseWork), Error> {
    let mut point = Vec::new();
    reserve(&mut point, i.num_vars as usize)?;
    let observed = work::DenseWork {
        tables: work::tables(&tables)?,
        point: work::bytes(&point)?,
    };
    let strategy = Capture {
        dense: Dense::new(i, tables)?,
        point: &mut point,
    };
    let proof = stele_sumcheck::prove(i, strategy, t)?;
    Ok((proof, point, observed))
}
// Mixed base/extension A1 strategy for base-field leaf selected products (task E20-02).
pub(super) fn prove_mixed<K: ChallengeField + Eq>(
    i: &Instance<K>,
    tables: Vec<stele_sumcheck::DenseTable<K>>,
    t: &mut Transcript<K>,
) -> Result<(stele_sumcheck::Proof<K>, Vec<K>), Error> {
    let mut point = Vec::new();
    reserve(&mut point, i.num_vars as usize)?;
    let strategy = Capture {
        dense: Dense::new_mixed(i, tables)?,
        point: &mut point,
    };
    let proof = stele_sumcheck::prove(i, strategy, t)?;
    Ok((proof, point))
}
/// Prebuilt dense fraction tree levels ready for [`Descriptor::prove_built`] (task E20-02).
pub struct BuiltTree<K> {
    levels: Vec<Vec<[K; 2]>>,
}

/// Base-field lookup leaves for [`Descriptor::prove_base_leaves`] (RFC-0008 A3, task E20-02).
/// Each position `i` represents `[s_i, 1 - s_i + s_i · (α - Σ_c β^c · x_c[i])]` without
/// allocating an extension-field leaf layer.
#[derive(Clone, Copy)]
pub enum BaseLeaves<'a, K> {
    /// Single-column (`c = 1`) lookup into a small domain `[0, table_size)` (`table_size <= 65536`):
    /// `denom[v] = α - M31(v)` is precomputed; when `table_size <= 256`, the entire
    /// `table_size × table_size` first-layer pair table is also precomputed.
    SmallDomain {
        sigma: &'a [M31],
        values: &'a [M31],
        alpha: K,
        table_size: usize,
    },
    /// General multi-column (`c >= 1`) base-field tuple lookup.
    General {
        sigma: &'a [M31],
        xs: &'a [Vec<M31>],
        alpha: K,
        beta: K,
    },
}

impl<K: ChallengeField + Eq> BaseLeaves<'_, K> {
    fn len(&self) -> usize {
        self.sigma().len()
    }
    fn sigma(&self) -> &[M31] {
        match self {
            Self::SmallDomain { sigma, .. } | Self::General { sigma, .. } => sigma,
        }
    }
    fn validate(&self, m: u32) -> Result<(), Error> {
        let sigma = self.sigma();
        if !sigma.len().is_power_of_two() || sigma.len().trailing_zeros() != m {
            return Err(Error::SourceShape);
        }
        match self {
            Self::SmallDomain { values, .. } => {
                if values.len() != sigma.len() {
                    return Err(Error::SourceShape);
                }
            }
            Self::General { xs, .. } => {
                if xs.iter().any(|x| x.len() != sigma.len()) {
                    return Err(Error::SourceShape);
                }
            }
        }
        Ok(())
    }
    #[inline]
    fn denom_at(&self, denom: &[K], idx: usize) -> K {
        let one = K::from_i64(1);
        let s = self.sigma()[idx];
        match self {
            Self::SmallDomain { values, alpha, .. } => {
                if s == M31::ZERO {
                    one
                } else if s == M31::ONE {
                    let v = values[idx].as_u32() as usize;
                    if v < denom.len() {
                        denom[v]
                    } else {
                        *alpha - one.mul_m31(values[idx])
                    }
                } else {
                    let sk = one.mul_m31(s);
                    one - sk + sk * (*alpha - one.mul_m31(values[idx]))
                }
            }
            Self::General {
                xs, alpha, beta, ..
            } => {
                if s == M31::ZERO {
                    one
                } else {
                    let row = xs
                        .iter()
                        .rev()
                        .fold(K::from_i64(0), |acc, x| acc * *beta + one.mul_m31(x[idx]));
                    if s == M31::ONE {
                        *alpha - row
                    } else {
                        let sk = one.mul_m31(s);
                        one - sk + sk * (*alpha - row)
                    }
                }
            }
        }
    }
    #[inline]
    fn leaf_at(&self, denom: &[K], idx: usize) -> [K; 2] {
        [
            K::from_i64(1).mul_m31(self.sigma()[idx]),
            self.denom_at(denom, idx),
        ]
    }
}

/// Prebuilt upper fraction-tree layers (`0..m`) and precomputed small-domain denominators for
/// [`Descriptor::prove_built_base`] (no `2^m` extension-field leaf layer allocated; E20-02).
pub struct BuiltBaseTree<K> {
    levels: Vec<Vec<[K; 2]>>,
    denom: Vec<K>,
    root: [K; 2],
}

/// Sumcheck strategy for the bottom fraction-tree layer (`k = m - 1 >= 1`) that keeps the leaf
/// layer in the base field during round 0, then folds directly into half-sized extension tables.
struct BaseLeafSummand<'a, K: ChallengeField + Eq> {
    leaves: BaseLeaves<'a, K>,
    denom: &'a [K],
    eq: Option<Vec<K>>,
    left: K,
    right: K,
    gamma: K,
    remaining: u32,
    folded: Option<Dense<K>>,
    point: &'a mut Vec<K>,
}

impl<K: ChallengeField + Eq> Summand<K> for BaseLeafSummand<'_, K> {
    fn shape(&self) -> (u32, usize) {
        (self.remaining, 5)
    }
    fn round(&self, instance: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        if let Some(dense) = &self.folded {
            return dense.round(instance);
        }
        let eq = self
            .eq
            .as_deref()
            .ok_or(stele_sumcheck::Error::PublicShape)?;
        if self.remaining == 0 || eq.len() != (1usize << self.remaining) {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let half = eq.len() / 2;
        let sigma = self.leaves.sigma();
        let (left, right, gamma) = (self.left, self.right, self.gamma);
        let mut evals = vec![K::from_i64(0); 4];
        stele_sumcheck::parallel::sum_ranges(half, &mut evals, |range, out| {
            for col in range {
                let lo0 = 2 * col;
                let hi0 = 2 * (col + half);
                let mut p0 = sigma[lo0];
                let dp0 = sigma[hi0] - p0;
                let mut p1 = sigma[lo0 + 1];
                let dp1 = sigma[hi0 + 1] - p1;
                let mut q0 = self.leaves.denom_at(self.denom, lo0);
                let dq0 = self.leaves.denom_at(self.denom, hi0) - q0;
                let mut q1 = self.leaves.denom_at(self.denom, lo0 + 1);
                let dq1 = self.leaves.denom_at(self.denom, hi0 + 1) - q1;
                let mut e = eq[col];
                let de = eq[col + half] - e;
                for slot in out.iter_mut().take(4) {
                    let num = left * q1.mul_m31(p0) + right * q0.mul_m31(p1) + gamma * (q0 * q1);
                    *slot = *slot + e * num;
                    p0 = p0 + dp0;
                    p1 = p1 + dp1;
                    q0 = q0 + dq0;
                    q1 = q1 + dq1;
                    e = e + de;
                }
            }
            Ok(())
        })?;
        Ok(evals)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        if self.remaining == 0 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        if let Some(dense) = &mut self.folded {
            dense.fold(r)?;
        } else {
            let mut eq = self.eq.take().ok_or(stele_sumcheck::Error::PublicShape)?;
            let half = eq.len() / 2;
            let one = K::from_i64(1);
            let zero = K::from_i64(0);
            let sigma = self.leaves.sigma();
            let alloc_half = || -> Result<Vec<K>, stele_sumcheck::Error> {
                let mut v = Vec::new();
                v.try_reserve_exact(half)
                    .map_err(|_| stele_sumcheck::Error::Capacity)?;
                v.resize(half, zero);
                Ok(v)
            };
            let mut f_p0 = alloc_half()?;
            let mut f_q0 = alloc_half()?;
            let mut f_p1 = alloc_half()?;
            let mut f_q1 = alloc_half()?;
            stele_sumcheck::parallel::for_each_chunk(&mut f_p0, |start, chunk| {
                for (j, dst) in chunk.iter_mut().enumerate() {
                    let col = start + j;
                    let a = sigma[2 * col];
                    let b = sigma[2 * (col + half)];
                    *dst = one.mul_m31(a) + r.mul_m31(b - a);
                }
            });
            stele_sumcheck::parallel::for_each_chunk(&mut f_q0, |start, chunk| {
                for (j, dst) in chunk.iter_mut().enumerate() {
                    let col = start + j;
                    let a = self.leaves.denom_at(self.denom, 2 * col);
                    let b = self.leaves.denom_at(self.denom, 2 * (col + half));
                    *dst = a + r * (b - a);
                }
            });
            stele_sumcheck::parallel::for_each_chunk(&mut f_p1, |start, chunk| {
                for (j, dst) in chunk.iter_mut().enumerate() {
                    let col = start + j;
                    let a = sigma[2 * col + 1];
                    let b = sigma[2 * (col + half) + 1];
                    *dst = one.mul_m31(a) + r.mul_m31(b - a);
                }
            });
            stele_sumcheck::parallel::for_each_chunk(&mut f_q1, |start, chunk| {
                for (j, dst) in chunk.iter_mut().enumerate() {
                    let col = start + j;
                    let a = self.leaves.denom_at(self.denom, 2 * col + 1);
                    let b = self.leaves.denom_at(self.denom, 2 * (col + half) + 1);
                    *dst = a + r * (b - a);
                }
            });
            stele_sumcheck::parallel::fold(&mut eq, r);
            self.folded = Some(Dense::from_folded(
                vec![f_p0, f_q0, f_p1, f_q1, eq],
                self.remaining - 1,
            )?);
        }
        self.remaining -= 1;
        self.point
            .try_reserve(1)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        self.point.push(r);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if self.remaining != 0 {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        self.folded
            .as_ref()
            .ok_or(stele_sumcheck::Error::PublicShape)?
            .final_values()
    }
}

impl<K: ChallengeField + Eq> Descriptor<K> {
    /// Build the dense fraction tree levels independently of the transcript so callers can
    /// overlap left and right tree construction on the work pool (task E20-02).
    pub fn build_levels(&self, leaves: &[[K; 2]]) -> Result<BuiltTree<K>, Error> {
        source(self, leaves)?;
        let mut levels = Vec::new();
        reserve(&mut levels, self.m as usize + 1)?;
        levels.push(owned(leaves)?);
        for k in (0..self.m as usize).rev() {
            let [a, b] = weights(self, k);
            let children = &levels[levels.len() - 1];
            let mut parents = Vec::new();
            reserve(&mut parents, children.len() / 2)?;
            parents.resize(children.len() / 2, [K::from_i64(0); 2]);
            // Each parent depends only on its two children: any split is identical.
            stele_sumcheck::parallel::for_each_chunk(&mut parents, |start, chunk| {
                for (j, parent) in chunk.iter_mut().enumerate() {
                    let [p0, q0] = children[2 * (start + j)];
                    let [p1, q1] = children[2 * (start + j) + 1];
                    *parent = [a * p0 * q1 + b * p1 * q0, q0 * q1];
                }
            });
            levels.push(parents);
        }
        levels.reverse();
        Ok(BuiltTree { levels })
    }

    /// Reduce a tree prebuilt by [`Self::build_levels`]; proof bytes match [`Self::prove`].
    pub fn prove_built(
        &self,
        tree: BuiltTree<K>,
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>), Error> {
        if tree.levels.len() != self.m as usize + 1
            || tree
                .levels
                .iter()
                .enumerate()
                .any(|(k, level)| level.len() != (1usize << k))
        {
            return Err(Error::SourceShape);
        }
        self.prove_levels(tree.levels, t)
            .map(|(proof, reduction, _)| (proof, reduction))
    }

    /// Build the upper fraction-tree layers directly from base-field leaves without allocating
    /// a `2^m` extension-field leaf layer, reading small-domain first layers from precomputed
    /// tables (task E20-02).
    pub fn build_base_levels(&self, leaves: BaseLeaves<'_, K>) -> Result<BuiltBaseTree<K>, Error> {
        leaves.validate(self.m)?;
        let one = K::from_i64(1);
        let zero = K::from_i64(0);
        let denom = match leaves {
            BaseLeaves::SmallDomain {
                alpha, table_size, ..
            } => {
                let cap = table_size.min(1 << 16);
                let mut d = Vec::new();
                reserve(&mut d, cap)?;
                for v in 0..cap {
                    d.push(alpha - K::from_i64(v as i64));
                }
                d
            }
            BaseLeaves::General { .. } => Vec::new(),
        };
        if self.m == 0 {
            let root = leaves.leaf_at(&denom, 0);
            return Ok(BuiltBaseTree {
                levels: Vec::new(),
                denom,
                root,
            });
        }
        let mut levels = Vec::new();
        reserve(&mut levels, self.m as usize)?;
        let k_bot = self.m as usize - 1;
        let [a, b] = weights(self, k_bot);
        let pair_count = leaves.len() / 2;
        let mut parents = Vec::new();
        reserve(&mut parents, pair_count)?;
        parents.resize(pair_count, [zero; 2]);
        match leaves {
            BaseLeaves::SmallDomain {
                sigma,
                values,
                alpha: _,
                ..
            } => {
                let t_cap = denom.len();
                let pair_table: Option<Vec<[K; 2]>> = if t_cap <= 256 {
                    let mut table = Vec::new();
                    reserve(&mut table, t_cap * t_cap)?;
                    for &q0 in &denom {
                        let bq0 = b * q0;
                        for &q1 in &denom {
                            table.push([a * q1 + bq0, q0 * q1]);
                        }
                    }
                    Some(table)
                } else {
                    None
                };
                stele_sumcheck::parallel::for_each_chunk(&mut parents, |start, chunk| {
                    for (j, parent) in chunk.iter_mut().enumerate() {
                        let i0 = 2 * (start + j);
                        let i1 = i0 + 1;
                        let (s0, s1) = (sigma[i0], sigma[i1]);
                        if s0 == M31::ZERO && s1 == M31::ZERO {
                            *parent = [zero, one];
                        } else if s0 == M31::ONE && s1 == M31::ONE {
                            let (v0, v1) =
                                (values[i0].as_u32() as usize, values[i1].as_u32() as usize);
                            if v0 < t_cap && v1 < t_cap {
                                if let Some(pairs) = &pair_table {
                                    *parent = pairs[v0 * t_cap + v1];
                                } else {
                                    let (q0, q1) = (denom[v0], denom[v1]);
                                    *parent = [a * q1 + b * q0, q0 * q1];
                                }
                            } else {
                                let (q0, q1) =
                                    (leaves.denom_at(&denom, i0), leaves.denom_at(&denom, i1));
                                *parent = [a * q1 + b * q0, q0 * q1];
                            }
                        } else if s0 == M31::ONE && s1 == M31::ZERO {
                            *parent = [a, leaves.denom_at(&denom, i0)];
                        } else if s0 == M31::ZERO && s1 == M31::ONE {
                            *parent = [b, leaves.denom_at(&denom, i1)];
                        } else {
                            let [p0, q0] = leaves.leaf_at(&denom, i0);
                            let [p1, q1] = leaves.leaf_at(&denom, i1);
                            *parent = [a * p0 * q1 + b * p1 * q0, q0 * q1];
                        }
                    }
                });
            }
            BaseLeaves::General { sigma, .. } => {
                stele_sumcheck::parallel::for_each_chunk(&mut parents, |start, chunk| {
                    for (j, parent) in chunk.iter_mut().enumerate() {
                        let i0 = 2 * (start + j);
                        let i1 = i0 + 1;
                        let (s0, s1) = (sigma[i0], sigma[i1]);
                        if s0 == M31::ZERO && s1 == M31::ZERO {
                            *parent = [zero, one];
                        } else if s0 == M31::ONE && s1 == M31::ONE {
                            let q0 = leaves.denom_at(&denom, i0);
                            let q1 = leaves.denom_at(&denom, i1);
                            *parent = [a * q1 + b * q0, q0 * q1];
                        } else if s0 == M31::ONE && s1 == M31::ZERO {
                            *parent = [a, leaves.denom_at(&denom, i0)];
                        } else if s0 == M31::ZERO && s1 == M31::ONE {
                            *parent = [b, leaves.denom_at(&denom, i1)];
                        } else {
                            let [p0, q0] = leaves.leaf_at(&denom, i0);
                            let [p1, q1] = leaves.leaf_at(&denom, i1);
                            *parent = [a * p0 * q1 + b * p1 * q0, q0 * q1];
                        }
                    }
                });
            }
        }
        levels.push(parents);
        for k in (0..k_bot).rev() {
            let [a, b] = weights(self, k);
            let children = &levels[levels.len() - 1];
            let mut next = Vec::new();
            reserve(&mut next, children.len() / 2)?;
            next.resize(children.len() / 2, [zero; 2]);
            stele_sumcheck::parallel::for_each_chunk(&mut next, |start, chunk| {
                for (j, parent) in chunk.iter_mut().enumerate() {
                    let [p0, q0] = children[2 * (start + j)];
                    let [p1, q1] = children[2 * (start + j) + 1];
                    *parent = [a * p0 * q1 + b * p1 * q0, q0 * q1];
                }
            });
            levels.push(next);
        }
        levels.reverse();
        let root = levels[0][0];
        Ok(BuiltBaseTree {
            levels,
            denom,
            root,
        })
    }

    /// Prove directly from base-field leaves and a [`BuiltBaseTree`] (bit-identical to [`Self::prove`]).
    pub fn prove_built_base(
        &self,
        leaves: BaseLeaves<'_, K>,
        tree: BuiltBaseTree<K>,
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>), Error> {
        leaves.validate(self.m)?;
        if tree.levels.len() != self.m as usize
            || tree
                .levels
                .iter()
                .enumerate()
                .any(|(k, level)| level.len() != (1usize << k))
        {
            return Err(Error::SourceShape);
        }
        let root = tree.root;
        let mut values = root;
        let mut point = Vec::new();
        let mut a = accounting(self)?;
        let mut steps = Vec::new();
        reserve(&mut steps, self.m as usize)?;
        bind(self, root, t)?;
        // Upper levels `1..m` from prebuilt extension pairs.
        for children in tree.levels.iter().skip(1) {
            let i = layer(self, &point, values, t, &mut a)?;
            let mut tables = Vec::new();
            reserve(&mut tables, 5)?;
            for (side, column) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                let mut table = Vec::new();
                reserve(&mut table, children.len() / 2)?;
                table.resize(children.len() / 2, K::from_i64(0));
                stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                    for (j, out) in chunk.iter_mut().enumerate() {
                        *out = children[2 * (start + j) + side][column];
                    }
                });
                tables.push(table);
            }
            tables.push(stele_sumcheck::parallel::eq_table(&point)?);
            let (step, next, _) = prove_dense(&i, tables, t)?;
            a.layers.push(ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            });
            let (advanced, next_values) = advance(&point, next, &step.final_values, t, &mut a)?;
            (point, values) = (advanced, next_values);
            steps.push(step);
        }
        // Bottom level (`k = m - 1`): keep leaf layer in base field during round 0.
        if self.m >= 1 {
            let i = layer(self, &point, values, t, &mut a)?;
            let (step, next) = if self.m == 1 {
                let [p0, q0] = leaves.leaf_at(&tree.denom, 0);
                let [p1, q1] = leaves.leaf_at(&tree.denom, 1);
                let tables = vec![vec![p0], vec![q0], vec![p1], vec![q1], vec![K::from_i64(1)]];
                let (s, n, _) = prove_dense(&i, tables, t)?;
                (s, n)
            } else {
                let eq = stele_sumcheck::parallel::eq_table(&point)?;
                let mut next = Vec::new();
                reserve(&mut next, i.num_vars as usize)?;
                let summand = BaseLeafSummand {
                    leaves,
                    denom: &tree.denom,
                    eq: Some(eq),
                    left: i.terms[0].coefficient,
                    right: i.terms[1].coefficient,
                    gamma: i.terms[2].coefficient,
                    remaining: i.num_vars,
                    folded: None,
                    point: &mut next,
                };
                let step = stele_sumcheck::prove(&i, summand, t)?;
                (step, next)
            };
            a.layers.push(ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            });
            let (advanced, next_values) = advance(&point, next, &step.final_values, t, &mut a)?;
            (point, values) = (advanced, next_values);
            steps.push(step);
        }
        Ok((Proof { root, steps }, result(self, point, values, a)))
    }

    /// Convenience wrapper combining [`Self::build_base_levels`] and [`Self::prove_built_base`].
    pub fn prove_base_leaves(
        &self,
        leaves: BaseLeaves<'_, K>,
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>), Error> {
        let built = self.build_base_levels(leaves)?;
        self.prove_built_base(leaves, built, t)
    }

    /// Build and reduce the dense tree; all returned original claims remain obligations.
    pub fn prove(
        &self,
        leaves: &[[K; 2]],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>), Error> {
        self.prove_measured(leaves, t)
            .map(|(proof, reduction, _)| (proof, reduction))
    }
    /// The same actual producer, with descriptive field-buffer observations.
    /// A3/A5 §6: no additional transcript work or independent tree is executed.
    pub fn prove_measured(
        &self,
        leaves: &[[K; 2]],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>, Work), Error> {
        let built = self.build_levels(leaves)?;
        self.prove_levels(built.levels, t)
    }
    fn prove_levels(
        &self,
        levels: Vec<Vec<[K; 2]>>,
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>, Work), Error> {
        let levels_bytes = work::tables(&levels)?;
        let mut work = Work::default();
        work.observe(levels_bytes, 0, 0, 0)?;
        let mut proof_bytes = 0;
        let root = levels[0][0];
        let mut values = root;
        let mut point = Vec::new();
        let mut a = accounting(self)?;
        let mut steps = Vec::new();
        reserve(&mut steps, self.m as usize)?;
        bind(self, root, t)?;
        for children in levels.iter().skip(1) {
            let i = layer(self, &point, values, t, &mut a)?;
            let mut tables = Vec::new();
            reserve(&mut tables, 5)?;
            for (side, column) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                let mut table = Vec::new();
                reserve(&mut table, children.len() / 2)?;
                table.resize(children.len() / 2, K::from_i64(0));
                stele_sumcheck::parallel::for_each_chunk(&mut table, |start, chunk| {
                    for (j, out) in chunk.iter_mut().enumerate() {
                        *out = children[2 * (start + j) + side][column];
                    }
                });
                tables.push(table);
            }
            tables.push(stele_sumcheck::parallel::eq_table(&point)?);
            let (step, next, dense) = prove_dense(&i, tables, t)?;
            // These exact outer buffers remain unchanged across the actual A1.
            work.observe(
                levels_bytes,
                dense.tables,
                proof_bytes,
                work::add(work::bytes(&point)?, dense.point)?,
            )?;
            proof_bytes = work::add(proof_bytes, work::proof(&step)?)?;
            work.observe(
                levels_bytes,
                0,
                proof_bytes,
                work::add(work::bytes(&point)?, work::bytes(&next)?)?,
            )?;
            a.layers.push(ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            });
            let (advanced, next_values) = advance(&point, next, &step.final_values, t, &mut a)?;
            work.observe(
                levels_bytes,
                0,
                proof_bytes,
                work::add(work::bytes(&point)?, work::bytes(&advanced)?)?,
            )?;
            (point, values) = (advanced, next_values);
            steps.push(step);
        }
        Ok((Proof { root, steps }, result(self, point, values, a), work))
    }
    /// Verify arithmetic only; the two original claims still require consumers.
    pub fn verify(&self, proof: &Proof<K>, t: &mut Transcript<K>) -> Result<Reduction<K>, Error> {
        proof.validate(self)?;
        let mut a = accounting(self)?;
        let mut point = Vec::new();
        let mut values = proof.root;
        bind(self, proof.root, t)?;
        for step in &proof.steps {
            let i = layer(self, &point, values, t, &mut a)?;
            let reduction = stele_sumcheck::verify(&i, step, t)?;
            a.layers.push(reduction.sc);
            (point, values) = advance(&point, reduction.point, &step.final_values, t, &mut a)?;
        }
        Ok(result(self, point, values, a))
    }
    /// Discharge both original claims against fixed public arrays, never internal levels.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        leaves: &[[K; 2]],
        t: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        source(self, leaves)?;
        let reduction = self.verify(proof, t)?;
        let eq = stele_poly::eq_table(&reduction.point).map_err(|_| Error::Capacity)?;
        let mut actual = [K::from_i64(0); 2];
        for (row, w) in leaves.iter().zip(eq) {
            for j in 0..2 {
                actual[j] = actual[j] + row[j] * w;
            }
        }
        if actual != reduction.claims.map(|c| c.1) {
            return Err(Error::LeafMismatch);
        }
        Ok(reduction)
    }
}
/// Check a rational root equation only; zero denominators always reject.
pub fn check_roots<K: ChallengeField + Eq>(left: [K; 2], right: [K; 2]) -> Result<(), Error> {
    if left[1] == K::from_i64(0) || right[1] == K::from_i64(0) {
        return Err(Error::Pole);
    }
    if left[0] * right[1] != right[0] * left[1] {
        return Err(Error::RootMismatch);
    }
    Ok(())
}
