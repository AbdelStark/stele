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
/// One fraction-tree layer's round state (RFC-0008 A3): the dense round polynomial of
/// `eq · (left·p0·q1 + right·p1·q0 + γ·q0·q1)` with `eq(r, ·)` kept factored. Its bound
/// prefix is a scalar, its current coordinate a line in the round variable and only its
/// suffix a table, so a round reads four tables at three points, not five at four. The
/// arithmetic is exact: every message equals the dense strategy's.
struct Layer<'a, K> {
    /// `p0, q0, p1, q1` over the unbound coordinates, leading coordinate first.
    tables: [Vec<K>; 4],
    /// The unbound coordinates of the layer point, leading first.
    r: &'a [K],
    /// `eq` of the bound coordinates.
    scale: K,
    /// `eq(r[1..], ·)`: half the tables' length.
    suffix: Vec<K>,
    /// `left, right, γ`.
    weights: [K; 3],
}
/// `eq(r, x)` on the line through `x = 0` and `x = 1`.
pub(super) fn eq_line<K: ChallengeField>(r: K, x: K) -> K {
    K::from_i64(1) - r - x + (r + r) * x
}
/// The degree-3 round values at 0..=3 of `scale · eq(r0, X) · t(X)`, from the quadratic
/// `t`'s values at 0 and 1 and its leading coefficient.
pub(super) fn factored_message<K: ChallengeField>(
    scale: K,
    r0: K,
    [at0, at1, lead]: [K; 3],
) -> Result<Vec<K>, stele_sumcheck::Error> {
    let slope = at1 - at0 - lead;
    let mut out = Vec::new();
    out.try_reserve_exact(4)
        .map_err(|_| stele_sumcheck::Error::Capacity)?;
    for node in 0..4 {
        let x = K::from_i64(node);
        out.push(scale * eq_line(r0, x) * (at0 + x * (slope + lead * x)));
    }
    Ok(out)
}
/// `eq(r[1..], ·)` after one more coordinate is bound: summed over its leading coordinate.
pub(super) fn halve_suffix<K: ChallengeField>(suffix: &mut Vec<K>) {
    let half = suffix.len() / 2;
    if half > 0 {
        let (low, high) = suffix.split_at_mut(half);
        for (a, b) in low.iter_mut().zip(high.iter()) {
            *a = *a + *b;
        }
        suffix.truncate(half);
    }
}
impl<'a, K: ChallengeField + Eq> Layer<'a, K> {
    fn new(tables: [Vec<K>; 4], r: &'a [K], weights: [K; 3]) -> Result<Self, Error> {
        if tables.iter().any(|t| t.len() != 1usize << r.len()) {
            return Err(Error::SourceShape);
        }
        Ok(Self {
            tables,
            r,
            scale: K::from_i64(1),
            suffix: stele_sumcheck::parallel::eq_table(r.get(1..).unwrap_or(&[]))?,
            weights,
        })
    }
    /// The round values at 0..=3 from the suffix-weighted sums of the summand at 0, at 1
    /// and of its leading coefficient (it is quadratic in the round variable).
    fn message(&self, sums: [K; 3]) -> Result<Vec<K>, stele_sumcheck::Error> {
        let r0 = *self.r.first().ok_or(stele_sumcheck::Error::PublicShape)?;
        factored_message(self.scale, r0, sums)
    }
    fn round(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        let half = self.suffix.len();
        let [p0, q0, p1, q1] = &self.tables;
        if self.r.is_empty() || p0.len() != 2 * half {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let [left, right, gamma] = self.weights;
        let one = K::from_i64(1);
        let unit = left == one && right == one;
        // Bilinear in (p0, q0) and (p1, q1).
        let term = |p0: K, q0: K, p1: K, q1: K| {
            if unit {
                q1 * (p0 + gamma * q0) + p1 * q0
            } else {
                q1 * (left * p0 + gamma * q0) + right * p1 * q0
            }
        };
        let mut sums = [K::from_i64(0); 3];
        stele_sumcheck::parallel::sum_ranges(half, &mut sums, |range, out| {
            if unit {
                // QM31 layers take the host's kernel: the sums of the loop below.
                let kernel = stele_sumcheck::parallel::layer_round_kernel(
                    [&p0[..], &q0[..], &p1[..], &q1[..]],
                    &self.suffix,
                    gamma,
                    range.clone(),
                );
                if let Some(partial) = kernel {
                    for (total, part) in out.iter_mut().zip(partial) {
                        *total = *total + part;
                    }
                    return Ok(());
                }
            }
            for x in range {
                let y = x + half;
                let e = self.suffix[x];
                out[0] = out[0] + e * term(p0[x], q0[x], p1[x], q1[x]);
                out[1] = out[1] + e * term(p0[y], q0[y], p1[y], q1[y]);
                out[2] =
                    out[2] + e * term(p0[y] - p0[x], q0[y] - q0[x], p1[y] - p1[x], q1[y] - q1[x]);
            }
            Ok(())
        })?;
        self.message(sums)
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        let (&r0, rest) = self
            .r
            .split_first()
            .ok_or(stele_sumcheck::Error::PublicShape)?;
        for table in &mut self.tables {
            stele_sumcheck::parallel::fold(table, challenge);
        }
        self.bind(r0, challenge);
        self.r = rest;
        Ok(())
    }
    /// Move `r0` from the round variable to the bound prefix: `eq(r[2..], ·)` is
    /// `eq(r[1..], ·)` summed over its leading coordinate.
    fn bind(&mut self, r0: K, challenge: K) {
        self.scale = self.scale * eq_line(r0, challenge);
        halve_suffix(&mut self.suffix);
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        if !self.r.is_empty() {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(5)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        out.extend(self.tables.iter().map(|t| t[0]));
        out.push(self.scale);
        Ok(out)
    }
}
/// [`Layer`] as an A1 strategy that records the engine's challenges.
struct LayerSummand<'a, K> {
    layer: Layer<'a, K>,
    point: &'a mut Vec<K>,
}
impl<K: ChallengeField + Eq> Summand<K> for LayerSummand<'_, K> {
    fn shape(&self) -> (u32, usize) {
        (self.layer.r.len() as u32, 5)
    }
    fn validate_instance(&self, instance: &Instance<K>) -> Result<(), stele_sumcheck::Error> {
        if self.shape() != (instance.num_vars, instance.inputs.len())
            || !is_layer_instance(instance)
        {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        Ok(())
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.layer.round()
    }
    fn fold(&mut self, challenge: K) -> Result<(), stele_sumcheck::Error> {
        self.layer.fold(challenge)?;
        self.point
            .try_reserve(1)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        self.point.push(challenge);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.layer.final_values()
    }
}
/// [`stele_sumcheck::parallel::build`] with this crate's error.
fn built<T: Send>(len: usize, at: impl Fn(usize) -> T + Sync) -> Result<Vec<T>, Error> {
    stele_sumcheck::parallel::build(len, at).map_err(|_| Error::Capacity)
}
/// `p0, q0, p1, q1` of a level's child pairs: even children are the left side.
fn split_children<K: ChallengeField>(children: &[[K; 2]]) -> Result<[Vec<K>; 4], Error> {
    let table =
        |side: usize, column: usize| built(children.len() / 2, |j| children[2 * j + side][column]);
    Ok([table(0, 0)?, table(0, 1)?, table(1, 0)?, table(1, 1)?])
}
/// Reduce one layer over `p0, q0, p1, q1` at the layer point `r`; the proof bytes are
/// [`prove_dense`]'s over the same four tables and `eq(r, ·)`.
fn prove_layer<K: ChallengeField + Eq>(
    i: &Instance<K>,
    tables: [Vec<K>; 4],
    r: &[K],
    t: &mut Transcript<K>,
) -> Result<(stele_sumcheck::Proof<K>, Vec<K>), Error> {
    let mut point = Vec::new();
    reserve(&mut point, r.len())?;
    let weights = [
        i.terms[0].coefficient,
        i.terms[1].coefficient,
        i.terms[2].coefficient,
    ];
    let strategy = LayerSummand {
        layer: Layer::new(tables, r, weights)?,
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
/// layer in the base field during round 0, then folds directly into half-sized extension
/// tables and continues as a [`Layer`]. `eq` is factored from the first round on.
struct BaseLeafSummand<'a, K: ChallengeField + Eq> {
    leaves: BaseLeaves<'a, K>,
    denom: &'a [K],
    /// The layer point; `r[0]` is the first round's coordinate.
    r: &'a [K],
    /// `eq(r[1..], ·)`, until the first fold.
    suffix: Option<Vec<K>>,
    /// `left, right, γ`.
    weights: [K; 3],
    folded: Option<Layer<'a, K>>,
    point: &'a mut Vec<K>,
}

/// Leaf pairs copied into tables per kernel call of the base-leaf round: 16 KiB of QM31.
const LEAF_BLOCK: usize = 128;

/// Whether `i` is [`layer`]'s polynomial `left·p0·q1·eq + right·p1·q0·eq + γ·q0·q1·eq`: a
/// hand-written summand hard-codes this factor layout and reads only the coefficients.
fn is_layer_instance<K: ChallengeField>(i: &Instance<K>) -> bool {
    let layout: [&[u32]; 3] = [&[0, 3, 4], &[2, 1, 4], &[1, 3, 4]];
    i.inputs.len() == 5 && i.terms.iter().map(|t| t.factors.as_slice()).eq(layout)
}
impl<K: ChallengeField + Eq> Summand<K> for BaseLeafSummand<'_, K> {
    fn shape(&self) -> (u32, usize) {
        let remaining = self.folded.as_ref().map_or(self.r.len(), |l| l.r.len());
        (remaining as u32, 5)
    }
    fn validate_instance(&self, instance: &Instance<K>) -> Result<(), stele_sumcheck::Error> {
        if self.shape() != (instance.num_vars, instance.inputs.len())
            || !is_layer_instance(instance)
        {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        Ok(())
    }
    fn round(&self, _: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        if let Some(layer) = &self.folded {
            return layer.round();
        }
        let suffix = self
            .suffix
            .as_deref()
            .ok_or(stele_sumcheck::Error::PublicShape)?;
        let half = suffix.len();
        let sigma = self.leaves.sigma();
        if self.r.is_empty() || sigma.len() != 4 * half {
            return Err(stele_sumcheck::Error::PublicShape);
        }
        let [left, right, gamma] = self.weights;
        // Bilinear in (p0, q0) and (p1, q1), with the selectors in the base field.
        let term = |p0: M31, q0: K, p1: M31, q1: K| {
            left * q1.mul_m31(p0) + right * q0.mul_m31(p1) + gamma * (q0 * q1)
        };
        let q = |idx: usize| self.leaves.denom_at(self.denom, idx);
        let one = K::from_i64(1);
        // With unit weights the term is the layer's, `q1·(p0 + γ·q0) + p1·q0`, on the
        // embedded selectors. Where the host has a kernel, blocks of leaves are copied
        // into short tables for it: the same sums.
        let blocks =
            left == one && right == one && stele_sumcheck::parallel::kernels_available::<K>();
        let mut sums = [K::from_i64(0); 3];
        stele_sumcheck::parallel::sum_ranges(half, &mut sums, |range, out| {
            if blocks {
                let zero = K::from_i64(0);
                let mut tables = [[zero; 2 * LEAF_BLOCK]; 4];
                let mut start = range.start;
                while start < range.end {
                    let n = (range.end - start).min(LEAF_BLOCK);
                    for j in 0..n {
                        let (lo, hi) = (2 * (start + j), 2 * (start + j + half));
                        // Lower half: the pair at `x`; upper half: the pair at `x + half`.
                        for (at, leaf) in [(j, lo), (n + j, hi)] {
                            tables[0][at] = one.mul_m31(sigma[leaf]);
                            tables[1][at] = q(leaf);
                            tables[2][at] = one.mul_m31(sigma[leaf + 1]);
                            tables[3][at] = q(leaf + 1);
                        }
                    }
                    let partial = stele_sumcheck::parallel::layer_round_kernel(
                        [
                            &tables[0][..2 * n],
                            &tables[1][..2 * n],
                            &tables[2][..2 * n],
                            &tables[3][..2 * n],
                        ],
                        &suffix[start..start + n],
                        gamma,
                        0..n,
                    )
                    .ok_or(stele_sumcheck::Error::PublicShape)?;
                    for (total, part) in out.iter_mut().zip(partial) {
                        *total = *total + part;
                    }
                    start += n;
                }
                return Ok(());
            }
            for col in range {
                let (lo, hi) = (2 * col, 2 * (col + half));
                let (p0a, p0b, p1a, p1b) = (sigma[lo], sigma[hi], sigma[lo + 1], sigma[hi + 1]);
                let (q0a, q0b, q1a, q1b) = (q(lo), q(hi), q(lo + 1), q(hi + 1));
                let e = suffix[col];
                out[0] = out[0] + e * term(p0a, q0a, p1a, q1a);
                out[1] = out[1] + e * term(p0b, q0b, p1b, q1b);
                out[2] = out[2] + e * term(p0b - p0a, q0b - q0a, p1b - p1a, q1b - q1a);
            }
            Ok(())
        })?;
        Layer {
            tables: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            r: self.r,
            scale: K::from_i64(1),
            suffix: Vec::new(),
            weights: self.weights,
        }
        .message(sums)
    }
    fn fold(&mut self, r: K) -> Result<(), stele_sumcheck::Error> {
        if let Some(layer) = &mut self.folded {
            layer.fold(r)?;
        } else {
            let suffix = self
                .suffix
                .take()
                .ok_or(stele_sumcheck::Error::PublicShape)?;
            let (&r0, _) = self
                .r
                .split_first()
                .ok_or(stele_sumcheck::Error::PublicShape)?;
            let half = suffix.len();
            let one = K::from_i64(1);
            let sigma = self.leaves.sigma();
            use stele_sumcheck::parallel::build;
            let f_p0 = build(half, |col| {
                let a = sigma[2 * col];
                let b = sigma[2 * (col + half)];
                one.mul_m31(a) + r.mul_m31(b - a)
            })?;
            let f_q0 = build(half, |col| {
                let a = self.leaves.denom_at(self.denom, 2 * col);
                let b = self.leaves.denom_at(self.denom, 2 * (col + half));
                a + r * (b - a)
            })?;
            let f_p1 = build(half, |col| {
                let a = sigma[2 * col + 1];
                let b = sigma[2 * (col + half) + 1];
                one.mul_m31(a) + r.mul_m31(b - a)
            })?;
            let f_q1 = build(half, |col| {
                let a = self.leaves.denom_at(self.denom, 2 * col + 1);
                let b = self.leaves.denom_at(self.denom, 2 * (col + half) + 1);
                a + r * (b - a)
            })?;
            let mut layer = Layer {
                tables: [f_p0, f_q0, f_p1, f_q1],
                r: &self.r[1..],
                scale: one,
                suffix,
                weights: self.weights,
            };
            layer.bind(r0, r);
            self.folded = Some(layer);
        }
        self.point
            .try_reserve(1)
            .map_err(|_| stele_sumcheck::Error::Capacity)?;
        self.point.push(r);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
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
            // Each parent depends only on its two children: any split is identical.
            let parents = built(children.len() / 2, |j| {
                let [p0, q0] = children[2 * j];
                let [p1, q1] = children[2 * j + 1];
                [a * p0 * q1 + b * p1 * q0, q0 * q1]
            })?;
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
        self.prove_levels(tree.levels, t, false)
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
        let parents = match leaves {
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
                built(pair_count, |j| {
                    let i0 = 2 * j;
                    let i1 = i0 + 1;
                    let (s0, s1) = (sigma[i0], sigma[i1]);
                    if s0 == M31::ZERO && s1 == M31::ZERO {
                        [zero, one]
                    } else if s0 == M31::ONE && s1 == M31::ONE {
                        let (v0, v1) = (values[i0].as_u32() as usize, values[i1].as_u32() as usize);
                        if v0 < t_cap && v1 < t_cap {
                            if let Some(pairs) = &pair_table {
                                pairs[v0 * t_cap + v1]
                            } else {
                                let (q0, q1) = (denom[v0], denom[v1]);
                                [a * q1 + b * q0, q0 * q1]
                            }
                        } else {
                            let (q0, q1) =
                                (leaves.denom_at(&denom, i0), leaves.denom_at(&denom, i1));
                            [a * q1 + b * q0, q0 * q1]
                        }
                    } else if s0 == M31::ONE && s1 == M31::ZERO {
                        [a, leaves.denom_at(&denom, i0)]
                    } else if s0 == M31::ZERO && s1 == M31::ONE {
                        [b, leaves.denom_at(&denom, i1)]
                    } else {
                        let [p0, q0] = leaves.leaf_at(&denom, i0);
                        let [p1, q1] = leaves.leaf_at(&denom, i1);
                        [a * p0 * q1 + b * p1 * q0, q0 * q1]
                    }
                })?
            }
            BaseLeaves::General { sigma, .. } => built(pair_count, |j| {
                let i0 = 2 * j;
                let i1 = i0 + 1;
                let (s0, s1) = (sigma[i0], sigma[i1]);
                if s0 == M31::ZERO && s1 == M31::ZERO {
                    [zero, one]
                } else if s0 == M31::ONE && s1 == M31::ONE {
                    let q0 = leaves.denom_at(&denom, i0);
                    let q1 = leaves.denom_at(&denom, i1);
                    [a * q1 + b * q0, q0 * q1]
                } else if s0 == M31::ONE && s1 == M31::ZERO {
                    [a, leaves.denom_at(&denom, i0)]
                } else if s0 == M31::ZERO && s1 == M31::ONE {
                    [b, leaves.denom_at(&denom, i1)]
                } else {
                    let [p0, q0] = leaves.leaf_at(&denom, i0);
                    let [p1, q1] = leaves.leaf_at(&denom, i1);
                    [a * p0 * q1 + b * p1 * q0, q0 * q1]
                }
            })?,
        };
        levels.push(parents);
        for k in (0..k_bot).rev() {
            let [a, b] = weights(self, k);
            let children = &levels[levels.len() - 1];
            let next = built(children.len() / 2, |j| {
                let [p0, q0] = children[2 * j];
                let [p1, q1] = children[2 * j + 1];
                [a * p0 * q1 + b * p1 * q0, q0 * q1]
            })?;
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
        let BuiltBaseTree {
            levels,
            denom,
            root,
        } = tree;
        let mut values = root;
        let mut point = Vec::new();
        let mut a = accounting(self)?;
        let mut steps = Vec::new();
        reserve(&mut steps, self.m as usize)?;
        bind(self, root, t)?;
        // Upper levels `1..m` from prebuilt extension pairs. A level is freed once its
        // child tables are made: the levels are half the tree's memory.
        for children in levels.into_iter().skip(1) {
            let i = layer(self, &point, values, t, &mut a)?;
            let tables = split_children(&children)?;
            drop(children);
            let (step, next) = prove_layer(&i, tables, &point, t)?;
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
                let [p0, q0] = leaves.leaf_at(&denom, 0);
                let [p1, q1] = leaves.leaf_at(&denom, 1);
                let tables = vec![vec![p0], vec![q0], vec![p1], vec![q1], vec![K::from_i64(1)]];
                let (s, n, _) = prove_dense(&i, tables, t)?;
                (s, n)
            } else {
                let mut next = Vec::new();
                reserve(&mut next, i.num_vars as usize)?;
                let summand = BaseLeafSummand {
                    leaves,
                    denom: &denom,
                    r: &point,
                    suffix: Some(stele_sumcheck::parallel::eq_table(&point[1..])?),
                    weights: [
                        i.terms[0].coefficient,
                        i.terms[1].coefficient,
                        i.terms[2].coefficient,
                    ],
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
        self.prove_levels(built.levels, t, true)
    }
    /// `measured` keeps the dense strategy, whose buffers [`Work`] describes; otherwise
    /// each layer runs the factored one. The proof bytes are the same.
    fn prove_levels(
        &self,
        levels: Vec<Vec<[K; 2]>>,
        t: &mut Transcript<K>,
        measured: bool,
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
            let tables = split_children(children)?;
            if !measured {
                let (step, next) = prove_layer(&i, tables, &point, t)?;
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
                continue;
            }
            let mut tables = Vec::from(tables);
            reserve(&mut tables, 1)?;
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
