//! Masked A1 sumcheck, RFC-0013 A2 item 2 as replaced by A3 (labels RFC-0012 A18).
//!
//! The rounds run on `f + α·G` with the two-block mask
//! `G(X) = (1 − X_n)·g⁰(X) + X_n·g¹(X)`, `g^b = Σ_i g^b_i(X_i)`, where
//! `deg g^b_i ≤ δ` for `i < n` and `deg g^b_n ≤ δ − 1`. The caller binds the mask
//! (its committed source bytes) before `G` is absorbed; the result keeps A1's
//! final obligations and the mask obligation `(ρ, G(ρ))`. Only the RFC-0013 A3
//! consumer (`stele_reductions::zk`) discharges it; `scripts/gates/check.py`
//! quarantines every other use.
use crate::{
    interpolate, interpolation_weights, message_bytes, reserve, round_payload, Error, Instance,
    ScRecord, Summand,
};
use alloc::vec::Vec;
use stele_hash::mask::{MaskStream, SUMCHECK_MASK};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// The prover's secret two-block mask. `blocks[b][i]` holds `g^b_i` by its values
/// at nodes `0..=δ` (`i < n − 1`) or `0..δ` (`i = n − 1`).
pub struct Mask<K> {
    blocks: [Vec<Vec<K>>; 2],
}

/// Node count of variable `i` of an `n`-variable, degree-`δ` mask.
fn nodes(n: usize, degree: usize, i: usize) -> usize {
    if i + 1 == n {
        degree
    } else {
        degree + 1
    }
}

impl<K: ChallengeField> Mask<K> {
    /// Derive the mask for one instance from a fresh secret seed (A3 item 1):
    /// block 0 then block 1, variables ascending, nodes ascending, each value
    /// `D` M31 elements in limb order from the `zk/sumcheck-mask` stream.
    pub fn derive(seed: &[u8; 32], i: &Instance<K>) -> Result<Self, Error> {
        let degree = shape(i)?;
        let n = i.num_vars as usize;
        let mut stream = MaskStream::new(seed, SUMCHECK_MASK, i.id);
        let mut block = || -> Result<Vec<Vec<K>>, Error> {
            let mut rows = Vec::new();
            reserve(&mut rows, n)?;
            for index in 0..n {
                let mut row = Vec::new();
                reserve(&mut row, degree + 1)?;
                row.extend((0..nodes(n, degree, index)).map(|_| stream.element::<K>()));
                rows.push(row);
            }
            Ok(rows)
        };
        let first = block()?;
        let second = block()?;
        Ok(Self {
            blocks: [first, second],
        })
    }

    /// Number of mask coefficients per block, `n(δ + 1) − 1`.
    pub fn width(&self) -> usize {
        self.blocks[0].iter().map(Vec::len).sum()
    }

    /// The values of block `b` in canonical column order (variables, then nodes).
    pub fn columns(&self, b: usize) -> impl Iterator<Item = K> + '_ {
        self.blocks[b & 1].iter().flatten().copied()
    }

    /// `G = Σ_{x ∈ {0,1}^n} G(x)`.
    pub fn sum(&self) -> K {
        let n = self.blocks[0].len();
        let last = n - 1;
        let c0 = self.blocks[0][last][0] + at_one(&self.blocks[1][last]);
        let ends = (0..last).fold(K::from_i64(0), |s, j| {
            s + self.blocks[0][j][0]
                + self.blocks[0][j][1]
                + self.blocks[1][j][0]
                + self.blocks[1][j][1]
        });
        let half = K::from_i64(2).inverse().unwrap_or(K::from_i64(0));
        power_of_two::<K>(last) * (c0 + half * ends)
    }

    /// `G(ρ)`; the value the RFC-0013 A3 opening binds.
    pub fn evaluate(&self, point: &[K]) -> Result<K, Error> {
        let n = self.blocks[0].len();
        if point.len() != n {
            return Err(Error::ProofShape);
        }
        let mut total = [K::from_i64(0); 2];
        for (b, block) in self.blocks.iter().enumerate() {
            for (row, x) in block.iter().zip(point) {
                total[b] = total[b] + interpolate(row, *x)?;
            }
        }
        let last = point[n - 1];
        Ok((K::from_i64(1) - last) * total[0] + last * total[1])
    }
}

/// `g(1)` for a stored univariate; a constant (one node) is its own value.
fn at_one<K: ChallengeField>(row: &[K]) -> K {
    row[usize::from(row.len() > 1)]
}

/// The A3 opening weights over the `n(δ + 1) − 1` mask columns at `point`: the
/// Lagrange weight of each column's node at its variable's coordinate.
pub fn column_weights<K: ChallengeField>(
    num_vars: u32,
    degree: usize,
    point: &[K],
) -> Result<Vec<K>, Error> {
    let n = num_vars as usize;
    if n == 0 || degree == 0 || point.len() != n {
        return Err(Error::InvalidInstance);
    }
    let mut out = Vec::new();
    reserve(&mut out, n * (degree + 1))?;
    for (index, x) in point.iter().enumerate() {
        out.extend(interpolation_weights(nodes(n, degree, index), *x)?);
    }
    Ok(out)
}

/// Masked proof: `G`, the A1 rounds of `f + α·G`, the finals and `μ = G(ρ)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// The mask sum `G`, absorbed before `α`.
    pub mask_sum: K,
    /// Exactly `n` rows of `δ + 1` values at `0..=δ`.
    pub rounds: Vec<Vec<K>>,
    /// One value per ordered input tensor.
    pub final_values: Vec<K>,
    /// The mask final `μ = G(ρ)`.
    pub mask_final: K,
}

/// A1's reduction plus the mask obligation.
#[must_use = "every final claim and the mask obligation need a consumer"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// A1 claims at the shared point, with the unchanged SC record.
    pub reduction: crate::Reduction<K>,
    /// `μ`, claimed equal to `G(ρ)` at `reduction.point`.
    pub mask_final: K,
    /// The MASK ledger record for `α`: `1/|K|`, valid once the mask is bound.
    pub mask: MaskRecord,
}

/// One MASK draw (RFC-0012 A18): loss `1/p^field_degree`, charged once per
/// masked instance, valid only when the mask was bound before `G` (RFC-0013 A3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskRecord {
    /// Verifier-owned instance identity.
    pub id: u64,
    /// Canonical extension degree, 4 or 8.
    pub field_degree: u8,
}

/// The instance's validated degree `δ`, rejecting `n = 0` or `δ = 0` (A2).
pub fn degree<K: ChallengeField>(i: &Instance<K>) -> Result<usize, Error> {
    shape(i)
}

fn shape<K: ChallengeField>(i: &Instance<K>) -> Result<usize, Error> {
    let degree = i.validate()?;
    // A2: n = 0 or δ = 0 would reveal the mask and add no masking.
    if i.num_vars == 0 || degree == 0 {
        return Err(Error::InvalidInstance);
    }
    Ok(degree)
}

fn power_of_two<K: ChallengeField>(exponent: usize) -> K {
    (0..exponent).fold(K::from_i64(1), |p, _| p + p)
}

/// Absorb the instance, the mask binding and `G`, then draw `α` (A3 order).
fn start<K: ChallengeField>(
    i: &Instance<K>,
    binding: &[u8],
    mask_sum: K,
    t: &mut Transcript<K>,
) -> Result<K, Error> {
    t.absorb(AbsorbLabel::Instance, &i.encode()?)?;
    t.absorb(AbsorbLabel::FieldSources, binding)?;
    t.absorb(
        AbsorbLabel::ZkMaskSum,
        &message_bytes(i.id, 0, &[mask_sum])?,
    )?;
    Ok(t.challenge(ChallengeLabel::ZkMaskWeight)?)
}

/// Check `P(finals) + α·μ` and absorb `finals ‖ μ` at index `k + 1`.
fn finish<K: ChallengeField + Eq>(
    i: &Instance<K>,
    final_values: &[K],
    mask_final: K,
    alpha: K,
    running: K,
    t: &mut Transcript<K>,
) -> Result<(), Error> {
    if i.evaluate(final_values) + alpha * mask_final != running {
        return Err(Error::FinalEvaluationMismatch);
    }
    let mut values = Vec::new();
    reserve(&mut values, final_values.len() + 1)?;
    values.extend_from_slice(final_values);
    values.push(mask_final);
    t.absorb(
        AbsorbLabel::Final,
        &message_bytes(i.id, i.inputs.len() as u32 + 1, &values)?,
    )?;
    Ok(())
}

/// The mask's round polynomial at nodes `0..=δ` for round `index`, given the
/// block prefixes `P_b = Σ_{j<index} g^b_j(ρ_j)`.
fn mask_round<K: ChallengeField>(
    mask: &Mask<K>,
    index: usize,
    prefix: [K; 2],
    degree: usize,
) -> Result<Vec<K>, Error> {
    let n = mask.blocks[0].len();
    let last = n - 1;
    let mut out = Vec::new();
    reserve(&mut out, degree + 1)?;
    if index == last {
        // (1 − t)(P0 + g⁰_n(t)) + t(P1 + g¹_n(t)).
        for node in 0..=degree {
            let t = K::from_i64(node as i64);
            let g0 = interpolate(&mask.blocks[0][last], t)?;
            let g1 = interpolate(&mask.blocks[1][last], t)?;
            out.push((K::from_i64(1) - t) * (prefix[0] + g0) + t * (prefix[1] + g1));
        }
        return Ok(out);
    }
    // Summing X_n over {0,1} leaves h_j = g⁰_j + g¹_j and c0 = g⁰_n(0) + g¹_n(1).
    let c0 = mask.blocks[0][last][0] + at_one(&mask.blocks[1][last]);
    let suffix = (index + 1..last).fold(K::from_i64(0), |s, j| {
        s + mask.blocks[0][j][0]
            + mask.blocks[0][j][1]
            + mask.blocks[1][j][0]
            + mask.blocks[1][j][1]
    });
    let half = K::from_i64(2).inverse().ok_or(Error::InvalidInstance)?;
    let scale = power_of_two::<K>(last - index - 1);
    for (g0, g1) in mask.blocks[0][index].iter().zip(&mask.blocks[1][index]) {
        out.push(scale * (prefix[0] + prefix[1] + *g0 + *g1 + c0 + suffix * half));
    }
    Ok(out)
}

/// Prove the masked instance with the mask bound by `binding` (A3 item 2);
/// returns the proof and the challenge point `ρ`.
pub fn prove<K: ChallengeField + Eq>(
    i: &Instance<K>,
    mut summand: impl Summand<K>,
    mask: &Mask<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<(Proof<K>, Vec<K>), Error> {
    let degree = shape(i)?;
    summand.validate_instance(i)?;
    let n = i.num_vars as usize;
    if mask.blocks.iter().any(|block| {
        block.len() != n
            || block
                .iter()
                .enumerate()
                .any(|(j, row)| row.len() != nodes(n, degree, j))
    }) {
        return Err(Error::ProofShape);
    }
    let mask_sum = mask.sum();
    let alpha = start(i, binding, mask_sum, t)?;
    let mut prefix = [K::from_i64(0); 2];
    let mut running = i.claimed_sum + alpha * mask_sum;
    let mut point = Vec::new();
    reserve(&mut point, n)?;
    let mut rounds = Vec::new();
    reserve(&mut rounds, n)?;
    for index in 0..n {
        let mut values = summand.round(i)?;
        if values.len() != degree + 1 {
            return Err(Error::ProofShape);
        }
        for (value, g) in values
            .iter_mut()
            .zip(mask_round(mask, index, prefix, degree)?)
        {
            *value = *value + alpha * g;
        }
        let payload = message_bytes(i.id, index as u32, &values)?;
        let (challenge, next) = round_payload(&values, running, &payload, t)?;
        summand.fold(challenge)?;
        for (b, block) in mask.blocks.iter().enumerate() {
            prefix[b] = prefix[b] + interpolate(&block[index], challenge)?;
        }
        point.push(challenge);
        running = next;
        rounds.push(values);
    }
    let final_values = summand.final_values()?;
    if final_values.len() != i.inputs.len() {
        return Err(Error::ProofShape);
    }
    // G(ρ) = (1 − ρ_n)·g⁰(ρ) + ρ_n·g¹(ρ).
    let last = *point.last().ok_or(Error::ProofShape)?;
    let mask_final = (K::from_i64(1) - last) * prefix[0] + last * prefix[1];
    finish(i, &final_values, mask_final, alpha, running, t)?;
    Ok((
        Proof {
            mask_sum,
            rounds,
            final_values,
            mask_final,
        },
        point,
    ))
}

/// Verify the masked reduction after the caller absorbed nothing of the mask:
/// `binding` must be the exact bytes the prover bound. The finals and `μ`
/// remain obligations; RFC-0013 A3's consumer discharges `μ` by an opening.
pub fn verify<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    binding: &[u8],
    t: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    let degree = shape(i)?;
    if proof.rounds.len() != i.num_vars as usize
        || proof.final_values.len() != i.inputs.len()
        || proof.rounds.iter().any(|r| r.len() != degree + 1)
    {
        return Err(Error::ProofShape);
    }
    let alpha = start(i, binding, proof.mask_sum, t)?;
    let mut running = i.claimed_sum + alpha * proof.mask_sum;
    let mut point = Vec::new();
    reserve(&mut point, proof.rounds.len())?;
    for (index, values) in proof.rounds.iter().enumerate() {
        let payload = message_bytes(i.id, index as u32, values)?;
        let (challenge, next) = round_payload(values, running, &payload, t)?;
        point.push(challenge);
        running = next;
    }
    finish(i, &proof.final_values, proof.mask_final, alpha, running, t)?;
    let mut claims = Vec::new();
    reserve(&mut claims, i.inputs.len())?;
    claims.extend(
        i.inputs
            .iter()
            .copied()
            .zip(proof.final_values.iter().copied()),
    );
    let field_degree = K::from_i64(0).to_le_bytes().as_ref().len() as u8 / 4;
    Ok(Reduction {
        reduction: crate::Reduction {
            point,
            claims,
            sc: ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: degree as u8,
                field_degree,
                numerator: u64::from(i.num_vars) * degree as u64,
            },
        },
        mask_final: proof.mask_final,
        mask: MaskRecord {
            id: i.id,
            field_degree,
        },
    })
}
