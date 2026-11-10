//! Masked A1 sumcheck, RFC-0013 A2 item 2 (labels RFC-0012 A17).
//!
//! The rounds run on `f + α·g` with `g = Σ g_i(X_i)`. The result keeps A1's
//! final obligations and adds the undischarged mask obligation `(ρ, g(ρ))`:
//! soundness holds only if `g` was bound before its sum (A2, design note R2).
use crate::{
    interpolate, message_bytes, reserve, round_payload, Error, Instance, ScRecord, Summand,
};
use alloc::vec::Vec;
use stele_hash::mask::{MaskStream, SUMCHECK_MASK};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// The prover's secret mask: `n` univariates, each by its values at `0..=δ`.
pub struct Mask<K> {
    rows: Vec<Vec<K>>,
}
impl<K: ChallengeField> Mask<K> {
    /// Derive the mask for one instance from a fresh secret seed (A2 item 2):
    /// `g_1` first, nodes ascending, each value `D` M31 elements in limb order.
    pub fn derive(seed: &[u8; 32], i: &Instance<K>) -> Result<Self, Error> {
        let degree = shape(i)?;
        let mut stream = MaskStream::new(seed, SUMCHECK_MASK, i.id);
        let mut rows = Vec::new();
        reserve(&mut rows, i.num_vars as usize)?;
        for _ in 0..i.num_vars {
            let mut row = Vec::new();
            reserve(&mut row, degree + 1)?;
            row.extend((0..=degree).map(|_| stream.element::<K>()));
            rows.push(row);
        }
        Ok(Self { rows })
    }
    /// `G = 2^{n-1}·Σ_i (g_i(0) + g_i(1))`, the sum of `g` over the cube.
    pub fn sum(&self) -> K {
        let ends = self
            .rows
            .iter()
            .fold(K::from_i64(0), |s, r| s + r[0] + r[1]);
        ends * power_of_two(self.rows.len() - 1)
    }
    /// `g(ρ) = Σ_i g_i(ρ_i)`; the value a consumer must later bind.
    pub fn evaluate(&self, point: &[K]) -> Result<K, Error> {
        if point.len() != self.rows.len() {
            return Err(Error::ProofShape);
        }
        self.rows
            .iter()
            .zip(point)
            .try_fold(K::from_i64(0), |s, (row, x)| Ok(s + interpolate(row, *x)?))
    }
}

/// Masked proof: `G`, the A1 rounds of `f + α·g`, the finals and `μ = g(ρ)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    /// The mask sum `G`, absorbed before `α`.
    pub mask_sum: K,
    /// Exactly `n` rows of `δ + 1` values at `0..=δ`.
    pub rounds: Vec<Vec<K>>,
    /// One value per ordered input tensor.
    pub final_values: Vec<K>,
    /// The mask final `μ = g(ρ)`.
    pub mask_final: K,
}

/// A1's reduction plus the mask obligation; neither is discharged here.
#[must_use = "every final claim and the mask obligation need a consumer"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reduction<K> {
    /// A1 claims at the shared point, with the unchanged SC record.
    pub reduction: crate::Reduction<K>,
    /// `μ`, claimed equal to `g(ρ)` at `reduction.point`; no consumer is admitted.
    pub mask_final: K,
}

fn shape<K: ChallengeField>(i: &Instance<K>) -> Result<usize, Error> {
    let degree = i.validate()?;
    // A2: n = 0 or δ = 0 would reveal g and add no masking.
    if i.num_vars == 0 || degree == 0 {
        return Err(Error::InvalidInstance);
    }
    Ok(degree)
}

fn power_of_two<K: ChallengeField>(exponent: usize) -> K {
    (0..exponent).fold(K::from_i64(1), |p, _| p + p)
}

/// Absorb the instance and `G`, then draw `α` (A2 steps 1–3).
fn start<K: ChallengeField>(
    i: &Instance<K>,
    mask_sum: K,
    t: &mut Transcript<K>,
) -> Result<K, Error> {
    t.absorb(AbsorbLabel::Instance, &i.encode()?)?;
    t.absorb(
        AbsorbLabel::ZkMaskSum,
        &message_bytes(i.id, 0, &[mask_sum])?,
    )?;
    Ok(t.challenge(ChallengeLabel::ZkMaskWeight)?)
}

/// Check `P(finals) + α·μ` and absorb `finals ‖ μ` at index `k + 1` (A2 step 5).
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

/// Prove the masked instance. The strategy supplies `f`'s rounds; the mask adds
/// `α·Γ_i(t)` with `Γ_i(t) = 2^{n-i}(g_i(t) + Σ_{j<i} g_j(ρ_j) + Σ_{j>i}(g_j(0)+g_j(1))/2)`.
pub fn prove<K: ChallengeField + Eq>(
    i: &Instance<K>,
    mut summand: impl Summand<K>,
    mask: &Mask<K>,
    t: &mut Transcript<K>,
) -> Result<Proof<K>, Error> {
    let degree = shape(i)?;
    summand.validate_instance(i)?;
    let n = i.num_vars as usize;
    if mask.rows.len() != n || mask.rows.iter().any(|r| r.len() != degree + 1) {
        return Err(Error::ProofShape);
    }
    let mask_sum = mask.sum();
    let alpha = start(i, mask_sum, t)?;
    let half = K::from_i64(2).inverse().ok_or(Error::InvalidInstance)?;
    let mut suffix = mask
        .rows
        .iter()
        .fold(K::from_i64(0), |s, r| s + r[0] + r[1]);
    let (mut prefix, mut running) = (K::from_i64(0), i.claimed_sum + alpha * mask_sum);
    let mut rounds = Vec::new();
    reserve(&mut rounds, n)?;
    for (index, row) in mask.rows.iter().enumerate() {
        suffix = suffix - row[0] - row[1];
        let scale = power_of_two::<K>(n - index - 1);
        let mut values = summand.round(i)?;
        if values.len() != degree + 1 {
            return Err(Error::ProofShape);
        }
        for (value, g) in values.iter_mut().zip(row) {
            *value = *value + alpha * scale * (*g + prefix + suffix * half);
        }
        let payload = message_bytes(i.id, index as u32, &values)?;
        let (challenge, next) = round_payload(&values, running, &payload, t)?;
        summand.fold(challenge)?;
        prefix = prefix + interpolate(row, challenge)?;
        running = next;
        rounds.push(values);
    }
    let final_values = summand.final_values()?;
    if final_values.len() != i.inputs.len() {
        return Err(Error::ProofShape);
    }
    finish(i, &final_values, prefix, alpha, running, t)?;
    Ok(Proof {
        mask_sum,
        rounds,
        final_values,
        mask_final: prefix,
    })
}

/// Verify the masked reduction; the finals and `μ` remain obligations.
pub fn verify<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    let degree = shape(i)?;
    if proof.rounds.len() != i.num_vars as usize
        || proof.final_values.len() != i.inputs.len()
        || proof.rounds.iter().any(|r| r.len() != degree + 1)
    {
        return Err(Error::ProofShape);
    }
    let alpha = start(i, proof.mask_sum, t)?;
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
    Ok(Reduction {
        reduction: crate::Reduction {
            point,
            claims,
            sc: ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: degree as u8,
                field_degree: K::from_i64(0).to_le_bytes().as_ref().len() as u8 / 4,
                numerator: u64::from(i.num_vars) * degree as u64,
            },
        },
        mask_final: proof.mask_final,
    })
}
