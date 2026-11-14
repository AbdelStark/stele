//! The A1 sumcheck verifier, RFC-0006 §§1–2 and A1 (task E8-02a).
//!
//! An independent re-implementation for the `no_std` verifier (RFC-0016 §3): it shares
//! no code with `stele-sumcheck`, only the protocol text and the transcript
//! (`stele-hash`). Parity is checked against the shared A1 corpus
//! (`research/sumcheck/corpus.jsonl`) and the decisions and receipts that the
//! production verifier records for it (`research/sumcheck/corpus-receipts.jsonl`).
//!
//! Every input is validated before the first absorb. Every failure is a typed
//! [`Error`], and the verifier never panics on any input.

use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// Why a reduction was refused. Names match RFC-0006's rejection causes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// More than four factors, a factor ordinal out of range, a repeated input id,
    /// or a count that does not fit the canonical encoding.
    InvalidInstance,
    /// An A2 batch descriptor that is empty, repeats an id, or shares an input
    /// across instances of different sizes (E8-02b).
    InvalidBatch,
    /// An A3 zerocheck whose skip, degree or claimed sum is out of its rules (E8-02b).
    InvalidZerocheck,
    /// Round count, round width or final-value count differs from the instance.
    ProofShape,
    /// Public tables differ in count or size from the instance.
    PublicShape,
    /// `g_i(0) + g_i(1)` differs from the running claim.
    RoundSumMismatch,
    /// The polynomial at the final values differs from the last running claim.
    FinalEvaluationMismatch,
    /// A public table's evaluation at the point differs from its final value.
    ClaimMismatch,
    /// A size does not fit in memory or in the encoding.
    Capacity,
    /// The transcript refused an operation.
    Transcript(stele_hash::Error),
}

impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Error::Transcript(e)
    }
}

/// One product term: `coefficient · Π inputs[factors]`; at most four factors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Term<K> {
    pub coefficient: K,
    pub factors: Vec<u32>,
}

/// The verifier-owned polynomial `P` over `num_vars` Boolean variables and its
/// claimed hypercube sum. It is never read from a proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instance<K> {
    pub id: u64,
    pub num_vars: u32,
    /// Distinct tensor ids, in order.
    pub inputs: Vec<u64>,
    pub terms: Vec<Term<K>>,
    pub claimed_sum: K,
}

/// A1 proof: `num_vars` rounds of `degree + 1` evaluations at `0..=degree`, then one
/// final value per input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    pub rounds: Vec<Vec<K>>,
    pub final_values: Vec<K>,
}

/// The SC record `m·δ / p^d` of one verified instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScRecord {
    pub id: u64,
    pub m: u32,
    pub degree: u8,
    pub field_degree: u8,
    pub numerator: u64,
}

/// A verified reduction: the point and one `(input id, value)` claim per input,
/// which a consumer must still discharge.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "every claim needs a consumer"]
pub struct Reduction<K> {
    pub point: Vec<K>,
    pub claims: Vec<(u64, K)>,
    pub sc: ScRecord,
}

pub(crate) fn bytes_of<K: ChallengeField>(x: &K) -> usize {
    x.to_le_bytes().as_ref().len()
}

/// Checks the instance and returns its degree, the largest factor count.
pub(crate) fn degree<K: ChallengeField>(i: &Instance<K>) -> Result<usize, Error> {
    // RFC-0006 A1: input and term counts fit the u32 encoding.
    if u32::try_from(i.inputs.len()).is_err() || u32::try_from(i.terms.len()).is_err() {
        return Err(Error::InvalidInstance);
    }
    // RFC-0006 A1: input tensor ids are distinct.
    for (n, id) in i.inputs.iter().enumerate() {
        if i.inputs[n + 1..].contains(id) {
            return Err(Error::InvalidInstance);
        }
    }
    let mut d = 0;
    for t in &i.terms {
        // RFC-0006 A1: at most four factors, each an input ordinal.
        if t.factors.len() > 4 || t.factors.iter().any(|f| *f as usize >= i.inputs.len()) {
            return Err(Error::InvalidInstance);
        }
        d = d.max(t.factors.len());
    }
    Ok(d)
}

/// A growable byte buffer whose allocation failures are `Capacity`.
pub(crate) struct Bytes(pub(crate) Vec<u8>);

impl Bytes {
    pub(crate) fn with(size: usize) -> Result<Self, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        Ok(Bytes(v))
    }
    pub(crate) fn put(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
}

/// The canonical A1 instance payload (RFC-0006 A1): `u8 1`, `u8` field limbs / 4,
/// `u64 id`, `u32 num_vars`, `u8 degree`, `u32` input and term counts, the input
/// ids, each term (coefficient, `u8` factor count, `u32` ordinals), and the sum.
pub(crate) fn instance_bytes<K: ChallengeField>(
    i: &Instance<K>,
    degree: usize,
) -> Result<Vec<u8>, Error> {
    let k = bytes_of(&i.claimed_sum);
    let mut size = i
        .inputs
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_add(23 + k))
        .ok_or(Error::Capacity)?;
    for t in &i.terms {
        size = size
            .checked_add(k + 1 + 4 * t.factors.len())
            .ok_or(Error::Capacity)?;
    }
    let mut out = Bytes::with(size)?;
    // Version 1; field limb count over 4 (4 for QM31, 8 for OM31 = k / 4).
    out.put(&[1, (k / 4) as u8])
        .put(&i.id.to_le_bytes())
        .put(&i.num_vars.to_le_bytes())
        .put(&[degree as u8])
        .put(&(i.inputs.len() as u32).to_le_bytes())
        .put(&(i.terms.len() as u32).to_le_bytes());
    for id in &i.inputs {
        out.put(&id.to_le_bytes());
    }
    for t in &i.terms {
        out.put(t.coefficient.to_le_bytes().as_ref())
            .put(&[t.factors.len() as u8]);
        for f in &t.factors {
            out.put(&f.to_le_bytes());
        }
    }
    out.put(i.claimed_sum.to_le_bytes().as_ref());
    Ok(out.0)
}

/// A round or final message: `u64 id || u32 index || values`.
pub(crate) fn message<K: ChallengeField>(
    id: u64,
    index: u32,
    values: &[K],
) -> Result<Vec<u8>, Error> {
    let k = values.first().map_or(0, bytes_of);
    let size = values
        .len()
        .checked_mul(k)
        .and_then(|n| n.checked_add(12))
        .ok_or(Error::Capacity)?;
    let mut out = Bytes::with(size)?;
    out.put(&id.to_le_bytes()).put(&index.to_le_bytes());
    for v in values {
        out.put(v.to_le_bytes().as_ref());
    }
    Ok(out.0)
}

/// The degree-`n − 1` polynomial through `(j, values[j])`, `j = 0..n`, at `x`, by
/// Lagrange's formula over the field. `n` is at most 5 here; the field holds every
/// node difference, so no denominator is zero.
pub(crate) fn lagrange<K: ChallengeField>(values: &[K], x: K) -> Result<K, Error> {
    let n = values.len() as i64;
    let mut sum = K::from_i64(0);
    for (j, v) in (0i64..).zip(values) {
        let (mut num, mut den) = (K::from_i64(1), K::from_i64(1));
        for m in (0..n).filter(|m| *m != j) {
            num = num * (x - K::from_i64(m));
            den = den * K::from_i64(j - m);
        }
        sum = sum + *v * num * den.inverse().ok_or(Error::InvalidInstance)?;
    }
    Ok(sum)
}

/// `P` at the final values: `Σ_t coefficient_t · Π values[factors_t]`.
pub(crate) fn evaluate<K: ChallengeField>(i: &Instance<K>, values: &[K]) -> K {
    let mut sum = K::from_i64(0);
    for t in &i.terms {
        let mut product = t.coefficient;
        for f in &t.factors {
            product = product * values[*f as usize];
        }
        sum = sum + product;
    }
    sum
}

/// One A1 round: `g(0) + g(1)` must equal the running claim (a constant round has
/// the one node `g(0)` twice); absorb the round, draw `r`, and return `(r, g(r))`.
pub(crate) fn step<K: ChallengeField + Eq>(
    id: u64,
    index: u32,
    g: &[K],
    claim: K,
    t: &mut Transcript<K>,
) -> Result<(K, K), Error> {
    // RFC-0006 §1: g(0) + g(1) is the running claim.
    let at_one = if g.len() > 1 { g[1] } else { g[0] };
    if g[0] + at_one != claim {
        return Err(Error::RoundSumMismatch);
    }
    // RFC-0006 A1: the round message is absorbed, then r is drawn; g(r) is next.
    t.absorb(AbsorbLabel::Round, &message(id, index, g)?)?;
    let r = t.challenge(ChallengeLabel::Sumcheck)?;
    Ok((r, lagrange(g, r)?))
}

/// `Σ_x table[x]·eq(point, x)`: a public table's multilinear value at `point`.
pub(crate) fn mle_at<K: ChallengeField>(table: &[K], point: &[K]) -> K {
    // E8-02f1: a full table folds in O(2^n) with no allocation; the same sum.
    if u32::try_from(point.len())
        .ok()
        .and_then(|n| 1usize.checked_shl(n))
        == Some(table.len())
    {
        return fold(table, point);
    }
    let mut at = K::from_i64(0);
    for (x, entry) in table.iter().enumerate() {
        at = at + *entry * eq_at(point, x);
    }
    at
}

/// The MLE of a table of exactly `2^len(point)` entries: the first (most significant)
/// coordinate splits it into halves, `(1 − r)·low + r·high`.
fn fold<K: ChallengeField>(table: &[K], point: &[K]) -> K {
    match point.split_first() {
        None => table[0],
        Some((r, rest)) => {
            let (low, high) = table.split_at(table.len() / 2);
            let (a, b) = (fold(low, rest), fold(high, rest));
            a + *r * (b - a)
        }
    }
}

/// Verify one A1 reduction on `t`, which already holds everything absorbed before
/// it. The returned claims remain obligations.
pub fn verify<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    t: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    let d = degree(i)?;
    let m = usize::try_from(i.num_vars).map_err(|_| Error::Capacity)?;
    // RFC-0006 A1: exactly num_vars rounds of degree + 1 values and one final value per
    // input; a longer or shorter proof is refused before the first absorb.
    if proof.rounds.len() != m
        || proof.final_values.len() != i.inputs.len()
        || proof.rounds.iter().any(|r| r.len() != d + 1)
    {
        return Err(Error::ProofShape);
    }
    // RFC-0006 A1 / RFC-0012 A1: the instance is absorbed before any challenge.
    t.absorb(AbsorbLabel::Instance, &instance_bytes(i, d)?)?;
    let mut point = Vec::new();
    point.try_reserve_exact(m).map_err(|_| Error::Capacity)?;
    let mut claim = i.claimed_sum;
    for (index, g) in (0u32..).zip(&proof.rounds) {
        let r;
        (r, claim) = step(i.id, index, g, claim, t)?;
        point.push(r);
    }
    // RFC-0006 §1: P at the final values is the last running claim.
    if evaluate(i, &proof.final_values) != claim {
        return Err(Error::FinalEvaluationMismatch);
    }
    // RFC-0006 A1: the final values are absorbed before any later challenge.
    t.absorb(
        AbsorbLabel::Final,
        &message(i.id, i.inputs.len() as u32, &proof.final_values)?,
    )?;
    let mut claims = Vec::new();
    claims
        .try_reserve_exact(i.inputs.len())
        .map_err(|_| Error::Capacity)?;
    claims.extend(
        i.inputs
            .iter()
            .copied()
            .zip(proof.final_values.iter().copied()),
    );
    Ok(Reduction {
        point,
        claims,
        sc: ScRecord {
            id: i.id,
            m: i.num_vars,
            degree: d as u8,
            field_degree: (bytes_of(&i.claimed_sum) / 4) as u8,
            numerator: u64::from(i.num_vars) * d as u64,
        },
    })
}

/// `eq(point, x)` for the Boolean `x` with index `x`, the first coordinate being the
/// most significant bit.
pub(crate) fn eq_at<K: ChallengeField>(point: &[K], x: usize) -> K {
    let n = point.len();
    let mut w = K::from_i64(1);
    for (j, r) in point.iter().enumerate() {
        let bit = (x >> (n - 1 - j)) & 1 == 1;
        w = w * if bit { *r } else { K::from_i64(1) - *r };
    }
    w
}

/// [`verify`], then discharge every claim against the verifier's own public tables
/// (one per input, `2^num_vars` entries each), in input order.
pub fn verify_public<K: ChallengeField + Eq>(
    i: &Instance<K>,
    proof: &Proof<K>,
    tables: &[Vec<K>],
    t: &mut Transcript<K>,
) -> Result<Reduction<K>, Error> {
    degree(i)?;
    // RFC-0006 §2: one public table per input, each of exactly 2^num_vars entries.
    let sized = |n: usize| n.is_power_of_two() && n.trailing_zeros() == i.num_vars;
    if tables.len() != i.inputs.len() || tables.iter().any(|table| !sized(table.len())) {
        return Err(Error::PublicShape);
    }
    let reduction = verify(i, proof, t)?;
    for (table, (_, value)) in tables.iter().zip(&reduction.claims) {
        // RFC-0006 §2: each final value is its public table's MLE at the point.
        if mle_at(table, &reduction.point) != *value {
            return Err(Error::ClaimMismatch);
        }
    }
    Ok(reduction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    /// `P = x` over one variable with table `[3, 5]`: sum 8.
    fn instance() -> Instance<QM31> {
        Instance {
            id: 1,
            num_vars: 1,
            inputs: alloc::vec![11],
            terms: alloc::vec![Term {
                coefficient: QM31::from_i64(1),
                factors: alloc::vec![0],
            }],
            claimed_sum: QM31::from_i64(8),
        }
    }

    fn shape(proof: Proof<QM31>) -> Result<(), Error> {
        let mut t = Transcript::new(b"stele/test/a1-shape").expect("transcript");
        verify(&instance(), &proof, &mut t).map(|_| ())
    }

    fn v(x: i64) -> QM31 {
        QM31::from_i64(x)
    }

    /// The upper bounds of A1's shape (the corpus holds only short proofs).
    #[test]
    fn rejects_overlong_round_row() {
        let proof = Proof {
            rounds: alloc::vec![alloc::vec![v(3), v(5), v(0)]],
            final_values: alloc::vec![v(4)],
        };
        assert_eq!(shape(proof), Err(Error::ProofShape));
    }

    #[test]
    fn rejects_extra_round() {
        let proof = Proof {
            rounds: alloc::vec![alloc::vec![v(3), v(5)], alloc::vec![v(1), v(1)]],
            final_values: alloc::vec![v(4)],
        };
        assert_eq!(shape(proof), Err(Error::ProofShape));
    }

    #[test]
    fn rejects_extra_final() {
        let proof = Proof {
            rounds: alloc::vec![alloc::vec![v(3), v(5)]],
            final_values: alloc::vec![v(4), v(4)],
        };
        assert_eq!(shape(proof), Err(Error::ProofShape));
    }
}
