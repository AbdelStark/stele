//! The fraction tree and the selected-product leaf (RFC-0008 A3), the arithmetic of
//! LogUp's grand sum (task E8-02e).
//!
//! Provenance (ADR-128): written from the RFC-0008 A3 text and the Python reference
//! `research/logup-characteristic/fraction.py`, without `stele-lookup` open for this
//! piece. The author had read parts of `stele-lookup`'s tree accounting earlier, during
//! E8-05c, before ADR-128's rule. It is held to `research/logup-characteristic/
//! corpus.jsonl` and the production decisions recorded beside it.
//!
//! A tree over `2^m` pairs `(P, Q)` combines adjacent children,
//! `P = a·P0·Q1 + z·P1·Q0` and `Q = Q0·Q1`, with `(a, z) = (1 − θ_k, θ_k)` for
//! `k < m − b` and `(1, 1)` below. Its root is reduced layer by layer to one claim on
//! each original leaf column at a common point.

use crate::sumcheck::{self, bytes_of, Instance, Proof as A1, ScRecord, Term};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};

/// Why a tree, leaf or consumer was refused. A1 failures keep their own cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A descriptor outside A3 item 1 (`b ≤ m ≤ 63`, distinct leaf ids, `m − b` θ).
    TreeShape,
    /// A proof of the wrong length.
    ProofShape,
    /// A limb at or above p.
    NoncanonicalField,
    /// A layer's equality final differs from `eq(r, u)` (A3 item 3), or the leaf's.
    CoefficientMismatch,
    /// An original array's MLE differs from its claim.
    LeafMismatch,
    /// A root denominator is zero (A3 item 4).
    Pole,
    /// The two roots' fractions differ (A3 item 4).
    RootMismatch,
    /// The selector is not Boolean (A3 item 5).
    Selector,
    /// The selector's MLE differs from `p` or from the leaf's final (A3 item 5).
    SelectorMismatch,
    /// Leaf inputs of the wrong size or ids (A3 item 5).
    SourceShape,
    /// An original column's MLE differs from its leaf claim.
    SourceMismatch,
    /// A size does not fit in memory.
    Capacity,
    /// An A1 layer or leaf sumcheck failed.
    Sumcheck(sumcheck::Error),
    /// The transcript refused an operation.
    Transcript(stele_hash::Error),
}

impl From<sumcheck::Error> for Error {
    fn from(e: sumcheck::Error) -> Self {
        match e {
            sumcheck::Error::Capacity => Error::Capacity,
            e => Error::Sumcheck(e),
        }
    }
}

impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Error::Transcript(e)
    }
}

fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}

/// The verifier-owned tree descriptor (A3 item 1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor<K> {
    pub id: u64,
    pub m: u32,
    pub b: u32,
    /// The numerator and denominator leaf ids, distinct.
    pub leaves: [u64; 2],
    /// `m − b` weights, MSB-first.
    pub theta: Vec<K>,
}

/// A decoded tree proof: two roots, then per layer `k` its `k` A1 rows of four values
/// and five finals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K> {
    pub root: [K; 2],
    pub steps: Vec<A1<K>>,
}

/// A reduced tree: the point and the two leaf claims (numerator, denominator), with
/// the layer records.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "both leaf claims need a consumer"]
pub struct Reduction<K> {
    pub point: Vec<K>,
    pub values: [K; 2],
    pub ids: [u64; 2],
    pub layers: Vec<ScRecord>,
}

/// A reduced selected-product leaf: the point and one claim per original column.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "every original column claim needs a consumer"]
pub struct Leaf<K> {
    pub point: Vec<K>,
    pub claims: Vec<(u64, K)>,
    pub sc: ScRecord,
}

fn put<K: ChallengeField>(out: &mut Vec<u8>, values: &[K]) -> Result<(), Error> {
    let width = values.first().map_or(0, bytes_of);
    out.try_reserve(values.len() * width)
        .map_err(|_| Error::Capacity)?;
    for v in values {
        out.extend_from_slice(v.to_le_bytes().as_ref());
    }
    Ok(())
}

fn degree_of<K: ChallengeField>() -> u8 {
    (bytes_of(&K::from_i64(0)) / 4) as u8
}

impl<K: ChallengeField + Eq> Descriptor<K> {
    /// RFC-0008 A3: `u8 1, u8 field, u64 id, u32 m, u32 b, two u64 leaf ids`, then θ.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        // RFC-0008 A3 item 1: b ≤ m ≤ 63, distinct leaf ids, m − b weights.
        if self.b > self.m
            || self.m > 63
            || self.leaves[0] == self.leaves[1]
            || self.theta.len() != (self.m - self.b) as usize
        {
            return Err(Error::TreeShape);
        }
        let mut out = reserved(34)?;
        out.extend_from_slice(&[1, degree_of::<K>()]);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.b.to_le_bytes());
        out.extend_from_slice(&self.leaves[0].to_le_bytes());
        out.extend_from_slice(&self.leaves[1].to_le_bytes());
        put(&mut out, &self.theta)?;
        Ok(out)
    }

    /// `(a, z)` of parent layer `k`: `(1 − θ_k, θ_k)` while θ lasts, then `(1, 1)`.
    fn weights(&self, k: usize) -> (K, K) {
        let one = K::from_i64(1);
        match self.theta.get(k) {
            Some(t) => (one - *t, *t),
            None => (one, one),
        }
    }
}

/// `count` canonical K values from `raw`; a length error is ProofShape.
fn values<K: ChallengeField>(raw: &[u8], count: usize) -> Result<Vec<K>, Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let width = bytes_of(&K::from_i64(0));
    if raw.len() != count.checked_mul(width).ok_or(Error::Capacity)? {
        return Err(Error::ProofShape);
    }
    let mut out = reserved(count)?;
    for c in raw.chunks_exact(width) {
        let bytes = K::Bytes::try_from(c).map_err(|_| Error::ProofShape)?;
        out.push(K::from_le_bytes(bytes).ok_or(Error::NoncanonicalField)?);
    }
    Ok(out)
}

impl<K: ChallengeField + Eq> Proof<K> {
    /// Decode against a validated descriptor: exactly `2 + 2m² + 3m` values (A3).
    pub fn decode(d: &Descriptor<K>, raw: &[u8]) -> Result<Self, Error>
    where
        K::Bytes: for<'a> TryFrom<&'a [u8]>,
    {
        d.encode()?;
        let m = d.m as usize;
        let count = 2 + 2 * m * m + 3 * m;
        let all = values::<K>(raw, count)?;
        let mut at = 2;
        let mut steps = reserved(m)?;
        for k in 0..m {
            let mut rounds = reserved(k)?;
            for _ in 0..k {
                rounds.push(all[at..at + 4].to_vec());
                at += 4;
            }
            steps.push(A1 {
                rounds,
                final_values: all[at..at + 5].to_vec(),
            });
            at += 5;
        }
        Ok(Proof {
            root: [all[0], all[1]],
            steps,
        })
    }
}

/// RFC-0008 A3 item 5: a selected-product leaf proof for `c ≥ 1` columns is exactly
/// `4m + c + 2` canonical values (`4d(4m + c + 2)` bytes): `m` rows of four, then the
/// `c + 2` finals.
pub fn decode_leaf<K: ChallengeField + Eq>(
    d: &Descriptor<K>,
    c: usize,
    raw: &[u8],
) -> Result<A1<K>, Error>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    d.encode()?;
    if c == 0 {
        return Err(Error::SourceShape);
    }
    let m = d.m as usize;
    let count = m
        .checked_mul(4)
        .and_then(|n| n.checked_add(c))
        .and_then(|n| n.checked_add(2))
        .ok_or(Error::Capacity)?;
    let all = values::<K>(raw, count)?;
    let mut rounds = reserved(m)?;
    for row in all[..4 * m].chunks_exact(4) {
        rounds.push(row.to_vec());
    }
    Ok(A1 {
        rounds,
        final_values: all[4 * m..].to_vec(),
    })
}

/// `eq(r, u) = Π (r_i·u_i + (1 − r_i)(1 − u_i))`; lengths agree by construction.
fn eq<K: ChallengeField>(r: &[K], u: &[K]) -> K {
    let one = K::from_i64(1);
    r.iter()
        .zip(u)
        .fold(one, |acc, (x, y)| acc * (*x * *y + (one - *x) * (one - *y)))
}

/// The MLE of `table` at `point` (MSB-first, `sumcheck::mle_at`) once `table` has
/// exactly `2^len(point)` entries.
fn mle<K: ChallengeField>(table: &[K], point: &[K]) -> Result<K, Error> {
    let size = u32::try_from(point.len())
        .ok()
        .and_then(|n| 1usize.checked_shl(n))
        .ok_or(Error::SourceShape)?;
    if table.len() != size {
        return Err(Error::SourceShape);
    }
    Ok(sumcheck::mle_at(table, point))
}

/// RFC-0008 A3 items 2–3: reduce the tree's root to its two leaf claims.
pub fn verify<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    d: &Descriptor<K>,
    proof: &Proof<K>,
) -> Result<Reduction<K>, Error> {
    let descriptor = d.encode()?;
    // RFC-0008 A3: exactly m layers, layer k with k rows of four values and 5 finals.
    if proof.steps.len() != d.m as usize
        || proof.steps.iter().enumerate().any(|(k, s)| {
            s.rounds.len() != k
                || s.final_values.len() != 5
                || s.rounds.iter().any(|r| r.len() != 4)
        })
    {
        return Err(Error::ProofShape);
    }
    // RFC-0008 A3: the descriptor and both roots bind before any draw.
    let mut bound = descriptor;
    put(&mut bound, &proof.root)?;
    t.absorb(AbsorbLabel::Fraction, &bound)?;
    let (mut r, mut values): (Vec<K>, [K; 2]) = (reserved(d.m as usize)?, proof.root);
    let mut layers = reserved(d.m as usize)?;
    for (k, step) in proof.steps.iter().enumerate() {
        // RFC-0008 A3 item 2: bind tree id, k, r, p, q, then draw Gamma.
        let mut layer = reserved(12)?;
        layer.extend_from_slice(&d.id.to_le_bytes());
        layer.extend_from_slice(&(k as u32).to_le_bytes());
        put(&mut layer, &r)?;
        put(&mut layer, &values)?;
        t.absorb(AbsorbLabel::FractionLayer, &layer)?;
        let gamma = t.challenge(ChallengeLabel::FractionGamma)?;
        let (a, z) = d.weights(k);
        // Inputs P0, Q0, P1, Q1, Eq(r, ·): a·P0·Q1·Eq + z·P1·Q0·Eq + γ·Q0·Q1·Eq.
        let instance = Instance {
            id: k as u64,
            num_vars: k as u32,
            inputs: alloc::vec![0, 1, 2, 3, 4],
            terms: alloc::vec![
                Term {
                    coefficient: a,
                    factors: alloc::vec![0, 3, 4]
                },
                Term {
                    coefficient: z,
                    factors: alloc::vec![2, 1, 4]
                },
                Term {
                    coefficient: gamma,
                    factors: alloc::vec![1, 3, 4]
                },
            ],
            claimed_sum: values[0] + gamma * values[1],
        };
        let reduced = sumcheck::verify(&instance, step, t)?;
        layers.push(reduced.sc);
        let f = &step.final_values;
        // RFC-0008 A3 item 3: the equality final is exactly eq(r, u).
        if f[4] != eq(&r, &reduced.point) {
            return Err(Error::CoefficientMismatch);
        }
        let tau = t.challenge(ChallengeLabel::FractionFold)?;
        let blend = |x: K, y: K| x + tau * (y - x);
        values = [blend(f[0], f[2]), blend(f[1], f[3])];
        r = reduced.point;
        r.try_reserve(1).map_err(|_| Error::Capacity)?;
        r.push(tau);
    }
    Ok(Reduction {
        point: r,
        values,
        ids: d.leaves,
        layers,
    })
}

/// The public original-array consumer: each leaf column's MLE at the point equals
/// its claim (A3 item 3).
pub fn consume<K: ChallengeField + Eq>(
    result: &Reduction<K>,
    leaves: &[[K; 2]],
) -> Result<(), Error> {
    for side in 0..2 {
        let mut column = reserved(leaves.len())?;
        column.extend(leaves.iter().map(|pair| pair[side]));
        // RFC-0008 A3 item 3: the original arrays agree with the reduced claims.
        if mle(&column, &result.point)? != result.values[side] {
            return Err(Error::LeafMismatch);
        }
    }
    Ok(())
}

/// RFC-0008 A3 item 4: both denominators nonzero, then `p·b = a·q`.
pub fn root_equation<K: ChallengeField + Eq>(left: [K; 2], right: [K; 2]) -> Result<(), Error> {
    let zero = K::from_i64(0);
    if left[1] == zero || right[1] == zero {
        return Err(Error::Pole);
    }
    if left[0] * right[1] != right[0] * left[1] {
        return Err(Error::RootMismatch);
    }
    Ok(())
}

/// RFC-0008 A3 item 5: the selected-product leaf. `sigma` is the public Boolean
/// selector, `ids` the distinct original column ids (each at least 2), and `proof` an
/// A1 proof of `m` rows of four values and `c + 2` finals.
#[allow(clippy::too_many_arguments)]
pub fn verify_leaf<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    d: &Descriptor<K>,
    tree: &Reduction<K>,
    sigma: &[K],
    ids: &[u64],
    proof: &A1<K>,
    alpha: K,
    beta: K,
) -> Result<Leaf<K>, Error> {
    let descriptor = d.encode()?;
    let (zero, one) = (K::from_i64(0), K::from_i64(1));
    // RFC-0008 A3 item 5: a Boolean selector of 2^m entries.
    if sigma.len() != 1usize.checked_shl(d.m).ok_or(Error::SourceShape)? {
        return Err(Error::SourceShape);
    }
    if sigma.iter().any(|s| *s != zero && *s != one) {
        return Err(Error::Selector);
    }
    // RFC-0008 A3 item 5: the tree's own claims, and c > 0 distinct ids, each ≥ 2.
    let distinct = ids
        .iter()
        .enumerate()
        .all(|(n, i)| !ids[n + 1..].contains(i));
    if tree.ids != d.leaves
        || tree.point.len() != d.m as usize
        || ids.is_empty()
        || u32::try_from(ids.len()).is_err()
        || ids.iter().any(|i| *i < 2)
        || !distinct
    {
        return Err(Error::SourceShape);
    }
    let [p, q] = tree.values;
    // RFC-0008 A3 item 5: p is the selector's MLE at r.
    if p != mle(sigma, &tree.point)? {
        return Err(Error::SelectorMismatch);
    }
    let mut bound = descriptor;
    bound
        .try_reserve(4 + 8 * ids.len())
        .map_err(|_| Error::Capacity)?;
    bound.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for i in ids {
        bound.extend_from_slice(&i.to_le_bytes());
    }
    put(&mut bound, &[alpha, beta])?;
    put(&mut bound, &tree.point)?;
    put(&mut bound, &tree.values)?;
    t.absorb(AbsorbLabel::FractionLeaf, &bound)?;
    // H = 1 + (α − 1)·p − q, proved as Σ β^j·Eq(r, ·)·σ·x_j.
    let mut inputs = reserved(2 + ids.len())?;
    inputs.extend_from_slice(&[0, 1]);
    inputs.extend_from_slice(ids);
    let mut terms = reserved(ids.len())?;
    let mut power = one;
    for j in 0..ids.len() {
        terms.push(Term {
            coefficient: power,
            factors: alloc::vec![0, 1, (j + 2) as u32],
        });
        power = power * beta;
    }
    let instance = Instance {
        id: d.id,
        num_vars: d.m,
        inputs,
        terms,
        claimed_sum: one + (alpha - one) * p - q,
    };
    let reduced = sumcheck::verify(&instance, proof, t)?;
    let f = &proof.final_values;
    // RFC-0008 A3 item 5: the equality and selector finals, checked independently.
    if f[0] != eq(&tree.point, &reduced.point) {
        return Err(Error::CoefficientMismatch);
    }
    if f[1] != mle(sigma, &reduced.point)? {
        return Err(Error::SelectorMismatch);
    }
    let mut claims = reserved(ids.len())?;
    claims.extend(ids.iter().copied().zip(f[2..].iter().copied()));
    Ok(Leaf {
        point: reduced.point,
        claims,
        sc: reduced.sc,
    })
}

/// The public original-column consumer of a leaf: each column's MLE at the leaf
/// point equals its claim.
pub fn consume_sources<K: ChallengeField + Eq>(
    leaf: &Leaf<K>,
    ids: &[u64],
    columns: &[Vec<K>],
) -> Result<(), Error> {
    // RFC-0008 A3 item 5: one column per claim, in id order.
    if columns.len() != ids.len() || leaf.claims.iter().map(|(i, _)| *i).ne(ids.iter().copied()) {
        return Err(Error::SourceShape);
    }
    for (column, (_, value)) in columns.iter().zip(&leaf.claims) {
        if mle(column, &leaf.point)? != *value {
            return Err(Error::SourceMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_field::{Field, QM31};

    fn descriptor() -> Descriptor<QM31> {
        Descriptor {
            id: 7,
            m: 1,
            b: 1,
            leaves: [100, 101],
            theta: alloc::vec![],
        }
    }

    /// RFC-0008 A3's exact proof length: one value more or fewer is ProofShape.
    #[test]
    fn rejects_proof_bytes_one_value_off() {
        let d = descriptor();
        // m = 1: 2 roots + one layer of 0 rows and 5 finals = 7 values of 16 bytes.
        let honest = alloc::vec![0u8; 7 * 16];
        assert!(Proof::decode(&d, &honest).is_ok());
        for len in [6 * 16, 8 * 16, 7 * 16 + 1] {
            assert_eq!(
                Proof::decode(&d, &alloc::vec![0u8; len]),
                Err(Error::ProofShape)
            );
        }
    }

    /// The decoded shape is re-checked: an extra layer, an extra row, a long row or a
    /// sixth final is ProofShape before any absorb.
    #[test]
    fn rejects_overlong_tree_proofs() {
        let d = descriptor();
        let zero = QM31::from_i64(0);
        let honest = || Proof {
            root: [zero, zero],
            steps: alloc::vec![A1 {
                rounds: alloc::vec![],
                final_values: alloc::vec![zero; 5],
            }],
        };
        let mut long = [honest(), honest(), honest(), honest()];
        // A well-formed layer k = 1 (one row of four), so only the layer count is off.
        long[0].steps.push(A1 {
            rounds: alloc::vec![alloc::vec![zero; 4]],
            final_values: alloc::vec![zero; 5],
        });
        long[1].steps[0].rounds.push(alloc::vec![zero; 4]);
        long[2].steps[0].final_values.push(zero);
        long[3].steps[0].final_values.pop();
        for proof in long {
            let mut t = Transcript::new(b"stele/test/fraction-shape").expect("transcript");
            assert_eq!(
                verify(&mut t, &d, &proof).map(|_| ()),
                Err(Error::ProofShape)
            );
        }
    }

    /// RFC-0008 A3 item 3: finals that satisfy A1 but whose equality final is not
    /// eq(r, u) are refused. With m = 1 the point is empty, so eq = 1; finals
    /// (1, 1, 1, 1, e) and roots (2e, e) satisfy a·P0·Q1·E + z·P1·Q0·E + γ·Q0·Q1·E =
    /// p + γq for every γ.
    #[test]
    fn rejects_an_equality_final_other_than_eq() {
        let d = descriptor();
        let at = |e: i64| {
            let (one, e) = (QM31::from_i64(1), QM31::from_i64(e));
            let proof = Proof {
                root: [e + e, e],
                steps: alloc::vec![A1 {
                    rounds: alloc::vec![],
                    final_values: alloc::vec![one, one, one, one, e],
                }],
            };
            let mut t = Transcript::new(b"stele/test/fraction-eq").expect("transcript");
            verify(&mut t, &d, &proof).map(|_| ())
        };
        assert_eq!(at(1), Ok(()));
        assert_eq!(at(2), Err(Error::CoefficientMismatch));
    }

    #[test]
    fn rejects_bad_descriptors() {
        let d = descriptor();
        for bad in [
            Descriptor { b: 2, ..d.clone() },
            Descriptor {
                m: 64,
                b: 64,
                ..d.clone()
            },
            Descriptor {
                leaves: [5, 5],
                ..d.clone()
            },
            // m − b weights: one too many for b = m.
            Descriptor {
                theta: alloc::vec![QM31::from_i64(3)],
                ..d.clone()
            },
        ] {
            assert_eq!(bad.encode(), Err(Error::TreeShape));
        }
        // RFC-0008 A3 item 1 allows 0 ≤ b ≤ m: b = 0 with its one weight is accepted.
        let weighted = Descriptor {
            b: 0,
            theta: alloc::vec![QM31::from_i64(3)],
            ..d
        };
        assert!(weighted.encode().is_ok());
    }

    /// RFC-0008 A3 item 5: the leaf proof is exactly `4m + c + 2` values.
    #[test]
    fn decodes_leaf_proofs_of_exact_length() {
        let d = descriptor();
        // m = 1, c = 2: 4 + 2 + 2 = 8 values of 16 bytes.
        let leaf = decode_leaf(&d, 2, &[0u8; 8 * 16]).expect("leaf");
        assert_eq!((leaf.rounds.len(), leaf.final_values.len()), (1, 4));
        for len in [7 * 16, 9 * 16, 8 * 16 - 1] {
            assert_eq!(
                decode_leaf(&d, 2, &alloc::vec![0u8; len]),
                Err(Error::ProofShape)
            );
        }
        let mut limb = [0u8; 8 * 16];
        limb[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_leaf(&d, 2, &limb), Err(Error::NoncanonicalField));
        assert_eq!(decode_leaf(&d, 0, &[0u8; 6 * 16]), Err(Error::SourceShape));
    }

    /// m = 0, σ = [1], c = 1, α = 5, β = 3: the A1 proof has no rounds and finals
    /// (E, σ, x) = (1, 1, H) with H = 1 + (α − 1)p − q. A tree reduction with values
    /// (p, q) runs `verify_leaf` on a fresh transcript.
    fn leaf_at(sigma: QM31, p: QM31, q: QM31) -> Result<Leaf<QM31>, Error> {
        let d = Descriptor {
            id: 7,
            m: 0,
            b: 0,
            leaves: [100, 101],
            theta: alloc::vec![],
        };
        let k = QM31::from_i64;
        let (alpha, beta) = (k(5), k(3));
        let tree = Reduction {
            point: alloc::vec![],
            values: [p, q],
            ids: d.leaves,
            layers: alloc::vec![],
        };
        let h = k(1) + (alpha - k(1)) * p - q;
        let proof = A1 {
            rounds: alloc::vec![],
            final_values: alloc::vec![k(1), sigma, h],
        };
        let mut t = Transcript::new(b"stele/test/fraction-leaf").expect("transcript");
        verify_leaf(&mut t, &d, &tree, &[sigma], &[2], &proof, alpha, beta)
    }

    /// The leaf's A1 proves one combination of (p, q): (p + δ, q + (α − 1)δ) keeps H.
    /// Only the selector check `p = σ̃(r)` binds p, so the shifted claim must fail it.
    #[test]
    fn rejects_a_shifted_leaf_claim_with_an_unchanged_sum() {
        let k = QM31::from_i64;
        assert!(leaf_at(k(1), k(1), k(1)).is_ok());
        // δ = 1, α − 1 = 4: H is 1 + 4·2 − 5 = 4 = 1 + 4·1 − 1.
        assert_eq!(
            leaf_at(k(1), k(2), k(5)).map(|_| ()),
            Err(Error::SelectorMismatch)
        );
    }

    /// RFC-0008 A3 item 5: σ is Boolean; σ = [2] is Selector.
    #[test]
    fn rejects_a_non_boolean_selector() {
        let k = QM31::from_i64;
        assert_eq!(leaf_at(k(2), k(2), k(1)).map(|_| ()), Err(Error::Selector));
    }
}
