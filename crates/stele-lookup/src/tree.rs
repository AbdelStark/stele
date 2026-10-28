//! Conditional fraction tree and original public consumer, RFC-0008 A3.
//! c_sc/T_misc: linear tree/equality work; retained tree has 2N-1 pairs, plus
//! dense A1 copies, source, proof and coefficients. No intermediate commitment.
use super::{reserve, Descriptor, Error, Proof};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{Dense, Instance, ScRecord, Summand, Term};

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
impl<K: ChallengeField + Eq> Descriptor<K> {
    /// Build and reduce the dense tree; all returned original claims remain obligations.
    pub fn prove(
        &self,
        leaves: &[[K; 2]],
        t: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Reduction<K>), Error> {
        source(self, leaves)?;
        let mut levels = Vec::new();
        reserve(&mut levels, self.m as usize + 1)?;
        levels.push(owned(leaves)?);
        for k in (0..self.m as usize).rev() {
            let [a, b] = weights(self, k);
            let children = &levels[levels.len() - 1];
            let mut parents = Vec::new();
            reserve(&mut parents, children.len() / 2)?;
            for pair in children.chunks_exact(2) {
                let [p0, q0] = pair[0];
                let [p1, q1] = pair[1];
                parents.push([a * p0 * q1 + b * p1 * q0, q0 * q1]);
            }
            levels.push(parents);
        }
        levels.reverse();
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
                table.extend(children.chunks_exact(2).map(|pair| pair[side][column]));
                tables.push(table);
            }
            tables.push(stele_poly::eq_table(&point).map_err(|_| Error::Capacity)?);
            let mut next = Vec::new();
            reserve(&mut next, point.len())?;
            let strategy = Capture {
                dense: Dense::new(&i, tables)?,
                point: &mut next,
            };
            let step = stele_sumcheck::prove(&i, strategy, t)?;
            a.layers.push(ScRecord {
                id: i.id,
                m: i.num_vars,
                degree: 3,
                field_degree: K::DEGREE as u8,
                numerator: 3 * u64::from(i.num_vars),
            });
            (point, values) = advance(&point, next, &step.final_values, t, &mut a)?;
            steps.push(step);
        }
        Ok((Proof { root, steps }, result(self, point, values, a)))
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
