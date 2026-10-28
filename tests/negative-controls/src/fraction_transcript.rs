//! RFC-0008 A3 / RFC-0012 A9: adversarial replay, unchanged production verifier.
//! Workflow 08: only the separate control derives a wrong-order replacement;
//! the hook changes one real proof value. No alternate verifier or state import.
use crate::{
    check_proof_control,
    sumcheck::{instance, produce},
    ProverHook,
};
use stele_field::{OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{
    Descriptor, Error, LeafDescriptor, Proof as TreeProof, SelectedProduct,
};
use stele_sumcheck::{message_bytes, Dense, Instance, Proof, Term};
const CONTEXT: &[u8] = b"fraction transcript controls fixed originals";
fn fields<K: ChallengeField>(values: &[K]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
        .collect()
}
fn fraction<K: ChallengeField>(
    d: &Descriptor<K>,
    root: [K; 2],
    t: &mut Transcript<K>,
) -> Result<(), Error> {
    let mut bytes = d.encode()?;
    bytes.extend(fields(&root));
    t.absorb(AbsorbLabel::Fraction, &bytes)?;
    Ok(())
}
fn layer<K: ChallengeField>(
    d: &Descriptor<K>,
    k: u32,
    r: &[K],
    v: [K; 2],
    t: &mut Transcript<K>,
    early: Option<K>,
) -> Result<Instance<K>, Error> {
    let mut values = r.to_vec();
    values.extend(v);
    t.absorb(
        AbsorbLabel::FractionLayer,
        &message_bytes(d.id(), k, &values)?,
    )?;
    let gamma = match early {
        Some(g) => g,
        None => t.challenge(ChallengeLabel::FractionGamma)?,
    };
    let one = K::from_i64(1);
    let (a, b) = d
        .theta()
        .get(k as usize)
        .map_or((one, one), |x| (one - *x, *x));
    Ok(Instance {
        id: u64::from(k),
        num_vars: k,
        inputs: vec![0, 1, 2, 3, 4],
        terms: vec![
            Term {
                coefficient: a,
                factors: vec![0, 3, 4],
            },
            Term {
                coefficient: b,
                factors: vec![2, 1, 4],
            },
            Term {
                coefficient: gamma,
                factors: vec![1, 3, 4],
            },
        ],
        claimed_sum: v[0] + gamma * v[1],
    })
}
// 0 is the exact-order reference; 1 moves Gamma before Fraction, 2 before Layer,
// 3 moves Fold between the scalar A1 Instance and Final. Only this control replays.
fn first_round<K: ChallengeField + Eq>(
    d: &Descriptor<K>,
    p: &TreeProof<K>,
    leaves: &[[K; 2]],
    timing: u8,
) -> Result<Proof<K>, Error> {
    let mut t = Transcript::new(CONTEXT)?;
    let before_fraction = if timing == 1 {
        Some(t.challenge(ChallengeLabel::FractionGamma)?)
    } else {
        None
    };
    fraction(d, p.root, &mut t)?;
    let early = if timing == 2 {
        Some(t.challenge(ChallengeLabel::FractionGamma)?)
    } else {
        before_fraction
    };
    let i = layer(d, 0, &[], p.root, &mut t, early)?;
    t.absorb(AbsorbLabel::Instance, &i.encode()?)?;
    let before_final = if timing == 3 {
        Some(t.challenge(ChallengeLabel::FractionFold)?)
    } else {
        None
    };
    t.absorb(
        AbsorbLabel::Final,
        &message_bytes(0, 5, &p.steps[0].final_values)?,
    )?;
    let tau = match before_final {
        Some(r) => r,
        None => t.challenge(ChallengeLabel::FractionFold)?,
    };
    let f = &p.steps[0].final_values;
    let v = [f[0] + tau * (f[2] - f[0]), f[1] + tau * (f[3] - f[1])];
    let i = layer(d, 1, &[tau], v, &mut t, None)?;
    let mut tables: Vec<Vec<K>> = [(0, 0), (0, 1), (1, 0), (1, 1)]
        .iter()
        .map(|(side, col)| vec![leaves[*side][*col], leaves[2 + *side][*col]])
        .collect();
    tables.push(vec![K::from_i64(1) - tau, tau]);
    Ok(stele_sumcheck::prove(&i, Dense::new(&i, tables)?, &mut t)?)
}
struct RoundChange<K>(K);
impl<K: ChallengeField + Eq> ProverHook<TreeProof<K>> for RoundChange<K> {
    fn tamper(&self, p: &mut TreeProof<K>) {
        let scalars = |p: &TreeProof<K>| {
            p.root
                .iter()
                .chain(
                    p.steps
                        .iter()
                        .flat_map(|s| s.rounds.iter().flatten().chain(&s.final_values)),
                )
                .copied()
                .collect::<Vec<_>>()
        };
        let before = scalars(p);
        p.steps[1].rounds[0][0] = self.0;
        let after = scalars(p);
        assert_eq!(before.len(), after.len());
        assert_eq!(before.iter().zip(&after).filter(|(a, b)| a != b).count(), 1);
    }
}
fn order<K: ChallengeField + Eq + core::fmt::Debug>() -> Result<(), String> {
    for weighted in [false, true] {
        let theta = if weighted {
            vec![K::from_i64(7)]
        } else {
            vec![]
        };
        let d = Descriptor::new(86, 2, if weighted { 1 } else { 2 }, [71, 72], &theta)
            .map_err(|e| format!("{e:?}"))?;
        let leaves: Vec<_> = [[2, 3], [5, 7], [11, 13], [17, 19]]
            .map(|p| p.map(K::from_i64))
            .to_vec();
        let honest = || {
            d.prove(&leaves, &mut Transcript::new(CONTEXT)?)
                .map(|p| p.0)
        };
        let baseline = honest().map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            first_round(&d, &baseline, &leaves, 0).map_err(|e| format!("{e:?}"))?,
            baseline.steps[1]
        );
        for timing in 1..=3 {
            let wrong =
                first_round(&d, &baseline, &leaves, timing).map_err(|e| format!("{e:?}"))?;
            check_proof_control(
                honest,
                &RoundChange(wrong.rounds[0][0]),
                |p| {
                    d.verify_public(p, &leaves, &mut Transcript::new(CONTEXT)?)
                        .map(|_| ())
                },
                Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch),
            )
            .map_err(|e| format!("{e:?}"))?;
        }
    }
    Ok(())
}
/// NC-0411: both fields, ordinary/weighted trees, all three wrong-order placements.
pub fn run_order() -> Result<(), String> {
    order::<QM31>()?;
    order::<OM31>()
}
#[test]
fn rejects_fraction_challenge_order_tampers() {
    run_order().expect("exact real verifier rejection");
}

#[derive(Clone, PartialEq, Eq)]
struct Chain<K: ChallengeField> {
    tree: TreeProof<K>,
    leaf: Option<Proof<K>>,
    next: Proof<K>,
}
struct NextChange<K>(K);
impl<K: ChallengeField + Eq> ProverHook<Chain<K>> for NextChange<K> {
    fn tamper(&self, p: &mut Chain<K>) {
        let before = p.clone();
        p.next.final_values[0] = self.0;
        assert!(
            p.tree == before.tree && p.leaf == before.leaf && p.next.rounds == before.next.rounds
        );
        assert_eq!(
            p.next
                .final_values
                .iter()
                .zip(&before.next.final_values)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
    }
}
fn continuation<K: ChallengeField + Eq + core::fmt::Debug>(selected: bool) -> Result<(), String> {
    let one = K::from_i64(1);
    let zero = K::from_i64(0);
    let alpha = K::from_i64(19);
    let d = Descriptor::new(87, 1, 1, [71, 72], &[]).map_err(|e| format!("{e:?}"))?;
    let shape = LeafDescriptor::new(&d, &[91, 92]).map_err(|e| format!("{e:?}"))?;
    let sigma = vec![one, zero];
    let xs = vec![
        vec![K::from_i64(3), K::from_i64(5)],
        vec![K::from_i64(7), K::from_i64(11)],
    ];
    let leaves = if selected {
        vec![[one, alpha - K::from_i64(3)], [zero, one]]
    } else {
        vec![[K::from_i64(3), one], [K::from_i64(5), one]]
    };
    let next = instance(88, false);
    let honest = || -> Result<Chain<K>, Error> {
        let mut t = Transcript::new(CONTEXT)?;
        let (tree, r) = d.prove(&leaves, &mut t)?;
        let leaf = if selected {
            Some(
                SelectedProduct::new(shape, &r, &sigma, alpha, zero)?
                    .prove(&xs, &mut t)?
                    .0,
            )
        } else {
            None
        };
        Ok(Chain {
            tree,
            leaf,
            next: produce(&next, &mut t)?,
        })
    };
    let baseline = honest().map_err(|e| format!("{e:?}"))?;
    let replay = |omit: bool| -> Result<Proof<K>, Error> {
        let mut t = Transcript::new(CONTEXT)?;
        if let Some(leaf) = &baseline.leaf {
            let (_, r) = d.prove(&leaves, &mut t)?;
            let mut payload = d.encode()?;
            payload.extend(2u32.to_le_bytes());
            for id in shape.source_ids() {
                payload.extend(id.to_le_bytes());
            }
            payload.extend(fields(&[alpha, zero]));
            payload.extend(fields(&r.point));
            payload.extend(fields(&r.claims.map(|c| c.1)));
            t.absorb(AbsorbLabel::FractionLeaf, &payload)?;
            let i = Instance {
                id: d.id(),
                num_vars: 1,
                inputs: vec![0, 1, 91, 92],
                terms: vec![
                    Term {
                        coefficient: one,
                        factors: vec![0, 1, 2],
                    },
                    Term {
                        coefficient: zero,
                        factors: vec![0, 1, 3],
                    },
                ],
                claimed_sum: one + (alpha - one) * r.claims[0].1 - r.claims[1].1,
            };
            t.absorb(AbsorbLabel::Instance, &i.encode()?)?;
            for (k, row) in leaf.rounds.iter().enumerate() {
                t.absorb(AbsorbLabel::Round, &message_bytes(i.id, k as u32, row)?)?;
                t.challenge(ChallengeLabel::Sumcheck)?;
            }
            // Omit only the selected-product A1 Final before the following instance.
            if !omit {
                t.absorb(
                    AbsorbLabel::Final,
                    &message_bytes(i.id, i.inputs.len() as u32, &leaf.final_values)?,
                )?;
            }
        } else {
            fraction(&d, baseline.tree.root, &mut t)?;
            let i = layer(&d, 0, &[], baseline.tree.root, &mut t, None)?;
            t.absorb(AbsorbLabel::Instance, &i.encode()?)?;
            // Omit only the tree's scalar A1 Final, then retain its required Fold.
            if !omit {
                t.absorb(
                    AbsorbLabel::Final,
                    &message_bytes(i.id, 5, &baseline.tree.steps[0].final_values)?,
                )?;
            }
            t.challenge(ChallengeLabel::FractionFold)?;
        }
        Ok(produce(&next, &mut t)?)
    };
    assert_eq!(replay(false).map_err(|e| format!("{e:?}"))?, baseline.next);
    let wrong = replay(true).map_err(|e| format!("{e:?}"))?;
    assert_eq!(wrong.rounds, baseline.next.rounds);
    check_proof_control(
        honest,
        &NextChange(wrong.final_values[0]),
        |p| {
            let mut t = Transcript::new(CONTEXT)?;
            if let Some(leaf) = &p.leaf {
                let r = d.verify(&p.tree, &mut t)?;
                let _ = SelectedProduct::new(shape, &r, &sigma, alpha, zero)?
                    .verify_public(leaf, &xs, &mut t)?;
            } else {
                let _ = d.verify_public(&p.tree, &leaves, &mut t)?;
            }
            let _ = stele_sumcheck::verify_public(
                &next,
                &p.next,
                &[vec![K::from_i64(3), K::from_i64(5)]],
                &mut t,
            )?;
            Ok::<_, Error>(())
        },
        Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}
/// NC-0802 extension: missing tree/selected-product Final affects the next real proof.
pub fn run_continuation() -> Result<(), String> {
    for selected in [false, true] {
        continuation::<QM31>(selected)?;
        continuation::<OM31>(selected)?;
    }
    Ok(())
}
#[test]
fn rejects_fraction_missing_final_continuations() {
    run_continuation().expect("exact next-instance rejection");
}
