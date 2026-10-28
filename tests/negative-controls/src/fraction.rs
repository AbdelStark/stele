//! RFC-0008 A3: real fraction prover and unchanged original-array consumer.
use crate::{check_proof_control, ProverHook};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_lookup::fraction::{Descriptor, Error, Proof};
struct Change(u16);
impl<K: ChallengeField + Eq> ProverHook<Proof<K>> for Change {
    fn tamper(&self, proof: &mut Proof<K>) {
        let before = proof.clone();
        let value = match self.0 {
            406 => &mut proof.root[0],
            407 => &mut proof.steps[0].final_values[2],
            _ => &mut proof.steps[0].final_values[4],
        };
        *value = *value + K::from_i64(1);
        let scalars = |p: &Proof<K>| {
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
        assert_eq!(
            scalars(&before)
                .iter()
                .zip(scalars(proof))
                .filter(|(a, b)| **a != *b)
                .count(),
            1
        );
    }
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String> {
    let zero = K::from_i64(0);
    let d = Descriptor::new(41, 1, 1, [71, 72], &[]).map_err(|e| format!("{e:?}"))?;
    // Zero denominators make the P1 and Eq finals unused by A1; both still bind.
    let leaves = if id == 406 {
        vec![
            [K::from_i64(3), K::from_i64(1)],
            [K::from_i64(5), K::from_i64(1)],
        ]
    } else {
        vec![[zero, zero]; 2]
    };
    let transcript = || Transcript::<K>::new(b"fixed fraction originals").expect("transcript");
    check_proof_control(
        || d.prove(&leaves, &mut transcript()).map(|p| p.0),
        &Change(id),
        |p| d.verify_public(p, &leaves, &mut transcript()).map(|_| ()),
        match id {
            406 => Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
            407 => Error::LeafMismatch,
            _ => Error::CoefficientMismatch,
        },
    )
    .map_err(|e| format!("{e:?}"))
}
/// Execute each actual typed-rejection control in both extension fields.
pub fn run(id: u16) -> Result<(), String> {
    if !(406..=410).contains(&id) {
        return Err("unknown fraction control".into());
    }
    if id <= 408 {
        check::<QM31>(id)?;
        check::<OM31>(id)?;
    }
    if id == 409 {
        incoming_selector::<QM31>()?;
        incoming_selector::<OM31>()?;
    }
    if id >= 408 {
        selected::<QM31>(id)?;
        selected::<OM31>(id)?;
    }
    Ok(())
}
#[test]
fn rejects_fraction_tree_binding_tampers() {
    for id in [406, 407, 408, 409, 410] {
        run(id).expect("one-value real rejection");
    }
}

struct LeafChange(u16);
impl<K: ChallengeField + Eq + core::fmt::Debug> ProverHook<stele_sumcheck::Proof<K>>
    for LeafChange
{
    fn tamper(&self, p: &mut stele_sumcheck::Proof<K>) {
        let before = p.clone();
        let index = match self.0 {
            408 => 0,
            409 => 1,
            _ => 3,
        };
        p.final_values[index] = p.final_values[index] + K::from_i64(1);
        assert_eq!(before.rounds, p.rounds);
        assert_eq!(
            before
                .final_values
                .iter()
                .zip(&p.final_values)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
    }
}
fn selected<K: ChallengeField + Eq + core::fmt::Debug>(id: u16) -> Result<(), String> {
    use stele_lookup::fraction::{LeafDescriptor, SelectedProduct};
    let zero = K::from_i64(0);
    let one = K::from_i64(1);
    let alpha = K::from_i64(19);
    let d = Descriptor::new(43, 1, 1, [71, 72], &[]).map_err(|e| format!("{e:?}"))?;
    let sigma = vec![one; 2];
    let xs = vec![vec![zero; 2], vec![K::from_i64(7); 2]];
    let leaves = vec![[one, alpha]; 2];
    let context = b"fixed selected-product originals";
    let mut t = Transcript::new(context).expect("transcript");
    let (tree, original) = d.prove(&leaves, &mut t).map_err(|e| format!("{e:?}"))?;
    let shape = LeafDescriptor::new(&d, &[91, 92]).map_err(|e| format!("{e:?}"))?;
    let prover = SelectedProduct::new(shape, &original, &sigma, alpha, zero)
        .map_err(|e| format!("{e:?}"))?;
    check_proof_control(
        || prover.prove(&xs, &mut t).map(|p| p.0),
        &LeafChange(id),
        |p| {
            let mut t = Transcript::new(context)?;
            let original = d.verify(&tree, &mut t)?;
            SelectedProduct::new(shape, &original, &sigma, alpha, zero)?
                .verify_public(p, &xs, &mut t)
                .map(|_| ())
        },
        match id {
            408 => Error::CoefficientMismatch,
            409 => Error::SelectorMismatch,
            _ => Error::SourceMismatch,
        },
    )
    .map_err(|e| format!("{e:?}"))
}

struct IncomingSelector;
impl<K: ChallengeField + Eq> ProverHook<(Proof<K>, stele_sumcheck::Proof<K>)> for IncomingSelector {
    fn tamper(&self, p: &mut (Proof<K>, stele_sumcheck::Proof<K>)) {
        let selected = p.1.clone();
        Change(407).tamper(&mut p.0);
        assert!(p.1 == selected);
    }
}
fn incoming_selector<K: ChallengeField + Eq + core::fmt::Debug>() -> Result<(), String> {
    use stele_lookup::fraction::{LeafDescriptor, SelectedProduct};
    let one = K::from_i64(1);
    let alpha = K::from_i64(3);
    let zero = K::from_i64(0);
    let d = Descriptor::new(44, 1, 1, [71, 72], &[]).map_err(|e| format!("{e:?}"))?;
    let shape = LeafDescriptor::new(&d, &[91]).map_err(|e| format!("{e:?}"))?;
    let sigma = vec![one; 2];
    let xs = vec![vec![alpha; 2]];
    let leaves = vec![[one, zero]; 2];
    let context = b"incoming selector proof binding";
    check_proof_control(
        || {
            let mut t = Transcript::new(context)?;
            let (tree, r) = d.prove(&leaves, &mut t)?;
            let (leaf, _) =
                SelectedProduct::new(shape, &r, &sigma, alpha, zero)?.prove(&xs, &mut t)?;
            Ok::<_, Error>((tree, leaf))
        },
        &IncomingSelector,
        |(tree, leaf)| {
            let mut t = Transcript::new(context)?;
            let r = d.verify(tree, &mut t)?;
            SelectedProduct::new(shape, &r, &sigma, alpha, zero)?
                .verify_public(leaf, &xs, &mut t)
                .map(|_| ())
        },
        Error::SelectorMismatch,
    )
    .map_err(|e| format!("{e:?}"))
}
