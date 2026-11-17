//! RFC-0026 §§2.3, 4, 9, A17/A18: composed identity, root and routing controls.
use crate::{
    check_control, check_proof_control, development::span_of, development_messages::fixtures,
    ProverHook,
};
use development::Error;
use stele_hash::{merkle, Transcript};
use stele_pcs::{verify_certificate, Error as PcsError};
use stele_prover::development::{
    self, container::Container, Layout, PlanData, Public, Statement, Weights,
};
use stele_reductions::relation::{self, Sources};
use stele_reductions::stele_cqis::{
    execution::Executor,
    model::{Model, Preparation, Scales},
};
use stele_reductions::stele_ir::relation::{check, ColumnId, Relation, Values, Violation};

fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

struct WitnessChange<'a>(&'a Relation);
impl ProverHook<Values> for WitnessChange<'_> {
    fn tamper(&self, values: &mut Values) {
        let id = ColumnId(19);
        let column = self.0.column(id).expect("identity witness");
        assert_eq!(column.name, "L0/norm1/S_0");
        assert_eq!((column.width.bits, column.width.signed), (8, false));
        let before = values.clone();
        let mut entries = values.get(self.0, id).expect("assigned column").to_vec();
        assert_eq!(entries[0], 0);
        entries[0] += 1;
        assert!(column.width.contains(entries[0]));
        values.set(self.0, id, entries.clone()).expect("one entry");
        entries[0] -= 1;
        let mut restored = values.clone();
        restored.set(self.0, id, entries).expect("restore entry");
        assert_eq!(restored, before, "only one witness entry changes");
        assert_eq!(
            check(self.0, values),
            Err(Violation::Identity {
                relation: "L0/norm1/S/0".into(),
                point: 0,
            })
        );
    }
}

struct Route;
impl ProverHook<Option<ColumnId>> for Route {
    fn tamper(&self, column: &mut Option<ColumnId>) {
        assert_eq!(*column, None);
        *column = Some(ColumnId(147));
    }
}

struct Root;
impl ProverHook<Container> for Root {
    fn tamper(&self, proof: &mut Container) {
        let before = proof.clone();
        let root: [u8; 32] = proof.multiplicities[0][..32].try_into().expect("root");
        assert_ne!(&proof.groups[0][..32], root);
        proof.groups[0][..32].copy_from_slice(&root);
        let mut restored = proof.clone();
        restored.groups[0][..32].copy_from_slice(&before.groups[0][..32]);
        assert!(restored == before, "only the stacked root changes (A17)");
    }
}

fn root(public: &Public, statement: &Statement, proof: &Container) -> Result<(), String> {
    let cause = if public.sources == Sources::Expander {
        PcsError::Merkle(merkle::Error::RootMismatch)
    } else {
        PcsError::Transcript(stele_hash::Error::GrindMismatch)
    };
    let expected = Error::Engine(relation::Error::Pcs(cause));
    check_proof_control(
        || Ok::<_, Error>(proof.clone()),
        &Root,
        |p| development::verify(public, statement, &p.encode()).map(|_| ()),
        expected.clone(),
    )
    .map_err(err)?;
    eprintln!(
        "NC-1306: T={} sources={:?} honest accepted, exact {expected:?}",
        statement.tokens.len(),
        public.sources
    );
    Ok(())
}

/// Check the named RFC-0026 identity, root or column claim on honest and tampered
/// L0/L1 window proofs; success requires the exact A17/A18 rejection for each profile.
pub fn run(id: u16) -> Result<(), String> {
    if ![1302, 1306, 1308].contains(&id) {
        return Err(format!("unknown binding control {id}"));
    }
    for f in fixtures()? {
        if id == 1306 {
            root(&f.public, &f.statement, &f.proof)?;
            // One legacy Policy-1 fixture per rung, using the same full statement.
            if f.profile != development::CIRCLE_ALL_PROFILE {
                continue;
            }
        }
        let model = Model::decode(&f.public.model).map_err(err)?;
        let prep = Preparation::decode(&model, &f.public.preparation).map_err(err)?;
        let scales = Scales::decode(&model, &f.public.scales).map_err(err)?;
        let artifact = span_of(f.case, "artifact")?;
        let aid = development::artifact_id(artifact);
        let mut executor =
            Executor::new(&model, &prep, &scales, artifact, &aid, 1 << 34).map_err(err)?;
        let sources = if id == 1306 {
            Sources::Expander
        } else {
            f.public.sources
        };
        let weights = Weights::from_artifact_sources(&model, artifact, sources).map_err(err)?;
        if id == 1306 {
            let committed = development::Committed::new(&weights).map_err(err)?;
            let public = Public {
                sources,
                commitment: committed.commitment.clone(),
                ..f.public.clone()
            };
            let bytes =
                development::prove(&public, &mut executor, &weights, &committed, &f.statement)
                    .map_err(err)?;
            root(
                &public,
                &f.statement,
                &development::container::decode(&bytes).map_err(err)?,
            )?;
            continue;
        }
        let layout = Layout::declare(
            &PlanData {
                model: &model,
                scales: &scales,
                vectors: &f.public.vectors,
                zk: false,
            },
            &f.statement,
        )
        .map_err(err)?;
        let values = layout
            .assign(
                &executor.capture(&f.statement.tokens).map_err(err)?,
                &weights.codes,
            )
            .map_err(err)?;
        let rel = &layout.relation;
        check(rel, &values).map_err(err)?;
        let layouts = relation::model_layout(rel, sources).map_err(err)?;
        let messages = relation::model_messages(rel, &values).map_err(err)?;
        let prepared = layouts
            .iter()
            .zip(&messages)
            .map(|(l, m)| sources.prepare(l.id, l.ell, &l.code, m))
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        assert_eq!(prepared.len(), f.public.commitment.len());
        let certificates = prepared
            .iter()
            .zip(&f.public.commitment)
            .map(|(p, (root, bytes))| {
                assert_eq!(p.source().root(), *root);
                verify_certificate(*p.source(), bytes)
                    .map(|(c, _)| c)
                    .map_err(|e| err(e.cause))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let model_sources = prepared.iter().zip(&certificates).collect::<Vec<_>>();
        let input = development::public_input(&f.public, &f.proof.cqis_id, &f.statement);
        let prove = |forge: relation::Forge| -> Result<Container, String> {
            let mut t = Transcript::<relation::K>::new(&input).map_err(err)?;
            let p = relation::prove_forged(&mut t, rel, &values, &model_sources, sources, &forge)
                .map_err(err)?;
            Ok(Container {
                cqis_id: f.proof.cqis_id,
                statement: f.proof.statement,
                groups: p.groups,
                multiplicities: p.multiplicities,
                identities: p.identities,
                lookups: p.lookups,
                matmuls: p.matmuls,
                openings: p.openings,
            })
        };
        let verify =
            |p: &Container| development::verify(&f.public, &f.statement, &p.encode()).map(|_| ());
        let expected = Error::Engine(relation::Error::Sumcheck(if id == 1302 {
            stele_sumcheck::Error::FinalEvaluationMismatch
        } else {
            stele_sumcheck::Error::RoundSumMismatch
        }));
        if id == 1302 {
            let hook = WitnessChange(rel);
            let mut changed = values.clone();
            hook.tamper(&mut changed);
            check_control(
                &values,
                &hook,
                |v| {
                    let witness = if v == &values {
                        None
                    } else {
                        assert_eq!(v, &changed);
                        Some((ColumnId(19), 0))
                    };
                    // The producer retains reference rounds, but commits and evaluates
                    // exactly this changed witness at their genuine challenge points.
                    let p = prove(relation::Forge {
                        witness,
                        ..Default::default()
                    })?;
                    if witness.is_some() {
                        assert_ne!(p.groups[0][..32], f.proof.groups[0][..32]);
                    } else {
                        assert!(p == f.proof, "ordinary producer bytes");
                    }
                    Ok::<_, String>(p)
                },
                verify,
                expected.clone(),
            )
            .map_err(err)?;
        } else {
            let selected = values.get(rel, ColumnId(147)).ok_or("selected column")?;
            assert_eq!(
                rel.column(ColumnId(147)).expect("selected").name,
                "L0/norm1/Z0"
            );
            assert_eq!(
                rel.column(ColumnId(148)).expect("adjacent").name,
                "L0/norm1/Z1"
            );
            assert!(selected.iter().all(|&v| v == 0));
            assert_eq!(Some(selected), values.get(rel, ColumnId(148)));
            check_control(
                &None,
                &Route,
                |&column_claim| {
                    // Forge asserts one changed Boolean prefix, fixed tail/value,
                    // next real column in this group, and restoration of all claims.
                    let p = prove(relation::Forge {
                        column_claim,
                        ..Default::default()
                    })?;
                    if column_claim.is_some() {
                        assert_ne!(p.openings, f.proof.openings);
                        let mut restored = p.clone();
                        restored.openings.clone_from(&f.proof.openings);
                        assert!(
                            restored == f.proof,
                            "only dependent opening sections change (A18)"
                        );
                    } else {
                        assert!(p == f.proof, "ordinary producer bytes");
                    }
                    Ok::<_, String>(p)
                },
                verify,
                expected.clone(),
            )
            .map_err(err)?;
        }
        eprintln!(
            "NC-{id}: T={} profile={} honest accepted, exact {expected:?}",
            f.statement.tokens.len(),
            f.profile
        );
    }
    Ok(())
}
