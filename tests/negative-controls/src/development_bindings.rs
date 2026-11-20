//! RFC-0026 §§2.3, 4, 9, A17/A18: composed identity, root and routing controls.
use crate::{
    check_control, check_proof_control,
    development::span_of,
    development_messages::{
        encode_decoded, fixtures, header_of, seg0_groups, seg0_groups_mut, seg0_multiplicities,
    },
    ProverHook,
};
use development::Error;
use stele_hash::{merkle, Transcript};
use stele_pcs::{verify_certificate, Error as PcsError};
use stele_prover::development::{
    self,
    container::{self, Container, ContainerV2, Decoded, SegmentSections},
    Layout, PlanData, Public, Statement, Weights,
};
use stele_reductions::relation::{self, Sources};
use stele_reductions::stele_cqis::{
    execution::Executor,
    model::{Model, Preparation, Scales},
};
use stele_reductions::stele_ir::relation::{check, ColumnId, Kind, Relation, Values, Violation};

fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

/// Find a committed witness column read directly by an explicit identity whose entry 0
/// can be bumped by +1 within width and violates that identity.
fn pick_identity_witness(rel: &Relation, values: &Values) -> Result<(ColumnId, usize), String> {
    for (i, col) in rel.columns.iter().enumerate() {
        let id = ColumnId(i as u32);
        if !matches!(col.kind, Kind::Witness(_)) {
            continue;
        }
        let in_identity = rel.identities.iter().any(|idn| {
            idn.terms
                .iter()
                .any(|t| t.factors.iter().any(|f| f.column == id))
        });
        if !in_identity {
            continue;
        }
        let Some(entries) = values.get(rel, id) else {
            continue;
        };
        if let Some(j) = entries.iter().position(|&v| col.width.contains(v + 1)) {
            let mut mutated = values.clone();
            let mut e = entries.to_vec();
            e[j] += 1;
            mutated.set(rel, id, e).map_err(err)?;
            if matches!(check(rel, &mutated), Err(Violation::Identity { .. })) {
                return Ok((id, j));
            }
        }
    }
    Err("no suitable identity witness column found for NC-1302".into())
}

/// Find two adjacent committed witness columns `(col, next)` in the same commitment group
/// with identical values where `col` is referenced so it receives at least one claim.
fn pick_adjacent_equal_pair(
    rel: &Relation,
    values: &Values,
) -> Result<(ColumnId, ColumnId), String> {
    let mut groups: Vec<Vec<ColumnId>> = vec![Vec::new(); rel.groups.len()];
    for (i, col) in rel.columns.iter().enumerate() {
        if let Kind::Witness(g) = col.kind {
            groups[g.0 as usize].push(ColumnId(i as u32));
        }
    }
    let referenced = |id: ColumnId| {
        rel.identities.iter().any(|idn| {
            idn.terms
                .iter()
                .any(|t| t.factors.iter().any(|f| f.column == id))
        }) || rel
            .matmuls
            .iter()
            .any(|m| m.out.column == id || m.lhs.column == id || m.rhs.column == id)
            || rel.lookups.iter().any(|l| {
                l.tuple.iter().any(|r| r.column == id)
                    || l.selector.as_ref().is_some_and(|s| s.column == id)
            })
            || rel.ranges.iter().any(|r| r.column == id)
            || rel.columns.iter().any(|c| match &c.kind {
                Kind::Virtual(def) => def.operands().contains(&id),
                _ => false,
            })
    };
    for cols in groups {
        for pair in cols.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if referenced(a) && values.get(rel, a) == values.get(rel, b) {
                return Ok((a, b));
            }
        }
    }
    Err("no adjacent identical committed columns found for NC-1308".into())
}

struct WitnessChange<'a> {
    rel: &'a Relation,
    id: ColumnId,
    entry: usize,
}
impl ProverHook<Values> for WitnessChange<'_> {
    fn tamper(&self, values: &mut Values) {
        let column = self.rel.column(self.id).expect("identity witness");
        let before = values.clone();
        let mut entries = values
            .get(self.rel, self.id)
            .expect("assigned column")
            .to_vec();
        entries[self.entry] += 1;
        assert!(column.width.contains(entries[self.entry]));
        values
            .set(self.rel, self.id, entries.clone())
            .expect("one entry");
        entries[self.entry] -= 1;
        let mut restored = values.clone();
        restored
            .set(self.rel, self.id, entries)
            .expect("restore entry");
        assert_eq!(restored, before, "only one witness entry changes");
        assert!(matches!(
            check(self.rel, values),
            Err(Violation::Identity { .. })
        ));
    }
}

struct Route(ColumnId);
impl ProverHook<Option<ColumnId>> for Route {
    fn tamper(&self, column: &mut Option<ColumnId>) {
        assert_eq!(*column, None);
        *column = Some(self.0);
    }
}

struct Root;
impl ProverHook<Decoded> for Root {
    fn tamper(&self, proof: &mut Decoded) {
        let before = proof.clone();
        let root: [u8; 32] = seg0_multiplicities(proof)[0][..32]
            .try_into()
            .expect("root");
        assert_ne!(&seg0_groups(proof)[0][..32], root);
        seg0_groups_mut(proof)[0][..32].copy_from_slice(&root);
        let mut restored = proof.clone();
        seg0_groups_mut(&mut restored)[0][..32].copy_from_slice(&seg0_groups(&before)[0][..32]);
        assert!(restored == before, "only the stacked root changes (A17)");
    }
}

fn root(public: &Public, statement: &Statement, proof: &Decoded) -> Result<(), String> {
    let cause = if public.sources == Sources::Expander {
        PcsError::Merkle(merkle::Error::RootMismatch)
    } else {
        PcsError::Transcript(stele_hash::Error::GrindMismatch)
    };
    let expected = Error::Engine(relation::Error::Pcs(cause));
    check_proof_control(
        || Ok::<_, Error>(proof.clone()),
        &Root,
        |p| development::verify(public, statement, &encode_decoded(p)).map(|_| ()),
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
                &container::decode_any(&bytes).map_err(err)?,
            )?;
            continue;
        }
        let layout = Layout::declare(
            &PlanData {
                model: &model,
                scales: &scales,
                vectors: &f.public.vectors,
                zk: false,
                segment_layers: 0,
            },
            &f.statement,
        )
        .map_err(err)?;
        let values = layout
            .assign(
                &executor.capture(&f.statement.tokens).map_err(err)?,
                &weights,
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
        let (cqis_id, statement_digest) = header_of(&f.proof);
        let input = development::public_input(&f.public, &cqis_id, &f.statement);
        let prove = |forge: relation::Forge| -> Result<Decoded, String> {
            let mut t = Transcript::<relation::K>::new(&input).map_err(err)?;
            if rel.has_virtual() || rel.is_segmented() {
                let p = relation::prove_segmented_forged(
                    &mut t,
                    rel,
                    &values,
                    &model_sources,
                    sources,
                    &forge,
                )
                .map_err(err)?;
                Ok(Decoded::V2(ContainerV2 {
                    cqis_id,
                    statement: statement_digest,
                    segments: p
                        .segments
                        .into_iter()
                        .map(|s| SegmentSections {
                            groups: s.groups,
                            multiplicities: s.multiplicities,
                            identities: s.identities,
                            lookups: s.lookups,
                            matmuls: s.matmuls,
                            reductions: s.reductions,
                            openings: s.openings,
                        })
                        .collect(),
                    model_openings: p.model_openings,
                }))
            } else {
                let p =
                    relation::prove_forged(&mut t, rel, &values, &model_sources, sources, &forge)
                        .map_err(err)?;
                Ok(Decoded::V1(Container {
                    cqis_id,
                    statement: statement_digest,
                    groups: p.groups,
                    multiplicities: p.multiplicities,
                    identities: p.identities,
                    lookups: p.lookups,
                    matmuls: p.matmuls,
                    openings: p.openings,
                }))
            }
        };
        let verify = |p: &Decoded| {
            development::verify(&f.public, &f.statement, &encode_decoded(p)).map(|_| ())
        };
        let expected = Error::Engine(relation::Error::Sumcheck(if id == 1302 {
            stele_sumcheck::Error::FinalEvaluationMismatch
        } else {
            stele_sumcheck::Error::RoundSumMismatch
        }));
        if id == 1302 {
            let (col_id, entry) = pick_identity_witness(rel, &values)?;
            let hook = WitnessChange {
                rel,
                id: col_id,
                entry,
            };
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
                        Some((col_id, entry))
                    };
                    // The producer retains reference rounds, but commits and evaluates
                    // exactly this changed witness at their genuine challenge points.
                    let p = prove(relation::Forge {
                        witness,
                        ..Default::default()
                    })?;
                    if witness.is_some() {
                        assert_ne!(seg0_groups(&p)[0][..32], seg0_groups(&f.proof)[0][..32]);
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
            let (col_a, col_b) = pick_adjacent_equal_pair(rel, &values)?;
            assert_eq!(values.get(rel, col_a), values.get(rel, col_b));
            check_control(
                &None,
                &Route(col_a),
                |&column_claim| {
                    // Forge asserts one changed Boolean prefix, fixed tail/value,
                    // next real column in this group, and restoration of all claims.
                    let p = prove(relation::Forge {
                        column_claim,
                        ..Default::default()
                    })?;
                    if column_claim.is_some() {
                        match (&p, &f.proof) {
                            (Decoded::V1(a), Decoded::V1(b)) => {
                                assert_ne!(a.openings, b.openings);
                                let mut restored = a.clone();
                                restored.openings.clone_from(&b.openings);
                                assert!(
                                    restored == *b,
                                    "only dependent opening sections change (A18)"
                                );
                            }
                            (Decoded::V2(a), Decoded::V2(b)) => {
                                assert_ne!(a.segments[0].openings, b.segments[0].openings);
                                let mut restored = a.clone();
                                restored.segments[0]
                                    .openings
                                    .clone_from(&b.segments[0].openings);
                                restored.model_openings.clone_from(&b.model_openings);
                                assert!(
                                    restored == *b,
                                    "only dependent opening sections change (A18)"
                                );
                            }
                            _ => unreachable!("container version mismatch"),
                        }
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
