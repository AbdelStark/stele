//! RFC-0026 A16 §6 — actual registered replay, including two rebuilt true proofs.
use crate::{check_control, development::span, ProverHook};
use stele_prover::development::{self, container, Committed, Public, Statement, Weights};
use stele_reductions::relation::{self, Sources};
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{
    Artifact, ArtifactLayout, Model, Preparation, Role, Scales,
};
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{check, Kind, Relation, Values, Width};
use stele_reductions::stele_pcs::verify_certificate;
use stele_verifier::development::Error;

fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

#[derive(Clone, PartialEq, Eq)]
struct Case {
    entry: Vec<u8>,
    public: Vec<u8>,
    relation: Relation,
}
impl Case {
    fn bytes(&self) -> Vec<u8> {
        [
            self.entry.clone(),
            self.public.clone(),
            relation::encode(&self.relation),
        ]
        .concat()
    }
}
struct Hook {
    id: u16,
    scales_at: usize,
    root_at: usize,
}
impl ProverHook<Case> for Hook {
    fn tamper(&self, case: &mut Case) {
        let before = case.bytes();
        match self.id {
            1325 => case.entry[b"stele-dev-plan-v1".len() + 32] ^= 1,
            1326 => case.public[self.scales_at] ^= 1,
            1327 => case.public[self.root_at] ^= 1,
            1328..=1333 => {
                let names: &[&str] = match self.id {
                    1328 => &["G/embedding/O0"],
                    1329 | 1330 => &["G/embedding/m", "G/embedding/mm"],
                    1331 => &["G/argmax/onehot"],
                    1332 => &["G/argmax/below"],
                    _ => &["G/argmax/rows"],
                };
                let c = case
                    .relation
                    .columns
                    .iter_mut()
                    .find(|c| names.contains(&c.name.as_str()))
                    .expect("fixture request column");
                if self.id == 1330 {
                    c.width.bits ^= 1;
                } else if let Kind::Public(v) = &mut c.kind {
                    if self.id == 1328 {
                        assert_eq!(v[0], 0, "token 1 leaves the zero weight row unselected");
                    }
                    v[0] ^= 1;
                } else {
                    unreachable!("fixture request column is public");
                }
            }
            1334 => {
                let zero = case
                    .relation
                    .columns
                    .iter()
                    .position(|c| c.name == "L0/norm1/sigmaH")
                    .expect("fixture sigmaH");
                assert!(matches!(&case.relation.columns[zero].kind,
                    Kind::Public(v) if v.iter().all(|x| *x == 0)));
                let identity = case
                    .relation
                    .identities
                    .iter_mut()
                    .find(|i| i.name == "L0/norm1/output/0")
                    .expect("fixture identity");
                let term = identity
                    .terms
                    .iter_mut()
                    .find(|t| t.factors.iter().any(|r| r.column.0 as usize == zero))
                    .expect("zero-factor term");
                assert_eq!(term.coeff, 1);
                term.coeff = -1;
            }
            _ => unreachable!("fixed registry control inventory"),
        }
        let after = case.bytes();
        assert_eq!(before.len(), after.len());
        let changes: Vec<_> = before
            .iter()
            .zip(&after)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        if self.id == 1334 {
            // The sole i64 coefficient changes from +1 to -1; all other bytes stay fixed.
            assert_eq!(changes.len(), 8);
            assert_eq!(changes[7] - changes[0], 7);
        } else {
            assert_eq!(changes.len(), 1, "exactly one byte of the declared scalar");
        }
    }
}

struct Fixture {
    honest: Case,
    proof: Vec<u8>,
    rebuilt: Vec<(Case, Vec<u8>)>,
    scales_at: usize,
    root_at: usize,
    cqis: [u8; 32],
}

/// Test-only publisher from validated production data; not the registered verifier.
fn entry(
    public: &Public,
    statement: &Statement,
    rel: &Relation,
    model: &Model,
    scales: &Scales,
    token: u16,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let (cqis, identity) = development::model_identity(public).map_err(err)?;
    let mut static_hash = blake3::Hasher::new();
    static_hash.update(b"stele/v0.1/dev-e2e/plan-static/v1");
    static_hash.update(&(data.len() as u64).to_le_bytes());
    static_hash.update(data);
    static_hash.update(&(public.commitment.len() as u32).to_le_bytes());
    for (root, _) in &public.commitment {
        static_hash.update(root);
    }
    let mut normalized = rel.clone();
    for column in &mut normalized.columns {
        if column.name.starts_with("G/embedding/O")
            || matches!(
                column.name.as_str(),
                "G/embedding/m"
                    | "G/embedding/mm"
                    | "G/argmax/onehot"
                    | "G/argmax/below"
                    | "G/argmax/rows"
            )
        {
            let Kind::Public(values) = &mut column.kind else {
                return Err("request kind".into());
            };
            values.fill(0);
            column.width = Width::unsigned(1);
        }
    }
    let normalized = relation::encode(&normalized);
    let mut template = blake3::Hasher::new();
    template.update(b"stele/v0.1/dev-e2e/plan-template/v1");
    template.update(&(normalized.len() as u64).to_le_bytes());
    template.update(&normalized);
    let embedding = scales.matrix(token).ok_or("Token scales")?;
    let mut out = b"stele-dev-plan-v1".to_vec();
    out.extend_from_slice(&cqis);
    out.extend_from_slice(&identity);
    out.extend_from_slice(&(statement.tokens.len() as u32).to_le_bytes());
    out.push(5);
    out.extend_from_slice(static_hash.finalize().as_bytes());
    out.extend_from_slice(template.finalize().as_bytes());
    out.extend_from_slice(&(relation::encode(rel).len() as u64).to_le_bytes());
    out.extend_from_slice(&model.shape().vocabulary().to_le_bytes());
    out.extend_from_slice(&model.shape().width().to_le_bytes());
    out.extend_from_slice(&embedding.exponent().to_le_bytes());
    out.push(model.initial_fraction());
    out.extend_from_slice(&(embedding.mantissas().len() as u32).to_le_bytes());
    for m in embedding.mantissas() {
        out.extend_from_slice(&m.to_le_bytes());
    }
    assert_eq!(out.len(), 171 + 2 * model.shape().vocabulary() as usize);
    Ok(out)
}

fn fixture() -> Result<Fixture, String> {
    let model = Model::decode(span("model")?).map_err(err)?;
    let prep = Preparation::decode(&model, span("preparation")?).map_err(err)?;
    let scales = Scales::decode(&model, span("scales")?).map_err(err)?;
    let layout = ArtifactLayout::new(&model).map_err(err)?;
    let token = layout
        .records()
        .iter()
        .find(|r| {
            model
                .shape()
                .physical(r.ordinal())
                .is_some_and(|p| p.role() == Role::Token)
        })
        .ok_or("Token record")?;
    // An honest synthetic model with zero Token row 0 makes NC-1328's changed sum true.
    let mut artifact = span("artifact")?.to_vec();
    let row_bits = usize::from(model.shape().width()) * usize::from(token.bits());
    assert_eq!(row_bits % 8, 0);
    let start = token.payload_offset() as usize;
    artifact[start..start + row_bits / 8].fill(0);
    let artifact_id = Artifact::decode(&model, &prep, &scales, &artifact)
        .map_err(err)?
        .identity();
    let mut exec =
        Executor::new(&model, &prep, &scales, &artifact, &artifact_id, 1 << 34).map_err(err)?;
    let mut tokens = vec![1];
    let mut cache = None;
    let next = loop {
        let (step, c) = exec
            .step(*tokens.last().ok_or("tokens")?, cache.as_ref())
            .map_err(err)?;
        cache = Some(c);
        let max = step.logits().iter().max().ok_or("logits")?;
        let y = step
            .logits()
            .iter()
            .position(|v| v == max)
            .ok_or("argmax")? as u32;
        if tokens.len() == 4 {
            break y;
        }
        tokens.push(y);
    };
    let statement = Statement {
        tokens,
        start: 0,
        end: 4,
        next: Some(next),
    };
    let set = Sources::CircleAllGrind;
    let weights = Weights::from_artifact_sources(&model, &artifact, set).map_err(err)?;
    let committed = Committed::new(&weights).map_err(err)?;
    let public = Public {
        model: span("model")?.to_vec(),
        scales: span("scales")?.to_vec(),
        preparation: span("preparation")?.to_vec(),
        vectors: weights.vectors.clone(),
        commitment: committed.commitment.clone(),
        sources: set,
        segment_layers: 0,
    };
    let mut captured: Option<(Relation, Values)> = None;
    let proof = development::prove_tampered(
        &public,
        &mut exec,
        &weights,
        &committed,
        &statement,
        &mut |r, v| captured = Some((r.clone(), v.clone())),
    )
    .map_err(err)?;
    let (rel, values) = captured.ok_or("capture")?;
    check(&rel, &values).map_err(err)?;
    development::verify(&public, &statement, &proof).map_err(err)?;
    let wire = development::bundle::encode(&public, &statement);
    let data_len = 12
        + public.model.len()
        + public.scales.len()
        + public.preparation.len()
        + 4
        + public
            .vectors
            .iter()
            .map(|(_, v)| 6 + v.len() * 2)
            .sum::<usize>();
    let prefix = b"stele-dev-public-v4".len();
    let scales_at = prefix + 4 + public.model.len() + 4;
    let root_at = prefix + data_len + 4;
    let honest = Case {
        entry: entry(
            &public,
            &statement,
            &rel,
            &model,
            &scales,
            token.ordinal(),
            &wire[prefix..prefix + data_len],
        )?,
        public: wire,
        relation: rel,
    };
    let (cqis, _) = development::model_identity(&public).map_err(err)?;
    stele_verifier::registered::verify(
        &honest.public,
        &proof,
        &relation::encode(&honest.relation),
        &honest.entry,
    )
    .map_err(err)?;
    // Rebuild ordinary model sources, keeping the committed roots and all checks.
    let layouts = relation::model_layout(&honest.relation, set).map_err(err)?;
    let messages = relation::model_messages(&honest.relation, &values).map_err(err)?;
    let prepared = layouts
        .iter()
        .zip(&messages)
        .map(|(l, m)| set.prepare(l.id, l.ell, &l.code, m))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    assert_eq!(prepared.len(), public.commitment.len());
    let mut certificates = Vec::new();
    for (p, (root, certificate)) in prepared.iter().zip(&public.commitment) {
        assert_eq!(p.source().root(), *root);
        certificates.push(
            verify_certificate(*p.source(), certificate)
                .map_err(|f| err(f.cause))?
                .0,
        );
    }
    let sources: Vec<_> = prepared.iter().zip(&certificates).collect();
    let mut rebuilt = Vec::new();
    for id in [1328, 1334] {
        let mut case = honest.clone();
        Hook {
            id,
            scales_at,
            root_at,
        }
        .tamper(&mut case);
        check(&case.relation, &values).map_err(err)?;
        let input = development::public_input(&public, &cqis, &statement);
        let mut transcript = Transcript::<relation::K>::new(&input).map_err(err)?;
        let p = relation::prove(&mut transcript, &case.relation, &values, &sources, set)
            .map_err(err)?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"stele/v0.1/dev-e2e/statement");
        digest.update(&(input.len() as u64).to_le_bytes());
        digest.update(&input);
        digest.update(&relation::digest(&case.relation));
        let forged = container::Container {
            cqis_id: cqis,
            statement: *digest.finalize().as_bytes(),
            groups: p.groups,
            multiplicities: p.multiplicities,
            identities: p.identities,
            lookups: p.lookups,
            matmuls: p.matmuls,
            openings: p.openings,
        }
        .encode();
        stele_verifier::development::verify(
            &case.public,
            &forged,
            &relation::encode(&case.relation),
            &cqis,
        )
        .map_err(|e| format!("NC-{id} rebuilt A15: {e:?}"))?;
        rebuilt.push((case, forged));
    }
    Ok(Fixture {
        honest,
        proof,
        rebuilt,
        scales_at,
        root_at,
        cqis,
    })
}

/// Cache only genuine producer output; each invocation executes honest and tampered replay.
pub fn run(id: u16) -> Result<(), String> {
    static FIXTURE: std::sync::OnceLock<Result<Fixture, String>> = std::sync::OnceLock::new();
    let f = FIXTURE
        .get_or_init(fixture)
        .as_ref()
        .map_err(Clone::clone)?;
    let expected = match id {
        1325 | 1327 => Error::RegistryKeyMismatch,
        1326 => Error::RegistryStaticMismatch,
        1328..=1333 => Error::RegistryRequestMismatch,
        1334 => Error::RegistryTemplateMismatch,
        _ => return Err("unknown registry control".into()),
    };
    check_control(
        &f.honest,
        &Hook {
            id,
            scales_at: f.scales_at,
            root_at: f.root_at,
        },
        |case| {
            let proof = if matches!(id, 1328 | 1334) && case != &f.honest {
                &f.rebuilt
                    .iter()
                    .find(|(c, _)| c == case)
                    .ok_or("rebuilt proof must match the exact tampered relation")?
                    .1
            } else {
                &f.proof
            };
            Ok::<_, String>((case.clone(), proof))
        },
        |(case, proof)| {
            let relation = relation::encode(&case.relation);
            if matches!(id, 1328 | 1334) {
                stele_verifier::development::verify(&case.public, proof, &relation, &f.cqis)?;
            }
            stele_verifier::registered::verify(&case.public, proof, &relation, &case.entry)
                .map(|_| ())
        },
        expected,
    )
    .map_err(err)
}
