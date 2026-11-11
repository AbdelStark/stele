//! RFC-0026 §9 controls through the actual development verifier (task E16-10).
//!
//! Each control proves a 1-layer synthetic family-1 window (T = 4) with the real
//! prover, checks that the honest proof verifies, then changes exactly one value and
//! requires the verifier's exact rejection:
//! - NC-1300: a checked token `x_{i+1}` that is not the argmax (`RootMismatch`, E2);
//! - NC-1301: a next token `y` that is not the argmax (`RootMismatch`, E2);
//! - NC-1304: other weights proven under the expected model commitment (`RoundSumMismatch`:
//!   the engine absorbs the model root after the statement, RFC-0026 A5);
//! - NC-1305: one prover-side rounding exponent (`RoundSumMismatch`);
//! - NC-1309: a different checked range (`RoundSumMismatch`).
//!
//! NC-1305 and NC-1309 restamp the container's statement digest with the verifier's own,
//! so the rejection comes from the engine transcript, not the prover-written header.
use stele_prover::development::container;
use stele_prover::development::{
    artifact_id, prove, prove_tampered, statement_digest_for, verify, zk, Committed, Error, Public,
    Statement, Weights,
};
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{ArtifactLayout, Model, Preparation, Role, Scales};
use stele_reductions::stele_ir::relation::{Relation, Values};

const RAW: &[u8] = include_bytes!("../../../crates/stele-prover/tests/fixtures/synthetic-e2e.bin");
const JSON: &str = include_str!("../../../crates/stele-prover/tests/fixtures/synthetic-e2e.json");

/// `[offset, length]` of `key` in the first fixture case (`one-layer`).
fn span(key: &str) -> Result<&'static [u8], String> {
    span_of("one-layer", key)
}

/// A byte span of synthetic fixture case `name`.
fn span_of(name: &str, key: &str) -> Result<&'static [u8], String> {
    let case = JSON
        .split("\"name\": \"")
        .find(|c| c.starts_with(&format!("{name}\"")))
        .ok_or("fixture case")?;
    let at = case.find(&format!("\"{key}\": {{")).ok_or("fixture key")?;
    let numbers: Vec<usize> = case[at..]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .take(2)
        .map(|s| s.parse().map_err(|_| "fixture number"))
        .collect::<Result<_, _>>()?;
    RAW.get(numbers[0]..numbers[0] + numbers[1])
        .ok_or_else(|| "fixture span".into())
}

/// Verify `proof` with its prover-written statement digest replaced by the verifier's
/// own, so the rejection must come from the engine's transcript, not the header.
fn restamped(
    public: &Public,
    statement: &Statement,
    proof: &[u8],
) -> Result<Option<Error>, String> {
    let mut c = container::decode(proof).map_err(|e| format!("{e:?}"))?;
    c.statement = statement_digest_for(public, statement).map_err(|e| format!("{e:?}"))?;
    Ok(verify(public, statement, &c.encode()).err())
}

fn name(error: &Error) -> String {
    let debug = format!("{error:?}");
    let inner = debug.trim_end_matches(')');
    inner.rsplit('(').next().unwrap_or(inner).into()
}

/// Run control `id`; `Ok` only on the honest acceptance and the exact rejection.
/// A dev-zk model commitment of the window's model (RFC-0013 A6) with budget
/// `proofs`, committed on a reference window of 4 tokens from `seed`.
fn zk_commit(
    public: &Public,
    exec: &mut Executor<'_>,
    weights: &Weights,
    proofs: u32,
    seed: u8,
) -> Result<(Public, zk::ModelCommitment, zk::ModelState), String> {
    let base = Public {
        commitment: Vec::new(),
        ..public.clone()
    };
    let (commitment, state) =
        zk::commit(&base, exec, weights, 4, proofs, [seed; 32]).map_err(|e| format!("{e:?}"))?;
    let zk_public = Public {
        commitment: vec![(commitment.root, Vec::new())],
        ..public.clone()
    };
    Ok((zk_public, commitment, state))
}

/// The next dev-zk proof against `commitment`, advancing `state`.
fn zk_prove(
    zk_public: &Public,
    exec: &mut Executor<'_>,
    weights: &Weights,
    statement: &Statement,
    commitment: &zk::ModelCommitment,
    state: &mut zk::ModelState,
    seed: u8,
) -> Result<(Vec<u8>, u32), Error> {
    let index = state.take(commitment)?;
    let (proof, revealed) = zk::prove(
        zk_public,
        exec,
        weights,
        statement,
        zk::Seed::new([seed; 32]),
        commitment,
        state,
        index,
    )?;
    state.revealed.push(revealed);
    Ok((proof, index))
}

/// NC-0912's transcript-level half: a claims proof made under the development
/// transcript input (no profile byte, index or commitment) and stamped with the
/// correct dev-zk header. The header passes; the claims verifier, whose transcript
/// binds the dev-zk input, rejects it.
#[allow(clippy::too_many_arguments)]
fn transcript_profile(
    public: &Public,
    exec: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    zk_public: &Public,
    commitment: &zk::ModelCommitment,
    state: &zk::ModelState,
) -> Result<(), String> {
    use stele_prover::development::{model_identity, public_input};
    use stele_reductions::stele_field::QM31;
    use stele_reductions::stele_hash::Transcript;
    use stele_reductions::zk::claims::{self, Lifetime, ModelSecret};
    use stele_reductions::zk::relation as zk_relation;
    let mut captured = None;
    let mut hook = |r: &mut Relation, v: &mut Values| captured = Some((r.clone(), v.clone()));
    prove_tampered(public, exec, weights, committed, statement, &mut hook)
        .map_err(|e| format!("capture: {e:?}"))?;
    let (relation, values) = captured.ok_or("relation")?;
    let index = state.revealed.len() as u32;
    let (cqis_id, _) = model_identity(zk_public).map_err(|e| format!("{e:?}"))?;
    let mut t = Transcript::<QM31>::new(&public_input(zk_public, &cqis_id, statement))
        .map_err(|e| format!("{e:?}"))?;
    let lifetime = Lifetime {
        source: zk_relation::WEIGHTS,
        proofs: commitment.proofs as usize,
        index: index as usize,
        blocks: commitment.blocks.iter().map(|b| *b as usize).collect(),
    };
    let model = ModelSecret {
        seed: &state.seed,
        revealed: state.revealed.clone(),
    };
    let (proof, _) = zk_relation::prove_lifetime(
        &mut t,
        &relation,
        &values,
        zk::Seed::new([13; 32]),
        &lifetime,
        model,
    )
    .map_err(|e| format!("adversary: {e:?}"))?;
    let mut bytes = b"stele-dev-zk-v1".to_vec();
    bytes.extend_from_slice(&cqis_id);
    bytes.extend_from_slice(
        &zk::statement_digest_for(zk_public, statement, commitment, index, zk::PROFILE)
            .map_err(|e| format!("{e:?}"))?,
    );
    bytes.extend_from_slice(&claims::encode(&proof));
    match zk::verify(zk_public, statement, &bytes, commitment, index) {
        Err(Error::Zk(_)) => Ok(()),
        other => Err(format!("transcript-level NC-0912: {other:?}")),
    }
}

pub fn run(id: u16) -> Result<(), String> {
    let model = Model::decode(span("model")?).map_err(|e| format!("{e:?}"))?;
    let prep = Preparation::decode(&model, span("preparation")?).map_err(|e| format!("{e:?}"))?;
    let scales = Scales::decode(&model, span("scales")?).map_err(|e| format!("{e:?}"))?;
    let artifact = span("artifact")?;
    let with_id = |artifact: &[u8]| {
        let digest = artifact_id(artifact);
        let artifact = artifact.to_vec();
        (artifact, digest)
    };
    let (honest_artifact, honest_id) = with_id(artifact);
    let mut exec = Executor::new(
        &model,
        &prep,
        &scales,
        &honest_artifact,
        &honest_id,
        1 << 34,
    )
    .map_err(|e| format!("{e:?}"))?;
    // Greedy window of 4 tokens from token 1, checked over [0, 4) with y.
    let mut tokens = vec![1u32];
    let mut cache = None;
    let next = loop {
        let last = *tokens.last().ok_or("tokens")?;
        let (step, c) = exec
            .step(last, cache.as_ref())
            .map_err(|e| format!("{e:?}"))?;
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
    let honest = Statement {
        tokens,
        start: 0,
        end: 4,
        next: Some(next),
    };
    let weights = Weights::from_artifact(&model, artifact).map_err(|e| format!("{e:?}"))?;
    let committed = Committed::new(&weights).map_err(|e| format!("{e:?}"))?;
    let public = Public {
        model: span("model")?.to_vec(),
        scales: span("scales")?.to_vec(),
        preparation: span("preparation")?.to_vec(),
        vectors: weights.vectors.clone(),
        commitment: committed.commitment.clone(),
    };
    let proof = prove(&public, &mut exec, &weights, &committed, &honest)
        .map_err(|e| format!("honest prover: {e:?}"))?;
    verify(&public, &honest, &proof).map_err(|e| format!("honest rejected: {e:?}"))?;

    let mut noop = |_: &mut Relation, _: &mut Values| {};
    let (expected, rejection) = match id {
        1300 | 1301 => {
            let mut statement = honest.clone();
            if id == 1300 {
                statement.tokens[2] ^= 1;
            } else {
                statement.next = statement.next.map(|y| y ^ 1);
            }
            let proof = prove_tampered(
                &public, &mut exec, &weights, &committed, &statement, &mut noop,
            )
            .map_err(|e| format!("tampered prover: {e:?}"))?;
            ("RootMismatch", verify(&public, &statement, &proof).err())
        }
        1304 => {
            let layout = ArtifactLayout::new(&model).map_err(|e| format!("{e:?}"))?;
            let query = layout
                .records()
                .iter()
                .find(|r| {
                    model
                        .shape()
                        .physical(r.ordinal())
                        .is_some_and(|p| p.role() == Role::Query)
                })
                .ok_or("Q record")?;
            let mut other = artifact.to_vec();
            let at = query.payload_offset() as usize;
            other[at] = other[at].wrapping_add(1);
            let (other, other_id) = with_id(&other);
            let mut other_exec = Executor::new(&model, &prep, &scales, &other, &other_id, 1 << 34)
                .map_err(|e| format!("{e:?}"))?;
            let w = Weights::from_artifact(&model, &other).map_err(|e| format!("{e:?}"))?;
            let c = Committed::new(&w).map_err(|e| format!("{e:?}"))?;
            let proof = prove(&public, &mut other_exec, &w, &c, &honest)
                .map_err(|e| format!("tampered prover: {e:?}"))?;
            ("RoundSumMismatch", verify(&public, &honest, &proof).err())
        }
        1305 => {
            let mut changed = false;
            let mut hook = |relation: &mut Relation, _: &mut Values| {
                // Double one power-of-two rounding coefficient: one exponent + 1.
                if let Some(term) = relation
                    .identities
                    .iter_mut()
                    .flat_map(|i| i.terms.iter_mut())
                    .find(|t| t.coeff > 2 && (t.coeff as u64).is_power_of_two())
                {
                    term.coeff *= 2;
                    changed = true;
                }
            };
            let proof =
                prove_tampered(&public, &mut exec, &weights, &committed, &honest, &mut hook)
                    .map_err(|e| format!("tampered prover: {e:?}"))?;
            if !changed {
                return Err("no tamper".into());
            }
            ("RoundSumMismatch", restamped(&public, &honest, &proof)?)
        }
        912 => {
            let (zk_public, commitment, mut state) =
                zk_commit(&public, &mut exec, &weights, 2, 12)?;
            let (mut zk_proof, index) = zk_prove(
                &zk_public,
                &mut exec,
                &weights,
                &honest,
                &commitment,
                &mut state,
                12,
            )
            .map_err(|e| format!("dev-zk prover: {e:?}"))?;
            zk::verify(&zk_public, &honest, &zk_proof, &commitment, index)
                .map_err(|e| format!("honest dev-zk rejected: {e:?}"))?;
            // The profile byte flipped to development: the container names the
            // development statement of the same public input and window.
            let digest = zk::statement_digest_for(&zk_public, &honest, &commitment, index, 0)
                .map_err(|e| format!("{e:?}"))?;
            let at = b"stele-dev-zk-v1".len() + 32;
            zk_proof[at..at + 32].copy_from_slice(&digest);
            transcript_profile(
                &public,
                &mut exec,
                &weights,
                &committed,
                &honest,
                &zk_public,
                &commitment,
                &state,
            )?;
            (
                "StatementMismatch",
                zk::verify(&zk_public, &honest, &zk_proof, &commitment, index).err(),
            )
        }
        933 => {
            // A proof under commitment A, verified against commitment B of the same
            // weights (another model seed): the public input names B's root.
            let (a_public, a, mut a_state) = zk_commit(&public, &mut exec, &weights, 2, 33)?;
            let (_, b, _) = zk_commit(&public, &mut exec, &weights, 2, 34)?;
            let (proof, index) = zk_prove(
                &a_public,
                &mut exec,
                &weights,
                &honest,
                &a,
                &mut a_state,
                33,
            )
            .map_err(|e| format!("dev-zk prover: {e:?}"))?;
            zk::verify(&a_public, &honest, &proof, &a, index)
                .map_err(|e| format!("honest dev-zk rejected: {e:?}"))?;
            let pinned_a = zk::model_digest(&a_public, &a).map_err(|e| format!("{e:?}"))?;
            let b_public = Public {
                commitment: vec![(b.root, Vec::new())],
                ..a_public.clone()
            };
            let pinned_b = zk::model_digest(&b_public, &b).map_err(|e| format!("{e:?}"))?;
            if pinned_a == pinned_b {
                return Err("two commitments share a model digest".into());
            }
            (
                "StatementMismatch",
                zk::verify(&b_public, &honest, &proof, &b, index).err(),
            )
        }
        934 => {
            // Budget 2: two proofs, then the third index is refused. A state whose
            // earlier opening is missing (index 1 without opening 0) is refused too.
            let (zk_public, commitment, mut state) =
                zk_commit(&public, &mut exec, &weights, 2, 35)?;
            zk_prove(
                &zk_public,
                &mut exec,
                &weights,
                &honest,
                &commitment,
                &mut state,
                35,
            )
            .map_err(|e| format!("dev-zk prover: {e:?}"))?;
            let mut replay = state.clone();
            replay.revealed.clear();
            replay.next = 2;
            if !matches!(
                zk::prove(
                    &zk_public,
                    &mut exec,
                    &weights,
                    &honest,
                    zk::Seed::new([36; 32]),
                    &commitment,
                    &replay,
                    1,
                ),
                Err(Error::Zk(_))
            ) {
                return Err("index proved without its earlier opening".into());
            }
            zk_prove(
                &zk_public,
                &mut exec,
                &weights,
                &honest,
                &commitment,
                &mut state,
                37,
            )
            .map_err(|e| format!("dev-zk prover: {e:?}"))?;
            (
                "MaskBudget",
                zk_prove(
                    &zk_public,
                    &mut exec,
                    &weights,
                    &honest,
                    &commitment,
                    &mut state,
                    38,
                )
                .err(),
            )
        }
        1309 => {
            let statement = Statement {
                start: 1,
                ..honest.clone()
            };
            ("RoundSumMismatch", restamped(&public, &statement, &proof)?)
        }
        _ => return Err(format!("unknown development control {id}")),
    };
    match rejection {
        None => Err("tamper accepted".into()),
        Some(e) if name(&e) == expected => Ok(()),
        Some(e) => Err(format!("expected {expected}, got {e:?}")),
    }
}

/// RFC-0013 A5 item 7 privacy tests on the real one-layer window (T = 4, E12-14b,
/// review F4), at the relation level, through the actual verifier.
#[cfg(test)]
mod privacy {
    use super::*;
    use stele_reductions::stele_field::{Serialize, QM31};
    use stele_reductions::stele_hash::Transcript;
    use stele_reductions::zk::{claims::Proof, relation as zk_relation, Seed};

    /// The window's relation and values for an Artifact, with its greedy statement.
    fn window(
        case: &str,
        artifact: &[u8],
        t: usize,
    ) -> Result<(Statement, Relation, Values), String> {
        let span = |key: &str| span_of(case, key);
        let model = Model::decode(span("model")?).map_err(|e| format!("{e:?}"))?;
        let prep =
            Preparation::decode(&model, span("preparation")?).map_err(|e| format!("{e:?}"))?;
        let scales = Scales::decode(&model, span("scales")?).map_err(|e| format!("{e:?}"))?;
        let id = artifact_id(artifact);
        let mut exec = Executor::new(&model, &prep, &scales, artifact, &id, 1 << 34)
            .map_err(|e| format!("{e:?}"))?;
        let mut tokens = vec![1u32];
        let mut cache = None;
        let next = loop {
            let (step, c) = exec
                .step(*tokens.last().ok_or("tokens")?, cache.as_ref())
                .map_err(|e| format!("{e:?}"))?;
            cache = Some(c);
            let max = step.logits().iter().max().ok_or("logits")?;
            let y = step
                .logits()
                .iter()
                .position(|v| v == max)
                .ok_or("argmax")? as u32;
            if tokens.len() == t {
                break y;
            }
            tokens.push(y);
        };
        let statement = Statement {
            tokens,
            start: 0,
            end: t as u32,
            next: Some(next),
        };
        let weights = Weights::from_artifact(&model, artifact).map_err(|e| format!("{e:?}"))?;
        let committed = Committed::new(&weights).map_err(|e| format!("{e:?}"))?;
        let public = Public {
            model: span("model")?.to_vec(),
            scales: span("scales")?.to_vec(),
            preparation: span("preparation")?.to_vec(),
            vectors: weights.vectors.clone(),
            commitment: committed.commitment.clone(),
        };
        let mut captured = None;
        let mut hook = |r: &mut Relation, v: &mut Values| captured = Some((r.clone(), v.clone()));
        prove_tampered(
            &public, &mut exec, &weights, &committed, &statement, &mut hook,
        )
        .map_err(|e| format!("{e:?}"))?;
        let (relation, values) = captured.ok_or("relation")?;
        Ok((statement, relation, values))
    }

    fn proof(relation: &Relation, values: &Values, seed: u8) -> Proof<QM31> {
        let mut t = Transcript::new(b"dev-zk window privacy").expect("transcript");
        zk_relation::prove(&mut t, relation, values, Seed::new([seed; 32])).expect("prove")
    }

    fn histogram(proof: &Proof<QM31>) -> Vec<u128> {
        let mut h = vec![0u128; 16];
        for v in proof
            .relations
            .iter()
            .chain(&proof.gkr)
            .flat_map(|p| &p.final_values)
        {
            h[(v.to_le_bytes().as_ref()[0] % 16) as usize] += 1;
        }
        h
    }

    /// Ten times the two-sample homogeneity χ² (15 degrees of freedom).
    fn chi2_same_x10(a: &[u128], b: &[u128]) -> u128 {
        let (na, nb): (u128, u128) = (a.iter().sum(), b.iter().sum());
        a.iter()
            .zip(b)
            .filter(|(x, y)| **x + **y > 0)
            .map(|(x, y)| {
                let d = (x * nb).abs_diff(y * na);
                10 * d * d / (na * nb * (x + y))
            })
            .sum()
    }

    /// Every masked occurrence's revealed final differs from the bare `x̃` at its
    /// point (exact, every occurrence of the window), on `t` tokens.
    fn exact(case: &str, t: usize) {
        let artifact = span_of(case, "artifact").expect("artifact");
        let (_, relation, values) = window(case, artifact, t).expect("window");
        let p = proof(&relation, &values, 5);
        let mut tr = Transcript::new(b"dev-zk window privacy").expect("transcript");
        let (total, equal) = zk_relation::leaks(&mut tr, &relation, &values, &p).expect("accepted");
        assert!(total > 1000, "{total} occurrences");
        assert_eq!(
            equal, 0,
            "{equal} of {total} revealed finals equal the bare evaluation"
        );
        // The control: without masks the same count finds the bare evaluations.
        let mut tp = Transcript::new(b"dev-zk window privacy").expect("transcript");
        let bare = zk_relation::prove_unmasked(&mut tp, &relation, &values, Seed::new([5; 32]))
            .expect("prove");
        let mut tr = Transcript::new(b"dev-zk window privacy").expect("transcript");
        let (_, leaked) = zk_relation::leaks(&mut tr, &relation, &values, &bare).expect("accepted");
        assert!(leaked > 0, "the unmasked control leaks nothing");
    }

    #[test]
    fn rejects_bare_evaluations_on_the_one_layer_window() {
        exact("one-layer", 4);
    }

    /// The eight-layer acceptance window; release build only.
    #[test]
    #[ignore = "8 layers at T=64: run with --release -- --ignored"]
    fn rejects_bare_evaluations_on_the_eight_layer_window() {
        exact("eight-layer", 64);
    }

    /// RFC-0013 A6: two proofs against one published commitment both verify, at
    /// indices 0 and 1, and their revealed values stay independent: χ² homogeneity
    /// of the two proofs' finals, as for two fresh commitments.
    #[test]
    fn accepts_two_independent_proofs_against_one_commitment() {
        let model = Model::decode(span("model").expect("model")).expect("model");
        let prep = Preparation::decode(&model, span("preparation").expect("prep")).expect("prep");
        let scales = Scales::decode(&model, span("scales").expect("scales")).expect("scales");
        let artifact = span("artifact").expect("artifact");
        let id = artifact_id(artifact);
        let mut exec =
            Executor::new(&model, &prep, &scales, artifact, &id, 1 << 34).expect("executor");
        let (statement, _, _) = window("one-layer", artifact, 4).expect("window");
        let weights = Weights::from_artifact(&model, artifact).expect("weights");
        let public = Public {
            model: span("model").expect("model").to_vec(),
            scales: span("scales").expect("scales").to_vec(),
            preparation: span("preparation").expect("prep").to_vec(),
            vectors: weights.vectors.clone(),
            commitment: Vec::new(),
        };
        let (zk_public, commitment, mut state) =
            zk_commit(&public, &mut exec, &weights, 3, 41).expect("commit");
        let mut finals = Vec::new();
        for seed in [42, 43] {
            let (proof, index) = zk_prove(
                &zk_public,
                &mut exec,
                &weights,
                &statement,
                &commitment,
                &mut state,
                seed,
            )
            .expect("prove");
            zk::verify(&zk_public, &statement, &proof, &commitment, index).expect("verify");
            let header = b"stele-dev-zk-v1".len() + 64;
            finals.push(
                stele_reductions::zk::claims::decode::<QM31>(&proof[header..]).expect("decode"),
            );
        }
        assert_eq!(state.next, 2);
        assert_eq!(state.revealed.len(), 2);
        let chi2 = chi2_same_x10(&histogram(&finals[0]), &histogram(&finals[1]));
        assert!(chi2 < 377, "10·χ² {chi2}");
    }

    /// Two witnesses with one public statement: the window under the honest
    /// Artifact and under one with a Q weight code moved (same tokens and `y`).
    /// Same relation, equal proof bytes, χ²-homogeneous revealed values.
    #[test]
    fn accepts_same_distribution_for_two_window_witnesses() {
        let honest = span("artifact").expect("artifact");
        let (statement, relation, values) = window("one-layer", honest, 4).expect("window");
        let model = Model::decode(span("model").expect("model")).expect("model");
        let layout = ArtifactLayout::new(&model).expect("layout");
        let query = layout
            .records()
            .iter()
            .find(|r| {
                model
                    .shape()
                    .physical(r.ordinal())
                    .is_some_and(|p| p.role() == Role::Query)
            })
            .expect("Q record");
        let mut other = None;
        for k in 0..64usize {
            let mut a = honest.to_vec();
            let at = query.payload_offset() as usize + k;
            a[at] = a[at].wrapping_add(1);
            if let Ok((s, r, v)) = window("one-layer", &a, 4) {
                if s == statement && r == relation && v != values {
                    other = Some(v);
                    break;
                }
            }
        }
        let other = other.expect("a second witness of the same statement");
        let (p, q) = (proof(&relation, &values, 6), proof(&relation, &other, 7));
        assert_eq!(
            stele_reductions::zk::claims::encode(&p).len(),
            stele_reductions::zk::claims::encode(&q).len()
        );
        let chi2 = chi2_same_x10(&histogram(&p), &histogram(&q));
        assert!(chi2 < 377, "10·χ² {chi2}");
    }
}
