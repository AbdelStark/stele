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
    artifact_id, prove, prove_tampered, statement_digest_for, verify, Committed, Error, Public,
    Statement, Weights,
};
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{ArtifactLayout, Model, Preparation, Role, Scales};
use stele_reductions::stele_ir::relation::{Relation, Values};

const RAW: &[u8] = include_bytes!("../../../crates/stele-prover/tests/fixtures/synthetic-e2e.bin");
const JSON: &str = include_str!("../../../crates/stele-prover/tests/fixtures/synthetic-e2e.json");

/// `[offset, length]` of `key` in the first fixture case (`one-layer`).
fn span(key: &str) -> Result<&'static [u8], String> {
    let case = JSON
        .split("\"name\": \"")
        .nth(1)
        .filter(|c| c.starts_with("one-layer\""))
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
