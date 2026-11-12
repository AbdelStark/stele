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
//! - NC-1311..1315 (RFC-0026 A11, task E16-30): the honest proof is on the A11 Circle
//!   Policy 2 sources. NC-1311 reads it with the profile byte omitted and NC-1312
//!   reads a pre-A11 proof with the byte added (`ProofShape`: the verifier derives
//!   other model sources from the byte). NC-1313, NC-1314 and NC-1315 replace the
//!   column-round nonce of the stack certificate, the stack opening and the model
//!   certificate with one that fails the k_q = 16 predicate (`GrindMismatch`).
//! - NC-1316 (RFC-0026 A11, review fix 1): the transcript binding of the profile byte.
//!   The engine is run with the plan fixed at one source set and the transcript input of
//!   the other: an A11 proof under the input without the trailing `2`, and a pre-A11
//!   proof under the input with it (`RoundSumMismatch`). Unlike NC-1311/1312, no source
//!   shape differs, so only the public-input byte can reject.
//! - NC-1317..1320 (RFC-0026 A12, task E16-31): the honest proof is on A12 sources
//!   (profile byte 3: multiplicity sources at Circle rate 1/4); NC-1311..1316 keep an
//!   A11 (byte 2) honest proof. NC-1317 reads the A12 proof with byte 2 and NC-1318
//!   reads an A11 proof with byte 3 (`ProofShape`: the verifier derives the other
//!   multiplicity geometry). NC-1319 is the transcript binding of byte 3 alone, as
//!   NC-1316 (`RoundSumMismatch`). NC-1320 replaces the first multiplicity
//!   certificate's column-round nonce with one that fails the k_q = 16 predicate
//!   (`GrindMismatch`).
//!
//! NC-1310 (`run_width`) runs on a minimal relation through the relation-engine
//! prover and verifier (RFC-0026 A10), as a documented INV-4 exception (ADR-110).
//!
//! NC-1305 and NC-1309 restamp the container's statement digest with the verifier's own,
//! so the rejection comes from the engine transcript, not the prover-written header.
use stele_prover::development::container;
use stele_prover::development::{
    artifact_id, prove, prove_tampered, public_input, statement_digest_for, verify, zk, Committed,
    Error, Public, Statement, Weights,
};
use stele_reductions::relation::{self, Sources};
use stele_reductions::stele_cqis::execution::Executor;
use stele_reductions::stele_cqis::model::{ArtifactLayout, Model, Preparation, Role, Scales};
use stele_reductions::stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{Relation, Values};
use stele_reductions::stele_pcs::{verify_certificate, ProofKind, Source};

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

/// RFC-0026 A11, NC-1316: replay the engine with the plan and model sources fixed at
/// `plan` and the transcript started from `input`'s public input (same window).
fn engine_with_input(
    public: &Public,
    input: &Public,
    statement: &Statement,
    rel: &Relation,
    proof: &[u8],
    plan: Sources,
) -> Result<Option<Error>, String> {
    let c = container::decode(proof).map_err(|e| format!("{e:?}"))?;
    let layouts = relation::model_layout(rel, plan).map_err(|e| format!("{e:?}"))?;
    let mut certificates = Vec::new();
    for (l, (root, bytes)) in layouts.iter().zip(&public.commitment) {
        let source = l
            .sources
            .source(l.id, l.ell, &l.code, *root)
            .map_err(|e| format!("{e:?}"))?;
        let (verified, _) =
            verify_certificate(source, bytes).map_err(|f| format!("{:?}", f.cause))?;
        certificates.push(verified);
    }
    let bytes = public_input(input, &c.cqis_id, statement);
    let mut t = Transcript::<relation::K>::new(&bytes).map_err(|e| format!("{e:?}"))?;
    let sections = relation::Proof {
        groups: c.groups,
        multiplicities: c.multiplicities,
        identities: c.identities,
        lookups: c.lookups,
        matmuls: c.matmuls,
        openings: c.openings,
    };
    let refs: Vec<_> = certificates.iter().collect();
    Ok(relation::verify(&mut t, rel, &refs, &sections, plan)
        .err()
        .map(Error::Engine))
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
    zk_commit_profile(public, exec, weights, proofs, seed, zk::PROFILE)
}

/// [`zk_commit`] under `profile` (RFC-0013 A8: [`zk::PROFILE_BALANCED`]).
fn zk_commit_profile(
    public: &Public,
    exec: &mut Executor<'_>,
    weights: &Weights,
    proofs: u32,
    seed: u8,
    profile: u8,
) -> Result<(Public, zk::ModelCommitment, zk::ModelState), String> {
    let base = Public {
        commitment: Vec::new(),
        vectors: zk::published(&public.model, &public.vectors).map_err(|e| format!("{e:?}"))?,
        // dev-zk inputs omit the A11 byte: their hiding sources do not read it.
        sources: Sources::Expander,
        ..public.clone()
    };
    let (commitment, state) = zk::commit(&base, exec, weights, 4, proofs, [seed; 32], profile)
        .map_err(|e| format!("{e:?}"))?;
    let zk_public = Public {
        commitment: vec![(commitment.root, Vec::new())],
        ..base
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

/// NC-0933's transcript-level half: an adversary that proves with commitment A's
/// model seed and state (past the producer's root check, since its secret names
/// A's root) under B's public input, with a correct dev-zk header for B. Header
/// and transcript both name B; only the verifier's binding of the proof's weight
/// source to B's root rejects it (`RootMismatch`).
#[allow(clippy::too_many_arguments)]
fn commitment_transcript(
    public: &Public,
    exec: &mut Executor<'_>,
    weights: &Weights,
    committed: &Committed<'_>,
    statement: &Statement,
    b_public: &Public,
    b: &zk::ModelCommitment,
    a: &zk::ModelCommitment,
    a_state: &zk::ModelState,
) -> Result<(), String> {
    use stele_prover::development::model_identity;
    use stele_reductions::stele_field::QM31;
    use stele_reductions::stele_hash::Transcript;
    use stele_reductions::zk::claims::{self, Lifetime, ModelSecret};
    use stele_reductions::zk::relation as zk_relation;
    let _ = (public, committed);
    let (relation, values) =
        zk::window(b_public, exec, weights, statement).map_err(|e| format!("capture: {e:?}"))?;
    let index = a_state.revealed.len() as u32;
    let (cqis_id, _) = model_identity(b_public).map_err(|e| format!("{e:?}"))?;
    let input = zk::public_input(b_public, &cqis_id, statement, b, index);
    let mut t = Transcript::<QM31>::new(&input).map_err(|e| format!("{e:?}"))?;
    let lifetime = Lifetime {
        geometry: b.geometry(),
        source: zk_relation::WEIGHTS,
        proofs: b.proofs as usize,
        index: index as usize,
        blocks: b.blocks.iter().map(|x| *x as usize).collect(),
    };
    let model = ModelSecret {
        seed: &a_state.seed,
        revealed: a_state.revealed.clone(),
        root: a.root,
    };
    let (proof, _) = zk_relation::prove_lifetime(
        &mut t,
        &relation,
        &values,
        zk::Seed::new([39; 32]),
        &lifetime,
        model,
    )
    .map_err(|e| format!("adversary: {e:?}"))?;
    let mut bytes = b"stele-dev-zk-v1".to_vec();
    bytes.extend_from_slice(&cqis_id);
    bytes.extend_from_slice(
        &zk::statement_digest_for(b_public, statement, b, index, zk::PROFILE)
            .map_err(|e| format!("{e:?}"))?,
    );
    bytes.extend_from_slice(&claims::encode(&proof));
    let root = stele_reductions::zk::Error::Pcs(stele_reductions::stele_pcs::Error::Merkle(
        stele_reductions::stele_hash::merkle::Error::RootMismatch,
    ));
    match zk::verify(b_public, statement, &bytes, b, index) {
        Err(Error::Zk(e)) if e == root => Ok(()),
        other => Err(format!("transcript-level NC-0933: {other:?}")),
    }
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
    let _ = (public, committed);
    let (relation, values) =
        zk::window(zk_public, exec, weights, statement).map_err(|e| format!("capture: {e:?}"))?;
    let index = state.revealed.len() as u32;
    let (cqis_id, _) = model_identity(zk_public).map_err(|e| format!("{e:?}"))?;
    let mut t = Transcript::<QM31>::new(&public_input(zk_public, &cqis_id, statement))
        .map_err(|e| format!("{e:?}"))?;
    let lifetime = Lifetime {
        geometry: commitment.geometry(),
        source: zk_relation::WEIGHTS,
        proofs: commitment.proofs as usize,
        index: index as usize,
        blocks: commitment.blocks.iter().map(|b| *b as usize).collect(),
    };
    let model = ModelSecret {
        seed: &state.seed,
        revealed: state.revealed.clone(),
        root: commitment.root,
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
    // NC-1311..1316 test A11 (byte 2) proofs; every other control the default (A12).
    let set = match id {
        1311..=1316 => Sources::Circle,
        _ => Sources::CircleAll,
    };
    let weights =
        Weights::from_artifact_sources(&model, artifact, set).map_err(|e| format!("{e:?}"))?;
    let committed = Committed::new(&weights).map_err(|e| format!("{e:?}"))?;
    let public = Public {
        model: span("model")?.to_vec(),
        scales: span("scales")?.to_vec(),
        preparation: span("preparation")?.to_vec(),
        vectors: weights.vectors.clone(),
        commitment: committed.commitment.clone(),
        sources: weights.sources(),
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
            commitment_transcript(
                &public, &mut exec, &weights, &committed, &honest, &b_public, &b, &a, &a_state,
            )?;
            (
                "StatementMismatch",
                zk::verify(&b_public, &honest, &proof, &b, index).err(),
            )
        }
        939..=941 => {
            // RFC-0013 A8: an honest byte-4 proof, then its control.
            let (zk_public, commitment, mut state) =
                zk_commit_profile(&public, &mut exec, &weights, 2, 39, zk::PROFILE_BALANCED)?;
            let (proof, index) = zk_prove(
                &zk_public,
                &mut exec,
                &weights,
                &honest,
                &commitment,
                &mut state,
                39,
            )
            .map_err(|e| format!("dev-zk prover: {e:?}"))?;
            zk::verify(&zk_public, &honest, &proof, &commitment, index)
                .map_err(|e| format!("honest byte-4 dev-zk rejected: {e:?}"))?;
            match id {
                939 => {
                    // One byte of the witness source's certificate column-round nonce.
                    use stele_reductions::stele_field::QM31;
                    use stele_reductions::zk::claims;
                    let header = b"stele-dev-zk-v1".len() + 64;
                    let mut decoded =
                        claims::decode::<QM31>(&proof[header..]).map_err(|e| format!("{e:?}"))?;
                    let source = Source::<QM31>::from_bytes(&decoded.sources[0])
                        .map_err(|e| format!("{e:?}"))?;
                    let (tensor, column) = source.grind_bits(ProofKind::Certificate);
                    if column == 0 {
                        return Err("the witness source does not grind".into());
                    }
                    let at = 1 + if tensor > 0 { 8 } else { 0 } + 16 * source.columns();
                    decoded.certificates[0][at] ^= 1;
                    let mut tampered = proof[..header].to_vec();
                    tampered.extend_from_slice(&claims::encode(&decoded));
                    (
                        "GrindMismatch",
                        zk::verify(&zk_public, &honest, &tampered, &commitment, index).err(),
                    )
                }
                940 => {
                    // The same commitment presented as byte 1.
                    let narrow = zk::ModelCommitment {
                        profile: zk::PROFILE,
                        ..commitment.clone()
                    };
                    (
                        "StatementMismatch",
                        zk::verify(&zk_public, &honest, &proof, &narrow, index).err(),
                    )
                }
                _ => {
                    // The byte-4 public file relabelled as the byte-1 file.
                    use stele_prover::development::bundle;
                    let mut file = bundle::encode_zk(&zk_public, &honest, &commitment, index);
                    let (v2, v1) = (b"stele-dev-zk-public-v2", b"stele-dev-zk-public-v1");
                    if !file.starts_with(v2) {
                        return Err("not a byte-4 public file".into());
                    }
                    file[..v1.len()].copy_from_slice(v1);
                    ("StatementMismatch", bundle::decode_zk(&file).err())
                }
            }
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
        1311 => {
            if public.sources != Sources::Circle {
                return Err("honest proof not on A11 sources".into());
            }
            let omitted = Public {
                sources: Sources::Expander,
                ..public.clone()
            };
            ("ProofShape", restamped(&omitted, &honest, &proof)?)
        }
        1312 => {
            let w = Weights::from_artifact_sources(&model, artifact, Sources::Expander)
                .map_err(|e| format!("{e:?}"))?;
            let c = Committed::new(&w).map_err(|e| format!("{e:?}"))?;
            let old = Public {
                commitment: c.commitment.clone(),
                sources: Sources::Expander,
                ..public.clone()
            };
            let old_proof = prove(&old, &mut exec, &w, &c, &honest)
                .map_err(|e| format!("pre-A11 prover: {e:?}"))?;
            verify(&old, &honest, &old_proof).map_err(|e| format!("pre-A11 rejected: {e:?}"))?;
            let added = Public {
                sources: Sources::Circle,
                ..old
            };
            ("ProofShape", restamped(&added, &honest, &old_proof)?)
        }
        1316 => {
            let mut captured = None;
            let mut hook = |r: &mut Relation, _: &mut Values| captured = Some(r.clone());
            prove_tampered(&public, &mut exec, &weights, &committed, &honest, &mut hook)
                .map_err(|e| format!("capture prover: {e:?}"))?;
            let rel = captured.ok_or("no relation")?;
            let omitted = Public {
                sources: Sources::Expander,
                ..public.clone()
            };
            // The harness itself: the honest input under the honest plan accepts.
            if let Some(e) =
                engine_with_input(&public, &public, &honest, &rel, &proof, Sources::Circle)?
            {
                return Err(format!("honest replay rejected: {e:?}"));
            }
            let a11 = engine_with_input(&public, &omitted, &honest, &rel, &proof, Sources::Circle)?;
            // Reverse: a pre-A11 proof under its plan, transcript input with `2` appended.
            let w = Weights::from_artifact_sources(&model, artifact, Sources::Expander)
                .map_err(|e| format!("{e:?}"))?;
            let c = Committed::new(&w).map_err(|e| format!("{e:?}"))?;
            let old = Public {
                commitment: c.commitment.clone(),
                sources: Sources::Expander,
                ..public.clone()
            };
            let old_proof = prove(&old, &mut exec, &w, &c, &honest)
                .map_err(|e| format!("pre-A11 prover: {e:?}"))?;
            let added = Public {
                sources: Sources::Circle,
                ..old.clone()
            };
            let pre =
                engine_with_input(&old, &added, &honest, &rel, &old_proof, Sources::Expander)?;
            match (&a11, &pre) {
                (Some(a), Some(b)) if name(a) == name(b) => {}
                _ => return Err(format!("byte not bound: omitted {a11:?}, added {pre:?}")),
            }
            ("RoundSumMismatch", a11)
        }
        1317 => {
            if public.sources != Sources::CircleAll {
                return Err("honest proof not on A12 sources".into());
            }
            let a11 = Public {
                sources: Sources::Circle,
                ..public.clone()
            };
            ("ProofShape", restamped(&a11, &honest, &proof)?)
        }
        1318 | 1319 => {
            // An A11 (byte 2) proof of the same window; the model sources are the same.
            let a11 = Public {
                sources: Sources::Circle,
                ..public.clone()
            };
            let w = Weights::from_artifact_sources(&model, artifact, Sources::Circle)
                .map_err(|e| format!("{e:?}"))?;
            let a11_proof = prove(&a11, &mut exec, &w, &committed, &honest)
                .map_err(|e| format!("A11 prover: {e:?}"))?;
            verify(&a11, &honest, &a11_proof).map_err(|e| format!("A11 rejected: {e:?}"))?;
            if id == 1318 {
                ("ProofShape", restamped(&public, &honest, &a11_proof)?)
            } else {
                let mut captured = None;
                let mut hook = |r: &mut Relation, _: &mut Values| captured = Some(r.clone());
                prove_tampered(&public, &mut exec, &weights, &committed, &honest, &mut hook)
                    .map_err(|e| format!("capture prover: {e:?}"))?;
                let rel = captured.ok_or("no relation")?;
                let all = Sources::CircleAll;
                if let Some(e) = engine_with_input(&public, &public, &honest, &rel, &proof, all)? {
                    return Err(format!("honest replay rejected: {e:?}"));
                }
                // A12 proof and plan, byte 2 input; A11 proof and plan, byte 3 input.
                let a12 = engine_with_input(&public, &a11, &honest, &rel, &proof, all)?;
                let pre =
                    engine_with_input(&a11, &public, &honest, &rel, &a11_proof, Sources::Circle)?;
                match (&a12, &pre) {
                    (Some(a), Some(b)) if name(a) == name(b) => {}
                    _ => return Err(format!("byte not bound: as 2 {a12:?}, as 3 {pre:?}")),
                }
                ("RoundSumMismatch", a12)
            }
        }
        1320 => {
            let mut captured = None;
            let mut hook = |r: &mut Relation, _: &mut Values| captured = Some(r.clone());
            prove_tampered(&public, &mut exec, &weights, &committed, &honest, &mut hook)
                .map_err(|e| format!("capture prover: {e:?}"))?;
            let rel = captured.ok_or("no relation")?;
            let mut c = container::decode(&proof).map_err(|e| format!("{e:?}"))?;
            let root = c.multiplicities[0][..32].try_into().map_err(|_| "root")?;
            let source = relation::multiplicity_source(&rel, Sources::CircleAll, 0, root)
                .map_err(|e| format!("{e:?}"))?;
            // Certificate wire `u8(1) || [n_t] || t || n_q || ..` (as NC-1313).
            let (tensor, column) = source.grind_bits(ProofKind::Certificate);
            if column != 16 || source.code_id()[20] != 2 {
                return Err("multiplicity source not rate 1/4 with k_q = 16".into());
            }
            let at = 1 + if tensor > 0 { 8 } else { 0 } + source.columns() * 16;
            c.multiplicities[0][32 + at] ^= 1;
            ("GrindMismatch", verify(&public, &honest, &c.encode()).err())
        }
        1313..=1315 => {
            // The plan-derived relation, captured from the prover's own declaration.
            let mut captured = None;
            let mut hook = |r: &mut Relation, _: &mut Values| captured = Some(r.clone());
            prove_tampered(&public, &mut exec, &weights, &committed, &honest, &mut hook)
                .map_err(|e| format!("capture prover: {e:?}"))?;
            let rel = captured.ok_or("no relation")?;
            let mut c = container::decode(&proof).map_err(|e| format!("{e:?}"))?;
            let mut tampered = public.clone();
            // Certificate wire `u8(1) || [n_t] || t || n_q || ..`; opening `u8(1) || u || n_q || ..`.
            let nonce = |source: &Source<relation::K>, kind| {
                let (tensor, column) = source.grind_bits(kind);
                let tensor = if tensor > 0 { 8 } else { 0 };
                (column == 16).then_some(1 + tensor + source.columns() * 16)
            };
            match id {
                1313 | 1314 => {
                    let root = c.groups[0][..32].try_into().map_err(|_| "root")?;
                    let stack = relation::stack_source(&rel, Sources::Circle, root)
                        .map_err(|e| format!("{e:?}"))?
                        .ok_or("no stack")?;
                    if id == 1313 {
                        let at = nonce(&stack, ProofKind::Certificate).ok_or("no k_q = 16")?;
                        c.groups[0][32 + at] ^= 1;
                    } else {
                        // Claim-batch rounds (3 values each) and the final value precede it.
                        let bits = (stack.rows() * stack.columns()).trailing_zeros() as usize;
                        let at = nonce(&stack, ProofKind::Opening).ok_or("no k_q = 16")?;
                        c.openings[0][bits * 48 + 16 + at] ^= 1;
                    }
                }
                _ => {
                    let l = &relation::model_layout(&rel, Sources::Circle)
                        .map_err(|e| format!("{e:?}"))?[0];
                    let (root, certificate) = &mut tampered.commitment[0];
                    let model = l
                        .sources
                        .source(l.id, l.ell, &l.code, *root)
                        .map_err(|e| format!("{e:?}"))?;
                    let at = nonce(&model, ProofKind::Certificate).ok_or("no k_q = 16")?;
                    certificate[at] ^= 1;
                }
            }
            (
                "GrindMismatch",
                verify(&tampered, &honest, &c.encode()).err(),
            )
        }
        _ => return Err(format!("unknown development control {id}")),
    };
    match rejection {
        None => Err("tamper accepted".into()),
        Some(e) if name(&e) == expected => Ok(()),
        Some(e) => Err(format!("expected {expected}, got {e:?}")),
    }
}

#[cfg(feature = "controls")]
/// E12-27: one RMSNorm gain group (`H0, H1, σH, flipH` of `gains`, padded to 8
/// positions with `d = gains.len()`) committed by `zk::commit_records`.
fn records(gains: &[i16]) -> Result<(Relation, Values), String> {
    use stele_reductions::stele_ir::relation::{Kind, Width};
    let mut rel = Relation::default();
    let mut columns = [Vec::new(), Vec::new(), Vec::new(), vec![1i64; 8]];
    for c in &mut columns[..3] {
        *c = vec![0; 8];
    }
    for (k, h) in gains.iter().enumerate() {
        let h = i64::from(*h);
        columns[0][k] = h & 255;
        columns[1][k] = h >> 8;
        columns[2][k] = i64::from(h < 0);
        columns[3][k] = 1 - 2 * i64::from(h < 0);
    }
    for (name, values) in ["H0", "H1", "sigmaH", "flipH"].iter().zip(columns) {
        rel.add_column(
            &format!("L0/norm1/{name}"),
            Kind::Public(values),
            Width::signed(16),
            3,
        );
    }
    let empty = Values::new(&rel);
    let (rel_c, values) = zk::commit_records(&rel, Some((&empty, &rel)), gains.len())
        .map_err(|e| format!("{e:?}"))?;
    Ok((rel_c, values.ok_or("values")?))
}

#[cfg(feature = "controls")]
/// NC-0935..0938: one value of the committed gain encoding made inconsistent,
/// sent through `zk::relation::forge` on claims relation `target` (honest rounds,
/// true `μ`, no producer self-check). The same adversary on the honest encoding is
/// accepted (mutation M0).
fn records_control(
    tamper: impl Fn(&Relation, &mut Values) -> Result<(), String>,
    target: Target,
) -> Result<(), String> {
    use stele_reductions::stele_field::QM31;
    use stele_reductions::stele_hash::Transcript;
    use stele_reductions::zk::{relation as zk_relation, Seed};
    let gains = [-300i16, 7, i16::MIN, i16::MAX, -1, 0];
    let (rel, values) = records(&gains)?;
    let layout = zk_relation::layout(&rel).map_err(|e| format!("{e:?}"))?;
    let index = match target {
        Target::Identities => 0,
        Target::Check(l) => zk_relation::check_sum(&layout, l),
    };
    let run = |values: &Values| -> Result<(), stele_reductions::zk::Error> {
        let seed = Seed::new([51; 32]);
        let root = zk_relation::weight_root(&rel, values, &seed)?;
        let mut t = Transcript::<QM31>::new(b"dev-zk records").expect("transcript");
        let proof = zk_relation::forge(&mut t, &rel, values, Seed::new([51; 32]), index)?;
        let mut t = Transcript::<QM31>::new(b"dev-zk records").expect("transcript");
        zk_relation::verify(&mut t, &rel, root, &proof).map(|_| ())
    };
    run(&values).map_err(|e| format!("M0: honest encoding rejected: {e:?}"))?;
    let mut false_values = values.clone();
    tamper(&rel, &mut false_values)?;
    match run(&false_values) {
        Err(stele_reductions::zk::Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch)) => {
            Ok(())
        }
        other => Err(format!("unexpected: {other:?}")),
    }
}

/// Which claims relation [`records_control`] forges.
#[cfg(feature = "controls")]
enum Target {
    /// The combined identities of the gain domain (claims relation 0).
    Identities,
    /// Range check `l`'s `Σ h = 0`.
    Check(usize),
}

#[cfg(feature = "controls")]
fn set(rel: &Relation, values: &mut Values, suffix: &str, k: usize, v: i64) -> Result<(), String> {
    let id = rel
        .columns
        .iter()
        .position(|c| c.name.ends_with(suffix))
        .ok_or("column")?;
    let id = stele_reductions::stele_ir::relation::ColumnId(id as u32);
    let mut col = values.get(rel, id).ok_or("values")?.to_vec();
    col[k] = v;
    values.set(rel, id, col).map_err(|e| format!("{e:?}"))
}

/// Execute one E12-27 records control.
#[cfg(feature = "controls")]
pub fn run_records(id: u16) -> Result<(), String> {
    match id {
        // NC-0935: flipH = −1 with σH = 0 (gain 7): the flip identity.
        935 => records_control(|r, v| set(r, v, "/flipH", 1, -1), Target::Identities),
        // NC-0936: σH = 1 with H1 = 0 and flipH = −1 (gain 7), H1low = 128 so the
        // sign identity holds: the 7-bit range (check 3) rejects it.
        936 => records_control(
            |r, v| {
                set(r, v, "/sigmaH", 1, 1)?;
                set(r, v, "/flipH", 1, -1)?;
                set(r, v, "/H1low", 1, 128)
            },
            Target::Check(3),
        ),
        // NC-0937: a nonzero H0 past the model width d: the padding identity.
        937 => records_control(|r, v| set(r, v, "/H0", 7, 5), Target::Identities),
        // NC-0938: σH = 1 and flipH = −1 on gain 7 (H1 = 0), H1low = H1 = 0 in range
        // and the flip identity holding: only the sign identity rejects it.
        938 => records_control(
            |r, v| {
                set(r, v, "/sigmaH", 1, 1)?;
                set(r, v, "/flipH", 1, -1)?;
                set(r, v, "/H1low", 1, 0)
            },
            Target::Identities,
        ),
        _ => Err(format!("unknown records control {id}")),
    }
}

/// RFC-0013 A5 item 7 privacy tests on the real one-layer window (T = 4, E12-14b,
/// review F4), at the relation level, through the actual verifier.
#[cfg(all(test, feature = "controls"))]
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
            sources: weights.sources(),
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
    /// of the two proofs' finals, as for two fresh commitments. Under `profile` (byte 1,
    /// or RFC-0013 A8's byte 4), on `case`'s greedy window of `t` tokens; every proof's
    /// revealed finals also differ from the bare evaluations (exact, every occurrence).
    fn two_proofs(case: &str, t: usize, profile: u8) {
        use stele_prover::development::model_identity;
        use stele_reductions::zk::claims::Lifetime;
        let span = |key: &str| span_of(case, key).expect(key);
        let model = Model::decode(span("model")).expect("model");
        let prep = Preparation::decode(&model, span("preparation")).expect("prep");
        let scales = Scales::decode(&model, span("scales")).expect("scales");
        let artifact = span("artifact");
        let id = artifact_id(artifact);
        let mut exec =
            Executor::new(&model, &prep, &scales, artifact, &id, 1 << 34).expect("executor");
        let (statement, _, _) = window(case, artifact, t).expect("window");
        let weights = Weights::from_artifact(&model, artifact).expect("weights");
        let public = Public {
            model: span("model").to_vec(),
            scales: span("scales").to_vec(),
            preparation: span("preparation").to_vec(),
            vectors: zk::published(span("model"), &weights.vectors).expect("published"),
            commitment: Vec::new(),
            sources: Sources::Expander,
        };
        let (zk_public, commitment, mut state) =
            zk_commit_profile(&public, &mut exec, &weights, 3, 41, profile).expect("commit");
        let (relation, values) =
            zk::window(&zk_public, &mut exec, &weights, &statement).expect("window");
        let (cqis_id, _) = model_identity(&zk_public).expect("identity");
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
            let decoded =
                stele_reductions::zk::claims::decode::<QM31>(&proof[header..]).expect("decode");
            let lifetime = Lifetime {
                geometry: commitment.geometry(),
                source: zk_relation::WEIGHTS,
                proofs: commitment.proofs as usize,
                index: index as usize,
                blocks: commitment.blocks.iter().map(|b| *b as usize).collect(),
            };
            let input = zk::public_input(&zk_public, &cqis_id, &statement, &commitment, index);
            let mut tr = Transcript::new(&input).expect("transcript");
            let (total, equal) =
                zk_relation::leaks_lifetime(&mut tr, &relation, &values, &lifetime, &decoded)
                    .expect("accepted");
            assert!(total > 100, "{total} occurrences");
            assert_eq!(
                equal, 0,
                "{equal} of {total} finals equal the bare evaluation"
            );
            finals.push(decoded);
        }
        assert_eq!(state.next, 2);
        assert_eq!(state.revealed.len(), 2);
        let chi2 = chi2_same_x10(&histogram(&finals[0]), &histogram(&finals[1]));
        assert!(chi2 < 377, "10·χ² {chi2}");
    }

    #[test]
    fn accepts_two_independent_proofs_against_one_commitment() {
        two_proofs("one-layer", 4, zk::PROFILE);
    }

    /// RFC-0013 A8: the same on byte-4 sources.
    #[test]
    fn accepts_two_independent_proofs_against_one_commitment_balanced() {
        two_proofs("one-layer", 4, zk::PROFILE_BALANCED);
    }

    /// RFC-0013 A8 on the eight-layer acceptance window (balanced shapes at
    /// `ell ∈ {3, 6, 7, 9}`); release build only.
    #[test]
    #[ignore = "8 layers at T=64: run with --release -- --ignored"]
    fn rejects_bare_evaluations_on_the_eight_layer_window_balanced() {
        two_proofs("eight-layer", 64, zk::PROFILE_BALANCED);
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

/// NC-1310 (RFC-0026 §3.6, §9): a ranged witness value committed as `2^30`, outside its
/// declared width, with every identity recomputed, through the actual relation-engine
/// prover and verifier (`stele_reductions::relation`).
///
/// Documented INV-4 exception (ADR-110): two values change. In every development
/// window, each column that could rebalance an identity is itself read by another
/// identity or lookup. So the control uses a minimal relation: `x + 2^22·y − c = 0`,
/// with `x` unsigned 8, `y` signed 9 and `c` public. The tamper sets `x[0] = 2^30` and
/// `y[0] = −256`. The identity still holds, `y` stays inside its width, and `x` is the
/// only value outside one. `x`'s range is the relation's first range, so its A5 check
/// runs first, and the rejection, `RootMismatch` from its root equation, is `x`'s.
#[cfg(feature = "controls")]
pub fn run_width() -> Result<(), String> {
    use stele_hash::Transcript;
    use stele_reductions::relation::{prove, verify};
    use stele_reductions::stele_ir::relation::{
        check, Identity, Kind, Range, Ref, Term, Violation, Width,
    };

    const PUBLIC: &[u8] = b"stele/nc-1310/width";
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/width/1", 1));
    let x = rel.add_column("x", g.clone(), Width::unsigned(8), 1);
    let y = rel.add_column("y", g, Width::signed(9), 1);
    let c = rel.add_column("c", Kind::Public(vec![0, 7]), Width::unsigned(8), 1);
    let at = |column| vec![Ref::identity(column, 1)];
    rel.identities.push(Identity {
        name: "width".into(),
        vars: 1,
        terms: vec![
            Term {
                coeff: 1,
                factors: at(x),
            },
            Term {
                coeff: 1 << 22,
                factors: at(y),
            },
            Term {
                coeff: -1,
                factors: at(c),
            },
        ],
    });
    for (name, column, width) in [("x", x, Width::unsigned(8)), ("y", y, Width::signed(9))] {
        rel.ranges.push(Range {
            name: name.into(),
            column,
            width,
        });
    }
    let witness = |tampered: &bool| -> Result<Values, String> {
        let mut values = Values::new(&rel);
        let (xs, ys) = if *tampered {
            (vec![1 << 30, 7], vec![-256, 0])
        } else {
            (vec![0, 7], vec![0, 0])
        };
        values.set(&rel, x, xs).map_err(|e| format!("{e:?}"))?;
        values.set(&rel, y, ys).map_err(|e| format!("{e:?}"))?;
        Ok(values)
    };
    // The plain checker confirms the tamper keeps the identity and y's width: its only
    // violation is x's range. It is a fixture check, not the rejection under test.
    match check(&rel, &witness(&true)?) {
        Err(Violation::Range { relation, .. }) if relation == "x" => {}
        other => return Err(format!("tamper is not exactly x's width: {other:?}")),
    }
    crate::check_control(
        &false,
        &Tamper1310,
        |tampered| {
            let values = witness(tampered)?;
            let mut t = Transcript::new(PUBLIC).map_err(|e| format!("{e:?}"))?;
            prove(
                &mut t,
                &rel,
                &values,
                &[],
                stele_reductions::relation::Sources::Expander,
            )
            .map_err(|e| format!("{e:?}"))
        },
        |proof| {
            let mut t = Transcript::new(PUBLIC).map_err(|e| format!("{e:?}"))?;
            verify(
                &mut t,
                &rel,
                &[],
                proof,
                stele_reductions::relation::Sources::Expander,
            )
            .map(|_| ())
            .map_err(|e| name_of(&format!("{e:?}")))
        },
        "RootMismatch".to_string(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// The innermost variant name of a nested error's debug form.
#[cfg(feature = "controls")]
fn name_of(debug: &str) -> String {
    let inner = debug.trim_end_matches(')');
    inner.rsplit('(').next().unwrap_or(inner).into()
}

#[cfg(feature = "controls")]
struct Tamper1310;
#[cfg(feature = "controls")]
impl crate::ProverHook<bool> for Tamper1310 {
    fn tamper(&self, tampered: &mut bool) {
        *tampered = true;
    }
}

#[cfg(all(test, feature = "controls"))]
#[test]
fn rejects_nc_1310_out_of_width() {
    run_width().expect("NC-1310");
}
