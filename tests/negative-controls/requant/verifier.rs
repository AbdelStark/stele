//! RFC-0023 §§2,4–6: actual native consumers of frozen independent full wires.
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, ProofKind, Source, Usage, VerifiedCertificate};
use stele_reductions::{
    lookup::TableField,
    requant::{Descriptor, Format, Limits, Schema, Statement},
};
use stele_sumcheck::{Instance, Proof, Term};
mod coefficients;
mod producer;
mod records;
use records::{fields, hashes, hex, lookup, opening, sc, usage};

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/requant")
            .join(name),
    )
    .expect("valid pinned fixture")
}

fn unhex(v: &Value) -> Vec<u8> {
    v.as_str()
        .expect("valid pinned fixture")
        .as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).expect("valid pinned fixture"), 16)
                .expect("valid pinned fixture")
        })
        .collect()
}
fn field<K: ChallengeField>(v: &Value) -> K
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let bytes: Vec<_> = v
        .as_array()
        .expect("valid pinned fixture")
        .iter()
        .flat_map(|v| (v.as_u64().expect("valid pinned fixture") as u32).to_le_bytes())
        .collect();
    K::from_le_bytes(
        K::Bytes::try_from(bytes.as_slice())
            .ok()
            .expect("valid pinned fixture"),
    )
    .expect("valid pinned fixture")
}

// Positive lifetime check: owned schema, point, proof and descriptor die here.
// Only the genuine original/advice/multiplicity owners constrain the result.
fn verify_temporary<'cert, K: ChallengeField + CodeField + TableField + Eq>(
    c: &Value,
    input: &'cert VerifiedCertificate<K>,
    advice: &'cert VerifiedCertificate<K>,
    mu: [&[&'cert VerifiedCertificate<K>]; 2],
    t: &mut Transcript<K>,
    proof: &[u8],
) -> Result<(stele_reductions::requant::Record<'cert, K>, Usage), stele_reductions::requant::Failure>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let p = &c["parameters"];
    let schema = Schema::new(
        p["mantissa"].as_u64().expect("mantissa") as u32,
        p["shift"].as_u64().expect("shift") as u32,
        if p["bits"] == 8 {
            Format::Int8
        } else {
            Format::Int16
        },
    )
    .expect("fixed parameters");
    let point: Vec<K> = c["point"]
        .as_array()
        .expect("point")
        .iter()
        .map(field)
        .collect();
    let proof = proof.to_vec();
    Descriptor::new(
        Statement {
            stage: 31,
            n: c["n"].as_u64().expect("n"),
            schema: &schema,
            repetitions: c["repetitions"].as_u64().expect("repetitions") as u8,
            advice_blowup: c["blowup"].as_u64().expect("blowup") as u8,
            point: &point,
            value: field(&c["value"]),
            input,
        },
        advice,
        Limits {
            positions: 4096,
            public_bytes: 32_000_000,
            proof_bytes: 32_000_000,
        },
    )
    .expect("expected descriptor")
    .verify_measured(t, mu, &proof)
    .map(|(record, usage, work)| {
        let width = core::mem::size_of::<K>();
        for (actual, g) in work.group_coefficients_bytes.iter().zip(record.groups()) {
            assert!(actual[0] >= g.opening().certificate().source().rows() * width);
            assert!(actual[1] >= g.opening().certificate().source().columns() * width);
            assert!(actual[2] >= g.claims().len() * width);
        }
        (record, usage)
    })
}
fn rebuilt_failure<K: ChallengeField + CodeField + TableField + Eq>(
    c: &Value,
    schema: &Schema,
    input: &VerifiedCertificate<K>,
    wire: &[u8],
) -> stele_reductions::requant::Failure
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let n = c["n"].as_u64().expect("valid pinned fixture");
    let blowup = c["blowup"].as_u64().expect("valid pinned fixture") as u8;
    let root = wire[2..34].try_into().expect("valid pinned fixture");
    let source = schema
        .advice_source::<K>(31, n, blowup, root)
        .expect("valid pinned fixture");
    let end = 34
        + source
            .proof_size(ProofKind::Certificate)
            .expect("valid pinned fixture");
    let (advice, _) = schema
        .register_advice::<K>(31, n, blowup, root, &wire[34..end], usize::MAX)
        .expect("valid pinned fixture");
    let point: Vec<K> = c["point"]
        .as_array()
        .expect("valid pinned fixture")
        .iter()
        .map(field)
        .collect();
    let d = Descriptor::new(
        Statement {
            stage: 31,
            n,
            schema,
            repetitions: c["repetitions"].as_u64().expect("valid pinned fixture") as u8,
            advice_blowup: blowup,
            point: &point,
            value: field(&c["value"]),
            input,
        },
        &advice,
        Limits {
            positions: 4096,
            public_bytes: 32_000_000,
            proof_bytes: 32_000_000,
        },
    )
    .expect("valid pinned fixture");
    let (handles, _) = d
        .register_multiplicities(wire, 32_000_000)
        .expect("valid pinned fixture");
    let refs = handles.each_ref().map(|hs| hs.iter().collect::<Vec<_>>());
    let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("valid pinned fixture");
    d.verify(&mut t, [&refs[0], &refs[1]], wire)
        .err()
        .expect("valid pinned fixture")
}
fn run<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>()
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let (mut accepted, mut rejected) = (0, 0);
    for kind in ["scalar", "wide", "shift62", "ties", "padded", "high-tail"] {
        let name = format!("{kind}-K{}", <K as CodeField>::DEGREE);
        let c: Value = serde_json::from_slice(&fixture(&format!("{name}.json")))
            .expect("valid pinned fixture");
        let expect = &c["expected"];
        let keys: &[&str] = match kind {
            "scalar" => &[
                "false-carry",
                "false-source-functional-0",
                "false-source-functional-1",
                "false-source-functional-2",
                "genuine-wrong-advice-handle",
                "noncanonical-A3",
                "noncanonical-output",
                "trailing",
                "truncated",
            ],
            "padded" => &["nonzero-padding", "nonzero-reserved-plane"],
            _ => &[],
        };
        let actual: std::collections::BTreeSet<_> = expect
            .get("controls")
            .map(|c| {
                c.as_object()
                    .expect("control object")
                    .keys()
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            actual,
            keys.iter().copied().collect(),
            "complete saved control set"
        );
        let n = c["n"].as_u64().expect("valid pinned fixture");
        let m = n.next_power_of_two().trailing_zeros() as u8;
        let input_context = unhex(&c["input_source"]);
        let input_source = Source::new(
            73,
            2,
            m,
            1,
            input_context[73..105]
                .try_into()
                .expect("valid pinned fixture"),
        )
        .expect("valid pinned fixture");
        assert_eq!(
            hex(&input_source.bytes()),
            c["input_source"].as_str().expect("valid pinned fixture")
        );
        let (input, import) = verify_certificate(
            input_source,
            &fixture(
                c["input_certificate"]
                    .as_str()
                    .expect("valid pinned fixture"),
            ),
        )
        .expect("valid pinned fixture");
        assert_eq!(
            hashes(import.transcript),
            expect["input_registration"]["created_transcripts"][0]
        );
        assert_eq!(
            hashes(import.non_transcript),
            expect["input_registration"]["non_transcript"]
        );
        let p = &c["parameters"];
        let schema = Schema::new(
            p["mantissa"].as_u64().expect("valid pinned fixture") as u32,
            p["shift"].as_u64().expect("valid pinned fixture") as u32,
            if p["bits"] == 8 {
                Format::Int8
            } else {
                Format::Int16
            },
        )
        .expect("valid pinned fixture");
        let mut wire = fixture(c["wire"].as_str().expect("valid pinned fixture"));
        let root = wire[2..34].try_into().expect("valid pinned fixture");
        let blowup = c["blowup"].as_u64().expect("valid pinned fixture") as u8;
        let source = schema
            .advice_source::<K>(31, n, blowup, root)
            .expect("valid pinned fixture");
        let end = 34
            + source
                .proof_size(ProofKind::Certificate)
                .expect("valid pinned fixture");
        let advice_budget = b"stele/v0.1/pcs-certificate/public".len() + 105 + (end - 34) - 1;
        let failure = schema
            .register_advice::<K>(31, n, blowup, root, &wire[34..end], advice_budget - 1)
            .err()
            .expect("one-byte-low import cap");
        assert_eq!(
            failure.cause,
            stele_reductions::requant::Error::ResourceLimit
        );
        assert_eq!(failure.usage, Usage::default());
        let (advice, import) = schema
            .register_advice::<K>(31, n, blowup, root, &wire[34..end], advice_budget)
            .expect("valid pinned fixture");
        assert_eq!(
            hashes(import.transcript),
            expect["advice_registration"]["created_transcripts"][0]
        );
        assert_eq!(
            hashes(import.non_transcript),
            expect["advice_registration"]["non_transcript"]
        );
        let point: Vec<K> = c["point"]
            .as_array()
            .expect("valid pinned fixture")
            .iter()
            .map(field)
            .collect();
        let statement = Statement {
            stage: 31,
            n,
            schema: &schema,
            repetitions: c["repetitions"].as_u64().expect("valid pinned fixture") as u8,
            advice_blowup: blowup,
            point: &point,
            value: field(&c["value"]),
            input: &input,
        };
        let limits = Limits {
            positions: 4096,
            public_bytes: 32_000_000,
            proof_bytes: 32_000_000,
        };
        let d = Descriptor::new(statement, &advice, limits).expect("valid pinned fixture");
        if kind != "high-tail" {
            let produced = producer::frozen(kind, &c, &schema, &d, &input, &advice);
            assert_eq!(produced, wire, "complete independently frozen wire: {name}");
            wire = produced;
        }
        let mu_source = Source::<K>::new(
            (31u64 << 40) + 16,
            0,
            8 + <K as CodeField>::DEGREE.ilog2() as u8,
            1,
            [0; 32],
        )
        .expect("fixed A5 mu layout");
        let mu_bytes = mu_source
            .proof_size(ProofKind::Certificate)
            .expect("mu size");
        let mu_budget = 2
            * usize::from(statement.repetitions)
            * (b"stele/v0.1/pcs-certificate/public".len() + 105 + mu_bytes - 1);
        let failure = d
            .register_multiplicities(&wire, mu_budget - 1)
            .err()
            .expect("cumulative import cap");
        assert_eq!(
            failure.cause,
            stele_reductions::requant::Error::ResourceLimit
        );
        assert_eq!(failure.registrations, [[None; 2]; 2]);
        let (handles, imports) = d
            .register_multiplicities(&wire, mu_budget)
            .expect("valid pinned fixture");
        let refs = handles.each_ref().map(|hs| hs.iter().collect::<Vec<_>>());
        if kind == "wide" {
            let mut bad = wire.clone();
            // One path byte in input repetition1's certificate, after repetition0.
            let at = end + 2 + (32 + mu_bytes) + 32 + mu_bytes - 1;
            bad[at] ^= 1;
            let failure = d
                .register_multiplicities(&bad, mu_budget)
                .err()
                .expect("actual failed second import");
            assert_eq!(
                failure.cause,
                stele_reductions::requant::Error::Lookup(stele_reductions::lookup::Error::Pcs(
                    stele_pcs::Error::Merkle(stele_hash::merkle::Error::RootMismatch)
                ))
            );
            assert_eq!(failure.registrations[0][0], imports[0][0]);
            let failed = failure.registrations[0][1].expect("failed import Usage");
            let mut expected = imports[0][1].expect("complete second import Usage");
            expected.transcript.hash_evaluations -= 1;
            expected.transcript.state_updates -= 1;
            expected.non_transcript.hash_evaluations -= 1;
            assert_eq!(
                failed, expected,
                "all queries, no response absorb or packet-id H"
            );
            assert_eq!(failure.registrations[1], [None; 2]);
        }
        if kind == "scalar" {
            let mut bad = wire.clone();
            bad[end - 1] ^= 1;
            let import_failure = schema
                .register_advice::<K>(31, n, blowup, root, &bad[34..end], advice_budget)
                .err()
                .expect("actual failed advice import");
            assert_eq!(
                import_failure.cause,
                stele_reductions::requant::Error::Pcs(stele_pcs::Error::Merkle(
                    stele_hash::merkle::Error::RootMismatch
                ))
            );
            let mut failed_import = import;
            failed_import.transcript.hash_evaluations -= 1;
            failed_import.transcript.state_updates -= 1;
            failed_import.non_transcript.hash_evaluations -= 1;
            assert_eq!(
                import_failure.usage, failed_import,
                "all queries, no response absorb or final packet-id H"
            );
            let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("prefix");
            let before = t.usage();
            let failure = d
                .verify(&mut t, [&refs[0], &refs[1]], &bad)
                .err()
                .expect("packet identity");
            assert_eq!(
                failure.cause,
                stele_reductions::requant::Error::CertificateIdentity
            );
            assert_eq!(failure.usage.transcript, before);
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: 1,
                    ..HashUsage::default()
                }
            );
            let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("prefix");
            let failure = d
                .verify(&mut t, [&refs[0], &refs[0]], &wire)
                .err()
                .expect("second-child context");
            assert_eq!(
                failure.cause,
                stele_reductions::requant::Error::Lookup(
                    stele_reductions::lookup::Error::CertificateContext
                )
            );
            assert_eq!(
                hashes(failure.usage.transcript),
                expect["records"]["lookups"][0]["usage"]["transcript"]
            );
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: 1 + expect["records"]["lookups"][0]["usage"]
                        ["non_transcript"]["hash_evaluations"]
                        .as_u64()
                        .expect("earlier H"),
                    ..HashUsage::default()
                }
            );
            let mut bad = wire.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("prefix");
            let failure = d
                .verify(&mut t, [&refs[0], &refs[1]], &bad)
                .err()
                .expect("actual final Merkle consumer");
            assert_eq!(
                failure.cause,
                stele_reductions::requant::Error::Pcs(stele_pcs::Error::Merkle(
                    stele_hash::merkle::Error::RootMismatch
                ))
            );
            let mut expected = expect["records"]["usage"].clone();
            for key in ["hash_evaluations", "state_updates"] {
                expected[key] = json!(expected[key].as_u64().expect("completed Usage") - 1);
            }
            assert_eq!(hashes(failure.usage.transcript), expected);
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: expect["local_hashes"].as_u64().expect("all local H"),
                    ..HashUsage::default()
                }
            );
        }
        if kind == "padded" {
            // New bounded construction, separate from the frozen 5/13 corpus.
            // Keep the original owners, public statement and A5 registrations.
            let name = format!("input-padding-K{}", <K as CodeField>::DEGREE);
            let candidate = fixture(&format!("{name}.bin"));
            let metadata: Value = serde_json::from_slice(&fixture(&format!("{name}.json")))
                .expect("pinned input-padding metadata");
            let expected = &metadata["expected"];
            let at = metadata["arithmetic_offset"].as_u64().expect("A3 offset") as usize;
            let end = at + metadata["arithmetic_size"].as_u64().expect("A3 size") as usize;
            assert_eq!(&candidate[..at], &wire[..at], "unchanged source/A5 prefix");
            assert_eq!(
                &candidate[end..],
                &wire[end..],
                "unreachable original suffix"
            );
            assert_ne!(&candidate[at..end], &wire[at..end]);
            let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("fixed prefix");
            let failure = d
                .verify(&mut t, [&refs[0], &refs[1]], &candidate)
                .err()
                .expect("padded input byte must reject");
            assert_eq!(
                failure.cause,
                stele_reductions::requant::Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch)
            );
            assert_eq!(
                hashes(failure.usage.transcript),
                expected["failed_prefix_usage"]
            );
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: expected["local_hashes"].as_u64().expect("local H"),
                    ..HashUsage::default()
                }
            );
            assert_eq!(
                json!(imports.map(|row| row.map(|u| u.map(usage)))),
                expected["registrations"]
            );
        }
        let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("valid pinned fixture");
        let result = verify_temporary(&c, &input, &advice, [&refs[0], &refs[1]], &mut t, &wire);
        if kind == "high-tail" {
            rejected += 1;
            let failure = result.err().expect("valid pinned fixture");
            assert_eq!(
                format!("{:?}", failure.cause),
                "Sumcheck(FinalEvaluationMismatch)"
            );
            assert_eq!(
                hashes(failure.usage.transcript),
                expect["control"]["failed_prefix_usage"]
            );
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: expect["control"]["local_hashes"]
                        .as_u64()
                        .expect("valid pinned fixture"),
                    ..HashUsage::default()
                }
            );
            continue;
        }
        let (record, observed) = result.expect("valid pinned fixture");
        if kind == "ties" {
            coefficients::rejects_sigma(
                &c,
                &schema,
                &input,
                &advice,
                [&refs[0], &refs[1]],
                &d,
                &wire,
            );
        }
        accepted += 1;
        assert_eq!(
            observed.non_transcript,
            HashUsage {
                hash_evaluations: expect["local_hashes"].as_u64().expect("local H"),
                ..HashUsage::default()
            }
        );
        assert_eq!(
            record
                .rlc()
                .iter()
                .map(|r| r.weights().len())
                .sum::<usize>(),
            expect["records"]["weights"].as_u64().expect("draw count") as usize
        );
        drop(d); // A temporary descriptor and proof do not own accepting obligations.
        drop(wire);
        assert_eq!(
            hashes(observed.transcript),
            expect["records"]["usage"],
            "{name}"
        );
        assert_eq!(
            observed.non_transcript.hash_evaluations,
            expect["local_hashes"]
                .as_u64()
                .expect("valid pinned fixture")
        );
        for (b, roster) in imports.iter().enumerate() {
            assert_eq!(
                json!(roster.map(|u| u.map(usage))),
                expect["records"]["lookups"][b]["registrations"]
            );
            assert_eq!(
                lookup(&record.lookups()[b]),
                expect["records"]["lookups"][b]["record"]
            );
        }
        for (phase, rlc) in record.rlc().iter().enumerate() {
            let expected = &expect["records"]["rlc"][phase];
            assert_eq!(
                json!([
                    rlc.stage(),
                    rlc.phase(),
                    rlc.field_degree(),
                    rlc.numerator(),
                    rlc.weights().len()
                ]),
                json!([
                    expected["stage"],
                    expected["phase"],
                    expected["field_degree"],
                    expected["numerator"],
                    expected["count"]
                ])
            );
        }
        for (b, g) in record.groups().iter().enumerate() {
            let expected = &expect["records"]["groups"][b];
            assert_eq!(fields(g.point()), expected["point"]);
            assert_eq!(
                json!(g.claims().iter().map(|c| c.0).collect::<Vec<_>>()),
                expected["rows"]
            );
            assert_eq!(
                json!(g.claims().iter().map(|c| c.1).collect::<Vec<_>>()),
                expected["ids"]
            );
            assert_eq!(
                fields(&g.claims().iter().map(|c| c.2).collect::<Vec<_>>()),
                expected["claims"]
            );
            assert_eq!(fields(record.rlc()[b + 1].weights()), expected["weights"]);
            assert_eq!(opening(g.opening()), expected["opening_record"]);
        }
        let zero = record.zerocheck();
        for (actual, expected) in zero.claims.iter().zip(
            expect["records"]["zero"]["claims"]
                .as_array()
                .expect("valid pinned fixture"),
        ) {
            assert_eq!(
                json!([
                    actual.tensor,
                    fields(&actual.point),
                    fields(&[actual.value])[0]
                ]),
                *expected
            );
        }
        assert_eq!(
            zero.claims.len(),
            expect["records"]["zero"]["claims"]
                .as_array()
                .expect("valid pinned fixture")
                .len()
        );
        for (phase, actual) in zero.sc.iter().enumerate() {
            let mut value = sc(actual);
            value["phase"] = json!(phase);
            assert_eq!(value, expect["records"]["zero"]["sc"][phase]);
        }
        let output = record.output();
        assert_eq!(fields(&output.point), expect["records"]["output"]["point"]);
        assert_eq!(sc(&output.sc), expect["records"]["output"]["sc"]);
        assert_eq!(
            json!(output
                .claims
                .iter()
                .map(|(id, v)| json!([id, fields(&[*v])[0]]))
                .collect::<Vec<_>>()),
            expect["records"]["output"]["claims"]
        );
        let following = &expect["following_a1"];
        let proof = Proof {
            rounds: following["proof"]["rounds"]
                .as_array()
                .expect("valid pinned fixture")
                .iter()
                .map(|r| {
                    r.as_array()
                        .expect("valid pinned fixture")
                        .iter()
                        .map(field)
                        .collect()
                })
                .collect(),
            final_values: following["proof"]["final"]
                .as_array()
                .expect("valid pinned fixture")
                .iter()
                .map(field)
                .collect(),
        };
        let id = (31u64 << 40) + (1 << 29);
        let instance = Instance {
            id,
            num_vars: 1,
            inputs: vec![id + 1],
            terms: vec![Term {
                coefficient: K::from_i64(1),
                factors: vec![0],
            }],
            claimed_sum: K::from_i64(3),
        };
        let next = stele_sumcheck::verify_public(
            &instance,
            &proof,
            &[vec![K::from_i64(1), K::from_i64(2)]],
            &mut t,
        )
        .expect("valid pinned fixture");
        assert_eq!(fields(&next.point), following["record"]["point"]);
        assert_eq!(sc(&next.sc), following["record"]["sc"]);
        assert_eq!(
            hex(t
                .challenge(ChallengeLabel::Sumcheck)
                .expect("valid pinned fixture")
                .to_le_bytes()
                .as_ref()),
            following["continuation"]
                .as_str()
                .expect("valid pinned fixture")
        );
        let wire = fixture(c["wire"].as_str().expect("valid pinned fixture"));
        let d = Descriptor::new(statement, &advice, limits).expect("valid pinned fixture");
        if let Some(controls) = expect["controls"].as_object() {
            for (label, expected) in controls {
                rejected += 1;
                let failure = if let Some(packet) = expected.get("wire") {
                    let basename =
                        PathBuf::from(packet["path"].as_str().expect("valid pinned fixture"))
                            .file_name()
                            .expect("valid pinned fixture")
                            .to_owned();
                    rebuilt_failure(
                        &c,
                        &schema,
                        &input,
                        &fixture(basename.to_str().expect("valid pinned fixture")),
                    )
                } else if label == "genuine-wrong-advice-handle" {
                    let substitute = &expected["substituted"];
                    let source = schema
                        .advice_source::<K>(
                            31,
                            n,
                            blowup,
                            unhex(&substitute["source"])[73..105]
                                .try_into()
                                .expect("valid pinned fixture"),
                        )
                        .expect("valid pinned fixture");
                    let (other, _) = verify_certificate(
                        source,
                        &fixture(&format!("{name}-different-advice-certificate.bin")),
                    )
                    .expect("valid pinned fixture");
                    let d =
                        Descriptor::new(statement, &other, limits).expect("valid pinned fixture");
                    let mut t =
                        Transcript::new(&unhex(&c["public_hex"])).expect("valid pinned fixture");
                    d.verify(&mut t, [&refs[0], &refs[1]], &wire)
                        .err()
                        .expect("valid pinned fixture")
                } else {
                    let mut bad = wire.clone();
                    let w = 4 * usize::from(<K as CodeField>::DEGREE);
                    let input_open = input_source
                        .proof_size(ProofKind::Opening)
                        .expect("valid pinned fixture");
                    let advice_open = source
                        .proof_size(ProofKind::Opening)
                        .expect("valid pinned fixture");
                    let output_bytes =
                        w * (4 * usize::from(m) + 2 + schema.values()[2].value().len());
                    let zero_bytes = w * (4 * usize::from(m) + 5 + schema.rows());
                    let output_at = bad.len() - advice_open - output_bytes;
                    let zero_at = output_at - advice_open - input_open - zero_bytes;
                    if label == "truncated" {
                        bad.pop();
                    } else if label == "trailing" {
                        bad.push(0);
                    } else if label.starts_with("noncanonical") {
                        let at = if label == "noncanonical-A3" {
                            zero_at
                        } else {
                            output_at
                        };
                        bad[at..at + 4].copy_from_slice(&2147483647u32.to_le_bytes());
                    } else {
                        let b = label
                            .strip_prefix("false-source-functional-")
                            .expect("valid pinned fixture")
                            .parse::<usize>()
                            .expect("valid pinned fixture");
                        let at = [
                            zero_at + zero_bytes,
                            zero_at + zero_bytes + input_open,
                            bad.len() - advice_open,
                        ][b] + 1;
                        let old = u32::from_le_bytes(
                            bad[at..at + 4].try_into().expect("valid pinned fixture"),
                        );
                        bad[at..at + 4].copy_from_slice(&((old + 1) % 2147483647).to_le_bytes());
                    }
                    let mut t =
                        Transcript::new(&unhex(&c["public_hex"])).expect("valid pinned fixture");
                    d.verify(&mut t, [&refs[0], &refs[1]], &bad)
                        .err()
                        .expect("valid pinned fixture")
                };
                let decision = expected["decision"].as_str().expect("valid pinned fixture");
                let cause = match decision {
                    "ValueMismatch" => "Pcs(ValueMismatch)",
                    "FinalEvaluationMismatch" => "Sumcheck(FinalEvaluationMismatch)",
                    "RoundSumMismatch" => "Sumcheck(RoundSumMismatch)",
                    other => other,
                };
                assert_eq!(format!("{:?}", failure.cause), cause, "{name} {label}");
                let expected_usage = if expected["failed_prefix_usage"].is_null() {
                    hashes(
                        Transcript::<K>::new(&unhex(&c["public_hex"]))
                            .expect("valid pinned fixture")
                            .usage(),
                    )
                } else {
                    expected["failed_prefix_usage"].clone()
                };
                assert_eq!(
                    hashes(failure.usage.transcript),
                    expected_usage,
                    "{name} {label}"
                );
                assert_eq!(
                    failure.usage.non_transcript.hash_evaluations,
                    expected["local_hashes"]
                        .as_u64()
                        .expect("valid pinned fixture"),
                    "{name} {label}"
                );
                assert_eq!(
                    failure.usage.non_transcript,
                    HashUsage {
                        hash_evaluations: expected["local_hashes"].as_u64().expect("local H"),
                        ..HashUsage::default()
                    }
                );
            }
        }
        if let Some(stale) = following.get("stale_control") {
            rejected += 1;
            let mut t = Transcript::new(&unhex(&c["public_hex"])).expect("valid pinned fixture");
            let (_record, _) = d
                .verify(&mut t, [&refs[0], &refs[1]], &wire)
                .expect("valid pinned fixture");
            let stale_proof = Proof {
                rounds: proof.rounds,
                final_values: stale["proof"]["final"]
                    .as_array()
                    .expect("valid pinned fixture")
                    .iter()
                    .map(field)
                    .collect(),
            };
            let cause = stele_sumcheck::verify_public(
                &instance,
                &stale_proof,
                &[vec![K::from_i64(1), K::from_i64(2)]],
                &mut t,
            )
            .expect_err("valid pinned fixture");
            assert_eq!(cause, stele_sumcheck::Error::FinalEvaluationMismatch);
            assert_eq!(hashes(t.usage()), stale["failed_prefix_usage"]);
        }
    }
    assert_eq!(
        (accepted, rejected),
        (5, 13),
        "complete independent corpus per field"
    );
}
#[test]
fn matches_reference_requant_full_wire_qm31() {
    run::<QM31>();
}
#[test]
fn matches_reference_requant_full_wire_om31() {
    run::<OM31>();
}

#[test]
fn rejects_requant_scoped_cqis_bindings() {
    for id in [100, 101, 109] {
        stele_negative_controls::requant::run(id).expect("actual native binding rejection");
    }
}

#[test]
fn rejects_requant_output_coefficient_at_actual_a7() {
    stele_negative_controls::requant::run_output_coefficient()
        .expect("zero output must not hide a false equality coefficient");
}

#[test]
fn rejects_requant_producer_late_arithmetic_with_exact_usage() {
    stele_negative_controls::requant::run_producer_failures()
        .expect("actual failed A3/A1 prefixes in both fields");
}
