//! RFC-0010 A9 §§3–6,9 / RFC-0018 §1: complete native PCS and closed A1 measurements.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Instant};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{CodeField, Functional, OpeningRecord, PreparedSource, Usage, VerifiedCertificate};
use stele_sumcheck::{Dense, Instance, Term};

const PUBLIC: &[u8] = b"stele field PCS complete measurement v1";
type Times = BTreeMap<&'static str, u64>;
fn timed<T>(times: &mut Times, name: &'static str, call: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = call();
    *times.entry(name).or_default() += u64::try_from(start.elapsed().as_nanos()).expect("timer");
    value
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    // Receipt identity only. Protocol randomness comes exclusively from Transcript.
    blake3::hash(bytes).to_hex().to_string()
}
fn hashes(h: HashUsage) -> Value {
    json!({"hash_evaluations":h.hash_evaluations,"xof_requests":h.xof_requests,
        "xof_bytes":h.xof_bytes,"state_updates":h.state_updates,
        "candidate_words":h.candidate_words,"column_attempts":h.column_attempts})
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"local":hashes(u.non_transcript)})
}
fn coefficient<K: ChallengeField>(seed: usize) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes: Vec<_> = (0..K::DEGREE)
        .flat_map(|k| ((37 * seed + 17 * k + 9) as u32).to_le_bytes())
        .collect();
    K::from_le_bytes(
        K::Bytes::try_from(bytes.as_slice())
            .ok()
            .expect("field bytes"),
    )
    .expect("canonical coefficient")
}
fn bundle<K: ChallengeField>(certificates: &[VerifiedCertificate<K>]) -> Vec<u8> {
    let mut bytes = 71u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(certificates.len() as u32).to_le_bytes());
    for c in certificates {
        bytes.extend_from_slice(&c.record().source().bytes());
        bytes.extend_from_slice(&c.record().id());
    }
    bytes
}
fn opening_record<K: ChallengeField>(record: &OpeningRecord<'_, K>, proof: &Vec<u8>) -> Value {
    json!({"id":record.id(),"queries":record.queries(),
        "certificate_id":hex(&record.certificate().id()),"bytes":proof.len(),
        "capacity_bytes":proof.capacity(),"digest":digest(proof)})
}

fn measure<K: ChallengeField + CodeField + Eq>(mode: &str, ell: u8, m: u8, blowup: u8) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut times = Times::new();
    let count = if mode == "a1" { 3 } else { 1 };
    let (rows, columns) = (1usize << ell, 1usize << m);
    let messages: Vec<Vec<_>> = timed(&mut times, "fixture", || {
        (0..count)
            .map(|s| {
                (0..rows * columns)
                    .map(|i| M31::from_i64(((37 * i + 101 * s + 9) % 2147483647) as i64))
                    .collect()
            })
            .collect()
    });
    let mut sources = Vec::new();
    let mut prepared = Vec::new();
    let mut certificate_bytes = Vec::new();
    let mut certificates = Vec::new();
    for (s, message) in messages.iter().enumerate() {
        let mut work = HashUsage::default();
        let p = timed(&mut times, "prepare", || {
            PreparedSource::<K>::new(41 + s as u64, ell, m, blowup, message, &mut work)
                .expect("prepare")
        });
        let (bytes, producer) = timed(&mut times, "certificate_prove", || {
            p.certificate().expect("certificate")
        });
        let (certificate, verifier) = timed(&mut times, "certificate_verify", || {
            stele_pcs::verify_certificate(*p.source(), &bytes).expect("certificate consumer")
        });
        assert_eq!(producer, verifier.transcript);
        let w = p.work();
        let parameters = certificate.record().parameters();
        sources.push(json!({"id":41+s,"source_bytes":hex(&p.source().bytes()),
            "certificate_id":hex(&certificate.record().id()),"certificate_bytes":bytes.len(),
            "certificate_capacity_bytes":bytes.capacity(),"certificate_digest":digest(&bytes),
            "certificate_prove":hashes(producer),"certificate_verify":usage(verifier),
            "preparation_hashes":hashes(work),"input_capacity_bytes":message.capacity()*4,
            "queries_certificate":parameters.certificate_queries,"queries_opening":parameters.opening_queries,
            "preparation":{"borrowed_message_bytes":w.borrowed_message_bytes,
                "encoded_columns_bytes":w.encoded_columns_bytes,"encoder_peak_bytes":w.encoder_peak_bytes,
                "leaf_references_bytes":w.leaf_references_bytes,"merkle_nodes_bytes":w.merkle_nodes_bytes,
                "peak_owned_bytes":w.peak_owned_bytes}}));
        prepared.push(p);
        certificate_bytes.push(bytes);
        certificates.push(certificate);
    }
    let (mut producer, mut consumer) = timed(&mut times, "transcripts", || {
        (
            Transcript::<K>::new(PUBLIC).expect("producer"),
            Transcript::<K>::new(PUBLIC).expect("consumer"),
        )
    });
    let mut proofs = Vec::new();
    let mut openings = Vec::new();
    let mut a1 = Value::Null;
    let consumer_usage;
    if mode == "a1" {
        let (instance, dense, bound) = timed(&mut times, "a1_setup", || {
            let coefficient = coefficient::<K>(17);
            let instance = Instance {
                id: 71,
                num_vars: u32::from(ell + m),
                inputs: vec![41, 42, 43],
                terms: vec![
                    Term {
                        coefficient,
                        factors: vec![0],
                    },
                    Term {
                        coefficient: K::from_i64(0),
                        factors: vec![2],
                    },
                ],
                claimed_sum: messages[0].iter().fold(K::from_i64(0), |v, x| {
                    v + K::from_i64(i64::from(x.as_u32()))
                }) * coefficient,
            };
            let tables = messages
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|x| K::from_i64(i64::from(x.as_u32())))
                        .collect()
                })
                .collect();
            let dense = Dense::new(&instance, tables).expect("dense originals");
            (instance, dense, bundle(&certificates))
        });
        let proof = timed(&mut times, "a1_prove", || {
            producer
                .absorb(AbsorbLabel::FieldSources, &bound)
                .expect("bind originals");
            stele_sumcheck::prove(&instance, dense, &mut producer).expect("A1 producer")
        });
        // A1's public producer does not return its point: charge this full replay.
        let (reduction, replay_usage) = timed(&mut times, "a1_replay", || {
            let mut replay = Transcript::<K>::new(PUBLIC).expect("replay");
            replay
                .absorb(AbsorbLabel::FieldSources, &bound)
                .expect("replay bundle");
            let r = stele_sumcheck::verify(&instance, &proof, &mut replay).expect("A1 replay");
            assert_eq!(producer.usage(), replay.usage());
            (r, replay.usage())
        });
        let (a, b) = timed(&mut times, "coefficients", || {
            (
                stele_poly::eq_table(&reduction.point[..ell as usize]).expect("row weights"),
                stele_poly::eq_table(&reduction.point[ell as usize..]).expect("column weights"),
            )
        });
        let mut producer_snapshots = Vec::new();
        for ((p, c), (id, value)) in prepared.iter().zip(&certificates).zip(&reduction.claims) {
            let (bytes, used) = timed(&mut times, "opening_prove", || {
                p.opening(
                    &mut producer,
                    c,
                    Functional {
                        id: *id,
                        a: &a,
                        b: &b,
                        value: *value,
                    },
                )
                .expect("original opening")
            });
            producer_snapshots.push(usage(used));
            proofs.push(bytes);
        }
        let cert_refs: Vec<_> = certificates.iter().collect();
        let proof_refs: Vec<_> = proofs.iter().map(Vec::as_slice).collect();
        let (record, used) = timed(&mut times, "closed_verify", || {
            stele_reductions::verify_field_sources(
                &mut consumer,
                &instance,
                &cert_refs,
                &proof,
                &proof_refs,
            )
            .expect("complete actual A1 consumer")
        });
        consumer_usage = used;
        timed(&mut times, "validation", || {
            assert_eq!(record.sc(), &reduction.sc);
            assert_eq!(record.openings().len(), certificates.len());
            for ((r, c), bytes) in record.openings().iter().zip(&certificates).zip(&proofs) {
                assert!(std::ptr::eq(r.certificate(), c.record()));
                openings.push(opening_record(r, bytes));
            }
            let mut messages = Vec::new();
            for (i, round) in proof.rounds.iter().enumerate() {
                messages.extend(
                    stele_sumcheck::message_bytes(instance.id, i as u32, round)
                        .expect("round frame"),
                );
            }
            messages.extend(
                stele_sumcheck::message_bytes(
                    instance.id,
                    instance.inputs.len() as u32,
                    &proof.final_values,
                )
                .expect("final frame"),
            );
            let sc = record.sc();
            a1 = json!({"bundle_bytes":bound.len(),"bundle_digest":digest(&bound),
                "instance_bytes":instance.encode().expect("instance frame").len(),
                "instance_digest":digest(&instance.encode().expect("instance frame")),
                "message_bytes":messages.len(),"message_digest":digest(&messages),
                "rounds":proof.rounds.len(),"finals":proof.final_values.len(),
                "replay_usage":hashes(replay_usage),"opening_producer_snapshots":producer_snapshots,
                "sc":{"id":sc.id,"m":sc.m,"degree":sc.degree,"field_degree":sc.field_degree,"numerator":sc.numerator}});
        });
    } else {
        let mut local = HashUsage::default();
        for index in 0..2 {
            let (a, b, value) = timed(&mut times, "coefficients", || {
                let a: Vec<_> = (0..rows).map(|i| coefficient::<K>(i + index + 1)).collect();
                let b: Vec<_> = (0..columns)
                    .map(|i| coefficient::<K>(i + index + 7))
                    .collect();
                let mut value = K::from_i64(0);
                for (r, a) in a.iter().enumerate() {
                    for (c, b) in b.iter().enumerate() {
                        value = value
                            + *a * *b
                                * K::from_i64(i64::from(messages[0][r * columns + c].as_u32()));
                    }
                }
                (a, b, value)
            });
            let functional = Functional {
                id: 100 + index as u64,
                a: &a,
                b: &b,
                value,
            };
            let (bytes, producer_usage) = timed(&mut times, "opening_prove", || {
                prepared[0]
                    .opening(&mut producer, &certificates[0], functional)
                    .expect("functional producer")
            });
            let (record, used) = timed(&mut times, "opening_verify", || {
                stele_pcs::verify_opening(&mut consumer, &certificates[0], functional, &bytes)
                    .expect("functional consumer")
            });
            timed(&mut times, "validation", || {
                assert!(std::ptr::eq(record.certificate(), certificates[0].record()));
                assert_eq!(producer_usage.transcript, used.transcript);
                local.hash_evaluations += used.non_transcript.hash_evaluations;
                let mut entry = opening_record(&record, &bytes);
                entry["producer_usage"] = usage(producer_usage);
                entry["verifier_usage"] = usage(used);
                openings.push(entry);
            });
            proofs.push(bytes); // Retain both complete opening proofs through the second consumer.
        }
        consumer_usage = Usage {
            transcript: consumer.usage(),
            non_transcript: local,
        };
    }
    let (producer_continuation, consumer_continuation) = timed(&mut times, "validation", || {
        assert_eq!(producer.usage(), consumer_usage.transcript);
        assert_eq!(consumer.usage(), consumer_usage.transcript);
        let a = producer
            .challenge(ChallengeLabel::Sumcheck)
            .expect("producer continuation");
        let b = consumer
            .challenge(ChallengeLabel::Sumcheck)
            .expect("consumer continuation");
        assert!(a == b);
        (hex(a.to_le_bytes().as_ref()), hex(b.to_le_bytes().as_ref()))
    });
    // Keep the declared caller schedule observable to the optimizing benchmark build.
    std::hint::black_box((
        &messages,
        &prepared,
        &certificate_bytes,
        &certificates,
        &proofs,
    ));
    json!({"mode":mode,"ell":ell,"m":m,"blowup":blowup,"degree":<K as CodeField>::DEGREE,
        "source_count":count,"sources":sources,"openings":openings,"a1":a1,
        "consumer_usage":usage(consumer_usage),"producer_continuation":producer_continuation,
        "consumer_continuation":consumer_continuation,"stages_ns":times})
    // All retained messages, prepared storage, certificates and proof Vecs drop before return.
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 5, "mode ell m blowup degree");
    let (mode, ell, m, b, d) = (
        args[0].as_str(),
        args[1].parse::<u8>().expect("ell"),
        args[2].parse::<u8>().expect("m"),
        args[3].parse::<u8>().expect("blowup"),
        args[4].parse::<u8>().expect("degree"),
    );
    assert!(matches!(mode, "primitive" | "a1") && matches!(b, 1 | 2));
    assert!(if mode == "a1" {
        (ell, m) == (2, 1)
    } else {
        matches!((ell, m), (0, 0) | (2, 1) | (4, 12) | (12, 4))
    });
    let start = Instant::now();
    let mut receipt = match d {
        4 => measure::<QM31>(mode, ell, m, b),
        8 => measure::<OM31>(mode, ell, m, b),
        _ => unreachable!("field degree"),
    };
    receipt["total_ns"] =
        json!(u64::try_from(start.elapsed().as_nanos()).expect("inclusive timer"));
    let stages: u64 = receipt["stages_ns"]
        .as_object()
        .expect("stages")
        .values()
        .map(|v| v.as_u64().expect("stage duration"))
        .sum();
    receipt["remainder_ns"] = json!(receipt["total_ns"].as_u64().expect("total") - stages);
    println!("{receipt}");
}
