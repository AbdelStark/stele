//! RFC-0006 A4 §§4,6 / RFC-0018 §1: complete conditional stacked measurements.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, mem::size_of, time::Instant};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{self, Claim, Limits, Order, Prepared, Statement},
};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{CodeField, PreparedSource, ProofKind, Usage};
use stele_sumcheck::{Proof, ScRecord, Term};

const PUBLIC: &[u8] = b"stele complete stacked measurement v1";
const LIMITS: Limits = Limits {
    descriptor_bytes: 1 << 28,
    proof_bytes: 1 << 28,
    prepared_entries: 1 << 24,
    partial_entries: 1 << 20,
    axis_entries: 1 << 20,
};
type Times = BTreeMap<String, u64>;
fn timed<T>(times: &mut Times, name: impl Into<String>, call: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = call();
    *times.entry(name.into()).or_default() +=
        u64::try_from(start.elapsed().as_nanos()).expect("timer");
    value
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(bytes: &[u8]) -> Value {
    // Receipt identity only, never a source of protocol randomness.
    json!({"bytes":bytes.len(),"digest":blake3::hash(bytes).to_hex().to_string()})
}
fn fields<K: Field>(values: &[K]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
        .collect()
}
fn hashes(h: HashUsage) -> Value {
    json!({"hash_evaluations":h.hash_evaluations,"xof_requests":h.xof_requests,
        "xof_bytes":h.xof_bytes,"state_updates":h.state_updates,
        "candidate_words":h.candidate_words,"column_attempts":h.column_attempts})
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"local":hashes(u.non_transcript)})
}
fn scalar<K: ChallengeField>(seed: usize) -> K
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes: Vec<_> = (0..K::DEGREE)
        .flat_map(|j| ((37 * seed + 17 * j + 9) as u32).to_le_bytes())
        .collect();
    K::from_le_bytes(K::Bytes::try_from(bytes.as_slice()).ok().expect("limbs"))
        .expect("canonical fixture")
}
fn value(source: usize, index: usize) -> M31 {
    M31::from_i64(((37 * index + 101 * source + 9) % 2147483647) as i64)
}
fn sc(sc: &ScRecord) -> Value {
    json!({"id":sc.id,"m":sc.m,"degree":sc.degree,"field_degree":sc.field_degree,"numerator":sc.numerator})
}
fn proof<K: ChallengeField>(proof: &Proof<K>, id: u64) -> Value {
    let mut wire = Vec::new();
    for (j, round) in proof.rounds.iter().enumerate() {
        wire.extend(stele_sumcheck::message_bytes(id, j as u32, round).expect("round frame"));
    }
    wire.extend(
        stele_sumcheck::message_bytes(id, proof.final_values.len() as u32, &proof.final_values)
            .expect("final frame"),
    );
    json!({"rounds":proof.rounds.len(),"finals":proof.final_values.len(),"messages":bytes(&wire),
        "field_capacity_bytes":(proof.rounds.iter().map(Vec::capacity).sum::<usize>()+proof.final_values.capacity())*size_of::<K>(),
        "round_headers_capacity_bytes":proof.rounds.capacity()*size_of::<Vec<K>>()})
}
fn measure<K: ChallengeField + CodeField + Eq>(mode: &str, order_name: &str, scale: &str) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut times = Times::new();
    let certified = mode == "certified";
    let bits = if scale == "full" {
        [4u8, 5, 5]
    } else {
        [1, 1, 1]
    };
    let row_bits = if scale == "full" {
        [4, 7, 10]
    } else {
        [0, 1, 3]
    };
    let m: u8 = bits.iter().sum();
    let n = 1usize << m;
    let order = if order_name == "first" {
        Order::LayerFirst
    } else {
        Order::LayerLast
    };
    let axes = bits.map(|bits| Axis {
        bits,
        real: 1 << bits,
    });
    let (messages, tables, selected, coefficient, terms, claim) =
        timed(&mut times, "fixture", || {
            let messages: Vec<Vec<M31>> = if certified {
                (0..3)
                    .map(|s| (0..n).map(|i| value(s, i)).collect())
                    .collect()
            } else {
                vec![]
            };
            let tables: Vec<Vec<K>> = if certified {
                vec![]
            } else {
                (0..3)
                    .map(|s| {
                        (0..n)
                            .map(|i| K::from_i64(i64::from(value(s, i).as_u32())))
                            .collect()
                    })
                    .collect()
            };
            let selected: Vec<K> = (0..bits[0]).map(|i| scalar(17 + usize::from(i))).collect();
            let coefficient: Vec<_> = (0..1usize << (m - bits[0]))
                .map(|i| M31::from_i64((13 * i + 7) as i64))
                .collect();
            let terms = [
                Term {
                    coefficient: K::from_i64(3),
                    factors: vec![0, 0, 0],
                },
                Term {
                    coefficient: K::from_i64(0),
                    factors: vec![2],
                },
            ];
            let claim = (0..n).fold(K::from_i64(0), |sum, i| {
                let a = selected.iter().enumerate().fold(
                    K::from_i64(i64::from(coefficient[i % coefficient.len()].as_u32())),
                    |a, (j, z)| {
                        a * if i >> (usize::from(m) - j - 1) & 1 == 1 {
                            *z
                        } else {
                            K::from_i64(1) - *z
                        }
                    },
                );
                let x = K::from_i64(i64::from(value(0, i).as_u32()));
                sum + a * K::from_i64(3) * x * x * x
            });
            (messages, tables, selected, coefficient, terms, claim)
        });
    let statement = Statement {
        id: 71,
        axes: &axes,
        order,
        output: Claim {
            id: 17,
            axes: &[],
            point: &[],
            value: claim,
        },
        coefficient_id: 99,
        inputs: &[41, 42, 43],
        terms: &terms,
        selectors: &[Some(&selected), None, None],
        kind: Kind::RopeTables {
            axes: &[1, 2],
            values: &coefficient,
        },
        source_id: Some(119),
    };
    let mut materials = Vec::new();
    let mut certificates = Vec::new();
    let mut certificate_proofs = Vec::new();
    let mut sources = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        let mut local = HashUsage::default();
        let p = timed(&mut times, format!("prepare/{i}"), || {
            PreparedSource::<K>::new(
                41 + i as u64,
                row_bits[i],
                m - row_bits[i],
                1,
                message,
                &mut local,
            )
            .expect("prepare")
        });
        let (wire, produced) = timed(&mut times, format!("certificate_prove/{i}"), || {
            p.certificate().expect("certificate producer")
        });
        let (c, used) = timed(&mut times, format!("certificate_verify/{i}"), || {
            stele_pcs::verify_certificate(*p.source(), &wire).expect("certificate consumer")
        });
        timed(&mut times, "observations", || {
            assert_eq!(produced, used.transcript);
            assert_eq!(c.record().kind(), ProofKind::Certificate);
            let w = p.work();
            let q = c.record().parameters();
            sources.push(json!({"id":41+i,"context":hex(&c.record().source().bytes()),"certificate_id":hex(&c.record().id()),
                "row_bits":c.record().ell(),"field_degree":c.record().degree(),"kind":format!("{:?}",c.record().kind()),
                "parameters":{"length":q.length,"distance":q.distance,"radius":q.radius,"certificate_queries":q.certificate_queries,"opening_queries":q.opening_queries},
                "certificate":bytes(&wire),"certificate_capacity_bytes":wire.capacity(),"producer":hashes(produced),"verifier":usage(used),"preparation_hashes":hashes(local),
                "preparation":{"borrowed_message_bytes":w.borrowed_message_bytes,"encoded_columns_bytes":w.encoded_columns_bytes,
                    "encoder_peak_bytes":w.encoder_peak_bytes,"leaf_references_bytes":w.leaf_references_bytes,
                    "merkle_nodes_bytes":w.merkle_nodes_bytes,"peak_owned_bytes":w.peak_owned_bytes},
                "point_weight_entries":p.source().rows()+p.source().columns()}));
        });
        materials.push(p);
        certificates.push(c);
        certificate_proofs.push(wire);
    }
    let (mut producer, mut consumer) = timed(&mut times, "transcripts", || {
        (
            Transcript::<K>::new(PUBLIC).expect("producer"),
            Transcript::<K>::new(PUBLIC).expect("consumer"),
        )
    });
    let sumcheck;
    let opening_proofs;
    let produced;
    let consumed;
    let work;
    let record;
    if certified {
        let material: Vec<_> = materials.iter().collect();
        let handles: Vec<_> = certificates.iter().collect();
        let (p, u, w) = timed(&mut times, "produce", || {
            stele_reductions::prove_stacked_sources_measured(
                &mut producer,
                &statement,
                &material,
                &handles,
                LIMITS,
            )
            .expect("closed producer")
        });
        sumcheck = p.sumcheck;
        opening_proofs = p.openings;
        produced = u;
        work = w;
        let opens: Vec<_> = opening_proofs.iter().map(Vec::as_slice).collect();
        let (r, u) = timed(&mut times, "verify", || {
            stele_reductions::verify_stacked_sources(
                &mut consumer,
                &statement,
                &handles,
                &sumcheck,
                &opens,
                LIMITS,
            )
            .expect("closed consumer")
        });
        consumed = u;
        record = timed(&mut times, "observations", || {
            assert_eq!(r.openings().len(), 3);
            let openings:Vec<_>=r.openings().iter().zip(&certificates).zip(&opening_proofs).enumerate().map(|(i,((r,c),p))| {
                assert_eq!(r.id(),41+i as u64); assert!(std::ptr::eq(r.certificate(),c.record())); assert_eq!(r.kind(),ProofKind::Opening);
                json!({"id":r.id(),"queries":r.queries(),"kind":format!("{:?}",r.kind()),"certificate_id":hex(&r.certificate().id()),"wire":bytes(p),"capacity_bytes":p.capacity()})
            }).collect();
            json!({"sc":sc(r.sc()),"openings":openings,"claims":[]})
        });
    } else {
        let table_refs: Vec<_> = tables.iter().map(Vec::as_slice).collect();
        let (p, w) = timed(&mut times, "produce", || {
            stacked::prove_public_measured(&mut producer, &statement, &table_refs, LIMITS)
                .expect("public producer")
        });
        sumcheck = p;
        opening_proofs = vec![];
        work = w;
        produced = Usage {
            transcript: producer.usage(),
            non_transcript: HashUsage::default(),
        };
        let (r, u) = timed(&mut times, "verify", || {
            stacked::verify_public(&mut consumer, &statement, &sumcheck, &table_refs, LIMITS)
                .expect("public consumer")
        });
        consumed = Usage {
            transcript: u,
            non_transcript: HashUsage::default(),
        };
        record = timed(&mut times, "observations", || {
            assert_eq!(
                r.claims().iter().map(|x| x.0).collect::<Vec<_>>(),
                vec![41, 42, 43]
            );
            let claims: Vec<_> = r
                .claims()
                .iter()
                .map(|(id, value)| json!({"id":id,"value":hex(value.to_le_bytes().as_ref())}))
                .collect();
            json!({"sc":sc(r.sc()),"openings":[],"claims":claims})
        });
    }
    let (framing, a1, inputs, continuation) = timed(&mut times, "observations", || {
        assert_eq!(produced.transcript, consumed.transcript);
        assert_eq!(consumer.usage(), consumed.transcript);
        assert_eq!(produced.non_transcript, HashUsage::default());
        let expected_local: u64 = certificates
            .iter()
            .map(|c| {
                u64::from(c.record().source().queries(ProofKind::Opening))
                    * (1 + c.record().source().path_height() as u64)
            })
            .sum();
        assert_eq!(consumed.non_transcript.hash_evaluations, expected_local);
        assert_eq!(
            record["sc"],
            json!({"id":71,"m":m,"degree":4,"field_degree":<K as CodeField>::DEGREE,"numerator":u64::from(m)*4})
        );
        assert_eq!(work.rounds, usize::from(m));
        assert_eq!(sumcheck.final_values.len(), 4);
        let next = producer
            .challenge(ChallengeLabel::Sumcheck)
            .expect("producer next");
        let consumer_next = consumer
            .challenge(ChallengeLabel::Sumcheck)
            .expect("consumer next");
        assert!(next == consumer_next);
        // Reconstruct expected frames for receipt identity only; no replay or Dense allocation.
        let prepared = if certified {
            Prepared::for_certified_sources(&statement, LIMITS)
        } else {
            Prepared::new(&statement, LIMITS)
        }
        .expect("expected framing");
        let bound = if certified {
            let mut b = vec![1, 1];
            b.extend(71u64.to_le_bytes());
            b.extend(3u32.to_le_bytes());
            for c in &certificates {
                b.extend(c.record().source().bytes());
                b.extend(c.record().id());
            }
            b
        } else {
            prepared
                .source_bytes(&tables.iter().map(Vec::as_slice).collect::<Vec<_>>())
                .expect("public framing")
        };
        let inputs:Vec<_>=(0..3).map(|i|json!({"id":41+i,
            "canonical":bytes(&if certified {fields(&messages[i])} else {fields(&tables[i])}),
            "capacity_bytes":if certified {messages[i].capacity()*size_of::<M31>()} else {tables[i].capacity()*size_of::<K>()}})).collect();
        (
            json!({"stack":bytes(prepared.bytes()),"sources":bytes(&bound),"instance":bytes(&prepared.instance().encode().expect("instance"))}),
            proof(&sumcheck, 71),
            inputs,
            json!({"producer":hex(next.to_le_bytes().as_ref()),"consumer":hex(consumer_next.to_le_bytes().as_ref())}),
        )
    });
    std::hint::black_box((
        &messages,
        &tables,
        &selected,
        &coefficient,
        &terms,
        &materials,
        &certificates,
        &certificate_proofs,
        &sumcheck,
        &opening_proofs,
    ));
    json!({"mode":mode,"order":order_name,"field_degree":<K as CodeField>::DEGREE,"scale":scale,
        "axes":axes.map(|a|json!({"bits":a.bits,"real":a.real})),"claim":hex(claim.to_le_bytes().as_ref()),
        "coefficient":bytes(&fields(&coefficient)),"selector":hex(&fields(&selected)),"inputs":inputs,
        "backing_capacity_bytes":{"selector":selected.capacity()*size_of::<K>(),"coefficient":coefficient.capacity()*size_of::<M31>(),"term_factors":terms.iter().map(|t|t.factors.capacity()*size_of::<u32>()).sum::<usize>()},
        "framing":framing,"sources":sources,"record":record,"a1":a1,
        "dense":{"dense_entries":work.dense_entries,"partial_entries":work.partial_entries,"round_entries":work.round_entries,"round_scratch_entries":work.round_scratch_entries,"rounds":work.rounds},
        "producer_usage":usage(produced),"consumer_usage":usage(consumed),"continuation":continuation,"stages_ns":times})
    // All protocol buffers drop before this function returns to the inclusive timer.
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 4
            && ["public", "certified"].contains(&args[0].as_str())
            && ["first", "last"].contains(&args[1].as_str())
            && ["full", "smoke"].contains(&args[3].as_str()),
        "mode order field scale"
    );
    let start = Instant::now();
    let mut receipt = match args[2].as_str() {
        "4" => measure::<QM31>(&args[0], &args[1], &args[3]),
        "8" => measure::<OM31>(&args[0], &args[1], &args[3]),
        _ => {
            eprintln!("expected field 4 or 8");
            std::process::exit(2);
        }
    };
    let total = u64::try_from(start.elapsed().as_nanos()).expect("timer");
    let measured: u64 = receipt["stages_ns"]
        .as_object()
        .expect("stages")
        .values()
        .map(|v| v.as_u64().expect("time"))
        .sum();
    receipt["total_ns"] = json!(total);
    receipt["remainder_ns"] = json!(total.checked_sub(measured).expect("disjoint timings"));
    println!("{}", serde_json::to_string(&receipt).expect("receipt"));
}
