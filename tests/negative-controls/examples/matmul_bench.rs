//! RFC-0007 A2 §6 / RFC-0018 §1: complete conditional matmul measurements.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, mem::size_of, time::Instant};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked::Limits;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{CodeField, OpeningRecord, PreparedSource, Usage, VerifiedCertificate};
use stele_reductions::matmul::{self, Statement};
use stele_sumcheck::{Dense, Instance, ScRecord, Term};

const PUBLIC: &[u8] = b"stele complete matmul measurement v1";
const MEMORY_SCOPE: &str = "actual protocol Vec capacities through closed matmul; stack, allocator, runtime, benchmark bookkeeping and subsequent diagnostic A1 excluded; whole-worker RSS separate";
type Times = BTreeMap<String, u64>;
fn timed<T>(times: &mut Times, name: impl Into<String>, call: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = call();
    *times.entry(name.into()).or_default() +=
        u64::try_from(start.elapsed().as_nanos()).expect("timer");
    value
}
fn bytes<T>(v: &Vec<T>) -> usize {
    v.capacity()
        .checked_mul(size_of::<T>())
        .expect("capacity bytes")
}
fn add(a: usize, b: usize) -> usize {
    a.checked_add(b).expect("capacity sum")
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
// A2 §6: export the actual observation fields by name, without recomputing them.
macro_rules! fields {
    ($v:expr; $($key:ident),+ $(,)?) => {{ let v = $v; json!({$((stringify!($key)):v.$key),+}) }};
}
fn hashes(h: HashUsage) -> Value {
    fields!(h; hash_evaluations, xof_requests, xof_bytes, state_updates, candidate_words, column_attempts)
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript)})
}
fn pcs_prover(w: stele_pcs::ProverWork) -> Value {
    fields!(w; proof_bytes, frame_bytes, weights_bytes, path_peak_bytes, peak_owned_bytes,
        source_elements, row_values, responses, column_bytes_copied, path_bytes_copied)
}
fn pcs_verifier(w: stele_pcs::VerifierWork) -> Value {
    let mut v = fields!(w; frame_bytes, weights_bytes, row_bytes, encoded_bytes, peak_owned_bytes,
        responses, column_bytes_authenticated, column_bytes_decoded, path_bytes_copied, encoded_values_read);
    v["encoder"] = fields!(w.encoder; peak_owned_bytes, hash_blocks, generated_rows,
        sparse_limb_additions, sparse_limb_products, initialized_symbols, copied_symbols,
        circle_calls, circle_transform_additions, circle_transform_products, twiddle_elements,
        inverse_prefix_elements, max_recursive_frames);
    v
}
fn producer(w: matmul::Work) -> Value {
    let mut v = fields!(w; context_bytes, prepared_bytes, proof_bytes, row_weights_bytes,
        dense_bytes, captured_point_bytes, column_weights_bytes, round_scratch_peak_bytes,
        fold_peak_bytes, opening_peak_bytes, peak_owned_bytes);
    v["retained_rows"] = json!(w
        .retained_rows
        .map(|r| fields!(r; source_visits, source_elements, retained_bytes)));
    v["dense"] = fields!(w.dense; dense_entries, partial_entries, round_entries, round_scratch_entries, rounds);
    v["a1"] = fields!(w.a1; round_headers_bytes, instance_bytes, final_values_bytes, final_payload_bytes, proof_bytes, peak_owned_bytes);
    v["openings"] = json!(w.openings.map(pcs_prover));
    v
}
fn verifier(w: matmul::VerifierWork) -> Value {
    let mut v = fields!(w; context_bytes, prepared_bytes, decoded_proof_bytes, restored_points_bytes,
        reduction_peak_bytes, opening_peak_bytes, peak_owned_bytes);
    v["a1"] = fields!(w.a1; instance_bytes, round_payload_bytes, final_payload_bytes, point_bytes, claims_bytes, peak_owned_bytes);
    v["openings"] = json!(w.openings.map(pcs_verifier));
    v
}
fn point<K: ChallengeField>(values: &[K]) -> Vec<Vec<u32>> {
    values
        .iter()
        .map(|v| {
            v.to_le_bytes()
                .as_ref()
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().expect("limb")))
                .collect()
        })
        .collect()
}
fn sc(r: &ScRecord) -> Value {
    fields!(r; id, m, degree, field_degree, numerator)
}
fn opening<K: ChallengeField>(o: &OpeningRecord<'_, K>) -> Value {
    let c = o.certificate();
    let p = c.parameters();
    json!({"id":o.id(),"queries":o.queries(),"kind":format!("{:?}",o.kind()),"certificate":{
        "id":hex(&c.id()),"source":hex(&c.source().bytes()),"ell":c.ell(),"degree":c.degree(),
        "kind":format!("{:?}",c.kind()),"length":p.length,"distance":p.distance,"radius":p.radius,
        "certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries}})
}
fn eq<K: ChallengeField>(point: &[K], index: usize) -> K {
    point.iter().enumerate().fold(K::from_i64(1), |v, (j, r)| {
        v * if index >> (point.len() - 1 - j) & 1 == 1 {
            *r
        } else {
            K::from_i64(1) - *r
        }
    })
}
fn measure<K: ChallengeField + CodeField + Eq>(scenario: &str, scale: &str) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut times = Times::new();
    let full = scale == "full";
    let bits: [u8; 4] = match scenario {
        "scalar" => [0, 0, 0, 0],
        "single" => {
            if full {
                [0, 4, 5, 3]
            } else {
                [0, 1, 1, 2]
            }
        }
        "stacked" => {
            if full {
                [2, 3, 4, 2]
            } else {
                [1, 1, 1, 2]
            }
        }
        "zero" => {
            if full {
                [2, 2, 4, 3]
            } else {
                [1, 1, 1, 2]
            }
        }
        _ => unreachable!("validated scenario"),
    };
    let [h, a, b, c] = bits.map(usize::from);
    let [layers, n, inner, m] = bits.map(|x| 1usize << x);
    let (logical, coordinates) = timed(&mut times, "fixture", || {
        let x = (0..layers * n * inner)
            .map(|i| M31::from_i64((i % 31) as i64 - 15))
            .collect::<Vec<_>>();
        let w = (0..layers * inner * m)
            .map(|i| {
                M31::from_i64(if scenario == "zero" {
                    0
                } else {
                    (i % 29) as i64 - 14
                })
            })
            .collect::<Vec<_>>();
        let point = (0..h + a + c)
            .map(|i| K::from_i64(2 + i as i64))
            .collect::<Vec<_>>();
        ([x, w], point)
    });
    // Expected public claim is fixed before registration/proving. No output tensor
    // or L*n*d*m witness is materialized; this fixture work is separately timed.
    let value = timed(&mut times, "expected_claim", || {
        let mut value = K::from_i64(0);
        for l in 0..layers {
            for i in 0..n {
                for j in 0..m {
                    let weight = eq(&coordinates[..h], l)
                        * eq(&coordinates[h..h + a], i)
                        * eq(&coordinates[h + a..], j);
                    let mut dot = M31::from_i64(0);
                    for k in 0..inner {
                        dot = dot
                            + logical[0][(l * n + i) * inner + k]
                                * logical[1][(l * inner + k) * m + j];
                    }
                    value = value + weight * K::from_i64(i64::from(dot.as_u32()));
                }
            }
        }
        value
    });
    let messages = timed(&mut times, "physical_layout", || {
        core::array::from_fn::<_, 2, _>(|side| {
            let rows = if side == 0 { n } else { m };
            (0..rows * layers * inner)
                .map(|index| {
                    let row = index / (layers * inner);
                    let l = index / inner % layers;
                    let k = index % inner;
                    logical[side][if side == 0 {
                        (l * n + row) * inner + k
                    } else {
                        (l * inner + k) * m + row
                    }]
                })
                .collect::<Vec<_>>()
        })
    });
    let caller = add(
        add(bytes(&messages[0]), bytes(&messages[1])),
        bytes(&coordinates),
    );
    let logical_input_bytes = [bytes(&logical[0]), bytes(&logical[1])];
    let fixture_peak = add(caller, add(logical_input_bytes[0], logical_input_bytes[1]));
    drop(logical);
    let mut live = caller;
    let mut peaks = BTreeMap::from([("fixture_layout".to_owned(), fixture_peak)]);
    let sources = core::array::from_fn::<_, 2, _>(|i| {
        let mut local = HashUsage::default();
        let p = timed(&mut times, format!("prepare/{i}"), || {
            PreparedSource::<K>::new(
                101 + i as u64,
                [bits[1], bits[3]][i],
                bits[0] + bits[2],
                1 + i as u8,
                &messages[i],
                &mut local,
            )
            .expect("preparation")
        });
        peaks.insert(format!("prepare/{i}"), add(live, p.work().peak_owned_bytes));
        live = add(
            live,
            add(p.work().encoded_columns_bytes, p.work().merkle_nodes_bytes),
        );
        let (wire, produced, pw) = timed(&mut times, format!("certificate_prove/{i}"), || {
            p.certificate_measured().expect("certificate")
        });
        peaks.insert(
            format!("certificate_prove/{i}"),
            add(live, pw.peak_owned_bytes),
        );
        live = add(live, bytes(&wire));
        let (certificate, consumed, vw) =
            timed(&mut times, format!("certificate_verify/{i}"), || {
                stele_pcs::verify_certificate_measured(*p.source(), &wire)
                    .expect("certificate verification")
            });
        peaks.insert(
            format!("certificate_verify/{i}"),
            add(live, vw.peak_owned_bytes),
        );
        assert_eq!(produced, consumed.transcript);
        (p, wire, certificate, local, produced, consumed, pw, vw)
    });
    let statement = Statement {
        id: 105,
        output_id: 103,
        coefficient_id: 104,
        inputs: [101, 102],
        bits,
        point: &coordinates,
        value,
    };
    let limits = Limits {
        descriptor_bytes: 16_000_000,
        proof_bytes: 16_000_000,
        prepared_entries: 65_536,
        partial_entries: 65_536,
        axis_entries: 65_536,
    };
    let (mut pt, mut vt) = timed(&mut times, "transcripts", || {
        (
            Transcript::<K>::new(PUBLIC).expect("transcript"),
            Transcript::<K>::new(PUBLIC).expect("transcript"),
        )
    });
    let certs = [&sources[0].2, &sources[1].2];
    let (wire, produced, pw) = timed(&mut times, "prove", || {
        matmul::prove_measured(
            &mut pt,
            &statement,
            [&sources[0].0, &sources[1].0],
            certs,
            limits,
            65_536,
        )
        .expect("matmul production")
    });
    peaks.insert("prove".into(), add(live, pw.peak_owned_bytes));
    let (record, consumed, vw) = timed(&mut times, "verify", || {
        matmul::verify_measured(&mut vt, &statement, certs, &wire, limits).expect("closed matmul")
    });
    peaks.insert(
        "verify".into(),
        add(add(live, bytes(&wire)), vw.peak_owned_bytes),
    );
    assert_eq!(produced.transcript, consumed.transcript);
    for (o, c) in record.openings().iter().zip(certs) {
        assert!(core::ptr::eq(o.certificate(), c.record()));
    }
    // A real following A1 binds its Final to the post-consumer history. It is a
    // diagnostic after the measured matmul capacity interval, never a replay.
    let (following_wire, continuation, producer_continuation) = timed(
        &mut times,
        "following_a1",
        || {
            let instance = Instance {
                id: 901,
                num_vars: 1,
                inputs: vec![902],
                terms: vec![Term {
                    coefficient: K::from_i64(1),
                    factors: vec![0],
                }],
                claimed_sum: K::from_i64(7),
            };
            let tables = vec![vec![K::from_i64(2), K::from_i64(5)]];
            let proof = stele_sumcheck::prove(
                &instance,
                Dense::new(&instance, tables.clone()).expect("following strategy"),
                &mut pt,
            )
            .expect("following proof");
            let next = stele_sumcheck::verify_public(&instance, &proof, &tables, &mut vt)
                .expect("following public consumer");
            assert_eq!(pt.usage(), vt.usage());
            let observed = vt.usage();
            let pprobe = pt
                .challenge(ChallengeLabel::Sumcheck)
                .expect("diagnostic probe");
            let vprobe = vt
                .challenge(ChallengeLabel::Sumcheck)
                .expect("diagnostic probe");
            assert!(pprobe == vprobe);
            let raw: Vec<_> = proof
                .rounds
                .iter()
                .flatten()
                .chain(&proof.final_values)
                .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
                .collect();
            (
                raw,
                json!({"decision":"accept","sc":sc(&next.sc),"point":next.point.iter().map(|v|hex(v.to_le_bytes().as_ref())).collect::<Vec<_>>(),"usage":hashes(observed),"probe":hex(vprobe.to_le_bytes().as_ref())}),
                json!({"usage":hashes(observed),"probe":hex(pprobe.to_le_bytes().as_ref())}),
            )
        },
    );
    let mut out = timed(&mut times, "observations", || {
        let originals: Vec<_> = sources.iter().enumerate().map(|(i,(p,wire,_,local,produced,consumed,pw,vw))| {
            let prep = p.work();
            json!({"message_bytes":messages[i].len()*size_of::<M31>(),"message_capacity_bytes":bytes(&messages[i]),"certificate_capacity_bytes":bytes(wire),
                "preparation":fields!(prep; borrowed_message_bytes,encoded_columns_bytes,encoder_peak_bytes,leaf_references_bytes,merkle_nodes_bytes,peak_owned_bytes),
                "preparation_hashes":hashes(*local),"producer_usage":hashes(*produced),"verifier_usage":usage(*consumed),"producer_work":pcs_prover(*pw),"verifier_work":pcs_verifier(*vw)})
        }).collect();
        let public_sources: Vec<_> = sources.iter().enumerate().map(|(i,(p,wire,_,_,_,_,_,_))|
            json!({"id":101+i,"ell":([a,c][i]),"m":h+b,"blowup":1+i,"root_hex":hex(&p.source().bytes()[73..]),"source_hex":hex(&p.source().bytes()),"certificate_hex":hex(wire)})).collect();
        json!({"scenario":scenario,"scale":scale,"field_degree":<K as CodeField>::DEGREE,
            "request":{"degree":<K as CodeField>::DEGREE,"dims":bits,"ids":[101,102,103,104,105],"point":[point(&coordinates[..h]),point(&coordinates[h..h+a]),point(&coordinates[h+a..])],"value":point(&[value])[0],"public_hex":hex(PUBLIC),"originals":public_sources,"proof_hex":hex(&wire),"following_hex":hex(&following_wire)},
            "verification":{"phase":"outer","decision":"accept","imports":sources.iter().map(|s|usage(s.5)).collect::<Vec<_>>(),"usage":usage(consumed),
                "record":{"sc":sc(record.sc()),"openings":record.openings().iter().map(opening).collect::<Vec<_>>()},
                "restored_points":record.points().map(point),"consumed_claims":record.openings().iter().zip(record.values()).map(|(o,v)|json!([o.id(),hex(v.to_le_bytes().as_ref())])).collect::<Vec<_>>(),"continuation":continuation},
            "producer_usage":usage(produced),"producer_continuation":producer_continuation,"diagnostic_probe_usage":{"producer":hashes(pt.usage()),"consumer":hashes(vt.usage())},"originals":originals,"work":{"prover":producer(pw),"verifier":verifier(vw)},
            "memory":{"scope":MEMORY_SCOPE,"caller_bytes":caller,"logical_input_bytes":logical_input_bytes,"output_point_bytes":bytes(&coordinates),"registration_retained_bytes":live,
                "phase_peak_bytes":peaks,"peak_owned_bytes":peaks.values().max().expect("nonempty peaks"),
                "stack_type_bytes":{"prepared_source":size_of::<PreparedSource<'_,K>>(),"certificate":size_of::<VerifiedCertificate<K>>(),"record":size_of::<matmul::Record<'_,K>>(),"transcript":size_of::<Transcript<K>>(),"producer_work":size_of::<matmul::Work>(),"verifier_work":size_of::<matmul::VerifierWork>()}}})
    });
    // Keep all genuine protocol owners alive through observations, then include
    // their cleanup in the timer. JSON diagnostics are outside capacity peaks.
    std::hint::black_box((&record, &wire, &sources, &messages, &coordinates));
    let cleanup = Instant::now();
    drop(record);
    drop(wire);
    drop(sources);
    drop(messages);
    drop(coordinates);
    times.insert(
        "cleanup".into(),
        u64::try_from(cleanup.elapsed().as_nanos()).expect("timer"),
    );
    out["stages_ns"] = json!(times);
    out
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() == 4
            && ["scalar", "single", "stacked", "zero"].contains(&args[1].as_str())
            && ["smoke", "full"].contains(&args[3].as_str()),
        "scenario degree scale"
    );
    let start = Instant::now();
    let mut out = match args[2].as_str() {
        "4" => measure::<QM31>(&args[1], &args[3]),
        "8" => measure::<OM31>(&args[1], &args[3]),
        _ => {
            eprintln!("field degree must be 4 or 8");
            std::process::exit(2);
        }
    };
    let total = u64::try_from(start.elapsed().as_nanos()).expect("timer");
    let stages: u64 = out["stages_ns"]
        .as_object()
        .expect("times")
        .values()
        .map(|v| v.as_u64().expect("time"))
        .sum();
    out["total_ns"] = json!(total);
    out["remainder_ns"] = json!(total.checked_sub(stages).expect("disjoint stages"));
    println!("{out}");
}
