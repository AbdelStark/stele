//! RFC-0023 §6 / RFC-0018 §1: complete bounded Requant resource observations.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, mem::size_of, time::Instant};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{CodeField, PreparedSource};
use stele_reductions::{
    lookup::TableField,
    requant::{Descriptor, Format, Limits, ProducerLimits, Schema, Statement},
};
use stele_sumcheck::{Dense, Instance, Term};
#[path = "../requant/records.rs"]
mod records;
use records::{fields, hashes, hex, lookup, opening, sc, usage};

const PUBLIC: &[u8] = b"stele complete requant measurement v1";
const STAGE: u32 = 41;
const BASE: u64 = (STAGE as u64) << 40;
const MEMORY_SCOPE: &str = "actual retained witness and scoped producer/verifier Vec capacities; excludes metadata, A3/A1 internal scratch and PCS opening scratch; no combined heap peak; complete fresh-worker RSS separate";
type Times = BTreeMap<String, u64>;
fn timed<T>(times: &mut Times, name: impl Into<String>, call: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = call();
    assert!(times
        .insert(
            name.into(),
            u64::try_from(start.elapsed().as_nanos()).expect("timer")
        )
        .is_none());
    result
}
macro_rules! observed {
    ($v:expr; $($key:ident),+ $(,)?) => {{ let v = $v; json!({$((stringify!($key)):v.$key),+}) }};
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
fn reduction<K: ChallengeField>(r: &stele_sumcheck::Reduction<K>) -> Value {
    json!({"sc":sc(&r.sc),"point":fields(&r.point),
        "claims":r.claims.iter().map(|(id,v)|json!([id,fields(&[*v])[0]])).collect::<Vec<_>>()})
}
fn measure<K: ChallengeField + CodeField + TableField + Eq>(scenario: &str) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut times = Times::new();
    let (mantissa, shift, bits, inputs, repetitions, advice_blowup, input_blowup): (
        u32,
        u32,
        u8,
        Vec<i32>,
        u8,
        u8,
        u8,
    ) = match scenario {
        "scalar" => (1, 0, 8, vec![-128], 1, 1, 1),
        "ties" => (1, 1, 8, vec![-1, 0, 1], 2, 2, 1),
        "wide" => (65535, 32, 16, vec![i32::MIN, 0, i32::MAX], 2, 1, 1),
        "shift62" => (65535, 62, 16, vec![i32::MIN, i32::MAX], 1, 2, 1),
        "radix255" => (255, 8, 8, vec![-128, 0, 127], 1, 1, 2),
        "radix256" => (256, 8, 16, vec![-32768, 0, 32767], 2, 2, 1),
        _ => unreachable!("validated scenario"),
    };
    let n = inputs.len();
    let padded = n.next_power_of_two();
    let m = padded.ilog2() as u8;
    let schema = timed(&mut times, "schema", || {
        Schema::new(
            mantissa,
            shift,
            if bits == 8 {
                Format::Int8
            } else {
                Format::Int16
            },
        )
        .expect("schema")
    });
    let witness = timed(&mut times, "witness", || {
        schema.witness(&inputs, 4096).expect("witness")
    });
    let (point, value) = timed(&mut times, "expected_claim", || {
        let point: Vec<_> = (0..m).map(|j| K::from_i64(2 + i64::from(j))).collect();
        let value = witness
            .output()
            .iter()
            .enumerate()
            .fold(K::from_i64(0), |v, (i, y)| {
                v + eq(&point, i) * K::from_i64(i64::from(*y))
            });
        (point, value)
    });
    let mut preparations = [HashUsage::default(); 2];
    let sources = core::array::from_fn::<_, 2, _>(|i| {
        let p = timed(&mut times, format!("prepare/{i}"), || {
            PreparedSource::<K>::new(
                [73, BASE + 2][i],
                [2, schema.rows().ilog2() as u8][i],
                m,
                [input_blowup, advice_blowup][i],
                [witness.input(), witness.advice()][i],
                &mut preparations[i],
            )
            .expect("preparation")
        });
        let (wire, produced, work) = timed(&mut times, format!("certificate_prove/{i}"), || {
            p.certificate_measured().expect("certificate")
        });
        let (certificate, consumed, verify_work) =
            timed(&mut times, format!("certificate_import/{i}"), || {
                stele_pcs::verify_certificate_measured(*p.source(), &wire)
                    .expect("certificate import")
            });
        assert_eq!(produced, consumed.transcript);
        (p, wire, certificate, produced, consumed, work, verify_work)
    });
    let descriptor = timed(&mut times, "expected_descriptor", || {
        Descriptor::new(
            Statement {
                stage: STAGE,
                n: n as u64,
                schema: &schema,
                repetitions,
                advice_blowup,
                point: &point,
                value,
                input: &sources[0].2,
            },
            &sources[1].2,
            Limits {
                positions: 4096,
                public_bytes: 32_000_000,
                proof_bytes: 32_000_000,
            },
        )
        .expect("descriptor")
    });
    let limits = ProducerLimits {
        public_bytes: descriptor.producer_public_bytes().expect("public bound"),
        dense_elements: descriptor.producer_dense_elements().expect("dense bound"),
    };
    let (mut pt, mut vt) = timed(&mut times, "transcripts", || {
        (
            Transcript::<K>::new(PUBLIC).expect("transcript"),
            Transcript::<K>::new(PUBLIC).expect("transcript"),
        )
    });
    let (wire, produced, pw) = timed(&mut times, "prove", || {
        descriptor
            .prove_measured(
                &mut pt,
                [&sources[0].0, &sources[1].0],
                &sources[1].1,
                limits,
            )
            .expect("complete producer")
    });
    let (handles, imports) = timed(&mut times, "multiplicity_imports", || {
        descriptor
            .register_multiplicities(&wire, 32_000_000)
            .expect("multiplicity imports")
    });
    let refs = handles.each_ref().map(|h| h.iter().collect::<Vec<_>>());
    let (record, consumed, vw) = timed(&mut times, "closed_relation", || {
        descriptor
            .verify_measured(&mut vt, [&refs[0], &refs[1]], &wire)
            .expect("closed consumer")
    });
    assert_eq!(produced.transcript, consumed.transcript);
    for (i, g) in record.groups().iter().enumerate() {
        assert!(core::ptr::eq(
            g.opening().certificate(),
            sources[usize::from(i != 0)].2.record()
        ));
    }
    let (following, continuation) = timed(&mut times, "continuation", || {
        let instance = Instance {
            id: BASE + (1 << 29),
            num_vars: 1,
            inputs: vec![BASE + (1 << 29) + 1],
            terms: vec![Term {
                coefficient: K::from_i64(1),
                factors: vec![0],
            }],
            claimed_sum: K::from_i64(3),
        };
        let tables = vec![vec![K::from_i64(1), K::from_i64(2)]];
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
        let pp = pt.challenge(ChallengeLabel::Sumcheck).expect("probe");
        let vp = vt.challenge(ChallengeLabel::Sumcheck).expect("probe");
        assert!(pp == vp);
        let wire: Vec<_> = proof
            .rounds
            .iter()
            .flatten()
            .chain(&proof.final_values)
            .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
            .collect();
        (
            wire,
            json!({"record":{"sc":sc(&next.sc),"point":fields(&next.point)},"usage":hashes(observed),"probe":hex(vp.to_le_bytes().as_ref())}),
        )
    });
    let mut result = timed(&mut times, "observations", || {
        let zero = record.zerocheck();
        let zero_sc: Vec<_> = zero
            .sc
            .iter()
            .enumerate()
            .map(|(phase, r)| {
                let mut v = sc(r);
                v["phase"] = json!(phase);
                v
            })
            .collect();
        let originals:Vec<_> = sources.iter().enumerate().map(|(i,(p,packet,_,prod,imp,cp,cv))| {
            let mut verifier=observed!(cv;frame_bytes,weights_bytes,row_bytes,encoded_bytes,peak_owned_bytes,responses,column_bytes_authenticated,column_bytes_decoded,path_bytes_copied,encoded_values_read);
            verifier["encoder"]=observed!(cv.encoder;peak_owned_bytes,hash_blocks,generated_rows,sparse_limb_additions,sparse_limb_products,initialized_symbols,copied_symbols,circle_calls,circle_transform_additions,circle_transform_products,twiddle_elements,inverse_prefix_elements,max_recursive_frames);
            json!({"message_bytes":([witness.input().len(),witness.advice().len()][i]*4),"certificate_bytes":packet.len(),
                "preparation":observed!(p.work();borrowed_message_bytes,encoded_columns_bytes,encoder_peak_bytes,leaf_references_bytes,merkle_nodes_bytes,peak_owned_bytes),
                "preparation_hashes":hashes(preparations[i]),"producer_usage":hashes(*prod),"verifier_usage":usage(*imp),
                "certificate_producer":observed!(cp;proof_bytes,frame_bytes,weights_bytes,path_peak_bytes,peak_owned_bytes,source_elements,row_values,responses,column_bytes_copied,path_bytes_copied),
                "certificate_verifier":verifier})
        }).collect();
        json!({"scenario":scenario,"field_degree":<K as CodeField>::DEGREE,
            "request":{"degree":<K as CodeField>::DEGREE,"stage":STAGE,"n":n,"parameters":{"mantissa":mantissa,"shift":shift,"bits":bits},"repetitions":repetitions,"advice_blowup":advice_blowup,"point":fields(&point),"value":fields(&[value])[0],"public_hex":hex(PUBLIC),
                "input":{"id":73,"blowup":input_blowup,"root_hex":hex(&sources[0].0.source().root()),"source_hex":hex(&sources[0].0.source().bytes()),"certificate_hex":hex(&sources[0].1)},"proof_hex":hex(&wire),"following_hex":hex(&following)},
            "verification":{"imports":{"input":usage(sources[0].4),"advice":usage(sources[1].4),"multiplicities":imports.map(|r|r.map(|u|u.map(usage)))},"usage":usage(consumed),
                "record":{"lookups":record.lookups().iter().map(lookup).collect::<Vec<_>>(),
                    "zero":{"claims":zero.claims.iter().map(|c|json!([c.tensor,fields(&c.point),fields(&[c.value])[0]])).collect::<Vec<_>>(),"sc":zero_sc},"output":reduction(record.output()),
                    "groups":record.groups().iter().map(|g|json!({"point":fields(g.point()),"claims":g.claims().iter().map(|(r,id,v)|json!([r,id,fields(&[*v])[0]])).collect::<Vec<_>>(),"opening":opening(g.opening())})).collect::<Vec<_>>(),
                    "rlc":record.rlc().iter().map(|r|json!({"stage":r.stage(),"phase":r.phase(),"field_degree":r.field_degree(),"count":r.weights().len(),"numerator":r.numerator(),"weights":fields(r.weights())})).collect::<Vec<_>>()},"continuation":continuation},
            "producer_usage":{"transcript":hashes(produced.transcript),"non_transcript":hashes(produced.non_transcript),"registrations":produced.registrations.map(|r|r.map(|u|u.map(|u|json!({"production":hashes(u.production),"verification":usage(u.verification)}))))},
            "diagnostic_probe_usage":{"producer":hashes(pt.usage()),"consumer":hashes(vt.usage())},"originals":originals,
            "work":{"prover":observed!(pw;proof_bytes,aggregate_tables_bytes,aggregate_point_bytes,output_tables_bytes,output_point_bytes,group_coefficients_bytes),"verifier":observed!(vw;group_coefficients_bytes),
                "lookups":pw.lookups.map(|w|observed!(w;proof_bytes,units_bytes,index_bytes,group_weights_bytes,mu_values_bytes,mu_limbs_bytes,originals_bytes,selector_bytes,prepared_bytes,coefficients_bytes,temporary_wire_bytes,local_peak_observed_bytes,peak_observed_bytes))},
            "memory":{"scope":MEMORY_SCOPE,"witness_bytes":witness.owned_bytes().expect("witness capacity"),"point_bytes":point.capacity()*size_of::<K>()},
            "sizes":{"proof_bytes":wire.len(),"statement_bytes":descriptor.statement_size(),"constraints_bytes":descriptor.constraints_size(),"public_bytes":descriptor.public_bytes(),"producer_public_bytes":limits.public_bytes,"producer_dense_elements":limits.dense_elements}})
    });
    std::hint::black_box((&record, &wire, &sources, &witness, &handles, &descriptor));
    let cleanup = Instant::now();
    drop(record);
    drop(refs);
    drop(handles);
    drop(descriptor);
    drop(wire);
    drop(sources);
    drop(witness);
    drop(schema);
    drop(inputs);
    drop(point);
    drop(following);
    times.insert(
        "cleanup".into(),
        u64::try_from(cleanup.elapsed().as_nanos()).expect("timer"),
    );
    result["stages_ns"] = json!(times);
    result
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() == 3
            && ["scalar", "ties", "wide", "shift62", "radix255", "radix256"]
                .contains(&args[1].as_str()),
        "scenario degree"
    );
    let start = Instant::now();
    let mut out = match args[2].as_str() {
        "4" => measure::<QM31>(&args[1]),
        "8" => measure::<OM31>(&args[1]),
        _ => {
            eprintln!("degree must be 4 or 8");
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
