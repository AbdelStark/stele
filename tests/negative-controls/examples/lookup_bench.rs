//! RFC-0008 A5 §6 / RFC-0018 §1: complete conditional lookup measurements.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use std::{collections::BTreeMap, mem::size_of, time::Instant};
use stele_field::{Field, Serialize, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_lookup::fraction::{Reduction, Work};
use stele_pcs::{CertificateRecord, CodeField, PreparationWork, PreparedSource, ProofKind, Usage};
use stele_reductions::lookup::{
    Descriptor, Layout, Limits, ProducerLimits, ProverWork, Statement, Table, TableDescriptor,
    TableField,
};

const PUBLIC: &[u8] = b"stele complete lookup measurement v1";
const MEMORY_SCOPE: &str = "actual named producer boundary capacities; excludes metadata and internal scratch; whole-worker RSS separate";
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
fn bytes(bytes: &[u8], digests: &mut u64) -> Value {
    // Diagnostic hashes are counted separately; never protocol challenges.
    *digests += 1;
    json!({"bytes":bytes.len(),"digest":blake3::hash(bytes).to_hex().to_string()})
}
fn hashes(h: HashUsage) -> Value {
    json!({"hash_evaluations":h.hash_evaluations,"xof_requests":h.xof_requests,
        "xof_bytes":h.xof_bytes,"state_updates":h.state_updates,
        "candidate_words":h.candidate_words,"column_attempts":h.column_attempts})
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"local":hashes(u.non_transcript)})
}
fn difference(after: HashUsage, before: HashUsage) -> HashUsage {
    HashUsage {
        hash_evaluations: after
            .hash_evaluations
            .checked_sub(before.hash_evaluations)
            .expect("hash delta"),
        xof_requests: after
            .xof_requests
            .checked_sub(before.xof_requests)
            .expect("XOF delta"),
        xof_bytes: after
            .xof_bytes
            .checked_sub(before.xof_bytes)
            .expect("byte delta"),
        state_updates: after
            .state_updates
            .checked_sub(before.state_updates)
            .expect("state delta"),
        candidate_words: after
            .candidate_words
            .checked_sub(before.candidate_words)
            .expect("candidate delta"),
        column_attempts: after
            .column_attempts
            .checked_sub(before.column_attempts)
            .expect("column delta"),
    }
}
fn preparation(w: PreparationWork) -> Value {
    json!({"borrowed_message_bytes":w.borrowed_message_bytes,"encoded_columns_bytes":w.encoded_columns_bytes,
        "encoder_peak_bytes":w.encoder_peak_bytes,"leaf_references_bytes":w.leaf_references_bytes,
        "merkle_nodes_bytes":w.merkle_nodes_bytes,"peak_owned_bytes":w.peak_owned_bytes})
}
fn fraction(w: Work) -> Value {
    json!({"levels_bytes":w.levels_bytes,"dense_bytes":w.dense_bytes,"proof_bytes":w.proof_bytes,
        "point_bytes":w.point_bytes,"peak_observed_bytes":w.peak_observed_bytes})
}
fn work(w: ProverWork) -> Value {
    json!({"proof_bytes":w.proof_bytes,"units_bytes":w.units_bytes,"index_bytes":w.index_bytes,
        "group_weights_bytes":w.group_weights_bytes,"mu_values_bytes":w.mu_values_bytes,
        "mu_limbs_bytes":w.mu_limbs_bytes,"originals_bytes":w.originals_bytes,"selector_bytes":w.selector_bytes,
        "prepared_bytes":w.prepared_bytes,"coefficients_bytes":w.coefficients_bytes,"temporary_wire_bytes":w.temporary_wire_bytes,
        "local_peak_observed_bytes":w.local_peak_observed_bytes,"peak_observed_bytes":w.peak_observed_bytes,
        "preparations":w.preparations.map(|p|p.map(preparation)),
        "repetitions":w.repetitions.map(|r|r.map(|r|json!({"lookup":fraction(r.lookup),"table":fraction(r.table),"selected":fraction(r.selected)})))})
}
fn certificate<K: ChallengeField>(c: &CertificateRecord<K>) -> Value {
    let p = c.parameters();
    json!({"id":c.source().descriptor().id,"context":hex(&c.source().bytes()),"certificate_id":hex(&c.id()),
        "ell":c.ell(),"degree":c.degree(),"kind":format!("{:?}",c.kind()),
        "length":p.length,"distance":p.distance,"radius":p.radius,
        "certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries})
}
fn sc(r: &stele_sumcheck::ScRecord) -> Value {
    json!({"id":r.id,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
}
fn point<K: ChallengeField>(values: &[K]) -> Vec<String> {
    values
        .iter()
        .map(|v| hex(v.to_le_bytes().as_ref()))
        .collect()
}
fn claims<K: ChallengeField>(values: &[(u64, K)]) -> Vec<Value> {
    values
        .iter()
        .map(|(id, v)| json!([id, hex(v.to_le_bytes().as_ref())]))
        .collect()
}
fn tree<K: ChallengeField>(r: &Reduction<K>) -> Value {
    let a = &r.accounting;
    json!({"point":point(&r.point),"claims":claims(&r.claims),"accounting":{
        "tree_id":a.tree_id,"field_degree":a.field_degree,"gamma":a.gamma,"fold":a.fold,
        "layers":a.layers.iter().map(sc).collect::<Vec<_>>()}})
}
fn section(rest: &mut &[u8], name: String, count: usize, digests: &mut u64) -> Value {
    let (part, tail) = rest.split_at(count);
    *rest = tail;
    json!({"name":name,"wire":bytes(part,digests)})
}
fn measure<K: ChallengeField + CodeField + TableField + Eq>(scenario: &str, scale: &str) -> Value
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let d = <K as CodeField>::DEGREE;
    let mut times = Times::new();
    let mut digests = 0;
    let (m, b, table, selector, messages, ells, layouts) = timed(&mut times, "fixture", || {
        let full = scale == "full";
        let (name, params, m, b, ells, layout) = match scenario {
            "scalar" => ("range_8", &[] as &[u8], 0u8, 0u8, vec![0], vec![(4, 1)]),
            "grouped" => (
                "exp_q/hi",
                &[7, 0, 0, 6][..],
                if full { 12 } else { 2 },
                0,
                if full { vec![4, 8] } else { vec![0, 2] },
                vec![(1, 1), (0, 2)],
            ),
            "signed" => (
                "exp_q/direct",
                &[7, 0, 0][..],
                if full { 12 } else { 2 },
                if full { 12 } else { 2 },
                if full { vec![4, 8] } else { vec![0, 2] },
                vec![(4, 1), (5, 2)],
            ),
            "zero" => (
                "exp_q/hi",
                &[7, 0, 0, 6][..],
                if full { 8 } else { 3 },
                if full { 4 } else { 1 },
                if full { vec![2, 6] } else { vec![1, 2] },
                vec![(2, 2)],
            ),
            _ => unreachable!("validated scenario"),
        };
        let table =
            Table::generate(TableDescriptor::new(name, 1, params).expect("Table descriptor"))
                .expect("Table");
        let n = 1usize << m;
        let shape = table.descriptor().shape();
        let c = usize::from(shape.columns());
        let selector: Vec<_> = (0..n)
            .map(|i| u8::from(scenario != "zero" && (scenario == "scalar" || i % 4 != 3)))
            .collect();
        let messages: Vec<Vec<M31>> = (0..c)
            .map(|column| {
                (0..n)
                    .map(|i| {
                        if selector[i] == 0 {
                            M31::from_i64(256)
                        } else {
                            let row = if scenario == "scalar" {
                                7
                            } else {
                                (37 * i + 11) % shape.rows() as usize
                            };
                            M31::from_i64(i64::from(table.entries()[row * c + column]))
                        }
                    })
                    .collect()
            })
            .collect();
        let layouts: Vec<_> = layout
            .into_iter()
            .enumerate()
            .map(|(j, (ell, blowup))| Layout {
                id: 81 + j as u64,
                ell,
                blowup,
            })
            .collect();
        (m, b, table, selector, messages, ells, layouts)
    });
    let mut materials = Vec::new();
    let mut certificates = Vec::new();
    let mut certificate_proofs = Vec::new();
    let mut originals = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        let mut local = HashUsage::default();
        let p = timed(&mut times, format!("prepare/{i}"), || {
            PreparedSource::<K>::new(41 + i as u64, ells[i], m - ells[i], 1, message, &mut local)
                .expect("original preparation")
        });
        let (wire, produced) = timed(&mut times, format!("certificate_prove/{i}"), || {
            p.certificate().expect("original certificate")
        });
        let (c, consumed) = timed(&mut times, format!("certificate_verify/{i}"), || {
            stele_pcs::verify_certificate(*p.source(), &wire).expect("original registration")
        });
        timed(&mut times, "observations", || {
            assert_eq!(produced, consumed.transcript);
            let input: Vec<_> = message.iter().flat_map(|x| x.to_le_bytes()).collect();
            originals.push(json!({"certificate":certificate(c.record()),"wire":bytes(&wire,&mut digests),
                "capacity_bytes":wire.capacity(),"input":bytes(&input,&mut digests),"input_capacity_bytes":message.capacity()*size_of::<M31>(),
                "preparation":preparation(p.work()),"preparation_hashes":hashes(local),"producer":hashes(produced),"verifier":usage(consumed)}));
        });
        materials.push(p);
        certificates.push(c);
        certificate_proofs.push(wire);
    }
    let handles: Vec<_> = certificates.iter().collect();
    let prepared: Vec<_> = materials.iter().collect();
    let (descriptor, limits, import_cap) = timed(&mut times, "descriptor", || {
        let descriptor = Descriptor::new(
            Statement {
                id: 71,
                m,
                b,
                table: &table,
                selector: &selector,
                originals: &handles,
                multiplicities: &layouts,
            },
            Limits {
                positions: 1 << 12,
                public_bytes: 1 << 28,
                proof_bytes: 1 << 28,
            },
        )
        .expect("descriptor");
        let limits = ProducerLimits {
            public_bytes: descriptor.producer_public_bytes().expect("producer bytes"),
            dense_elements: descriptor
                .producer_dense_elements()
                .expect("producer elements"),
        };
        let import_cap = limits
            .public_bytes
            .checked_sub(descriptor.public_bytes())
            .expect("registration difference")
            / 2;
        (descriptor, limits, import_cap)
    });
    let (mut pt, mut vt) = timed(&mut times, "transcripts", || {
        (
            Transcript::<K>::new(PUBLIC).expect("producer transcript"),
            Transcript::<K>::new(PUBLIC).expect("verifier transcript"),
        )
    });
    let (proof, produced, observed) = timed(
        &mut times,
        "produce_including_mu_preparation_and_registration",
        || {
            descriptor
                .prove_measured(&mut pt, &prepared, limits)
                .expect("complete producer")
        },
    );
    let (mu, imported) = timed(&mut times, "import_multiplicities", || {
        descriptor
            .register_multiplicities(&proof, import_cap)
            .expect("actual standalone imports")
    });
    let mu_refs: Vec<_> = mu.iter().collect();
    let (record, consumed) = timed(&mut times, "verify", || {
        descriptor
            .verify(&mut vt, &mu_refs, &proof)
            .expect("actual closed verifier")
    });
    let mut out = timed(&mut times, "observations", || {
        assert_eq!(produced.transcript, consumed.transcript);
        assert_eq!(consumed.transcript, vt.usage());
        assert_eq!(proof.len(), descriptor.proof_size());
        assert_eq!(proof.capacity(), observed.proof_bytes);
        let next = pt
            .challenge(ChallengeLabel::Sumcheck)
            .expect("producer continuation");
        let other = vt
            .challenge(ChallengeLabel::Sumcheck)
            .expect("consumer continuation");
        assert!(next == other);
        let mut diagnostic = HashUsage::default();
        let statement = descriptor
            .encode(&mut diagnostic)
            .expect("diagnostic expected frame");
        let metadata_len =
            u32::from_le_bytes(statement[19..23].try_into().expect("metadata length")) as usize;
        let data_offset = 23 + metadata_len;
        let data_len = u32::from_le_bytes(
            statement[data_offset..data_offset + 4]
                .try_into()
                .expect("data length"),
        ) as usize;
        let framing = json!({"statement":bytes(&statement,&mut digests),
            "table_metadata":bytes(&statement[23..data_offset],&mut digests),
            "table_data":bytes(&statement[data_offset+4..data_offset+4+data_len],&mut digests),
            "selector":bytes(&selector,&mut digests)});
        let mut rest = proof.as_slice();
        let mut sections = vec![section(&mut rest, "header".into(), 2, &mut digests)];
        let mut multiplicities = Vec::new();
        for (j, c) in mu.iter().enumerate() {
            sections.push(section(&mut rest, format!("mu/{j}/root"), 32, &mut digests));
            let count = c
                .record()
                .source()
                .proof_size(ProofKind::Certificate)
                .expect("certificate size");
            let part = section(
                &mut rest,
                format!("mu/{j}/certificate"),
                count,
                &mut digests,
            );
            multiplicities.push(json!({"certificate":certificate(c.record()),"wire":part["wire"],"import_usage":usage(imported[j].expect("import usage"))}));
            sections.push(part);
        }
        let shape = table.descriptor().shape();
        let k = shape.padded().trailing_zeros() as usize;
        let c = messages.len();
        let w = 4 * usize::from(d);
        let tree_size = |v: usize| w * (2 + 2 * v * v + 3 * v);
        let reps: Vec<_> = record.repetitions().iter().enumerate().map(|(j,r)| {
            for (name, count) in [("lookup",tree_size(usize::from(m))),("table",tree_size(k)),("selected",w*(4*usize::from(m)+c+2))] {
                sections.push(section(&mut rest,format!("repetition/{j}/{name}"),count,&mut digests));
            }
            let opening = |o:&stele_pcs::OpeningRecord<'_,K>, expected:&CertificateRecord<K>| {
                assert!(std::ptr::eq(o.certificate(),expected));
                assert_eq!(o.kind(),ProofKind::Opening);
                json!({"id":o.id(),"queries":o.queries(),"kind":format!("{:?}",o.kind()),"certificate_id":hex(&o.certificate().id())})
            };
            assert_eq!(r.originals().len(),certificates.len());
            let os:Vec<_>=r.originals().iter().zip(&certificates).enumerate().map(|(i,(o,c))| {
                sections.push(section(&mut rest,format!("repetition/{j}/original/{i}"),c.record().source().proof_size(ProofKind::Opening).expect("opening size"),&mut digests));
                opening(o,c.record())
            }).collect();
            let source=mu[j].record().source();
            let cut=shape.rows() as usize*usize::from(d);
            let pieces=usize::from(cut/source.columns()>0)+usize::from(!cut.is_multiple_of(source.columns()));
            assert_eq!(r.multiplicities().len(),pieces);
            sections.push(section(&mut rest,format!("repetition/{j}/piece_values"),pieces*w,&mut digests));
            let ms:Vec<_>=r.multiplicities().iter().enumerate().map(|(i,o)| {
                sections.push(section(&mut rest,format!("repetition/{j}/piece/{i}"),source.proof_size(ProofKind::Opening).expect("piece size"),&mut digests));
                opening(o,mu[j].record())
            }).collect();
            let s=r.selected_product();
            json!({"lookup":tree(r.lookup_tree()),"table":tree(r.table_tree()),
                "selected":{"tree_id":s.tree_id,"point":point(&s.point),"claims":claims(&s.claims),"sc":sc(&s.sc)},"originals":os,"multiplicities":ms})
        }).collect();
        assert!(rest.is_empty());
        let p = record.parameters();
        json!({"scenario":scenario,"scale":scale,"field_degree":d,
            "shape":{"m":m,"b":b,"table_rows":shape.rows(),"padded_rows":shape.padded(),"columns":c,"repetitions":layouts.len(),
                "original_ells":ells,"mu_layouts":layouts.iter().map(|l|json!({"id":l.id,"ell":l.ell,"blowup":l.blowup})).collect::<Vec<_>>()},
            "originals":originals,"multiplicities":multiplicities,"framing":framing,
            "proof":{"wire":bytes(&proof,&mut digests),"capacity_bytes":proof.capacity(),"sections":sections},
            "record":{"parameters":{"id":p.id,"degree":p.degree,"positions":p.positions,"table_rows":p.table_rows,"columns":p.columns,
                "group_bits":p.group_bits,"unit_bits":p.unit_bits,"repetitions":p.repetitions,"identity_numerator":p.identity_numerator},"repetitions":reps},
            "producer_usage":{"transcript":hashes(produced.transcript),"local":hashes(produced.non_transcript),
                "registrations":produced.registrations.map(|r|r.map(|r|json!({"production":hashes(r.production),"verification":usage(r.verification)})))},
            "consumer_usage":usage(consumed),"work":work(observed),"memory_scope":MEMORY_SCOPE,
            "admission":{"producer_public_bytes":limits.public_bytes,"producer_dense_elements":limits.dense_elements,
                "outer_public_bytes":descriptor.public_bytes(),"import_public_bytes":import_cap},
            "continuation":{"producer":hex(next.to_le_bytes().as_ref()),"consumer":hex(other.to_le_bytes().as_ref())},
            "diagnostics":{"statement_hashes":hashes(diagnostic),"receipt_digest_evaluations":digests,
                "continuations":{"producer":hashes(difference(pt.usage(),produced.transcript)),
                    "consumer":hashes(difference(vt.usage(),consumed.transcript))}}})
    });
    // Explicitly retain genuine inputs, preparation, certificates and proof through verify.
    std::hint::black_box((
        &messages,
        &materials,
        &certificates,
        &certificate_proofs,
        &mu,
        &proof,
        &record,
    ));
    out["stages_ns"] = json!(times);
    out
    // Protocol objects drop before returning to the inclusive timer; JSON serialization follows it.
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 3
            && ["scalar", "grouped", "signed", "zero"].contains(&args[0].as_str())
            && ["full", "smoke"].contains(&args[2].as_str()),
        "scenario field scale"
    );
    let start = Instant::now();
    let mut out = match args[1].as_str() {
        "4" => measure::<QM31>(&args[0], &args[2]),
        "8" => measure::<OM31>(&args[0], &args[2]),
        _ => {
            eprintln!("field must be 4 or 8");
            std::process::exit(2);
        }
    };
    let total = u64::try_from(start.elapsed().as_nanos()).expect("timer");
    let measured: u64 = out["stages_ns"]
        .as_object()
        .expect("stages")
        .values()
        .map(|v| v.as_u64().expect("time"))
        .sum();
    out["total_ns"] = json!(total);
    out["remainder_ns"] = json!(total.checked_sub(measured).expect("disjoint timings"));
    println!("{}", serde_json::to_string(&out).expect("receipt"));
}
