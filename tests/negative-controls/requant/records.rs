//! RFC-0023 §6: actual record serialization shared by controls and measurement.
use serde_json::{json, Value};
use stele_hash::{ChallengeField, HashUsage};
use stele_pcs::{OpeningRecord, Usage};
use stele_sumcheck::ScRecord;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn fields<K: ChallengeField>(v: &[K]) -> Value {
    json!(v
        .iter()
        .map(|v| v
            .to_le_bytes()
            .as_ref()
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("valid pinned fixture")))
            .collect::<Vec<_>>())
        .collect::<Vec<_>>())
}

pub(super) fn hashes(u: HashUsage) -> Value {
    json!({"hash_evaluations":u.hash_evaluations,"xof_requests":u.xof_requests,
        "xof_bytes":u.xof_bytes,"state_updates":u.state_updates,
        "candidate_words":u.candidate_words,"column_attempts":u.column_attempts})
}

pub(super) fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript)})
}

pub(super) fn sc(r: &ScRecord) -> Value {
    json!({"id":r.id,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
}

pub(super) fn opening<K: ChallengeField>(o: &OpeningRecord<'_, K>) -> Value {
    let c = o.certificate();
    let p = c.parameters();
    json!({"id":o.id(),"queries":o.queries(),"kind":format!("{:?}",o.kind()),"certificate":{
        "id":hex(&c.id()),"source":hex(&c.source().bytes()),"ell":c.ell(),"degree":c.degree(),
        "kind":format!("{:?}",c.kind()),"length":p.length,"distance":p.distance,"radius":p.radius,
        "certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries}})
}

fn hex_point<K: ChallengeField>(point: &[K]) -> Vec<String> {
    point
        .iter()
        .map(|v| hex(v.to_le_bytes().as_ref()))
        .collect()
}

fn hex_claims<K: ChallengeField>(claims: &[(u64, K)]) -> Vec<Value> {
    claims
        .iter()
        .map(|(id, v)| json!([id, hex(v.to_le_bytes().as_ref())]))
        .collect()
}

fn tree<K: ChallengeField>(r: &stele_lookup::fraction::Reduction<K>) -> Value {
    let a = &r.accounting;
    json!({"point":hex_point(&r.point),"claims":hex_claims(&r.claims),"accounting":{
        "tree_id":a.tree_id,"field_degree":a.field_degree,"gamma":a.gamma,"fold":a.fold,
        "layers":a.layers.iter().map(sc).collect::<Vec<_>>()}})
}

pub(super) fn lookup<K: ChallengeField>(
    r: &stele_reductions::lookup::LookupRecord<'_, K>,
) -> Value {
    let p = r.parameters();
    let repetitions:Vec<_>=r.repetitions().iter().map(|r|{
        let s=r.selected_product();
        json!({"lookup":tree(r.lookup_tree()),"table":tree(r.table_tree()),
            "selected":{"tree_id":s.tree_id,"point":hex_point(&s.point),"claims":hex_claims(&s.claims),"sc":sc(&s.sc)},
            "originals":r.originals().iter().map(opening).collect::<Vec<_>>(),
            "multiplicities":r.multiplicities().iter().map(opening).collect::<Vec<_>>()})
    }).collect();
    json!({"parameters":{"id":p.id,"degree":p.degree,"positions":p.positions,"table_rows":p.table_rows,
        "columns":p.columns,"group_bits":p.group_bits,"unit_bits":p.unit_bits,"repetitions":p.repetitions,
        "identity_numerator":p.identity_numerator},"repetitions":repetitions})
}
