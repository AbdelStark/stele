//! RFC-0008 A5 §7: serialize only actual closed consumer results for comparison.
use super::{hashes, hex, number, unhex};
use serde_json::{json, Value};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::Reduction;
use stele_pcs::{CodeField, OpeningRecord, Usage};
use stele_reductions::lookup::{Descriptor, TableField};

fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript)})
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
fn opening<K: ChallengeField>(o: &OpeningRecord<'_, K>) -> Value {
    let c = o.certificate();
    let p = c.parameters();
    json!({"id":o.id(),"queries":o.queries(),"kind":format!("{:?}",o.kind()),"certificate":{
        "id":hex(&c.id()),"source":hex(&c.source().bytes()),"ell":c.ell(),"degree":c.degree(),
        "kind":format!("{:?}",c.kind()),"length":p.length,"distance":p.distance,"radius":p.radius,
        "certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries}})
}
pub(super) fn verify<K: ChallengeField + CodeField + TableField + Eq>(
    case: &Value,
    d: &Descriptor<'_, '_, K>,
    mut out: Value,
) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let proof = unhex(&case["proof"])?;
    let registration = unhex(case.get("registration_proof").unwrap_or(&case["proof"]))?;
    let cap = match case.get("import_cap") {
        Some(v) => usize::try_from(number(v)?).map_err(|_| "FixtureCapacity")?,
        None => (d.producer_public_bytes().map_err(|e| format!("{e:?}"))? - d.public_bytes()) / 2,
    };
    let (handles, imports) = match d.register_multiplicities(&registration, cap) {
        Ok(result) => result,
        Err(f) => {
            out["phase"] = json!("import");
            out["decision"] = json!(format!("{:?}", f.cause));
            out["registrations"] = json!(f.registrations.map(|u| u.map(usage)));
            return Ok(out);
        }
    };
    out["registrations"] = json!(imports.map(|u| u.map(usage)));
    out["phase"] = json!("outer");
    let refs: Vec<_> = handles.iter().collect();
    let mut t = Transcript::new(&unhex(&case["public_hex"])?).map_err(|e| format!("{e:?}"))?;
    match d.verify(&mut t, &refs, &proof) {
        Err(f) => {
            out["decision"] = json!(format!("{:?}", f.cause));
            out["usage"] = usage(f.usage);
        }
        Ok((record, observed)) => {
            out["decision"] = json!("accept");
            out["usage"] = usage(observed);
            let p = record.parameters();
            let reps:Vec<_>=record.repetitions().iter().map(|r|{
                let s=r.selected_product();
                json!({"lookup":tree(r.lookup_tree()),"table":tree(r.table_tree()),
                    "selected":{"tree_id":s.tree_id,"point":point(&s.point),"claims":claims(&s.claims),"sc":sc(&s.sc)},
                    "originals":r.originals().iter().map(opening).collect::<Vec<_>>(),
                    "multiplicities":r.multiplicities().iter().map(opening).collect::<Vec<_>>()})
            }).collect();
            out["record"] = json!({"parameters":{"id":p.id,"degree":p.degree,"positions":p.positions,
                "table_rows":p.table_rows,"columns":p.columns,"group_bits":p.group_bits,"unit_bits":p.unit_bits,
                "repetitions":p.repetitions,"identity_numerator":p.identity_numerator},"repetitions":reps});
            out["continuation"] = json!(hex(t
                .challenge(ChallengeLabel::Sumcheck)
                .map_err(|e| format!("{e:?}"))?
                .to_le_bytes()
                .as_ref()));
        }
    }
    Ok(out)
}
