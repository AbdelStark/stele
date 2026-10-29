//! RFC-0008 A3 / RFC-0012 A9: actual public corpus adapter, not lookup acceptance.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{
    check_roots, Descriptor, Error, LeafDescriptor, Proof, SelectedProduct,
};
use stele_sumcheck::ScRecord;

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "CorpusShape".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "CorpusShape".into())
}
fn small(v: &Value) -> Result<u32, String> {
    number(v)?.try_into().map_err(|_| "CorpusShape".into())
}
fn raw(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or("CorpusShape")?;
    if !s.is_ascii() || s.len() % 2 != 0 {
        return Err("CorpusShape".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "CorpusShape".into()))
        .collect()
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes = raw(v)?;
    let encoded = K::Bytes::try_from(bytes.as_slice()).map_err(|_| "NoncanonicalField")?;
    K::from_le_bytes(encoded).ok_or_else(|| "NoncanonicalField".into())
}
fn values<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn pair<K: ChallengeField>(v: &Value) -> Result<[K; 2], String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    values(v)?.try_into().map_err(|_| "SourceShape".into())
}
fn error(e: Error) -> String {
    match e {
        Error::Sumcheck(inner) => format!("{inner:?}"),
        _ => format!("{e:?}"),
    }
}
fn hex<K: ChallengeField>(v: K) -> String {
    v.to_le_bytes()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn record(r: &ScRecord) -> Value {
    json!({"id":r.id,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
}
fn check<K: ChallengeField + Eq>(c: &Value) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let s = &c["descriptor"];
    let ids: Vec<u64> = array(&s["leaves"])?
        .iter()
        .map(number)
        .collect::<Result<_, _>>()?;
    let d = Descriptor::<K>::new(
        number(&s["id"])?,
        small(&s["m"])?,
        small(&s["b"])?,
        ids.try_into().map_err(|_| "InvalidDescriptor")?,
        &values(&s["theta"])?,
    )
    .map_err(error)?;
    let leaves = array(&c["leaves"])?
        .iter()
        .map(pair::<K>)
        .collect::<Result<Vec<_>, _>>()?;
    let proof = Proof::decode(&d, &raw(&c["tree"])?).map_err(error)?;
    let public = raw(&c["public"])?;
    let mut t = Transcript::new(&public).map_err(|e| format!("{e:?}"))?;
    let tree = d.verify_public(&proof, &leaves, &mut t).map_err(error)?;
    if let Some(right) = c.get("right") {
        check_roots(proof.root, pair(right)?).map_err(error)?;
    }
    // This marker controls additional prover parity only; verification always runs.
    let reprove = c["expected"] == "accept";
    let mut pt = Transcript::new(&public).map_err(|e| format!("{e:?}"))?;
    if reprove {
        let (produced, original) = d.prove(&leaves, &mut pt).map_err(error)?;
        if produced != proof || original != tree {
            return Err("ProverMismatch".into());
        }
    }
    let a = &tree.accounting;
    let mut result = json!({"tree":{
        "point":tree.point.iter().copied().map(hex).collect::<Vec<_>>(),
        "claims":tree.claims.iter().map(|(i,v)| json!([i,hex(*v)])).collect::<Vec<_>>(),
        "accounting":{"tree_id":a.tree_id,"field_degree":a.field_degree,"gamma":a.gamma,"fold":a.fold,
            "layers":a.layers.iter().map(record).collect::<Vec<_>>()},
        "numerator":a.gamma+a.fold+a.layers.iter().map(|r| r.numerator).sum::<u64>()
    }});
    if let Some(leaf) = c.get("leaf") {
        let ids = array(&leaf["sources"])?
            .iter()
            .map(number)
            .collect::<Result<Vec<_>, _>>()?;
        let sigma = values(&leaf["sigma"])?;
        let xs = array(&leaf["xs"])?
            .iter()
            .map(values::<K>)
            .collect::<Result<Vec<_>, _>>()?;
        let ld = LeafDescriptor::new(&d, &ids).map_err(error)?;
        let selected = SelectedProduct::new(
            ld,
            &tree,
            &sigma,
            field(&leaf["alpha"])?,
            field(&leaf["beta"])?,
        )
        .map_err(error)?;
        let proof = ld.decode(&raw(&leaf["proof"])?).map_err(error)?;
        let reduction = selected.verify_public(&proof, &xs, &mut t).map_err(error)?;
        if reprove {
            let (produced, original) = selected.prove(&xs, &mut pt).map_err(error)?;
            if produced != proof || original != reduction {
                return Err("ProverMismatch".into());
            }
        }
        result["leaf"] = json!({"tree_id":reduction.tree_id,
            "point":reduction.point.into_iter().map(hex).collect::<Vec<_>>(),
            "claims":reduction.claims.into_iter().map(|(i,v)| json!([i,hex(v)])).collect::<Vec<_>>(),
            "sc":record(&reduction.sc)});
    }
    let next = t
        .challenge(ChallengeLabel::Sumcheck)
        .map_err(|e| format!("{e:?}"))?;
    if reprove
        && pt
            .challenge(ChallengeLabel::Sumcheck)
            .map_err(|e| format!("{e:?}"))?
            != next
    {
        return Err("ProverMismatch".into());
    }
    result["continuation"] = json!(hex(next));
    Ok(result)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected corpus path")?;
    for line in std::fs::read_to_string(path)?.lines() {
        let c: Value = serde_json::from_str(line)?;
        let result = match c["degree"].as_u64() {
            Some(4) => check::<QM31>(&c),
            Some(8) => check::<OM31>(&c),
            _ => Err("CorpusShape".into()),
        };
        let mut result = result.unwrap_or_else(|error| json!({"error":error}));
        result["name"] = c["name"].clone();
        println!("{result}");
    }
    Ok(())
}
