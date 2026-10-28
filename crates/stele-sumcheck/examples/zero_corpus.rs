//! RFC-0006 A3: shared public-verifier corpus adapter; not an inference proof parser.
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    zerocheck::{Proof, Zerocheck},
    Instance, Term,
};

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "InvalidZerocheck".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "InvalidZerocheck".into())
}
fn small(v: &Value) -> Result<u32, String> {
    number(v)?.try_into().map_err(|_| "InvalidZerocheck".into())
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut raw = Vec::new();
    for limb in v.as_array().ok_or("NoncanonicalField")? {
        let word = limb.as_u64().ok_or("NoncanonicalField")?;
        let word: u32 = word.try_into().map_err(|_| "NoncanonicalField")?;
        raw.extend(word.to_le_bytes());
    }
    let bytes = raw.try_into().map_err(|_| "NoncanonicalField")?;
    K::from_le_bytes(bytes).ok_or_else(|| "NoncanonicalField".into())
}
fn values<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn instance<K: ChallengeField>(v: &Value) -> Result<Instance<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut terms = Vec::new();
    for t in array(&v["terms"])? {
        terms.push(Term {
            coefficient: field(&t[0])?,
            factors: array(&t[1])?.iter().map(small).collect::<Result<_, _>>()?,
        });
    }
    Ok(Instance {
        id: number(&v["id"])?,
        num_vars: small(&v["m"])?,
        inputs: array(&v["ids"])?
            .iter()
            .map(number)
            .collect::<Result<_, _>>()?,
        terms,
        claimed_sum: K::from_i64(0),
    })
}
fn limbs<K: ChallengeField>(v: K) -> Vec<u32> {
    v.to_le_bytes()
        .as_ref()
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
        .collect()
}
fn check<K: ChallengeField + Eq>(c: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let i = instance::<K>(&c["instance"])?;
    let z = Zerocheck {
        instance: &i,
        skip: number(&c["instance"]["k"])?
            .try_into()
            .map_err(|_| "InvalidZerocheck")?,
    };
    z.encode().map_err(|e| format!("{e:?}"))?;
    let tables = array(&c["tables"])?
        .iter()
        .map(values::<K>)
        .collect::<Result<Vec<_>, _>>()?;
    let proof = Proof {
        skip_values: values(&c["proof"]["skip"])?,
        rounds: array(&c["proof"]["rounds"])?
            .iter()
            .map(values::<K>)
            .collect::<Result<_, _>>()?,
        final_values: values(&c["proof"]["final"])?,
    };
    let mut t = Transcript::new(b"zerocheck").map_err(|e| format!("{e:?}"))?;
    let result = z
        .verify_public(&proof, &tables, &mut t)
        .map_err(|e| format!("{e:?}"))?;
    // Expected rejection never reaches the verifier; only accepted cases request prover parity.
    if c["expected"] == "accept" {
        let mut prover = Transcript::new(b"zerocheck").map_err(|e| format!("{e:?}"))?;
        if z.prove(&tables, &mut prover)
            .map_err(|e| format!("{e:?}"))?
            != proof
        {
            return Err("ProverMismatch".into());
        }
    }
    let next = t
        .challenge(ChallengeLabel::Sumcheck)
        .map_err(|e| format!("{e:?}"))?;
    let continuation: String = next
        .to_le_bytes()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(json!({
        "claims":result.claims.into_iter().map(|c| json!([c.tensor, c.point.into_iter().map(limbs).collect::<Vec<_>>(), limbs(c.value)])).collect::<Vec<_>>(),
        "sc":result.sc.iter().enumerate().map(|(phase, r)| json!({"id":r.id,"phase":phase,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})).collect::<Vec<_>>(),
        "continuation":continuation
    }))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected corpus path")?;
    for line in std::fs::read_to_string(path)?.lines() {
        let c: Value = serde_json::from_str(line)?;
        let result = match c["field"].as_u64() {
            Some(4) => check::<QM31>(&c),
            Some(8) => check::<OM31>(&c),
            _ => Err("InvalidZerocheck".into()),
        };
        let mut result = result.unwrap_or_else(|error| json!({"error":error}));
        result["name"] = c["name"].clone();
        println!("{result}");
    }
    Ok(())
}
