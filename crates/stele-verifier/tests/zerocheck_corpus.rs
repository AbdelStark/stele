//! E8-02b parity: the independent A3 zerocheck against `research/zerocheck/corpus.jsonl`.
//! Every case must give the production verifier's recorded decision. An accepted case
//! must also give the same claims, phase SC records and transcript continuation
//! (`research/zerocheck/corpus-receipts.jsonl`, which the zerocheck gate checks against
//! the production output).
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_verifier::sumcheck::{Instance, Term};
use stele_verifier::zerocheck::{Proof, Zerocheck};

const CORPUS: &str = include_str!("../../../research/zerocheck/corpus.jsonl");
const RECEIPTS: &str = include_str!("../../../research/zerocheck/corpus-receipts.jsonl");

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
        let word: u32 = limb
            .as_u64()
            .ok_or("NoncanonicalField")?
            .try_into()
            .map_err(|_| "NoncanonicalField")?;
        raw.extend(word.to_le_bytes());
    }
    K::from_le_bytes(raw.try_into().map_err(|_| "NoncanonicalField")?)
        .ok_or_else(|| "NoncanonicalField".into())
}
fn values<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn limbs<K: ChallengeField>(v: K) -> Vec<u32> {
    v.to_le_bytes()
        .as_ref()
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect()
}

fn check<K: ChallengeField + Eq>(c: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let v = &c["instance"];
    let mut terms = Vec::new();
    for t in array(&v["terms"])? {
        terms.push(Term {
            coefficient: field(&t[0])?,
            factors: array(&t[1])?.iter().map(small).collect::<Result<_, _>>()?,
        });
    }
    let i = Instance {
        id: number(&v["id"])?,
        num_vars: small(&v["m"])?,
        inputs: array(&v["ids"])?
            .iter()
            .map(number)
            .collect::<Result<_, _>>()?,
        terms,
        claimed_sum: K::from_i64(0),
    };
    let z = Zerocheck {
        instance: &i,
        skip: number(&v["k"])?
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
    let r = z
        .verify_public(&proof, &tables, &mut t)
        .map_err(|e| format!("{e:?}"))?;
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
        "claims": r.claims.into_iter().map(|c| json!([c.tensor, c.point.into_iter().map(limbs).collect::<Vec<_>>(), limbs(c.value)])).collect::<Vec<_>>(),
        "sc": r.sc.iter().enumerate().map(|(phase, s)| json!({"id": s.id, "phase": phase, "m": s.m, "degree": s.degree, "field_degree": s.field_degree, "numerator": s.numerator})).collect::<Vec<_>>(),
        "continuation": continuation,
    }))
}

#[test]
fn matches_reference_a3_corpus_decisions_and_receipts() {
    let (cases, recorded): (Vec<&str>, Vec<&str>) =
        (CORPUS.lines().collect(), RECEIPTS.lines().collect());
    assert_eq!((cases.len(), recorded.len()), (314, 314));
    let mut accepted = 0;
    for (line, expected) in cases.iter().zip(&recorded) {
        let c: Value = serde_json::from_str(line).expect("case");
        let expected: Value = serde_json::from_str(expected).expect("receipt");
        let result = match c["field"].as_u64() {
            Some(4) => check::<QM31>(&c),
            Some(8) => check::<OM31>(&c),
            _ => Err("InvalidZerocheck".into()),
        };
        let mut output = result.unwrap_or_else(|error| json!({ "error": error }));
        output["name"] = c["name"].clone();
        assert_eq!(output, expected, "case {}", c["name"]);
        accepted += usize::from(output.get("error").is_none());
    }
    assert_eq!(accepted, 314 - 174);
}
