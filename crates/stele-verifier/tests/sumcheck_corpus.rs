//! E8-02a parity: the independent A1 verifier against the shared corpus. Each of
//! `research/sumcheck/corpus.jsonl`'s cases must give the same decision (accept, or
//! the same rejection) and, when accepted, the same point, claims and SC record as the
//! production verifier recorded in `research/sumcheck/corpus-receipts.jsonl`. The
//! sumcheck gate checks that the recorded file still equals the production output.
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_verifier::sumcheck::{verify_public, Instance, Proof, Term};

const CORPUS: &str = include_str!("../../../research/sumcheck/corpus.jsonl");
const RECEIPTS: &str = include_str!("../../../research/sumcheck/corpus-receipts.jsonl");

// The fixture adapter's own rejections, named as the production adapter names them.
fn raw(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or("NoncanonicalField")?;
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("NoncanonicalField".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "NoncanonicalField".into()))
        .collect()
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let bytes = raw(v)?.try_into().map_err(|_| "NoncanonicalField")?;
    K::from_le_bytes(bytes).ok_or_else(|| "NoncanonicalField".into())
}
fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "InvalidInstance".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "InvalidInstance".into())
}
fn small(v: &Value) -> Result<u32, String> {
    number(v)?.try_into().map_err(|_| "InvalidInstance".into())
}
fn values<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn hex<K: ChallengeField>(v: K) -> String {
    v.to_le_bytes()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn check<K: ChallengeField + Eq>(case: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut t = Transcript::new(&raw(&case["public_hex"])?).map_err(|e| format!("{e:?}"))?;
    let mut receipts = Vec::new();
    for record in array(&case["instances"])? {
        let s = &record["instance"];
        let mut terms = Vec::new();
        for term in array(&s["terms"])? {
            terms.push(Term {
                coefficient: field::<K>(&term["coefficient"])?,
                factors: array(&term["factors"])?
                    .iter()
                    .map(small)
                    .collect::<Result<_, _>>()?,
            });
        }
        let i = Instance {
            id: number(&s["id"])?,
            num_vars: small(&s["m"])?,
            inputs: array(&s["ids"])?
                .iter()
                .map(number)
                .collect::<Result<_, _>>()?,
            terms,
            claimed_sum: field::<K>(&s["sum"])?,
        };
        let proof = Proof {
            rounds: array(&record["proof"]["rounds"])?
                .iter()
                .map(values::<K>)
                .collect::<Result<_, _>>()?,
            final_values: values::<K>(&record["proof"]["final"])?,
        };
        let tables = array(&record["tables"])?
            .iter()
            .map(values::<K>)
            .collect::<Result<Vec<_>, _>>()?;
        let r = verify_public(&i, &proof, &tables, &mut t).map_err(|e| format!("{e:?}"))?;
        receipts.push(json!({
            "point": r.point.into_iter().map(hex).collect::<Vec<_>>(),
            "claims": r.claims.into_iter().map(|(id, v)| json!([id, hex(v)])).collect::<Vec<_>>(),
            "sc": {"id": r.sc.id, "m": r.sc.m, "degree": r.sc.degree,
                   "field_degree": r.sc.field_degree, "numerator": r.sc.numerator},
        }));
    }
    Ok(json!({ "receipts": receipts }))
}

#[test]
fn matches_reference_a1_corpus_decisions_and_receipts() {
    let (cases, recorded): (Vec<&str>, Vec<&str>) =
        (CORPUS.lines().collect(), RECEIPTS.lines().collect());
    assert_eq!(cases.len(), recorded.len());
    assert_eq!(cases.len(), 196);
    let mut accepted = 0;
    for (line, expected) in cases.iter().zip(&recorded) {
        let case: Value = serde_json::from_str(line).expect("case");
        let expected: Value = serde_json::from_str(expected).expect("receipt");
        let result = match case["field_degree"].as_u64() {
            Some(4) => check::<QM31>(&case),
            Some(8) => check::<OM31>(&case),
            _ => Err("InvalidInstance".into()),
        };
        let mut output = result.unwrap_or_else(|error| json!({ "error": error }));
        output["name"] = case["name"].clone();
        assert_eq!(output, expected, "case {}", case["name"]);
        // The corpus's own expectation agrees too.
        let decision = output
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("accept");
        assert_eq!(decision, case["expected"].as_str().expect("expected"));
        accepted += usize::from(decision == "accept");
    }
    assert_eq!(accepted, 196 - 142);
}
