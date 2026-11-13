//! E8-02b parity: the independent A2 batches (mode 0, instances; mode 1, claims on one
//! tensor) against `research/batching/corpus.jsonl`. Every case must give the
//! production verifier's recorded decision. An accepted case must also give the same
//! point, claims, SC and RLC records, including after an A1 continuation where the case
//! has one (`research/batching/corpus-receipts.jsonl`, which the batching gate checks
//! against the production output).
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_verifier::batch::{Batch, ClaimBatch, Reduction};
use stele_verifier::sumcheck::{verify_public, Instance, Proof, Term};

const CORPUS: &str = include_str!("../../../research/batching/corpus.jsonl");
const RECEIPTS: &str = include_str!("../../../research/batching/corpus-receipts.jsonl");

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "InvalidBatch".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "InvalidBatch".into())
}
fn small(v: &Value) -> Result<u32, String> {
    number(v)?.try_into().map_err(|_| "InvalidBatch".into())
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
fn proof<K: ChallengeField>(v: &Value) -> Result<Proof<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    Ok(Proof {
        rounds: array(&v["rounds"])?
            .iter()
            .map(values::<K>)
            .collect::<Result<_, _>>()?,
        final_values: values::<K>(&v["final"])?,
    })
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
        claimed_sum: field(&v["sum"])?,
    })
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
    let b = &c["batch"];
    let id = number(&b["id"])?;
    let mut t = Transcript::new(b"batch study").map_err(|e| format!("{e:?}"))?;
    let r: Reduction<K> = match number(&b["mode"])? {
        0 => {
            let instances = array(&b["instances"])?
                .iter()
                .map(instance::<K>)
                .collect::<Result<Vec<_>, _>>()?;
            let batch = Batch {
                id,
                instances: &instances,
            };
            batch.encode().map_err(|e| format!("{e:?}"))?;
            let tables = array(&c["tables"])?
                .iter()
                .map(|group| {
                    array(group)?
                        .iter()
                        .map(values::<K>)
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, String>>()?;
            let p = proof(&c["proof"])?;
            batch
                .verify_public(&p, &tables, &mut t)
                .map_err(|e| format!("{e:?}"))?
        }
        1 => {
            let claims = array(&b["claims"])?
                .iter()
                .map(|c| Ok((values::<K>(&c[0])?, field::<K>(&c[1])?)))
                .collect::<Result<Vec<_>, String>>()?;
            let batch = ClaimBatch {
                id,
                tensor: number(&b["tensor"])?,
                num_vars: small(&b["m"])?,
                claims: &claims,
            };
            batch.encode().map_err(|e| format!("{e:?}"))?;
            let table = values::<K>(&c["tables"])?;
            let p = proof(&c["proof"])?;
            batch
                .verify_public(&p, &table, &mut t)
                .map_err(|e| format!("{e:?}"))?
        }
        _ => return Err("InvalidBatch".into()),
    };
    if let Some(next) = c.get("continuation") {
        // The production adapter's fixed A1 continuation: 2·x − 3 over one variable.
        let i = Instance {
            id: 99,
            num_vars: 1,
            inputs: vec![11],
            terms: vec![
                Term {
                    coefficient: K::from_i64(2),
                    factors: vec![0],
                },
                Term {
                    coefficient: K::from_i64(-3),
                    factors: vec![],
                },
            ],
            claimed_sum: K::from_i64(10),
        };
        let tables = vec![vec![K::from_i64(3), K::from_i64(5)]];
        let _ =
            verify_public(&i, &proof::<K>(next)?, &tables, &mut t).map_err(|e| format!("{e:?}"))?;
    }
    Ok(json!({
        "point": r.point.into_iter().map(limbs).collect::<Vec<_>>(),
        "claims": r.claims.into_iter().map(|c| json!([c.tensor, c.point.into_iter().map(limbs).collect::<Vec<_>>(), limbs(c.value)])).collect::<Vec<_>>(),
        "sc": {"id": r.sc.id, "m": r.sc.m, "degree": r.sc.degree, "field_degree": r.sc.field_degree, "numerator": r.sc.numerator},
        "rlc": {"id": r.rlc.id, "t": r.rlc.t, "field_degree": r.rlc.field_degree, "numerator": r.rlc.numerator},
    }))
}

#[test]
fn matches_reference_a2_corpus_decisions_and_receipts() {
    let (cases, recorded): (Vec<&str>, Vec<&str>) =
        (CORPUS.lines().collect(), RECEIPTS.lines().collect());
    assert_eq!((cases.len(), recorded.len()), (276, 276));
    let mut accepted = 0;
    for (line, expected) in cases.iter().zip(&recorded) {
        let c: Value = serde_json::from_str(line).expect("case");
        let expected: Value = serde_json::from_str(expected).expect("receipt");
        let result = match c["degree"].as_u64() {
            Some(4) => check::<QM31>(&c),
            Some(8) => check::<OM31>(&c),
            _ => Err("InvalidBatch".into()),
        };
        let mut output = result.unwrap_or_else(|error| json!({ "error": error }));
        output["name"] = c["name"].clone();
        assert_eq!(output, expected, "case {}", c["name"]);
        accepted += usize::from(output.get("error").is_none());
    }
    assert_eq!(accepted, 276 - 212);
}
