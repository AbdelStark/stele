//! RFC-0006 A2 / RFC-0002 S10: closed-statement batching corpus adapter.
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{batch, claim_batch, Instance, Proof, Term};

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
        .map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
        .collect()
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(c: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let b = &c["batch"];
    let id = number(&b["id"])?;
    let mut verifier = Transcript::new(b"batch study").map_err(|e| format!("{e:?}"))?;
    let mut prover = Transcript::new(b"batch study").map_err(|e| format!("{e:?}"))?;
    // Expected rejection is never an input to the verifier. It only gates honest prover parity.
    let honest = c["expected"] == "accept";
    let result = match number(&b["mode"])? {
        0 => {
            let instances = array(&b["instances"])?
                .iter()
                .map(instance::<K>)
                .collect::<Result<Vec<_>, _>>()?;
            let batch = batch::Batch {
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
            let r = batch
                .verify_public(&p, &tables, &mut verifier)
                .map_err(|e| format!("{e:?}"))?;
            if honest
                && batch
                    .prove(tables, &mut prover)
                    .map_err(|e| format!("{e:?}"))?
                    != p
            {
                return Err("ProverMismatch".into());
            }
            r
        }
        1 => {
            let claims = array(&b["claims"])?
                .iter()
                .map(|c| Ok((values::<K>(&c[0])?, field::<K>(&c[1])?)))
                .collect::<Result<Vec<_>, String>>()?;
            let batch = claim_batch::Batch {
                id,
                tensor: number(&b["tensor"])?,
                num_vars: small(&b["m"])?,
                claims: &claims,
            };
            batch.encode().map_err(|e| format!("{e:?}"))?;
            let tables = values::<K>(&c["tables"])?;
            let p = proof(&c["proof"])?;
            let r = batch
                .verify_public(&p, &tables, &mut verifier)
                .map_err(|e| format!("{e:?}"))?;
            if honest
                && batch
                    .prove(tables, &mut prover)
                    .map_err(|e| format!("{e:?}"))?
                    != p
            {
                return Err("ProverMismatch".into());
            }
            r
        }
        _ => return Err("InvalidBatch".into()),
    };
    if let Some(next) = c.get("continuation") {
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
        let p = proof::<K>(next)?;
        let _ = stele_sumcheck::verify_public(&i, &p, &tables, &mut verifier)
            .map_err(|e| format!("{e:?}"))?;
        if honest {
            let dense = stele_sumcheck::Dense::new(&i, tables).map_err(|e| format!("{e:?}"))?;
            if stele_sumcheck::prove(&i, dense, &mut prover).map_err(|e| format!("{e:?}"))? != p {
                return Err("ProverMismatch".into());
            }
        }
    }
    Ok(
        json!({"point": result.point.into_iter().map(limbs).collect::<Vec<_>>(),
        "claims": result.claims.into_iter().map(|c| json!([c.tensor, c.point.into_iter().map(limbs).collect::<Vec<_>>(), limbs(c.value)])).collect::<Vec<_>>(),
        "sc": {"id":result.sc.id, "m":result.sc.m, "degree":result.sc.degree, "field_degree":result.sc.field_degree, "numerator":result.sc.numerator},
        "rlc": {"id":result.rlc.id, "t":result.rlc.t, "field_degree":result.rlc.field_degree, "numerator":result.rlc.numerator}}),
    )
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected corpus path")?;
    for line in std::fs::read_to_string(path)?.lines() {
        let c: Value = serde_json::from_str(line)?;
        let result = match c["degree"].as_u64() {
            Some(4) => check::<QM31>(&c),
            Some(8) => check::<OM31>(&c),
            _ => Err("InvalidBatch".into()),
        };
        let mut result = result.unwrap_or_else(|error| json!({"error": error}));
        result["name"] = c["name"].clone();
        println!("{result}");
    }
    Ok(())
}
