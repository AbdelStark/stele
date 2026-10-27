//! RFC-0006 A1 / RFC-0002 S10: exercise the actual Rust APIs on the shared corpus.
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::{message_bytes, prove, verify_public, Dense, Instance, Proof, Term};

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
fn check<K: ChallengeField + Eq + core::fmt::Debug>(case: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let public = raw(&case["public_hex"])?;
    let mut verifier = Transcript::new(&public).map_err(|e| format!("{e:?}"))?;
    let mut prover = Transcript::new(&public).map_err(|e| format!("{e:?}"))?;
    let mut receipts = Vec::new();
    for record in array(&case["instances"])? {
        let s = &record["instance"];
        let mut terms = Vec::new();
        for t in array(&s["terms"])? {
            terms.push(Term {
                coefficient: field::<K>(&t["coefficient"])?,
                factors: array(&t["factors"])?
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
        if record.get("instance_hex").is_some() {
            assert_eq!(
                i.encode().expect("canonical instance"),
                raw(&record["instance_hex"])?
            );
            for (r, row) in proof.rounds.iter().enumerate() {
                assert_eq!(
                    message_bytes(i.id, r as u32, row).expect("canonical round"),
                    raw(&record["round_hex"][r])?
                );
            }
            assert_eq!(
                message_bytes(i.id, i.inputs.len() as u32, &proof.final_values)
                    .expect("canonical final"),
                raw(&record["final_hex"])?
            );
        }
        let receipt =
            verify_public(&i, &proof, &tables, &mut verifier).map_err(|e| format!("{e:?}"))?;
        // Honest fixtures also require production prover parity; rejection never depends on this flag.
        if case["expected"] == "accept" {
            let dense = Dense::new(&i, tables).map_err(|e| format!("{e:?}"))?;
            let produced = prove(&i, dense, &mut prover).map_err(|e| format!("{e:?}"))?;
            if produced != proof {
                return Err("ProverMismatch".into());
            }
        }
        receipts.push(json!({"point": receipt.point.into_iter().map(hex).collect::<Vec<_>>(),
            "claims": receipt.claims.into_iter().map(|(id, v)| json!([id, hex(v)])).collect::<Vec<_>>(),
            "sc": {"id": receipt.sc.id, "m": receipt.sc.m, "degree": receipt.sc.degree,
                   "field_degree": receipt.sc.field_degree, "numerator": receipt.sc.numerator}}));
    }
    Ok(json!({"receipts": receipts}))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("expected corpus path")?;
    for line in std::fs::read_to_string(path)?.lines() {
        let case: Value = serde_json::from_str(line)?;
        let result = match case["field_degree"].as_u64() {
            Some(4) => check::<QM31>(&case),
            Some(8) => check::<OM31>(&case),
            _ => Err("InvalidInstance".into()),
        };
        let mut output = result.unwrap_or_else(|error| json!({"error": error}));
        output["name"] = case["name"].clone();
        println!("{output}");
    }
    Ok(())
}
