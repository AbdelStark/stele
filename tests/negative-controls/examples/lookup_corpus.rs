//! RFC-0008 A5: independent fixture adapter to actual producer and closed verifier.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use stele_field::{M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource};
use stele_reductions::lookup::{
    Descriptor, Layout, Limits, ProducerLimits, ProverUsage, Statement, Table, TableDescriptor,
    TableField,
};
#[path = "support/lookup_verifier.rs"]
mod verification;

fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("FixtureNumber".into())
}
fn byte(v: &Value) -> Result<u8, String> {
    number(v)?.try_into().map_err(|_| "FixtureByte".into())
}
fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or("FixtureArray".into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(v: &Value) -> Result<Vec<u8>, String> {
    let text = v.as_str().ok_or("FixtureHex")?;
    if text.len() % 2 != 0 {
        return Err("FixtureHex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).map_err(|_| "FixtureHex")?, 16)
                .map_err(|_| "FixtureHex".into())
        })
        .collect()
}
fn hashes(u: HashUsage) -> Value {
    json!({"hash_evaluations":u.hash_evaluations,"xof_requests":u.xof_requests,
        "xof_bytes":u.xof_bytes,"state_updates":u.state_updates,
        "candidate_words":u.candidate_words,"column_attempts":u.column_attempts})
}
fn usage(u: ProverUsage) -> Value {
    let registrations: Vec<_> = u.registrations.into_iter().map(|r| r.map(|r| {
        json!({"production":hashes(r.production),"verification":{
            "transcript":hashes(r.verification.transcript),"non_transcript":hashes(r.verification.non_transcript)}})
    })).collect();
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript),"registrations":registrations})
}
fn produce<K: ChallengeField + CodeField + TableField + Eq>(case: &Value) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let m = byte(&case["m"])?;
    let info = &case["table"];
    let parameters = unhex(&info["params_hex"])?;
    let table = Table::generate(
        TableDescriptor::new(
            info["name"].as_str().ok_or("FixtureTable")?,
            number(&info["version"])?
                .try_into()
                .map_err(|_| "FixtureVersion")?,
            &parameters,
        )
        .map_err(|e| format!("{e:?}"))?,
    )
    .map_err(|e| format!("{e:?}"))?;
    let infos = array(&case["originals"])?;
    let messages: Vec<Vec<M31>> = infos
        .iter()
        .map(|info| {
            array(&info["message"])?
                .iter()
                .map(|v| {
                    u32::try_from(number(v)?)
                        .ok()
                        .and_then(M31::from_canonical)
                        .ok_or("FixtureField".into())
                })
                .collect()
        })
        .collect::<Result<_, String>>()?;
    let mut material = Vec::new();
    let mut certificates = Vec::new();
    let mut setup = Vec::new();
    for (info, message) in infos.iter().zip(&messages) {
        let ell = byte(&info["ell"])?;
        let prepared = PreparedSource::<K>::new(
            number(&info["id"])?,
            ell,
            m.checked_sub(ell).ok_or("FixtureShape")?,
            byte(&info["blowup"])?,
            message,
            &mut HashUsage::default(),
        )
        .map_err(|e| format!("{e:?}"))?;
        let (bytes, _) = prepared.certificate().map_err(|e| format!("{e:?}"))?;
        let (certificate, _) =
            verify_certificate(*prepared.source(), &bytes).map_err(|e| format!("{e:?}"))?;
        setup.push(json!({"source":hex(&prepared.source().bytes()),"certificate":hex(&bytes),"id":hex(&certificate.record().id())}));
        material.push(prepared);
        certificates.push(certificate);
    }
    let originals: Vec<_> = certificates.iter().collect();
    let prepared: Vec<_> = material.iter().collect();
    let selector: Vec<u8> = array(&case["selector"])?
        .iter()
        .map(byte)
        .collect::<Result<_, _>>()?;
    let layouts: Vec<_> = array(&case["multiplicities"])?
        .iter()
        .map(|v| {
            Ok(Layout {
                id: number(&v["id"])?,
                ell: byte(&v["ell"])?,
                blowup: byte(&v["blowup"])?,
            })
        })
        .collect::<Result<_, String>>()?;
    let descriptor = Descriptor::new(
        Statement {
            id: number(&case["lookup_id"])?,
            m,
            b: byte(&case["b"])?,
            table: &table,
            selector: &selector,
            originals: &originals,
            multiplicities: &layouts,
        },
        Limits {
            positions: 16,
            public_bytes: 16_000_000,
            proof_bytes: 16_000_000,
        },
    )
    .map_err(|e| format!("{e:?}"))?;
    match case.get("mode").and_then(Value::as_str) {
        Some("verify") => {
            return verification::verify(
                case,
                &descriptor,
                json!({"name":case["name"],"degree":case["degree"],"originals":setup}),
            )
        }
        None => {}
        _ => return Err("FixtureMode".into()),
    }
    // Diagnostic encoding is outside the measured producer call and its counters.
    let statement = descriptor
        .encode(&mut HashUsage::default())
        .map_err(|e| format!("{e:?}"))?;
    let limits = ProducerLimits {
        public_bytes: descriptor
            .producer_public_bytes()
            .map_err(|e| format!("{e:?}"))?,
        dense_elements: descriptor
            .producer_dense_elements()
            .map_err(|e| format!("{e:?}"))?,
    };
    let mut t = Transcript::new(&unhex(&case["public_hex"])?).map_err(|e| format!("{e:?}"))?;
    let mut result = json!({"name":case["name"],"degree":case["degree"],"statement":hex(&statement),"originals":setup});
    match descriptor.prove(&mut t, &prepared, limits) {
        Ok((proof, observed)) => {
            descriptor.preflight(&proof).map_err(|e| format!("{e:?}"))?;
            result["outcome"] = json!("produced");
            result["proof"] = json!(hex(&proof));
            result["usage"] = usage(observed);
            result["public_bytes"] = json!(limits.public_bytes);
            result["continuation"] = json!(hex(t
                .challenge(ChallengeLabel::Sumcheck)
                .map_err(|e| format!("{e:?}"))?
                .to_le_bytes()
                .as_ref()));
        }
        Err(failure) => {
            result["outcome"] = json!("error");
            result["cause"] = json!(format!("{:?}", failure.cause));
            result["usage"] = usage(failure.usage);
        }
    }
    Ok(result)
}
fn main() {
    for line in io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line.expect("fixture line")).expect("fixture JSON");
        let result = match case["degree"].as_u64() {
            Some(4) => produce::<QM31>(&case),
            Some(8) => produce::<OM31>(&case),
            _ => Err("FixtureDegree".into()),
        };
        println!("{}", result.expect("valid corpus fixture"));
    }
}
