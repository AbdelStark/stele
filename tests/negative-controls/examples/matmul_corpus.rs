//! RFC-0007 A2 / RFC-0010 A10: actual closed-verifier JSONL adapter.
//! Fixture bytes are untrusted. No matrices, expected records, state import or
//! producer replay are accepted; all records come from the actual consumers.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use stele_field::{OM31, QM31};
use stele_gkr::stacked::Limits;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, OpeningRecord, Source, Usage, VerifiedCertificate};
use stele_reductions::matmul::{self, Statement};
use stele_sumcheck::{Instance, Proof, ScRecord, Term};

fn keys(v: &Value, required: &[&str], optional: &[&str]) -> Result<(), String> {
    let object = v.as_object().ok_or("FixtureObject")?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("FixtureKeys".into());
    }
    Ok(())
}
fn array(v: &Value, len: usize) -> Result<&Vec<Value>, String> {
    v.as_array()
        .filter(|v| v.len() == len)
        .ok_or("FixtureArray".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("FixtureNumber".into())
}
fn byte(v: &Value) -> Result<u8, String> {
    number(v)?.try_into().map_err(|_| "FixtureByte".into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(v: &Value) -> Result<Vec<u8>, String> {
    let text = v.as_str().ok_or("FixtureHex")?;
    if !text.len().is_multiple_of(2) {
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
fn decode<K: ChallengeField>(bytes: &[u8]) -> Result<K, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    K::from_le_bytes(K::Bytes::try_from(bytes).map_err(|_| "FixtureField")?)
        .ok_or("FixtureField".into())
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut bytes = Vec::new();
    for limb in array(v, K::DEGREE)? {
        bytes.extend_from_slice(
            &u32::try_from(number(limb)?)
                .map_err(|_| "FixtureField")?
                .to_le_bytes(),
        );
    }
    decode::<K>(&bytes)
}
fn point<K: ChallengeField>(values: &[K]) -> Vec<Vec<u32>> {
    values
        .iter()
        .map(|v| {
            v.to_le_bytes()
                .as_ref()
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().expect("four-byte canonical limb")))
                .collect()
        })
        .collect()
}
fn hashes(u: HashUsage) -> Value {
    json!({"hash_evaluations":u.hash_evaluations,"xof_requests":u.xof_requests,
        "xof_bytes":u.xof_bytes,"state_updates":u.state_updates,
        "candidate_words":u.candidate_words,"column_attempts":u.column_attempts})
}
fn usage(u: Usage) -> Value {
    json!({"transcript":hashes(u.transcript),"non_transcript":hashes(u.non_transcript)})
}
fn sc(r: &ScRecord) -> Value {
    json!({"id":r.id,"m":r.m,"degree":r.degree,"field_degree":r.field_degree,"numerator":r.numerator})
}
fn opening<K: ChallengeField>(o: &OpeningRecord<'_, K>) -> Value {
    let c = o.certificate();
    let p = c.parameters();
    json!({"id":o.id(),"queries":o.queries(),"kind":format!("{:?}",o.kind()),"certificate":{
        "id":hex(&c.id()),"source":hex(&c.source().bytes()),"ell":c.ell(),"degree":c.degree(),
        "kind":format!("{:?}",c.kind()),"length":p.length,"distance":p.distance,"radius":p.radius,
        "certificate_queries":p.certificate_queries,"opening_queries":p.opening_queries}})
}
fn component(error: matmul::Error) -> &'static str {
    match error {
        matmul::Error::Stacked(_) => "stacked",
        matmul::Error::Pcs(_) => "pcs",
        matmul::Error::Transcript(_) => "transcript",
        _ => "matmul",
    }
}

/// Fixed public one-round A1 continuation from the independent oracle.
/// This decoder parses only that fixture's three fields; the actual A1 public
/// consumer determines acceptance. No following claim is supplied as a receipt.
fn following<K: ChallengeField + Eq>(t: &mut Transcript<K>, raw: &[u8]) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let width = 4 * K::DEGREE;
    if raw.len() != 3 * width {
        return Err("FixtureFollowingShape".into());
    }
    let values: Vec<K> = raw
        .chunks_exact(width)
        .map(decode::<K>)
        .collect::<Result<_, _>>()?;
    let proof = Proof {
        rounds: vec![values[..2].to_vec()],
        final_values: vec![values[2]],
    };
    let instance = Instance {
        id: 901,
        num_vars: 1,
        inputs: vec![902],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(7),
    };
    let tables = vec![vec![K::from_i64(2), K::from_i64(5)]];
    match stele_sumcheck::verify_public(&instance, &proof, &tables, t) {
        Err(cause) => Ok(json!({"decision":format!("{cause:?}"),"usage":hashes(t.usage())})),
        Ok(record) => {
            // Snapshot BEFORE the diagnostic probe. The actual following-A1
            // point binds its known Instance/Round to the post-matmul history.
            let observed = t.usage();
            let coordinates: Vec<_> = record
                .point
                .iter()
                .map(|value| hex(value.to_le_bytes().as_ref()))
                .collect();
            let mut out = json!({"decision":"accept","sc":sc(&record.sc),
                "point":coordinates,"usage":hashes(observed)});
            // Transcript exposes no raw state. This is a real registered fresh
            // challenge after successful complete continuation, not a state hash.
            match t.challenge(ChallengeLabel::Sumcheck) {
                Ok(value) => out["probe"] = json!(hex(value.to_le_bytes().as_ref())),
                Err(cause) => {
                    out["probe"] = Value::Null;
                    out["probe_error"] = json!(format!("{cause:?}"));
                    out["probe_usage"] = hashes(t.usage());
                }
            }
            Ok(out)
        }
    }
}

fn verify<K: ChallengeField + CodeField + Eq>(input: &Value) -> Result<Value, String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    keys(
        input,
        &[
            "degree",
            "dims",
            "ids",
            "point",
            "value",
            "public_hex",
            "originals",
            "proof_hex",
        ],
        &["following_hex"],
    )?;
    if number(&input["degree"])? != u64::from(<K as CodeField>::DEGREE) {
        return Err("FixtureDegree".into());
    }
    let dims = array(&input["dims"], 4)?;
    let bits = [
        byte(&dims[0])?,
        byte(&dims[1])?,
        byte(&dims[2])?,
        byte(&dims[3])?,
    ];
    let ids = array(&input["ids"], 5)?;
    let ids = [
        number(&ids[0])?,
        number(&ids[1])?,
        number(&ids[2])?,
        number(&ids[3])?,
        number(&ids[4])?,
    ];
    let groups = array(&input["point"], 3)?;
    let mut coordinates = Vec::new();
    for (group, len) in groups.iter().zip([bits[0], bits[1], bits[3]]) {
        coordinates.extend(
            array(group, usize::from(len))?
                .iter()
                .map(field::<K>)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let statement = Statement {
        id: ids[4],
        output_id: ids[2],
        coefficient_id: ids[3],
        inputs: [ids[0], ids[1]],
        bits,
        point: &coordinates,
        value: field::<K>(&input["value"])?,
    };
    let mut certificates = Vec::new();
    let mut imports = Vec::new();
    for (index, info) in array(&input["originals"], 2)?.iter().enumerate() {
        keys(
            info,
            &[
                "id",
                "ell",
                "m",
                "blowup",
                "root_hex",
                "source_hex",
                "certificate_hex",
            ],
            &[],
        )?;
        let source = match Source::<K>::new(
            number(&info["id"])?,
            byte(&info["ell"])?,
            byte(&info["m"])?,
            byte(&info["blowup"])?,
            unhex(&info["root_hex"])?
                .try_into()
                .map_err(|_| "FixtureRoot")?,
        ) {
            Ok(source) => source,
            Err(cause) => {
                return Ok(json!({"phase":"source","index":index,
                "decision":format!("{cause:?}"),"imports":imports,"usage":usage(Usage::default())}))
            }
        };
        if source.bytes().as_slice() != unhex(&info["source_hex"])? {
            return Err("FixtureSourceEncoding".into());
        }
        match verify_certificate(source, &unhex(&info["certificate_hex"])?) {
            Ok((certificate, observed)) => {
                certificates.push(certificate);
                imports.push(usage(observed));
            }
            Err(failure) => {
                imports.push(usage(failure.usage));
                return Ok(json!({"phase":"registration","index":index,
                    "decision":format!("{:?}",failure.cause),"imports":imports,"record":null}));
            }
        }
    }
    let certificates: [VerifiedCertificate<K>; 2] =
        certificates.try_into().map_err(|_| "FixtureSources")?;
    let proof = unhex(&input["proof_hex"])?;
    let mut t = Transcript::<K>::new(&unhex(&input["public_hex"])?)
        .map_err(|e| format!("FixtureTranscript({e:?})"))?;
    let before = t.usage();
    // Fixed explicit fixture budgets, independent of expected results. They
    // admit the bounded strata; static geometry and cap rejection are core tests.
    let limits = Limits {
        descriptor_bytes: 16_000_000,
        proof_bytes: 16_000_000,
        prepared_entries: 65_536,
        partial_entries: 65_536,
        axis_entries: 65_536,
    };
    // Never substitute replay of separate kernels for the actual closed consumer.
    match matmul::verify(
        &mut t,
        &statement,
        [&certificates[0], &certificates[1]],
        &proof,
        limits,
    ) {
        Err(failure) => {
            assert_eq!(failure.usage.transcript, t.usage());
            Ok(
                json!({"phase":"outer","decision":format!("{:?}",failure.cause),
                "component":component(failure.cause),"imports":imports,"usage":usage(failure.usage),
                "same_transcript_counters_as_entry":t.usage()==before,"record":null,
                "restored_points":null,"consumed_claims":null,"continuation":null}),
            )
        }
        Ok((record, observed)) => {
            assert_eq!(observed.transcript, t.usage());
            let openings = record.openings();
            let points = record.points();
            let values = record.values();
            let consumed: Vec<_> = openings
                .iter()
                .zip(values)
                .map(|(o, value)| json!([o.id(), hex(value.to_le_bytes().as_ref())]))
                .collect();
            let mut out = json!({"phase":"outer","decision":"accept","imports":imports,
                "usage":usage(observed),"record":{"sc":sc(record.sc()),
                    "openings":openings.iter().map(opening).collect::<Vec<_>>()},
                "restored_points":[point(points[0]),point(points[1])],"consumed_claims":consumed,
                "continuation":null});
            if let Some(raw) = input.get("following_hex") {
                out["continuation"] = following(&mut t, &unhex(raw)?)?;
            }
            Ok(out)
        }
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let input: Value =
            serde_json::from_str(&line.expect("fixture line")).expect("fixture JSON");
        let result = match input["degree"].as_u64() {
            Some(4) => verify::<QM31>(&input),
            Some(8) => verify::<OM31>(&input),
            _ => Err("FixtureDegree".into()),
        };
        println!("{}", result.expect("valid corpus request"));
    }
}
