//! Post-snapshot comparison with A16 declaration-only exports; no proof acceptance claim.
extern crate std;
use super::*;
use serde_json::Value;
use std::{format, fs, path::Path};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../research/plan-registry/vectors.json"
    ))
    .expect("A16 vectors")
}
fn unhex(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .expect("hex")
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(core::str::from_utf8(b).expect("ASCII"), 16).expect("hex byte"))
        .collect()
}
fn request(v: &Value) -> Request {
    Request {
        tokens: v["tokens"]
            .as_array()
            .expect("tokens")
            .iter()
            .map(|x| x.as_u64().expect("token") as u32)
            .collect(),
        begin: v["start"].as_u64().expect("start") as usize,
        end: v["end"].as_u64().expect("end") as usize,
        next: v["next"].as_u64().map(|y| y as u32),
    }
}

#[test]
fn matches_reference_a16_declaration_variants() {
    let Ok(directory) = std::env::var("STELE_DEV_REPLAY_DIR") else {
        std::eprintln!("STELE_DEV_REPLAY_DIR unset: A16 declaration exports not supplied");
        return;
    };
    let vectors = vectors();
    for case in vectors["declaration_variants"]
        .as_array()
        .expect("variants")
    {
        let name = case["name"].as_str().expect("name");
        let path = Path::new(&directory).join(name);
        let relation = fs::read(path.join("relation.bin")).expect("declaration export");
        let metadata: Value =
            serde_json::from_slice(&fs::read(path.join("request.json")).expect("request metadata"))
                .expect("request JSON");
        assert_eq!(metadata, case["request"], "{name}");
        assert_eq!(
            blake3_digest(&relation).as_slice(),
            unhex(&case["relation_blake3"]),
            "{name}"
        );
        let pin = vectors["production_pins"]
            .as_array()
            .expect("pins")
            .iter()
            .find(|p| name.starts_with(p["name"].as_str().expect("pin name")))
            .expect("window pin");
        let mut entry = Entry::decode(&unhex(&pin["entry_hex"])).expect("entry");
        // These are declaration comparisons, so only request metadata/template fields are used.
        entry.shift = metadata["ee"].as_i64().expect("exponent") as i32
            + metadata["f0"].as_u64().expect("fraction") as i32;
        entry.mantissas = metadata["mantissas"]
            .as_array()
            .expect("mantissas")
            .iter()
            .map(|m| m.as_u64().expect("mantissa") as u16)
            .collect();
        entry.template = unhex(&case["template_digest"]).try_into().expect("digest");
        entry.relation_len = relation.len() as u64;
        assert_eq!(
            bind_relation(&relation, &request(&metadata), &entry),
            Ok(()),
            "{name}"
        );
        std::eprintln!("A16 declaration {name}: request/template matched");
    }
}

fn column(out: &mut Vec<u8>, name: &str, values: &[i64], log: u8, normalized: bool) {
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(2);
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for &v in values {
        out.extend_from_slice(&(if normalized { 0 } else { v }).to_le_bytes());
    }
    out.extend_from_slice(&[0, 1, log]);
}
#[test]
fn matches_reference_a16_blocked_embedding() {
    let vectors = vectors();
    let v = &vectors["blocked_embedding"];
    let tokens: Vec<_> = v["tokens"]
        .as_array()
        .expect("tokens")
        .iter()
        .map(|x| x.as_u64().expect("token") as u32)
        .collect();
    let vocabulary = v["V"].as_u64().expect("V") as u32;
    let mut encoded = unhex(&vectors["codec_cases"][0]["entry_hex"]);
    encoded.truncate(171);
    encoded[158..162].copy_from_slice(&vocabulary.to_le_bytes());
    encoded[162..164].copy_from_slice(&(v["d"].as_u64().expect("d") as u16).to_le_bytes());
    encoded[164..166].copy_from_slice(&(-1i16).to_le_bytes());
    encoded[166] = 0;
    encoded[167..171].copy_from_slice(&vocabulary.to_le_bytes());
    for _ in 0..vocabulary {
        encoded.extend_from_slice(&1u16.to_le_bytes());
    }
    let mut entry = Entry::decode(&encoded).expect("blocked entry");
    assert_eq!(entry.lb, 0);
    let request = Request {
        tokens,
        begin: 0,
        end: 1,
        next: None,
    };
    let mut relation = b"stele/v0.1/relation/encoding/v1".to_vec();
    relation.extend_from_slice(&0u32.to_le_bytes());
    relation.extend_from_slice(&6u32.to_le_bytes());
    let mut normalized = relation.clone();
    for (name, pin) in v["columns"].as_object().expect("embedding blocks") {
        let mut values = alloc::vec![0; pin["length"].as_u64().expect("length") as usize];
        for i in pin["nonzero"].as_array().expect("nonzero indices") {
            values[i.as_u64().expect("index") as usize] = 1;
        }
        let log = pin["log_len"].as_u64().expect("log") as u8;
        column(&mut relation, name, &values, log, false);
        column(&mut normalized, name, &values, log, true);
    }
    let vp = 1usize << entry.lv;
    for (name, values, log) in [
        ("G/embedding/m", alloc::vec![1, 1], 1),
        (
            "G/argmax/onehot",
            (0..2 * vp).map(|i| i64::from(i == 1)).collect(),
            15,
        ),
        (
            "G/argmax/below",
            (0..2 * vp).map(|i| i64::from(i == 0)).collect(),
            15,
        ),
        ("G/argmax/rows", alloc::vec![1, 0], 1),
    ] {
        column(&mut relation, name, &values, log, false);
        column(&mut normalized, name, &values, log, true);
    }
    relation.extend_from_slice(&[0; 24]);
    normalized.extend_from_slice(&[0; 24]);
    let mut preimage = TEMPLATE_TAG.to_vec();
    preimage.extend_from_slice(&(normalized.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&normalized);
    entry.template = blake3_digest(&preimage);
    entry.relation_len = relation.len() as u64;
    assert_eq!(bind_relation(&relation, &request, &entry), Ok(()));
    let first_value = 31 + 4 + 4 + 4 + "G/embedding/O0".len() + 1 + 4;
    relation[first_value + 8192 * 8] = 0;
    assert_eq!(
        bind_relation(&relation, &request, &entry),
        Err(Error::RegistryRequestMismatch)
    );
    assert_eq!(
        request_id(b"G/embedding/O01", 2, -1),
        Err(Error::RegistryRequestMismatch)
    );
    assert_eq!(
        request_id(format!("G/embedding/O{}", usize::MAX).as_bytes(), 2, -1),
        Err(Error::RegistryRequestMismatch)
    );
}
