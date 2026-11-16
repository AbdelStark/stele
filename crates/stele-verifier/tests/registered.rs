//! Spec-derived RFC-0026 A16 cases, written before consulting registry vectors.
use stele_hash::blake3_digest;
use stele_verifier::{development::Error, registered};

#[derive(Clone)]
struct Column {
    name: String,
    kind: u8,
    values: Vec<i64>,
    signed: u8,
    bits: u8,
    log: u8,
}
fn blob(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}
fn tagged(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut out = tag.to_vec();
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    blake3_digest(&out)
}
fn relation(columns: &[Column], normalized: bool) -> Vec<u8> {
    let mut out = b"stele/v0.1/relation/encoding/v1".to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(columns.len() as u32).to_le_bytes());
    for c in columns {
        blob(&mut out, c.name.as_bytes());
        out.push(c.kind);
        if c.kind == 0 {
            out.extend_from_slice(&0u32.to_le_bytes());
        } else if c.kind == 2 {
            out.extend_from_slice(&(c.values.len() as u32).to_le_bytes());
            for v in &c.values {
                out.extend_from_slice(
                    &(if normalized
                        && (c.name.starts_with("G/embedding/O")
                            || matches!(
                                c.name.as_str(),
                                "G/embedding/m"
                                    | "G/embedding/mm"
                                    | "G/argmax/onehot"
                                    | "G/argmax/below"
                                    | "G/argmax/rows"
                            ))
                    {
                        0
                    } else {
                        *v
                    })
                    .to_le_bytes(),
                );
            }
        }
        out.extend_from_slice(&[
            c.signed,
            if normalized
                && (c.name.starts_with("G/embedding/O")
                    || matches!(
                        c.name.as_str(),
                        "G/embedding/m"
                            | "G/embedding/mm"
                            | "G/argmax/onehot"
                            | "G/argmax/below"
                            | "G/argmax/rows"
                    ))
            {
                1
            } else {
                c.bits
            },
            c.log,
        ]);
    }
    out.extend_from_slice(&[0; 24]);
    out
}
struct Case {
    entry: Vec<u8>,
    public: Vec<u8>,
    proof: Vec<u8>,
    columns: Vec<Column>,
}
impl Case {
    fn new(shift: i16, tokens: &[u32; 4], range: (u32, u32), next: Option<u32>) -> Self {
        let cqis = [3; 32];
        let mut data = Vec::new();
        for b in [b"model".as_slice(), b"scales", b"preparation"] {
            blob(&mut data, b);
        }
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&7u16.to_le_bytes());
        blob(&mut data, &[2, 0, 255, 255]);
        let mut public = b"stele-dev-public-v4".to_vec();
        public.extend_from_slice(&data);
        public.extend_from_slice(&0u32.to_le_bytes());
        let mut statement = 4u32.to_le_bytes().to_vec();
        for token in tokens {
            statement.extend_from_slice(&token.to_le_bytes());
        }
        statement.extend_from_slice(&range.0.to_le_bytes());
        statement.extend_from_slice(&range.1.to_le_bytes());
        statement.push(u8::from(next.is_some()));
        if let Some(y) = next {
            statement.extend_from_slice(&y.to_le_bytes());
        }
        public.extend_from_slice(&statement);
        let mut model = b"stele/v0.1/dev-e2e/model".to_vec();
        model.extend_from_slice(&cqis);
        model.extend_from_slice(&0u32.to_le_bytes());
        model.extend_from_slice(&1u32.to_le_bytes());
        model.extend_from_slice(&7u16.to_le_bytes());
        model.extend_from_slice(&2u32.to_le_bytes()); // code count, not blob byte count
        model.extend_from_slice(&[2, 0, 255, 255]);
        let mut static_bytes = b"stele/v0.1/dev-e2e/plan-static/v1".to_vec();
        static_bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        static_bytes.extend_from_slice(&data);
        static_bytes.extend_from_slice(&0u32.to_le_bytes());
        let column = |name: &str, values: Vec<i64>, bits, log| Column {
            name: name.into(),
            kind: 2,
            values,
            signed: 0,
            bits,
            log,
        };
        let mut columns = vec![column(
            "G/embedding/O0",
            (0..16)
                .map(|j| i64::from(j % 4 == tokens[j / 4] as usize))
                .collect(),
            1,
            4,
        )];
        let mantissas = [1u16, 255, 65535];
        let selected: Vec<_> = tokens
            .iter()
            .map(|&x| {
                let m = i64::from(mantissas[x as usize]);
                if shift < 0 {
                    m
                } else if shift >= 17 {
                    65536
                } else {
                    (m << shift).min(65536)
                }
            })
            .collect();
        let width = (64 - selected.iter().max().expect("four tokens").leading_zeros()) as u8;
        columns.push(column(
            if shift < 0 {
                "G/embedding/m"
            } else {
                "G/embedding/mm"
            },
            selected,
            width,
            2,
        ));
        for (name, below) in [("G/argmax/onehot", false), ("G/argmax/below", true)] {
            columns.push(column(
                name,
                (0..16)
                    .map(|j| {
                        let (i, v) = (j / 4, j % 4);
                        if i < range.0 as usize || i >= range.1 as usize || v >= 3 {
                            return 0;
                        }
                        let c = if i == 3 {
                            next.expect("checked last row")
                        } else {
                            tokens[i + 1]
                        } as usize;
                        i64::from(if below { v < c } else { v == c })
                    })
                    .collect(),
                1,
                4,
            ));
        }
        columns.push(column(
            "G/argmax/rows",
            (0..4)
                .map(|i| i64::from(range.0 <= i && i < range.1))
                .collect(),
            1,
            2,
        ));
        columns.push(column("static", vec![2], 2, 0));
        let rel = relation(&columns, false);
        let mut entry = b"stele-dev-plan-v1".to_vec();
        entry.extend_from_slice(&cqis);
        entry.extend_from_slice(&blake3_digest(&model));
        entry.extend_from_slice(&4u32.to_le_bytes());
        entry.push(5);
        entry.extend_from_slice(&blake3_digest(&static_bytes));
        entry.extend_from_slice(&tagged(
            b"stele/v0.1/dev-e2e/plan-template/v1",
            &relation(&columns, true),
        ));
        entry.extend_from_slice(&(rel.len() as u64).to_le_bytes());
        entry.extend_from_slice(&3u32.to_le_bytes());
        entry.extend_from_slice(&2u16.to_le_bytes());
        entry.extend_from_slice(&shift.to_le_bytes());
        entry.push(0);
        entry.extend_from_slice(&3u32.to_le_bytes());
        for m in mantissas {
            entry.extend_from_slice(&m.to_le_bytes());
        }
        assert_eq!(entry.len(), 177);
        let mut input = b"stele/v0.1/dev-e2e/public-input".to_vec();
        input.extend_from_slice(&cqis);
        input.extend_from_slice(&data);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&statement);
        input.push(5);
        let mut digest = b"stele/v0.1/dev-e2e/statement".to_vec();
        digest.extend_from_slice(&(input.len() as u64).to_le_bytes());
        digest.extend_from_slice(&input);
        digest.extend_from_slice(&blake3_digest(&rel));
        let mut proof = b"stele-dev-e2e-v1".to_vec();
        proof.extend_from_slice(&1u16.to_le_bytes());
        proof.extend_from_slice(&cqis);
        proof.extend_from_slice(&blake3_digest(&digest));
        proof.extend_from_slice(&[0; 24]);
        Self {
            entry,
            public,
            proof,
            columns,
        }
    }
    fn ordinary() -> Self {
        Self::new(-1, &[0, 2, 1, 0], (1, 4), Some(2))
    }
    fn check(&self) -> Result<registered::Verified, Error> {
        registered::verify(
            &self.public,
            &self.proof,
            &relation(&self.columns, false),
            &self.entry,
        )
    }
    fn resize_entry(&mut self) {
        self.entry[150..158]
            .copy_from_slice(&(relation(&self.columns, false).len() as u64).to_le_bytes());
    }
}

#[test]
fn accepts_spec_request_columns_and_original_relation_replay() {
    for shift in [-32768, -1, 0, 1, 16, 17, 32767] {
        for (tokens, range, next) in [([0, 2, 1, 0], (1, 4), Some(2)), ([0; 4], (0, 1), None)] {
            let c = Case::new(shift, &tokens, range, next);
            assert_eq!(
                c.check().expect("honest spec fixture").to_string(),
                "trusted plan registry; development: no security level"
            );
        }
    }
    let a = Case::new(-1, &[0; 4], (0, 1), None);
    let b = Case::ordinary();
    assert_ne!(a.columns[1].bits, b.columns[1].bits);
    assert_eq!(&a.entry[118..150], &b.entry[118..150]);
}

#[test]
fn rejects_registry_encodings_before_public_parsing() {
    let c = Case::ordinary();
    for n in 0..c.entry.len() {
        assert_eq!(
            registered::verify(&[], &[], &[], &c.entry[..n]),
            Err(Error::RegistryEncoding)
        );
    }
    let mut bad = vec![{
        let mut e = c.entry.clone();
        e.push(0);
        e
    }];
    for (at, value) in [
        (0, 0),
        (85, 4),
        (81, 3),
        (158, 0),
        (162, 0),
        (167, 2),
        (171, 0),
    ] {
        let mut e = c.entry.clone();
        e[at] = value;
        bad.push(e);
    }
    let mut e = c.entry.clone();
    e[150..158].copy_from_slice(&62u64.to_le_bytes());
    bad.push(e);
    let mut e = c.entry.clone();
    e[81..85].copy_from_slice(&(1u32 << 30).to_le_bytes());
    bad.push(e);
    let mut e = c.entry.clone();
    e[158..162].copy_from_slice(&u32::MAX.to_le_bytes());
    bad.push(e);
    for entry in bad {
        assert_eq!(
            registered::verify(&[], &[], &[], &entry),
            Err(Error::RegistryEncoding)
        );
    }
}

#[test]
fn rejects_public_tokens_and_key_before_static_and_relation() {
    let mut c = Case::ordinary();
    let tokens = c.public.len() - 33;
    c.public[tokens + 4..tokens + 8].copy_from_slice(&3u32.to_le_bytes());
    c.entry[48] ^= 1;
    assert_eq!(c.check(), Err(Error::StatementMismatch));
    let mut c = Case::ordinary();
    let y = c.public.len() - 4;
    c.public[y..].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(c.check(), Err(Error::StatementMismatch));
    let mut c = Case::ordinary();
    c.entry[48] ^= 1;
    c.entry[86] ^= 1;
    assert_eq!(c.check(), Err(Error::RegistryKeyMismatch));
    let mut c = Case::ordinary();
    c.entry[81..85].copy_from_slice(&8u32.to_le_bytes());
    assert_eq!(c.check(), Err(Error::RegistryKeyMismatch));
    let mut c = Case::ordinary();
    c.public[23] ^= 1;
    c.entry[150] ^= 1;
    assert_eq!(c.check(), Err(Error::RegistryStaticMismatch));
}

#[test]
fn rejects_relation_length_before_decoding_and_decoding_before_requests() {
    let c = Case::ordinary();
    assert_eq!(
        registered::verify(&c.public, &[], &[], &c.entry),
        Err(Error::RegistryTemplateMismatch)
    );
    let mut rel = relation(&c.columns, false);
    rel[0] ^= 1;
    assert_eq!(
        registered::verify(&c.public, &[], &rel, &c.entry),
        Err(Error::StatementMismatch)
    );
    let mut c = Case::ordinary();
    c.columns[0].values[0] ^= 1;
    let mut rel = relation(&c.columns, false);
    let last = rel.len() - 1;
    rel[last] = 255;
    assert_eq!(
        registered::verify(&c.public, &[], &rel, &c.entry),
        Err(Error::StatementMismatch)
    );
}

#[test]
fn rejects_request_names_kinds_lengths_values_widths_and_logs() {
    let mutations: Vec<fn(&mut Vec<Column>)> = vec![
        (|c| c.push(c[0].clone())),
        (|c| {
            c.remove(0);
        }),
        (|c| c[0].name = "G/embedding/O00".into()),
        (|c| c[0].name = "G/embedding/O1".into()),
        (|c| c[0].name = "G/embedding/O".into()),
        (|c| c[0].name = "G/embedding/O9999999999999999999999999".into()),
        (|c| c[1].name = "G/embedding/mm".into()),
        (|c| c[0].name = "relabelled".into()),
        (|c| c[0].kind = 0),
        (|c| c[0].kind = 1),
        (|c| {
            c[0].values.pop();
        }),
        (|c| c[0].values.push(0)),
        (|c| c[0].signed = 1),
        (|c| c[0].bits = 2),
        (|c| c[0].log = 255),
        (|c| c[1].bits -= 1),
    ];
    for mutate in mutations {
        let mut c = Case::ordinary();
        mutate(&mut c.columns);
        c.resize_entry();
        assert_eq!(c.check(), Err(Error::RegistryRequestMismatch));
    }
    for column in 0..5 {
        let mut c = Case::ordinary();
        c.columns[column].values[0] ^= 1;
        assert_eq!(c.check(), Err(Error::RegistryRequestMismatch));
    }
}

#[test]
fn rejects_template_before_validation_and_validation_before_proof() {
    let mut c = Case::ordinary();
    c.columns[5].log = 255;
    assert_eq!(c.check(), Err(Error::RegistryTemplateMismatch));
    let pin = tagged(
        b"stele/v0.1/dev-e2e/plan-template/v1",
        &relation(&c.columns, true),
    );
    c.entry[118..150].copy_from_slice(&pin);
    c.proof.clear();
    assert_eq!(c.check(), Err(Error::StatementMismatch));
    let mut c = Case::ordinary();
    c.proof.clear();
    assert_eq!(c.check(), Err(Error::Header));
}

// Comparison inputs first read after the independent implementation snapshot.
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../research/plan-registry/vectors.json"))
        .expect("A16 vectors")
}
fn unhex(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_str()
        .expect("hex string")
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}
#[test]
fn matches_reference_a16_vectors() {
    let vectors = vectors();
    let codecs = vectors["codec_cases"].as_array().expect("codec cases");
    for case in codecs {
        assert_eq!(
            registered::verify(
                &unhex(&case["public_hex"]),
                &[],
                &unhex(&case["relation_hex"]),
                &unhex(&case["entry_hex"])
            ),
            Err(Error::Header),
            "{}",
            case["name"]
        );
    }
    for key in ["negative_cases", "preflight_cases"] {
        for case in vectors[key].as_array().expect("mutation cases") {
            let base = codecs
                .iter()
                .find(|b| b["name"] == case["base"])
                .expect("named base");
            let mut entry = unhex(&base["entry_hex"]);
            let mut relation = unhex(case.get("relation_hex").unwrap_or(&base["relation_hex"]));
            if let Some(offset) = case["offset"].as_u64() {
                relation[offset as usize] = case["byte"].as_u64().expect("byte") as u8;
            }
            if case.get("append_hex").is_some() {
                relation.extend_from_slice(&unhex(&case["append_hex"]));
            }
            // Structural request controls explicitly reach the request check after the trusted length precheck.
            if key == "negative_cases" {
                entry[150..158].copy_from_slice(&(relation.len() as u64).to_le_bytes());
            }
            let expected = match case["error"].as_str().expect("error name") {
                "RegistryRequestMismatch" => Some(Error::RegistryRequestMismatch),
                "RegistryTemplateMismatch" => Some(Error::RegistryTemplateMismatch),
                "StatementMismatch" => Some(Error::StatementMismatch),
                _ => None,
            }
            .expect("known vector error");
            assert_eq!(
                registered::verify(&unhex(&base["public_hex"]), &[], &relation, &entry),
                Err(expected),
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn matches_reference_registered_windows() {
    let Ok(directory) = std::env::var("STELE_DEV_REPLAY_DIR") else {
        eprintln!("STELE_DEV_REPLAY_DIR unset: production byte-5 registry windows not supplied");
        return;
    };
    for pin in vectors()["production_pins"]
        .as_array()
        .expect("production pins")
    {
        let name = pin["name"].as_str().expect("window name");
        let path = std::path::Path::new(&directory).join(name);
        let read = |kind: &str| {
            let bytes = std::fs::read(path.join(format!("{kind}.bin"))).expect("exported window");
            assert_eq!(
                blake3_digest(&bytes).as_slice(),
                unhex(&pin[format!("{kind}_blake3")]),
                "{name}/{kind}"
            );
            bytes
        };
        let (public, proof, relation) = (read("public"), read("proof"), read("relation"));
        assert!(
            registered::verify(&public, &proof, &relation, &unhex(&pin["entry_hex"])).is_ok(),
            "{name}"
        );
        eprintln!("A16 registered {name}: accepted pinned proof");
    }
}

#[test]
fn rejects_malformed_public_and_relation_before_request_checks() {
    let c = Case::ordinary();
    let rel = relation(&c.columns, false);
    for n in 0..c.public.len() {
        assert_eq!(
            registered::verify(&c.public[..n], &[], &rel, &c.entry),
            Err(Error::StatementMismatch)
        );
    }
    let mut extra = c.public.clone();
    extra.push(0);
    assert_eq!(
        registered::verify(&extra, &[], &rel, &c.entry),
        Err(Error::StatementMismatch)
    );
    let kind = 43 + c.columns[0].name.len();
    let signed = kind + 1 + 4 + c.columns[0].values.len() * 8;
    for (at, byte) in [(43, 255), (kind, 3), (signed, 2)] {
        let mut malformed = rel.clone();
        malformed[at] = byte;
        assert_eq!(
            registered::verify(&c.public, &[], &malformed, &c.entry),
            Err(Error::StatementMismatch)
        );
    }
    let mut malformed = rel.clone();
    malformed[35..39].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        registered::verify(&c.public, &[], &malformed, &c.entry),
        Err(Error::StatementMismatch)
    );
    let mut malformed = rel;
    malformed[kind + 1..kind + 5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        registered::verify(&c.public, &[], &malformed, &c.entry),
        Err(Error::StatementMismatch)
    );
}

#[test]
fn rejects_reordered_columns_and_preserves_nonreserved_names() {
    let mut c = Case::ordinary();
    c.columns.swap(0, 1);
    assert_eq!(c.check(), Err(Error::RegistryTemplateMismatch));
    for name in ["G/embedding/more", "G/argmax/rows-extra"] {
        let mut c = Case::ordinary();
        c.columns[5].name = name.into();
        c.resize_entry();
        let template = tagged(
            b"stele/v0.1/dev-e2e/plan-template/v1",
            &relation(&c.columns, true),
        );
        c.entry[118..150].copy_from_slice(&template);
        c.proof.clear();
        assert_eq!(c.check(), Err(Error::Header));
        c.columns[5].values[0] ^= 1;
        assert_eq!(c.check(), Err(Error::RegistryTemplateMismatch));
    }
}
