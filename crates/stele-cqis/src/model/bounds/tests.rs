//! RFC-0025 collection §§1–4: complete typed-input validation and exact ordered bytes.
use super::{records, Bounds, Context, PREFIX};
use crate::{
    bounds::arithmetic,
    model::{Error, Model, Registry, Scales},
};
use alloc::{vec, vec::Vec};
use serde_json::Value;

fn blob<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(input[..4].try_into().expect("length")) as usize;
    let raw = &input[4..4 + n];
    *input = &input[4 + n..];
    raw
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn scale_bytes(model: &Model) -> Vec<u8> {
    let mut raw = b"stele/v0.1/cqis/scales".to_vec();
    raw.extend(model.identity());
    let mut j = 0;
    for ordinal in 0..model.shape().record_count() {
        let p = model.shape().physical(ordinal).expect("physical");
        if p.dimensions().len() != 2 {
            continue;
        }
        raw.extend(ordinal.to_le_bytes());
        raw.extend((if j % 2 == 0 { 1024i16 } else { -1099i16 }).to_le_bytes());
        for row in 0..p.dimensions()[0] {
            raw.extend([1u16, 65535, 32768, 255][row as usize % 4].to_le_bytes());
        }
        j += 1;
    }
    raw
}
fn fixtures(scope: &str, mut visit: impl FnMut(&Value, Model, Scales, &[u8])) {
    let data: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/bound-collections.json"
    ))
    .expect("reference");
    let mut models = include_bytes!("../../../tests/fixtures/bound-models.bin").as_slice();
    let mut registries = include_bytes!("../../../tests/fixtures/bound-registries.bin").as_slice();
    for c in data["cases"].as_array().expect("cases") {
        let raw = blob(&mut models);
        let registry = blob(&mut registries);
        if c["scope"] != scope {
            continue;
        }
        let model = Model::decode(raw).expect("Model");
        let scales = Scales::decode(&model, &scale_bytes(&model)).expect("Scales");
        assert_eq!(
            model.identity().as_slice(),
            hex(c["model_id"].as_str().expect("ModelId"))
        );
        assert_eq!(
            scales.identity().as_slice(),
            hex(c["scales_id"].as_str().expect("ScalesId"))
        );
        visit(c, model, scales, registry);
    }
    assert!(models.is_empty() && registries.is_empty());
}
fn encoded(model: &Model, scales: &Scales, registry: &Registry) -> (Bounds, Vec<u8>) {
    let mut raw = Vec::new();
    let bounds = Bounds::write_to(model, scales, registry, |part| {
        raw.extend(part);
        Ok::<_, ()>(())
    })
    .expect("complete Bounds");
    (bounds, raw)
}
fn spans(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut at = PREFIX.len() + 98;
    let mut result = Vec::new();
    while at < raw.len() {
        let n = u32::from_le_bytes(raw[at + 2..at + 6].try_into().expect("length")) as usize;
        result.push((at, at + 6 + n));
        at += 6 + n;
    }
    assert_eq!(at, raw.len());
    result
}

#[test]
fn matches_reference_complete_collections_and_rejects_each_slot_tamper() {
    let mut valid = 0;
    let mut invalid = 0;
    fixtures("complete", |c, model, scales, rr| {
        let registry = Registry::decode(&model, rr).expect("complete regenerated Registry");
        assert_eq!(
            registry.identity().as_slice(),
            hex(c["registry_id"].as_str().expect("RegistryId"))
        );
        if let Some(error) = c["error"].as_str() {
            let expected = Error::ArithmeticBounds(match error {
                "ScoreBound" => arithmetic::Error::ScoreBound,
                "BlockBound" => arithmetic::Error::BlockBound,
                _ => unreachable!("error"),
            });
            let mut written = 0;
            assert_eq!(
                Bounds::write_to(&model, &scales, &registry, |part| {
                    written += part.len();
                    Ok::<_, ()>(())
                }),
                Err(expected)
            );
            assert!(written > 0); // A partial sink does not yield a completed Bounds.
            invalid += 1;
            return;
        }
        valid += 1;
        let (bounds, raw) = encoded(&model, &scales, &registry);
        assert_eq!(
            bounds.identity().as_slice(),
            hex(c["identity"].as_str().expect("BoundsId"))
        );
        assert_eq!(bounds.byte_length(), c["length"].as_u64().expect("length"));
        assert_eq!(
            u64::from(bounds.record_count()),
            c["count"].as_u64().expect("count")
        );
        assert_eq!(bounds.model_identity(), model.identity());
        assert_eq!(bounds.scales_identity(), scales.identity());
        assert_eq!(bounds.registry_identity(), registry.identity());
        assert_eq!(blake3::hash(&raw).as_bytes(), &bounds.identity());
        let records = spans(&raw);
        for (i, ((start, end), expected)) in records
            .iter()
            .zip(c["records"].as_array().expect("records"))
            .enumerate()
        {
            assert_eq!(
                u16::from_le_bytes(raw[*start..*start + 2].try_into().expect("ordinal")) as usize,
                i
            );
            let record = &raw[*start + 6..*end];
            let offset = b"stele/v0.1/cqis/model-arithmetic".len();
            let n = u16::from_le_bytes(
                record[offset + 5..offset + 7]
                    .try_into()
                    .expect("parameters"),
            ) as usize;
            assert_eq!(
                u64::from(record[offset + 4]),
                expected["schema"].as_u64().expect("schema")
            );
            assert_eq!(
                &record[offset + 7..offset + 7 + n],
                hex(expected["parameters"].as_str().expect("parameters"))
            );
            assert_eq!(
                blake3::hash(record).to_hex().as_str(),
                expected["digest"].as_str().expect("digest")
            );
        }
        assert_eq!(
            Bounds::decode(&model, &scales, &registry, &raw),
            Ok(bounds.clone())
        );
        assert_eq!(Bounds::new(&model, &scales, &registry), Ok(bounds.clone()));
        let mut input = raw.as_slice();
        let streamed = Bounds::read_from(&model, &scales, &registry, raw.len() as u64, |out| {
            let n = out
                .len()
                .min(input.len())
                .min(if valid == 1 { 7 } else { 8192 });
            out[..n].copy_from_slice(&input[..n]);
            input = &input[n..];
            Ok::<_, ()>(n)
        })
        .expect("short-read accumulation");
        assert_eq!(streamed, bounds);
        assert!(input.is_empty());
        for (start, end) in &records {
            for at in [*start, *start + 2, *start + 6, *end - 1] {
                let mut bad = raw.clone();
                bad[at] ^= 1;
                assert_eq!(
                    Bounds::decode(&model, &scales, &registry, &bad),
                    Err(Error::Bounds)
                );
            }
            let mut omitted = raw[..*start].to_vec();
            omitted.extend_from_slice(&raw[*end..]);
            assert_eq!(
                Bounds::decode(&model, &scales, &registry, &omitted),
                Err(Error::Bounds)
            );
            let mut repeated = raw[..*end].to_vec();
            repeated.extend_from_slice(&raw[*start..]);
            assert_eq!(
                Bounds::decode(&model, &scales, &registry, &repeated),
                Err(Error::Bounds)
            );
        }
        if valid == 1 {
            rejection_boundaries(&model, &scales, &registry, &bounds, &raw);
        }
    });
    assert_eq!((valid, invalid), (4, 2));
}

fn rejection_boundaries(
    model: &Model,
    scales: &Scales,
    registry: &Registry,
    bounds: &Bounds,
    raw: &[u8],
) {
    let header = PREFIX.len() + 98;
    for at in 0..header {
        let mut bad = raw.to_vec();
        bad[at] ^= 1;
        assert_eq!(
            Bounds::decode(model, scales, registry, &bad),
            Err(Error::Bounds)
        );
    }
    for end in [0, 1, header - 1, raw.len() / 2, raw.len() - 1] {
        assert_eq!(
            Bounds::decode(model, scales, registry, &raw[..end]),
            Err(Error::Bounds)
        );
    }
    let mut bad = raw.to_vec();
    bad.push(0);
    assert_eq!(
        Bounds::decode(model, scales, registry, &bad),
        Err(Error::Bounds)
    );
    let mut wrong = bounds.identity();
    wrong[0] ^= 1;
    assert_eq!(
        Bounds::decode_expected(model, scales, registry, &wrong, raw),
        Err(Error::Identity)
    );
    let (a, b) = (spans(raw)[0], spans(raw)[1]);
    let mut swapped = raw[..a.0].to_vec();
    swapped.extend(&raw[b.0..b.1]);
    swapped.extend(&raw[a.0..a.1]);
    swapped.extend(&raw[b.1..]);
    assert_eq!(
        Bounds::decode(model, scales, registry, &swapped),
        Err(Error::Bounds)
    );
    let mut changed = scale_bytes(model);
    changed[58] = 2; // Original nonmaximum channel, same derived maxima.
    let changed = Scales::decode(model, &changed).expect("different complete Scales");
    let (other, other_raw) = encoded(model, &changed, registry);
    assert_eq!(&raw[header..], &other_raw[header..]);
    assert_ne!(other.identity(), bounds.identity());
    assert_eq!(
        Bounds::decode(model, &changed, registry, raw),
        Err(Error::Bounds)
    );
    let mut changed_model = model.encode().expect("Model");
    let logits = changed_model.len() - model.decoding().encode().expect("Decoding").len() - 5;
    changed_model[logits] = (changed_model[logits] + 1) % 31;
    let changed_model = Model::decode(&changed_model).expect("same-shape different Model");
    let changed_scales =
        Scales::decode(&changed_model, &scale_bytes(&changed_model)).expect("Scales");
    let mut calls = 0;
    assert_eq!(
        Bounds::write_to(&changed_model, scales, registry, |_| {
            calls += 1;
            Ok::<_, ()>(())
        }),
        Err(Error::Identity)
    );
    assert_eq!(
        Bounds::write_to(&changed_model, &changed_scales, registry, |_| {
            calls += 1;
            Ok::<_, ()>(())
        }),
        Err(Error::Identity)
    );
    assert_eq!(calls, 0);
    assert_eq!(
        Bounds::write_to(model, scales, registry, |_| Err::<(), _>(())),
        Err(Error::Write)
    );
    let mut calls = 0;
    assert_eq!(
        Bounds::write_to(model, scales, registry, |_| {
            calls += 1;
            if calls == 1 + 2 * usize::from(bounds.record_count()) {
                Err(())
            } else {
                Ok(())
            }
        }),
        Err(Error::Write)
    );
    let before = calls;
    assert_eq!(
        Bounds::read_from(model, scales, registry, (1 << 29) + 1, |_| {
            calls += 1;
            Ok::<_, ()>(0)
        }),
        Err(Error::Capacity)
    );
    assert_eq!(before, calls);
    assert_eq!(
        Bounds::read_from(model, scales, registry, u64::MAX, |_| {
            calls += 1;
            Ok::<_, ()>(0)
        }),
        Err(Error::Capacity)
    );
    assert_eq!(before, calls);
    assert_eq!(
        Bounds::read_from(
            model,
            scales,
            registry,
            raw.len() as u64,
            |_| Err::<usize, _>(())
        ),
        Err(Error::Read)
    );
    assert_eq!(
        Bounds::read_from(
            model,
            scales,
            registry,
            raw.len() as u64,
            |out| Ok::<_, ()>(out.len() + 1)
        ),
        Err(Error::Read)
    );
    for length in [raw.len() - 1, raw.len(), raw.len() + 1] {
        let mut input = if length == raw.len() {
            bad.as_slice()
        } else {
            raw
        };
        assert_eq!(
            Bounds::read_from(model, scales, registry, length as u64, |out| {
                let n = input.len().min(out.len());
                out[..n].copy_from_slice(&input[..n]);
                input = &input[n..];
                Ok::<_, ()>(n)
            }),
            Err(Error::Bounds)
        );
    }
}

#[test]
fn matches_reference_named_and_maximal_record_layouts_without_claiming_registry_admission() {
    let mut counts = Vec::new();
    fixtures("record-layout-only", |c, model, scales, rr| {
        assert!(rr.is_empty());
        // Private record layout only: no Registry or completed Bounds is constructed.
        let context = Context {
            model: &model,
            scales: &scales,
        };
        let mut hash = blake3::Hasher::new();
        let mut count = 0u16;
        let mut length = 0u64;
        records(&context, |record| {
            let raw = record.as_bytes();
            hash.update(&count.to_le_bytes());
            hash.update(&(raw.len() as u32).to_le_bytes());
            hash.update(raw);
            count += 1;
            length += 6 + raw.len() as u64;
            Ok(())
        })
        .expect("complete static layout");
        assert_eq!(u64::from(count), c["count"].as_u64().expect("count"));
        assert_eq!(length, c["record_bytes"].as_u64().expect("length"));
        assert_eq!(
            hash.finalize().to_hex().as_str(),
            c["records_digest"].as_str().expect("digest")
        );
        counts.push(count);
    });
    assert_eq!(counts, vec![481, 1164, 5005, 4620]);
}
