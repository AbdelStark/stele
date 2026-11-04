//! RFC-0025 encoding §3: complete Artifact streams and full-domain layout parity.
use serde_json::Value;
use stele_cqis::model::{Artifact, ArtifactLayout, Error, Model, Preparation, Scales};

fn blob<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(input[..4].try_into().expect("length")) as usize;
    let out = &input[4..4 + n];
    *input = &input[4 + n..];
    out
}
fn read(input: &mut &[u8], out: &mut [u8], limit: usize) -> Result<usize, ()> {
    assert!(!out.is_empty() && out.len() <= 65536);
    let n = out.len().min(input.len()).min(limit);
    out[..n].copy_from_slice(&input[..n]);
    *input = &input[n..];
    Ok(n)
}

#[test]
fn matches_reference_complete_artifact_streams_and_named_maximal_layouts() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/artifact-streams.json")).expect("fixtures");
    let mut input = include_bytes!("fixtures/artifact-streams.bin").as_slice();
    let mut layouts = Vec::new();
    let mut complete = 0;
    let mut generated = 0;
    for (i, c) in fixtures["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let model = Model::decode(blob(&mut input)).expect("Model");
        let layout = ArtifactLayout::new(&model).expect("full-domain layout");
        assert_eq!(layout.model_identity(), model.identity());
        assert_eq!(layout.byte_length(), c["length"].as_u64().expect("length"));
        assert_eq!(
            layout.records().len(),
            usize::from(model.shape().record_count())
        );
        let expected = c["records"].as_array().expect("records");
        assert_eq!(expected.len(), layout.records().len());
        for (r, e) in layout.records().iter().zip(expected) {
            for (name, actual) in [
                ("ordinal", u64::from(r.ordinal())),
                ("record_offset", r.record_offset()),
                ("payload_offset", r.payload_offset()),
                ("payload_length", r.payload_length()),
                ("record_length", r.record_length()),
                ("elements", r.elements()),
                ("bits", u64::from(r.bits())),
            ] {
                assert_eq!(actual, e[name].as_u64().expect("field"), "{name}");
            }
        }
        if c["scope"] == "layout-only" {
            layouts.push((layout.records().len(), layout.byte_length()));
            continue;
        }
        if c["scope"] == "generated-complete" {
            let prep = Preparation::decode(&model, blob(&mut input)).expect("Preparation");
            matches_reference_payload_above_former_element_cap(&model, &prep, &layout, c);
            generated += 1;
            continue;
        }
        complete += 1;
        let prep_raw = blob(&mut input);
        let scale_raw = blob(&mut input);
        let raw = blob(&mut input);
        let prep = Preparation::decode(&model, prep_raw).expect("Preparation");
        let scales = Scales::decode(&model, scale_raw).expect("Scales");
        let count = u16::from_le_bytes(input[..2].try_into().expect("payload count"));
        input = &input[2..];
        let payloads: Vec<_> = (0..count).map(|_| blob(&mut input)).collect();
        assert_eq!(payloads.len(), layout.records().len());
        let mut source = raw;
        let checked = Artifact::read_from(&model, &prep, &scales, |out| {
            read(&mut source, out, if i == 0 { 3 } else { 65536 })
        })
        .expect("complete stream");
        assert!(source.is_empty());
        assert_eq!(checked.byte_length(), layout.byte_length());
        assert_eq!(checked.record_count(), count);
        assert_eq!(checked.model_identity(), model.identity());
        assert_eq!(checked.preparation_identity(), prep.identity());
        assert_eq!(checked.scales_identity(), scales.identity());
        assert_eq!(
            blake3::Hash::from(checked.identity()).to_hex().as_str(),
            c["identity"].as_str().expect("digest")
        );
        assert_eq!(
            Artifact::decode_expected(&model, &prep, &scales, &checked.identity(), raw),
            Ok(checked.clone())
        );
        let mut remaining = payloads.clone();
        let mut produced = Vec::new();
        let mut max_chunk = 0;
        let emitted = Artifact::write_to(
            &model,
            &prep,
            &scales,
            |ordinal, out| {
                read(
                    &mut remaining[usize::from(ordinal)],
                    out,
                    if i == 0 { 3 } else { 65536 },
                )
            },
            |part| {
                assert!(part.len() <= 65536);
                max_chunk = max_chunk.max(part.len());
                produced.extend_from_slice(part);
                Ok::<_, ()>(())
            },
        )
        .expect("complete producer");
        assert!(remaining.iter().all(|p| p.is_empty()));
        assert_eq!(produced, raw);
        assert_eq!(emitted, checked);
        if i == 0 {
            rejects_framing_and_io(&model, &prep, &scales, raw, &payloads, &layout, scale_raw);
        }
        if i >= 32 {
            assert_eq!(max_chunk, 65536);
            let r = &layout.records()[0];
            assert!(r.payload_length() > 65536);
            let mut bad = raw.to_vec();
            bad[r.payload_offset() as usize + 65536] = if r.bits() == 4 { 8 } else { 128 };
            assert_eq!(
                Artifact::decode(&model, &prep, &scales, &bad),
                Err(Error::ArtifactCode)
            );
            let mut bad = raw.to_vec();
            bad[r.payload_offset() as usize - 8 - 2 * 43693 + 65536] ^= 1;
            assert_eq!(
                Artifact::decode(&model, &prep, &scales, &bad),
                Err(Error::Artifact)
            );
            if r.bits() == 4 {
                assert_eq!(r.elements() % 2, 1);
                let mut bad = raw.to_vec();
                bad[(r.payload_offset() + r.payload_length() - 1) as usize] = 25;
                assert_eq!(
                    Artifact::decode(&model, &prep, &scales, &bad),
                    Err(Error::ArtifactPadding)
                );
            }
        }
    }
    assert!(input.is_empty());
    assert_eq!(complete, 34);
    assert_eq!(generated, 1);
    assert_eq!(
        layouts.iter().map(|x| x.0).collect::<Vec<_>>(),
        [196, 291, 2052, 1155]
    );
    assert!(layouts[3].1 > 1 << 38 && layouts.iter().all(|x| x.1 < 1 << 39));
}

fn matches_reference_payload_above_former_element_cap(
    model: &Model,
    prep: &Preparation<'_>,
    layout: &ArtifactLayout,
    case: &Value,
) {
    assert!(layout.records()[0].elements() > 1 << 22);
    let mut scales = b"stele/v0.1/cqis/scales".to_vec();
    scales.extend(model.identity());
    for i in 0..model.shape().record_count() {
        let physical = model.shape().physical(i).expect("physical");
        if physical.dimensions().len() == 2 {
            scales.extend(i.to_le_bytes());
            scales.extend((-1099i16).to_le_bytes());
            for _ in 0..physical.dimensions()[0] {
                scales.extend(65535u16.to_le_bytes());
            }
        }
    }
    let scales = Scales::decode(model, &scales).expect("complete original channels");
    let mut positions = vec![0u64; layout.records().len()];
    let mut raw = Vec::new();
    let produced = Artifact::write_to(
        model,
        prep,
        &scales,
        |i, out| {
            assert!(out.len() <= 65536);
            let record = &layout.records()[usize::from(i)];
            let position = &mut positions[usize::from(i)];
            let n = (record.payload_length() - *position).min(out.len() as u64) as usize;
            for (j, byte) in out[..n].iter_mut().enumerate() {
                *byte = if record.bits() == 8 {
                    127
                } else {
                    [0, 128][((*position + j as u64) % 2) as usize]
                };
            }
            *position += n as u64;
            Ok::<_, ()>(n)
        },
        |part| {
            assert!(part.len() <= 65536);
            raw.extend_from_slice(part);
            Ok::<_, ()>(())
        },
    )
    .expect("complete large payload");
    assert_eq!(
        blake3::Hash::from(produced.identity()).to_hex().as_str(),
        case["identity"].as_str().expect("identity")
    );
    assert_eq!(Artifact::decode(model, prep, &scales, &raw), Ok(produced));
}

fn rejects_framing_and_io(
    model: &Model,
    prep: &Preparation<'_>,
    scales: &Scales,
    raw: &[u8],
    payloads: &[&[u8]],
    layout: &ArtifactLayout,
    scale_raw: &[u8],
) {
    let validate = |bytes: &[u8]| Artifact::decode(model, prep, scales, bytes);
    for range in core::iter::once(0..49).chain(
        layout
            .records()
            .iter()
            .map(|r| (r.record_offset() - 8) as usize..r.payload_offset() as usize),
    ) {
        for at in range {
            let mut bad = raw.to_vec();
            bad[at] ^= 1;
            assert_eq!(validate(&bad), Err(Error::Artifact));
        }
    }
    let mut huge = raw.to_vec();
    huge[49..57].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(validate(&huge), Err(Error::Artifact));
    for r in layout.records() {
        for end in [
            r.record_offset() - 8,
            r.payload_offset(),
            r.payload_offset() + r.payload_length() - 1,
        ] {
            assert_eq!(validate(&raw[..end as usize]), Err(Error::Artifact));
        }
        let start = (r.record_offset() - 8) as usize;
        let end = (r.record_offset() + r.record_length()) as usize;
        let mut omitted = raw[..start].to_vec();
        omitted.extend_from_slice(&raw[end..]);
        assert_eq!(validate(&omitted), Err(Error::Artifact));
        let mut repeated = raw[..end].to_vec();
        repeated.extend_from_slice(&raw[start..]);
        assert_eq!(validate(&repeated), Err(Error::Artifact));
    }
    for end in [0, 1, raw.len() / 2, raw.len() - 1] {
        assert_eq!(validate(&raw[..end]), Err(Error::Artifact));
    }
    let mut suffix = raw.to_vec();
    suffix.push(0);
    assert_eq!(validate(&suffix), Err(Error::Artifact));
    let first = &layout.records()[0];
    let start = first.payload_offset() as usize;
    let last = (first.payload_offset() + first.payload_length() - 1) as usize;
    for (at, byte, error) in [
        (start, 8, Error::ArtifactCode),
        (start, 128, Error::ArtifactCode),
        (last, 16, Error::ArtifactPadding),
    ] {
        let mut bad = raw.to_vec();
        bad[at] = byte;
        assert_eq!(validate(&bad), Err(error));
    }
    let mut changed = raw.to_vec();
    changed[start] = (changed[start] & 240) | if changed[start] & 15 == 7 { 6 } else { 7 };
    let new = validate(&changed).expect("legal code remains canonical");
    assert_ne!(new.identity(), *blake3::hash(raw).as_bytes());
    assert_eq!(
        Artifact::decode_expected(model, prep, scales, blake3::hash(raw).as_bytes(), &changed),
        Err(Error::Identity)
    );
    let mut source = changed.as_slice();
    assert_eq!(
        Artifact::read_from_expected(model, prep, scales, blake3::hash(raw).as_bytes(), |out| {
            read(&mut source, out, 7)
        }),
        Err(Error::Identity)
    );
    assert!(source.is_empty());
    let mut changed_scale = scale_raw.to_vec();
    let m = u16::from_le_bytes(changed_scale[58..60].try_into().expect("mantissa"));
    changed_scale[58..60].copy_from_slice(&(m % 65535 + 1).to_le_bytes());
    let changed_scale = Scales::decode(model, &changed_scale).expect("changed complete Scales");
    assert_eq!(
        Artifact::decode(model, prep, &changed_scale, raw),
        Err(Error::Artifact)
    );
    let mut changed_prep = prep.encode().expect("Preparation");
    changed_prep[b"stele/v0.1/cqis/quantiser".len()
        + 4
        + b"stele/v0.1/cqis/source-map".len()
        + 4
        + 21
        + 2] ^= 1;
    let changed_prep = Preparation::decode(model, &changed_prep).expect("changed Map");
    assert_eq!(
        Artifact::decode(model, &changed_prep, scales, raw),
        Err(Error::Artifact)
    );
    let mut changed_model = model.encode().expect("Model");
    let at = changed_model.len() - model.decoding().encode().expect("Decoding").len() - 5;
    changed_model[at] = (changed_model[at] + 1) % 31;
    let changed_model = Model::decode(&changed_model).expect("same physical Model");
    let prep_raw = prep.encode().expect("Preparation");
    let rebound = Preparation::decode(&changed_model, &prep_raw).expect("same quantiser");
    assert_eq!(rebound.identity(), prep.identity());
    let mut calls = 0;
    for p in [prep, &rebound] {
        assert_eq!(
            Artifact::read_from(&changed_model, p, scales, |_| {
                calls += 1;
                Ok::<_, ()>(0)
            }),
            Err(Error::Identity)
        );
    }
    assert_eq!(calls, 0);
    assert_eq!(
        Artifact::read_from(model, prep, scales, |_| Err::<usize, _>(())),
        Err(Error::Read)
    );
    assert_eq!(
        Artifact::read_from(model, prep, scales, |out| Ok::<_, ()>(out.len() + 1)),
        Err(Error::Read)
    );
    let mut source = raw;
    assert_eq!(
        Artifact::read_from(model, prep, scales, |out| if source.is_empty() {
            Err(())
        } else {
            read(&mut source, out, 65536)
        }),
        Err(Error::Read)
    );
    let mut source = raw;
    assert_eq!(
        Artifact::read_from(model, prep, scales, |out| if source.is_empty() {
            Ok(out.len() + 1)
        } else {
            read(&mut source, out, 65536)
        }),
        Err(Error::Read)
    );
    for fail_at in [0, raw.len() - 1] {
        let mut pp = payloads.to_vec();
        let mut written = 0;
        assert_eq!(
            Artifact::write_to(
                model,
                prep,
                scales,
                |i, out| read(&mut pp[usize::from(i)], out, 65536),
                |part| {
                    if written + part.len() > fail_at {
                        Err(())
                    } else {
                        written += part.len();
                        Ok(())
                    }
                }
            ),
            Err(Error::Write)
        );
    }
    assert_eq!(
        Artifact::write_to(
            model,
            prep,
            scales,
            |_, _| Err::<usize, _>(()),
            |_| Ok::<_, ()>(())
        ),
        Err(Error::Read)
    );
    assert_eq!(
        Artifact::write_to(
            model,
            prep,
            scales,
            |_, _| Ok::<_, ()>(0),
            |_| Ok::<_, ()>(())
        ),
        Err(Error::Artifact)
    );
    assert_eq!(
        Artifact::write_to(
            model,
            prep,
            scales,
            |_, out| Ok::<_, ()>(out.len() + 1),
            |_| Ok::<_, ()>(())
        ),
        Err(Error::Read)
    );
    let mut pp = payloads.to_vec();
    assert_eq!(
        Artifact::write_to(
            model,
            prep,
            scales,
            |i, out| {
                let p = &mut pp[usize::from(i)];
                if p.is_empty() {
                    out[0] = 0;
                    Ok(1)
                } else {
                    read(p, out, 65536)
                }
            },
            |_| Ok::<_, ()>(())
        ),
        Err(Error::Artifact)
    );
    let mut pp = payloads.to_vec();
    let mut corrupt = payloads[0].to_vec();
    corrupt[0] = 8;
    pp[0] = &corrupt;
    assert_eq!(
        Artifact::write_to(
            model,
            prep,
            scales,
            |i, out| read(&mut pp[usize::from(i)], out, 65536),
            |_| Ok::<_, ()>(())
        ),
        Err(Error::ArtifactCode)
    );
}
