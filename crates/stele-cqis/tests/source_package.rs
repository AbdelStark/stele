//! RFC-0025 source §§1–4: actual native package joins and checked consuming views.
use serde_json::Value;
use sha2::{Digest, Sha256};
use stele_cqis::model::{Assets, Error, Source, SourceMap, SourcePackage};

struct File<'a> {
    name: &'a str,
    prefix: &'a [u8],
    length: u64,
    patches: Vec<(u64, u8)>,
}
fn blob<'a>(data: &'a [u8], span: &Value) -> &'a [u8] {
    let start = span["offset"].as_u64().expect("offset") as usize;
    let length = span["length"].as_u64().expect("length") as usize;
    &data[start..start + length]
}
fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("digest"))
        .collect()
}
fn read(files: &[File<'_>], name: &str, offset: u64, out: &mut [u8]) -> Result<usize, ()> {
    let file = files.iter().find(|f| f.name == name).ok_or(())?;
    if offset >= file.length {
        return Ok(0);
    }
    assert!(out.len() <= 65536);
    let n = (file.length - offset).min(out.len() as u64) as usize;
    out[..n].fill(0);
    if offset < file.prefix.len() as u64 {
        let start = offset as usize;
        let copied = n.min(file.prefix.len() - start);
        out[..copied].copy_from_slice(&file.prefix[start..start + copied]);
    }
    for &(at, byte) in &file.patches {
        if offset <= at && at - offset < n as u64 {
            out[(at - offset) as usize] = byte;
        }
    }
    Ok(n)
}

#[test]
fn matches_reference_complete_source_packages_and_raw_views() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/source-package.json")).expect("fixtures");
    let data = include_bytes!("fixtures/source-package.bin");
    for case in fixtures["cases"].as_array().expect("cases") {
        let label = case["label"].as_str().expect("label");
        let map = SourceMap::decode(blob(data, &case["map"])).expect("Map");
        let source = Source::decode(blob(data, &case["source"])).expect("Source");
        let assets = Assets::decode(blob(data, &case["assets"])).expect("Assets");
        let files: Vec<_> = case["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| File {
                name: f["name"].as_str().expect("name"),
                prefix: blob(data, &f["prefix"]),
                length: f["length"].as_u64().expect("length"),
                patches: f["patches"]
                    .as_array()
                    .expect("patches")
                    .iter()
                    .map(|p| {
                        (
                            p[0].as_u64().expect("patch offset"),
                            p[1].as_u64().expect("patch byte") as u8,
                        )
                    })
                    .collect(),
            })
            .collect();
        let mut names: Vec<_> = files.iter().rev().map(|f| f.name).collect();
        if label == "checkpoint auxiliary collision" {
            names.push(source.files()[0].name());
        }
        let reader = |name: &str, offset, out: &mut [u8]| {
            let length = out.len().min(if label == "complete 0" { 7 } else { 65536 });
            read(&files, name, offset, &mut out[..length])
        };
        let mut calls = 0;
        let result = SourcePackage::read_from(
            &map,
            &source,
            &assets,
            &names,
            1 << 24,
            1 << 26,
            |name, offset, out| {
                calls += 1;
                reader(name, offset, out)
            },
        );
        if let Some(error) = case["error"].as_str() {
            let expected = match error {
                "SourceSelection" => Error::SourceSelection,
                "SourceDtype" => Error::SourceDtype,
                "SourceShape" => Error::SourceShape,
                "SourceAlias" => Error::SourceAlias,
                "SourceShard" => Error::SourceShard,
                "SourceTotalSize" => Error::SourceTotalSize,
                "SourceDuplicate" => Error::SourceDuplicate,
                "SourceHeader" => Error::SourceHeader,
                "FileSet" => Error::FileSet,
                "FileLength" => Error::FileLength,
                _ => unreachable!(),
            };
            assert_eq!(result.err(), Some(expected), "{label}");
            if matches!(expected, Error::FileSet | Error::FileLength) {
                assert_eq!(calls, 0, "preflight {label}");
            }
            continue;
        }
        let package = result.expect("complete package");
        assert_eq!(
            package.source().identity().as_slice(),
            hex(case["source_identity"].as_str().expect("identity"))
        );
        assert_eq!(
            package.source().frame_identity().as_slice(),
            hex(case["source_frame_identity"]
                .as_str()
                .expect("frame identity"))
        );
        assert_eq!(
            package.assets().identity().as_slice(),
            hex(case["assets_identity"].as_str().expect("assets identity"))
        );
        assert_eq!(
            package.source_map().identity().as_slice(),
            hex(case["map_identity"].as_str().expect("map identity"))
        );
        let expected = case["selected"].as_array().expect("selected");
        assert_eq!(expected.len(), map.entries().len());
        for (ordinal, e) in expected.iter().enumerate() {
            let view = package.tensor(ordinal as u16).expect("physical source");
            assert_eq!(view.length(), e["length"].as_u64().expect("length"));
            let mut position = 0;
            let mut hash = Sha256::new();
            while position < view.length() {
                let chunk = view.chunk(position, reader).expect("checked tensor bytes");
                assert_eq!(chunk.offset(), position);
                assert!(!chunk.as_bytes().is_empty() && chunk.as_bytes().len() <= 65536);
                hash.update(chunk.as_bytes());
                position += chunk.as_bytes().len() as u64;
            }
            assert_eq!(
                hash.finalize().as_slice(),
                hex(e["sha256"].as_str().expect("raw SHA-256"))
            );
            let mut calls = 0;
            assert_eq!(
                view.chunk(view.length(), |_, _, _| {
                    calls += 1;
                    Ok::<_, ()>(0)
                })
                .err(),
                Some(Error::SourceOffset)
            );
            assert_eq!(calls, 0);
            let changed = view.offset() + view.length() - 1;
            assert_eq!(
                view.chunk(view.length() - 1, |name, offset, out| {
                    let n = reader(name, offset, out)?;
                    if offset <= changed && changed - offset < n as u64 {
                        out[(changed - offset) as usize] ^= 1;
                    }
                    Ok::<_, ()>(n)
                })
                .err(),
                Some(Error::SnapshotData)
            );
        }
        assert!(package.tensor(map.shape().record_count()).is_none());
        for file in core::iter::once(assets.config())
            .chain(assets.tokenizers())
            .chain(assets.generation())
        {
            let view = package.asset(file.name()).expect("declared asset");
            assert_eq!(view.file(), file);
            assert_eq!(view.offset(), 0);
            assert_eq!(view.length(), file.length());
            let mut position = 0;
            let mut hash = Sha256::new();
            while position < view.length() {
                let chunk = view.chunk(position, reader).expect("checked asset bytes");
                hash.update(chunk.as_bytes());
                position += chunk.as_bytes().len() as u64;
            }
            assert_eq!(hash.finalize().as_slice(), file.sha256());
        }
        assert!(package.asset(source.files()[0].name()).is_none());
        if let Some(index) = source.index() {
            assert!(package.asset(index.name()).is_none());
        }
        assert!(package.asset("unlisted").is_none());
        // A wrong file set or insufficient admission must not invoke the reader.
        let mut wrong = names.clone();
        wrong[0] = wrong[1];
        for labels in [&names[..names.len() - 1], wrong.as_slice()] {
            let mut calls = 0;
            assert_eq!(
                SourcePackage::read_from(
                    &map,
                    &source,
                    &assets,
                    labels,
                    1 << 24,
                    1 << 26,
                    |_, _, _| {
                        calls += 1;
                        Ok::<_, ()>(0)
                    }
                )
                .err(),
                Some(Error::FileSet)
            );
            assert_eq!(calls, 0);
        }
        for (snapshots, metadata) in [(0, 1 << 26), (1 << 24, 0)] {
            let mut calls = 0;
            assert_eq!(
                SourcePackage::read_from(
                    &map,
                    &source,
                    &assets,
                    &names,
                    snapshots,
                    metadata,
                    |_, _, _| {
                        calls += 1;
                        Ok::<_, ()>(0)
                    }
                )
                .err(),
                Some(Error::Capacity)
            );
            assert_eq!(calls, 0);
        }
        if label == "complete 0" {
            let shortened = &files[0];
            assert_eq!(
                SourcePackage::read_from(
                    &map,
                    &source,
                    &assets,
                    &names,
                    1 << 24,
                    1 << 26,
                    |name, offset, out| {
                        if name == shortened.name {
                            if offset >= shortened.length - 1 {
                                return Ok(0);
                            }
                            let length = out.len().min((shortened.length - 1 - offset) as usize);
                            reader(name, offset, &mut out[..length])
                        } else {
                            reader(name, offset, out)
                        }
                    }
                )
                .err(),
                Some(Error::FileLength)
            );
            assert_eq!(
                SourcePackage::read_from(
                    &map,
                    &source,
                    &assets,
                    &names,
                    1 << 24,
                    1 << 26,
                    |name, offset, out| {
                        if name == shortened.name && offset == shortened.length {
                            out[0] = 0;
                            Ok(1)
                        } else {
                            reader(name, offset, out)
                        }
                    }
                )
                .err(),
                Some(Error::FileLength)
            );
            for changed in &files {
                assert_eq!(
                    SourcePackage::read_from(
                        &map,
                        &source,
                        &assets,
                        &names,
                        1 << 24,
                        1 << 26,
                        |name, offset, out| {
                            let n = reader(name, offset, out)?;
                            if name == changed.name && offset == 0 {
                                out[0] ^= 1;
                            }
                            Ok::<_, ()>(n)
                        }
                    )
                    .err(),
                    Some(Error::FileDigest)
                );
            }
            assert_eq!(
                SourcePackage::read_from(
                    &map,
                    &source,
                    &assets,
                    &names,
                    1 << 24,
                    1 << 26,
                    |_, _, _| Err::<usize, _>(())
                )
                .err(),
                Some(Error::Read)
            );
        }
    }
    assert_eq!(fixtures["cases"].as_array().expect("cases").len(), 39);
}
