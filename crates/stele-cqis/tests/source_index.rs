//! RFC-0025 source §2: exact original index bytes and complete structural mapping.
use serde_json::Value;
use stele_cqis::model::{Assets, Error, SourceIndex, SourceSnapshot};

fn frame(raw: &[u8], digest: &str) -> Vec<u8> {
    let mut frame = b"stele/v0.1/cqis/source-assets".to_vec();
    file(
        &mut frame,
        "index.json",
        raw.len() as u64,
        &(0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&digest[i..i + 2], 16).expect("SHA-256"))
            .collect::<Vec<_>>(),
    );
    frame.extend(1u32.to_le_bytes());
    file(&mut frame, "tokenizer.bin", 0, &[0; 32]);
    frame.push(0);
    frame
}
fn file(out: &mut Vec<u8>, name: &str, length: u64, digest: &[u8]) {
    out.extend((name.len() as u16).to_le_bytes());
    out.extend(name.as_bytes());
    out.extend(length.to_le_bytes());
    out.extend(digest);
}

#[test]
fn matches_reference_complete_original_index() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/source-index.json")).expect("fixtures");
    let data = include_bytes!("fixtures/source-index.bin");
    for case in fixtures["cases"].as_array().expect("cases") {
        let label = case["label"].as_str().expect("label");
        let offset = case["offset"].as_u64().expect("offset") as usize;
        let length = case["length"].as_u64().expect("length") as usize;
        let raw = &data[offset..offset + length];
        let frame = frame(raw, case["sha256"].as_str().expect("digest"));
        let assets = Assets::decode(&frame).expect("File metadata");
        let mut position = 0;
        let snapshot = SourceSnapshot::read_from(*assets.config(), usize::MAX, |out| {
            let n = out.len().min(raw.len() - position);
            out[..n].copy_from_slice(&raw[position..position + n]);
            position += n;
            Ok::<_, ()>(n)
        })
        .expect("original index snapshot");
        let read = |offset: u64, out: &mut [u8]| {
            let offset = offset as usize;
            let n = out.len().min(raw.len() - offset).min(29);
            out[..n].copy_from_slice(&raw[offset..offset + n]);
            Ok::<_, ()>(n)
        };
        let result = SourceIndex::read_from(&snapshot, 1 << 24, read);
        if let Some(error) = case["error"].as_str() {
            let expected = match error {
                "SourceJson" => Error::SourceJson,
                "SourceIndex" => Error::SourceIndex,
                "SourceDuplicate" => Error::SourceDuplicate,
                "FileName" => Error::FileName,
                "SourceFiles" => Error::SourceFiles,
                _ => unreachable!(),
            };
            assert_eq!(result.err(), Some(expected), "{label}");
            continue;
        }
        let index = result.expect("complete index");
        assert_eq!(index.file(), assets.config());
        assert_eq!(
            index.total_size(),
            case["total_size"].as_u64().expect("total")
        );
        let entries = case["entries"].as_array().expect("entries");
        assert_eq!(index.entries().len(), entries.len());
        for (entry, expected) in index.entries().iter().zip(entries) {
            assert_eq!(entry.name(), expected["name"].as_str().expect("name"));
            assert_eq!(
                entry.file_name(),
                expected["file_name"].as_str().expect("label")
            );
        }
        let mut calls = 0;
        assert_eq!(
            SourceIndex::read_from(&snapshot, raw.len() - 1, |_, _| {
                calls += 1;
                Ok::<_, ()>(0)
            })
            .err(),
            Some(Error::Capacity)
        );
        assert_eq!(calls, 0);
        assert_eq!(
            SourceIndex::read_from(&snapshot, raw.len(), read).err(),
            Some(Error::Capacity)
        );
        assert_eq!(
            SourceIndex::read_from(&snapshot, 1 << 24, |_, _| Err::<usize, _>(())).err(),
            Some(Error::Read)
        );
        let changed = raw.len() - 1;
        assert_eq!(
            SourceIndex::read_from(&snapshot, 1 << 24, |offset, out| {
                let n = read(offset, out)?;
                if offset <= changed as u64 && (changed as u64 - offset) < n as u64 {
                    out[changed - offset as usize] ^= 1;
                }
                Ok::<_, ()>(n)
            })
            .err(),
            Some(Error::SnapshotData)
        );
    }
    assert_eq!(fixtures["cases"].as_array().expect("cases").len(), 81);
}
