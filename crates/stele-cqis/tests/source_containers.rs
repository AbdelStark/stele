//! RFC-0025 source §2: complete structural checks over verified original bytes.
use serde_json::Value;
use stele_cqis::model::{Error, Source, SourceContainer, SourceSnapshot};

fn frame(raw: &[u8], digest: &str) -> Vec<u8> {
    let mut frame = b"stele/v0.1/cqis/source\0".to_vec();
    let name = b"original.safetensors";
    frame.extend((name.len() as u16).to_le_bytes());
    frame.extend(name);
    frame.extend((raw.len() as u64).to_le_bytes());
    frame.extend(
        (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&digest[i..i + 2], 16).expect("SHA-256")),
    );
    frame
}

#[test]
fn matches_reference_complete_safetensors_containers() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/source-containers.json")).expect("fixtures");
    let bytes = include_bytes!("fixtures/source-containers.bin");
    for case in fixtures["cases"].as_array().expect("cases") {
        let label = case["label"].as_str().expect("label");
        let offset = case["offset"].as_u64().expect("offset") as usize;
        let length = case["length"].as_u64().expect("length") as usize;
        let raw = &bytes[offset..offset + length];
        let frame = frame(raw, case["sha256"].as_str().expect("digest"));
        let source = Source::decode(&frame).expect("Source");
        let mut position = 0;
        let snapshot = SourceSnapshot::read_from(source.files()[0], usize::MAX, |out| {
            let n = out.len().min(raw.len() - position);
            out[..n].copy_from_slice(&raw[position..position + n]);
            position += n;
            Ok::<_, ()>(n)
        })
        .expect("original snapshot");
        let read = |offset: u64, out: &mut [u8]| {
            let offset = offset as usize;
            let n = out.len().min(raw.len() - offset).min(37);
            out[..n].copy_from_slice(&raw[offset..offset + n]);
            Ok::<_, ()>(n)
        };
        let result = SourceContainer::read_from(&snapshot, 1 << 24, read);
        if let Some(error) = case["error"].as_str() {
            let expected = match error {
                "SourceHeader" => Error::SourceHeader,
                "SourceJson" => Error::SourceJson,
                "SourceContainer" => Error::SourceContainer,
                "SourceDuplicate" => Error::SourceDuplicate,
                "SourceCoverage" => Error::SourceCoverage,
                _ => unreachable!(),
            };
            assert_eq!(result.err(), Some(expected), "{label}");
            continue;
        }
        let container = result.expect("complete structure");
        assert_eq!(container.file(), &source.files()[0]);
        let header = u64::from_le_bytes(raw[..8].try_into().expect("length"));
        assert_eq!(container.payload_offset(), 8 + header);
        assert_eq!(container.payload_length(), raw.len() as u64 - 8 - header);
        let expected = case["tensors"].as_array().expect("tensors");
        assert_eq!(container.tensors().len(), expected.len(), "{label}");
        for (tensor, expected) in container.tensors().iter().zip(expected) {
            assert_eq!(tensor.name(), expected["name"].as_str().expect("name"));
            assert_eq!(tensor.dtype(), expected["dtype"].as_str().expect("dtype"));
            assert_eq!(
                tensor.dimensions(),
                expected["shape"]
                    .as_array()
                    .expect("shape")
                    .iter()
                    .map(|v| v.as_u64().expect("dimension"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                tensor.offset(),
                expected["offset"].as_u64().expect("offset")
            );
            assert_eq!(
                tensor.length(),
                expected["length"].as_u64().expect("length")
            );
        }
        assert_eq!(
            SourceContainer::read_from(&snapshot, 0, read).err(),
            Some(Error::Capacity)
        );
        if !expected.is_empty() {
            assert_eq!(
                SourceContainer::read_from(&snapshot, header as usize, read).err(),
                Some(Error::Capacity)
            );
        }
        if header + 8 > 65536 {
            assert_eq!(
                SourceContainer::read_from(&snapshot, 1 << 24, |offset, out| {
                    if offset >= 65536 {
                        Err(())
                    } else {
                        read(offset, out)
                    }
                })
                .err(),
                Some(Error::Read)
            );
            assert_eq!(
                SourceContainer::read_from(&snapshot, 1 << 24, |offset, out| {
                    let n = read(offset, out)?;
                    if offset == 65536 {
                        out[0] ^= 1;
                    }
                    Ok::<_, ()>(n)
                })
                .err(),
                Some(Error::SnapshotData)
            );
        }
        assert_eq!(
            SourceContainer::read_from(&snapshot, 1 << 24, |_, _| Err::<usize, _>(())).err(),
            Some(Error::Read)
        );
        assert_eq!(
            SourceContainer::read_from(&snapshot, 1 << 24, |offset, out| {
                let n = read(offset, out)?;
                out[0] ^= 1;
                Ok::<_, ()>(n)
            })
            .err(),
            Some(Error::SnapshotData)
        );
    }
}
