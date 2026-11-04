//! RFC-0025 source §4: complete original-file hashing and immutable checked replay.
use serde_json::Value;
use stele_cqis::model::{Error, Source, SourceSnapshot};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn byte(i: u64, seed: u8) -> u8 {
    (i.wrapping_mul(17) ^ (i >> 8) ^ (i >> 16) ^ (i >> 24) ^ u64::from(seed)) as u8
}
fn frame(length: u64, digest: &[u8]) -> Vec<u8> {
    let mut raw = b"stele/v0.1/cqis/source\0".to_vec();
    let name = b"original.safetensors";
    raw.extend((name.len() as u16).to_le_bytes());
    raw.extend(name);
    raw.extend(length.to_le_bytes());
    raw.extend(digest);
    raw
}
fn read_at(length: u64, seed: u8, offset: u64, out: &mut [u8], limit: usize) -> Result<usize, ()> {
    assert!(!out.is_empty() && out.len() <= 65536);
    assert!(offset <= length);
    let n = (length - offset).min(out.len() as u64).min(limit as u64) as usize;
    for (j, b) in out[..n].iter_mut().enumerate() {
        *b = byte(offset + j as u64, seed);
    }
    Ok(n)
}

#[test]
fn matches_reference_complete_file_hashes_and_checked_chunks() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/source-snapshots.json")).expect("fixtures");
    for (i, c) in fixtures["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let length = c["length"].as_u64().expect("length");
        let seed = c["seed"].as_u64().expect("seed") as u8;
        let digest = hex(c["sha256"].as_str().expect("SHA-256"));
        let raw = frame(length, &digest);
        let source = Source::decode(&raw).expect("File declaration");
        let file = source.files()[0];
        let count = length.div_ceil(65536);
        let budget = usize::try_from(32 * count).expect("index bytes");
        let mut position = 0;
        let snapshot = SourceSnapshot::read_from(file, budget, |out| {
            let n = read_at(length, seed, position, out, if i < 9 { 3 } else { 65536 })?;
            position += n as u64;
            Ok::<_, ()>(n)
        })
        .expect("complete file SHA-256 and EOF");
        assert_eq!(snapshot.file(), &file);
        assert_eq!(snapshot.chunk_count(), count);
        assert_eq!(snapshot.index_bytes(), budget);
        assert_eq!(position, length);
        for index in (0..count).rev() {
            let chunk = snapshot
                .chunk(index, |offset, out| {
                    read_at(length, seed, offset, out, if i < 9 { 7 } else { 65536 })
                })
                .expect("revalidated chunk");
            assert_eq!(chunk.file_sha256().as_slice(), digest);
            assert_eq!(chunk.offset(), index * 65536);
            assert_eq!(
                chunk.as_bytes().len() as u64,
                (length - index * 65536).min(65536)
            );
            assert!(chunk
                .as_bytes()
                .iter()
                .enumerate()
                .all(|(j, b)| *b == byte(chunk.offset() + j as u64, seed)));
            assert_eq!(
                snapshot
                    .chunk(index, |offset, out| read_at(
                        length,
                        seed ^ 1,
                        offset,
                        out,
                        65536
                    ))
                    .err(),
                Some(Error::SnapshotData)
            );
        }
        let mut calls = 0;
        for index in [count, u64::MAX] {
            assert_eq!(
                snapshot
                    .chunk(index, |_, _| {
                        calls += 1;
                        Ok::<_, ()>(0)
                    })
                    .err(),
                Some(Error::SourceOffset)
            );
        }
        assert_eq!(calls, 0);
        if budget != 0 {
            assert_eq!(
                SourceSnapshot::read_from(file, budget - 1, |_| {
                    calls += 1;
                    Ok::<_, ()>(0)
                })
                .err(),
                Some(Error::Capacity)
            );
            assert_eq!(calls, 0);
        }
        if i == 16 {
            rejects_failed_or_changed_reads(file, &snapshot, length, seed, budget);
        }
    }
    assert_eq!(fixtures["cases"].as_array().expect("cases").len(), 52);
    let raw = frame(u64::MAX, &[0; 32]);
    let source = Source::decode(&raw).expect("full u64 metadata");
    let mut calls = 0;
    assert_eq!(
        SourceSnapshot::read_from(source.files()[0], 0, |_| {
            calls += 1;
            Ok::<_, ()>(0)
        })
        .err(),
        Some(Error::Capacity)
    );
    assert_eq!(calls, 0);
}

fn rejects_failed_or_changed_reads(
    file: stele_cqis::model::SourceFile<'_>,
    snapshot: &SourceSnapshot<'_>,
    length: u64,
    seed: u8,
    budget: usize,
) {
    assert_eq!(
        SourceSnapshot::read_from(file, budget, |_| Err::<usize, _>(())).err(),
        Some(Error::Read)
    );
    assert_eq!(
        SourceSnapshot::read_from(file, budget, |out| Ok::<_, ()>(out.len() + 1)).err(),
        Some(Error::Read)
    );
    for missing in [length, 1] {
        let mut position = 0;
        assert_eq!(
            SourceSnapshot::read_from(file, budget, |out| {
                let n = read_at(length - missing, seed, position, out, 65536)?;
                position += n as u64;
                Ok::<_, ()>(n)
            })
            .err(),
            Some(Error::FileLength)
        );
    }
    let mut position = 0;
    assert_eq!(
        SourceSnapshot::read_from(file, budget, |out| {
            let n = read_at(length + 1, seed, position, out, 65536)?;
            position += n as u64;
            Ok::<_, ()>(n)
        })
        .err(),
        Some(Error::FileLength)
    );
    let mut position = 0;
    assert_eq!(
        SourceSnapshot::read_from(file, budget, |out| {
            let n = read_at(length, seed ^ 1, position, out, 65536)?;
            position += n as u64;
            Ok::<_, ()>(n)
        })
        .err(),
        Some(Error::FileDigest)
    );
    let mut position = 0;
    assert_eq!(
        SourceSnapshot::read_from(file, budget, |out| {
            if position == length {
                Err(())
            } else {
                let n = read_at(length, seed, position, out, 65536)?;
                position += n as u64;
                Ok(n)
            }
        })
        .err(),
        Some(Error::Read)
    );
    assert_eq!(
        snapshot.chunk(0, |_, _| Err::<usize, _>(())).err(),
        Some(Error::Read)
    );
    assert_eq!(
        snapshot.chunk(0, |_, out| Ok::<_, ()>(out.len() + 1)).err(),
        Some(Error::Read)
    );
    assert_eq!(
        snapshot.chunk(0, |_, _| Ok::<_, ()>(0)).err(),
        Some(Error::FileLength)
    );
    assert_eq!(
        snapshot
            .chunk(1, |offset, out| read_at(
                length,
                seed,
                offset - 65536,
                out,
                65536
            ))
            .err(),
        Some(Error::SnapshotData)
    );
    // One changed byte must fail even when every other original byte matches.
    for changed in [0, 65535, 65536, length - 1] {
        let mut position = 0;
        assert_eq!(
            SourceSnapshot::read_from(file, budget, |out| {
                let n = read_changed(length, seed, position, out, changed)?;
                position += n as u64;
                Ok::<_, ()>(n)
            })
            .err(),
            Some(Error::FileDigest)
        );
        assert_eq!(
            snapshot
                .chunk(changed / 65536, |offset, out| {
                    read_changed(length, seed, offset, out, changed)
                })
                .err(),
            Some(Error::SnapshotData)
        );
    }
    assert_eq!(
        snapshot
            .chunk(1, |offset, out| {
                read_at(length - 1, seed, offset, out, 65536)
            })
            .err(),
        Some(Error::FileLength)
    );
    // The returned chunk owns its bytes, independent of subsequent replacement.
    let mut backing: Vec<u8> = (0..65536).map(|i| byte(i, seed)).collect();
    let chunk = snapshot
        .chunk(0, |_, out| {
            out.copy_from_slice(&backing);
            Ok::<_, ()>(out.len())
        })
        .expect("owned chunk");
    backing[0] ^= 1;
    assert_eq!(chunk.as_bytes()[0], byte(0, seed));
    assert_eq!(
        snapshot
            .chunk(0, |_, out| {
                out.copy_from_slice(&backing);
                Ok::<_, ()>(out.len())
            })
            .err(),
        Some(Error::SnapshotData)
    );
}

fn read_changed(
    length: u64,
    seed: u8,
    offset: u64,
    out: &mut [u8],
    changed: u64,
) -> Result<usize, ()> {
    let n = read_at(length, seed, offset, out, 65536)?;
    if changed >= offset && changed - offset < n as u64 {
        out[(changed - offset) as usize] ^= 1;
    }
    Ok(n)
}
