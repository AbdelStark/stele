//! RFC-0025 source §§1,3: canonical metadata, full lengths and exact identities.
use serde_json::Value;
use stele_cqis::model::{Assets, Error, Source, SourceFile};

fn blob<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(input[..4].try_into().expect("length")) as usize;
    let raw = &input[4..4 + n];
    *input = &input[4 + n..];
    raw
}
fn hex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("hex"))
        .collect()
}
fn check_file(file: &SourceFile<'_>, expected: &Value) -> u64 {
    assert_eq!(file.name(), expected["name"].as_str().expect("name"));
    assert_eq!(file.length(), expected["length"].as_u64().expect("length"));
    assert_eq!(
        file.sha256().as_slice(),
        hex(expected["sha256"].as_str().expect("SHA-256"))
    );
    file.length()
}

#[test]
fn matches_reference_complete_source_assets_and_typed_checkpoint_identity() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-assets.json")).expect("fixtures");
    let mut input = include_bytes!("fixtures/source-assets.bin").as_slice();
    let mut kinds = [0; 2];
    let mut generation = 0;
    for (i, c) in fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let sr = blob(&mut input);
        let ar = blob(&mut input);
        let sh: [u8; 32] = hex(c["source_frame_identity"].as_str().expect("frame hash"))
            .try_into()
            .expect("digest");
        let ah: [u8; 32] = hex(c["assets_identity"].as_str().expect("assets hash"))
            .try_into()
            .expect("digest");
        let source = Source::decode_expected_frame(&sh, sr).expect("complete Source frame");
        let assets = Assets::decode_expected(&ah, ar).expect("complete Assets frame");
        assert_eq!(source.as_bytes(), sr);
        assert_eq!(assets.as_bytes(), ar);
        assert_eq!(source.frame_identity(), sh);
        assert_eq!(assets.identity(), ah);
        assert_eq!(
            source.identity().as_slice(),
            hex(c["source_identity"].as_str().expect("typed identity"))
        );
        assert_eq!(u64::from(source.kind()), c["kind"].as_u64().expect("kind"));
        kinds[usize::from(source.kind())] += 1;
        assert_eq!(
            source.files().len(),
            c["files"].as_array().expect("files").len()
        );
        let mut total = 0u64;
        for (file, expected) in source
            .files()
            .iter()
            .zip(c["files"].as_array().expect("files"))
        {
            total = total.checked_add(check_file(file, expected)).expect("sum");
        }
        if let Some(index) = source.index() {
            total = total
                .checked_add(check_file(index, &c["index"]))
                .expect("sum");
        } else {
            assert!(c["index"].is_null());
        }
        assert_eq!(source.total_length(), total);
        let mut total = check_file(assets.config(), &c["config"]);
        assert_eq!(
            assets.tokenizers().len(),
            c["tokenizers"].as_array().expect("tokenizers").len()
        );
        for (file, expected) in assets
            .tokenizers()
            .iter()
            .zip(c["tokenizers"].as_array().expect("tokenizers"))
        {
            total = total.checked_add(check_file(file, expected)).expect("sum");
        }
        if let Some(file) = assets.generation() {
            total = total
                .checked_add(check_file(file, &c["generation"]))
                .expect("sum");
            generation += 1;
        } else {
            assert!(c["generation"].is_null());
        }
        assert_eq!(assets.total_length(), total);
        if i < 2 {
            for end in 0..sr.len() {
                assert!(Source::decode(&sr[..end]).is_err());
            }
            for end in 0..ar.len() {
                assert!(Assets::decode(&ar[..end]).is_err());
            }
            let mut renamed = sr.to_vec();
            renamed[b"stele/v0.1/cqis/source".len() + 3] ^= 1;
            let other = Source::decode(&renamed).expect("legal label change");
            assert_ne!(source.frame_identity(), other.frame_identity());
            if source.kind() == 0 {
                assert_eq!(source.identity(), other.identity());
            } else {
                assert_ne!(source.identity(), other.identity());
            }
            assert_eq!(
                Source::decode_expected_frame(&sh, &renamed),
                Err(Error::Identity)
            );
            let mut changed = ar.to_vec();
            let last = changed.len() - if assets.generation().is_some() { 1 } else { 2 };
            changed[last] ^= 1;
            assert!(Assets::decode(&changed).is_ok());
            assert_eq!(Assets::decode_expected(&ah, &changed), Err(Error::Identity));
        }
        if i == 64 {
            assert_eq!(source.files()[0].name().len(), 65535);
            assert_eq!(source.total_length(), u64::MAX);
            assert_eq!(assets.config().name().len(), 65535);
            assert_eq!(assets.total_length(), u64::MAX);
        }
    }
    assert!(input.is_empty());
    assert_eq!(kinds, [23, 43]);
    assert_eq!(generation, 34);
}

#[test]
fn rejects_source_assets_names_counts_order_roles_and_length_overflow() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-assets.json")).expect("fixtures");
    for c in fixture["invalid"].as_array().expect("invalid") {
        let raw = hex(c["raw"].as_str().expect("bytes"));
        let expected = match c["error"].as_str().expect("error") {
            "FileName" => Error::FileName,
            "FileSet" => Error::FileSet,
            "FileOrder" => Error::FileOrder,
            "FileLength" => Error::FileLength,
            "SourceKind" => Error::SourceKind,
            "SourceFiles" => Error::SourceFiles,
            "SourceIndex" => Error::SourceIndex,
            "Assets" => Error::Assets,
            "Capacity" => Error::Capacity,
            "Encoding" => Error::Encoding,
            _ => unreachable!("fixture error"),
        };
        if c["kind"] == "source" {
            assert_eq!(Source::decode(&raw), Err(expected));
        } else {
            assert_eq!(Assets::decode(&raw), Err(expected));
        }
    }
}
