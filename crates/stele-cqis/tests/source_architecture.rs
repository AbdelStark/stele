//! RFC-0025 source architecture §§1–4: exact original config and complete joins.
use serde_json::Value;
use stele_cqis::model::{
    Architecture, Assets, Error, Model, Source, SourceConfig, SourceMap, SourcePackage,
};

fn blob<'a>(data: &'a [u8], span: &Value) -> &'a [u8] {
    let start = span["offset"].as_u64().expect("offset") as usize;
    let length = span["length"].as_u64().expect("length") as usize;
    &data[start..start + length]
}
fn error(name: &str) -> Error {
    match name {
        "Capacity" => Error::Capacity,
        "Shape" => Error::Shape,
        "Activation" => Error::Activation,
        "Rotation" => Error::Rotation,
        "SourceLayout" => Error::SourceLayout,
        "SourceJson" => Error::SourceJson,
        "SourceDuplicate" => Error::SourceDuplicate,
        "SourceNumber" => Error::SourceNumber,
        "SourceString" => Error::SourceString,
        "SourceDepth" => Error::SourceDepth,
        "SourceFields" => Error::SourceFields,
        "SourceFamily" => Error::SourceFamily,
        "SourceRational" => Error::SourceRational,
        "SourceMetadata" => Error::SourceMetadata,
        "SourceFlags" => Error::SourceFlags,
        "SourceToken" => Error::SourceToken,
        "SourceEpsilon" => Error::SourceEpsilon,
        "SourceRole" => Error::SourceRole,
        "SourceIgnored" => Error::SourceIgnored,
        "SourceAlias" => Error::SourceAlias,
        _ => unreachable!("unknown error {name}"),
    }
}
#[test]
fn matches_reference_exact_configuration_architecture() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-architecture.json")).expect("fixtures");
    let data = include_bytes!("fixtures/source-architecture.bin");
    for case in fixture["cases"].as_array().expect("cases") {
        let label = case["label"].as_str().expect("label");
        let layout = case["kind"].as_u64().expect("layout") as u8;
        let raw = blob(data, &case["raw"]);
        let result = Architecture::derive(layout, raw, 1 << 27);
        if let Some(e) = case["error"].as_str() {
            assert_eq!(result.err(), Some(error(e)), "{label}");
            continue;
        }
        let architecture = result.expect(label);
        assert_eq!(
            architecture.encode().expect("encode"),
            blob(data, &case["expected"]),
            "{label}"
        );
        assert_eq!(architecture.layout(), layout);
        assert!(architecture.eos().windows(2).all(|v| v[0] < v[1]));
        assert!(architecture.bos() < architecture.shape().vocabulary());
        assert!(architecture
            .pad()
            .is_none_or(|p| p < architecture.shape().vocabulary()));
        assert!(architecture.epsilon().0 > 0 && architecture.epsilon().1 > 0);
        assert_eq!(architecture.rotation().is_some(), layout == 2);
        assert_eq!(
            Architecture::derive(layout, raw, 0).err(),
            Some(Error::Capacity)
        );
    }
}

#[test]
fn matches_reference_authenticated_source_configuration() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-architecture.json")).expect("fixtures");
    let data = include_bytes!("fixtures/source-architecture.bin");
    for case in fixture["bindings"].as_array().expect("bindings") {
        let label = case["label"].as_str().expect("label");
        let layout = case["kind"].as_u64().expect("layout") as u8;
        let model = Model::decode(blob(data, &case["model"])).expect("Model");
        let map = SourceMap::decode(blob(data, &case["map"])).expect("Map");
        let source = Source::decode(blob(data, &case["source"])).expect("Source");
        let assets = Assets::decode(blob(data, &case["assets"])).expect("Assets");
        let files: Vec<_> = case["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| (f["name"].as_str().expect("name"), blob(data, &f["raw"])))
            .collect();
        let names: Vec<_> = files.iter().map(|(name, _)| *name).collect();
        let read = |name: &str, offset: u64, out: &mut [u8]| {
            let raw = files.iter().find(|(n, _)| *n == name).ok_or(())?.1;
            let offset = usize::try_from(offset).map_err(|_| ())?;
            let n = out.len().min(raw.len().saturating_sub(offset)).min(37);
            if n > 0 {
                out[..n].copy_from_slice(&raw[offset..offset + n]);
            }
            Ok::<_, ()>(n)
        };
        let package =
            SourcePackage::read_from(&map, &source, &assets, &names, 1 << 24, 1 << 26, read)
                .expect("complete original package");
        let result = SourceConfig::read_from(&model, &package, layout, 1 << 27, read);
        if let Some(e) = case["error"].as_str() {
            assert_eq!(result.err(), Some(error(e)), "{label}");
            continue;
        }
        let config = result.expect(label);
        let expected = blob(data, &case["expected"]);
        assert_eq!(config.as_bytes(), expected, "{label}");
        assert_eq!(config.identity(), *blake3::hash(expected).as_bytes());
        assert_eq!(config.architecture().shape(), model.shape());
        config.verify(expected).expect("whole expected binding");
        for at in [0, 28, 60, 92, expected.len() - 1] {
            let mut changed = expected.to_vec();
            changed[at] ^= 1;
            assert_eq!(config.verify(&changed), Err(Error::SourceConfig));
        }
        assert_eq!(
            config.verify(&expected[..expected.len() - 1]),
            Err(Error::SourceConfig)
        );
        let mut extra = expected.to_vec();
        extra.push(0);
        assert_eq!(config.verify(&extra), Err(Error::SourceConfig));
        let mut calls = 0;
        assert_eq!(
            SourceConfig::read_from(&model, &package, layout, 0, |_, _, _| {
                calls += 1;
                Ok::<_, ()>(0)
            })
            .err(),
            Some(Error::Capacity)
        );
        assert_eq!(calls, 0);
        assert_eq!(
            SourceConfig::read_from(
                &model,
                &package,
                layout,
                1 << 27,
                |_, _, _| Err::<usize, _>(())
            )
            .err(),
            Some(Error::Read)
        );
        let last = assets.config().length() - 1;
        assert_eq!(
            SourceConfig::read_from(&model, &package, layout, 1 << 27, |name, offset, out| {
                let n = read(name, offset, out)?;
                if name == assets.config().name() && offset <= last && last - offset < n as u64 {
                    out[(last - offset) as usize] ^= 1;
                }
                Ok::<_, ()>(n)
            })
            .err(),
            Some(Error::SnapshotData)
        );
    }
}
