//! RFC-0025 encoding §6/execution preparation: original bytes through stored Artifact.
use core::cell::Cell;
use serde_json::Value;
use stele_cqis::model::{
    Artifact, ArtifactLayout, Assets, Bounds, Conversion, Error, Model, NumericalIdentity,
    Preparation, Registry, Source, SourceConfig, SourcePackage,
};

fn blob<'a>(data: &'a [u8], span: &Value) -> &'a [u8] {
    let at = span["offset"].as_u64().expect("offset") as usize;
    let size = span["length"].as_u64().expect("length") as usize;
    &data[at..at + size]
}
#[test]
fn matches_reference_preparation_and_rejects_config_and_stored_byte_changes() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/preparation-pipeline.json")).expect("fixtures");
    let data = include_bytes!("fixtures/preparation-pipeline.bin");
    let cases = fixtures["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 6);
    for case in cases {
        let model = Model::decode(blob(data, &case["model"])).expect("Model");
        let preparation =
            Preparation::decode(&model, blob(data, &case["preparation"])).expect("Preparation");
        let source = Source::decode(blob(data, &case["source"])).expect("Source");
        let assets = Assets::decode(blob(data, &case["assets"])).expect("Assets");
        let layout = case["layout"].as_u64().expect("layout") as u8;
        let files: Vec<_> = case["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| (f["name"].as_str().expect("name"), blob(data, &f["raw"])))
            .collect();
        let writes = Cell::new(0);
        let prepare = |assets: &Assets, files: &[(&str, &[u8])], tamper: bool| {
            writes.set(0);
            let names: Vec<_> = files.iter().map(|(name, _)| *name).collect();
            let read = |name: &str, offset: u64, out: &mut [u8]| {
                let (_, raw) = files.iter().find(|(n, _)| *n == name).ok_or(())?;
                let at = usize::try_from(offset).map_err(|_| ())?;
                let remaining = raw.get(at..).ok_or(())?;
                let n = out.len().min(remaining.len()).min(37);
                out[..n].copy_from_slice(&remaining[..n]);
                Ok::<_, ()>(n)
            };
            let package = SourcePackage::read_from(
                preparation.map(),
                &source,
                assets,
                &names,
                1 << 20,
                1 << 24,
                read,
            )?;
            let config = SourceConfig::read_from(&model, &package, layout, 1 << 24, read)?;
            let allowance = Conversion::required_cache_bytes(&model, &package)?;
            let mut output = Vec::new();
            let converted =
                Conversion::write_to(&model, &preparation, &package, allowance, read, |raw| {
                    writes.set(writes.get() + 1);
                    output.extend_from_slice(raw);
                    Ok::<_, ()>(raw.len())
                })?;
            if tamper {
                let geometry = ArtifactLayout::new(&model)?;
                let vector = geometry
                    .records()
                    .iter()
                    .find(|r| r.bits() == 16)
                    .expect("vector");
                output[vector.payload_offset() as usize] ^= 1;
            }
            // Re-read actual stored bytes, keeping the emitted digest fixed.
            let mut input = output.as_slice();
            let stored = Artifact::read_from_expected(
                &model,
                &preparation,
                converted.scales(),
                &converted.artifact().identity(),
                |out| {
                    let n = out.len().min(input.len()).min(29);
                    out[..n].copy_from_slice(&input[..n]);
                    input = &input[n..];
                    Ok::<_, ()>(n)
                },
            )?;
            assert!(input.is_empty());
            Ok::<_, Error>((config, converted, stored, output))
        };
        let (config, converted, stored, output) =
            prepare(&assets, &files, false).expect("complete original-byte preparation");
        assert_eq!(config.verify(blob(data, &case["source_config"])), Ok(()));
        assert_eq!(converted.source_identity(), source.identity());
        assert_eq!(converted.assets_identity(), assets.identity());
        assert_eq!(
            converted.scales().encode().expect("Scales"),
            blob(data, &case["scales"])
        );
        assert_eq!(output, blob(data, &case["artifact"]));
        assert_eq!(&stored, converted.artifact());
        let registry = Registry::decode(&model, blob(data, &case["registry"]))
            .expect("complete native Registry regeneration");
        let bounds =
            Bounds::new(&model, converted.scales(), &registry).expect("complete static Bounds");
        assert_eq!(
            blake3::Hash::from(bounds.identity()).to_hex().as_str(),
            case["bounds_id"].as_str().expect("Bounds identity")
        );
        assert_eq!(
            bounds.byte_length(),
            case["bounds_bytes"].as_u64().expect("Bounds length")
        );
        let identity = NumericalIdentity::new(&model, converted.scales(), &registry, &bounds)
            .expect("complete numerical identity");
        assert_eq!(identity.verify(blob(data, &case["identity"])), Ok(()));
        assert_eq!(
            blake3::Hash::from(identity.identity()).to_hex().as_str(),
            case["cqis_id"].as_str().expect("cqis_id")
        );

        assert_eq!(prepare(&assets, &files, true).err(), Some(Error::Identity));
        assert!(writes.get() > 0);
        let mut changed = files.clone();
        changed
            .iter_mut()
            .find(|(name, _)| *name == "config.json")
            .expect("config")
            .1 = blob(data, &case["wrong_config"]);
        // Original expected Assets reject the changed file before conversion.
        assert_eq!(
            prepare(&assets, &changed, false).err(),
            Some(Error::FileDigest)
        );
        assert_eq!(writes.get(), 0);
        // Even freshly hashed Assets cannot authorize a different Model epsilon.
        let wrong_assets = Assets::decode(blob(data, &case["wrong_assets"])).expect("new Assets");
        assert_eq!(
            prepare(&wrong_assets, &changed, false).err(),
            Some(Error::SourceEpsilon)
        );
        assert_eq!(writes.get(), 0);
    }
}
