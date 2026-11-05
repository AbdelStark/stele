//! RFC-0025 §2.1/conversion §§1–3: original source bytes to complete Artifact.
use core::cell::Cell;
use serde_json::Value;
use stele_cqis::model::{
    Artifact, ArtifactLayout, Assets, Conversion, Error, Model, Preparation, Source, SourcePackage,
};

fn blob<'a>(data: &'a [u8], span: &Value) -> &'a [u8] {
    let at = span["offset"].as_u64().expect("offset") as usize;
    let size = span["length"].as_u64().expect("length") as usize;
    &data[at..at + size]
}
struct File<'a> {
    name: &'a str,
    prefix: &'a [u8],
    length: u64,
    period: &'a [u8],
    start: u64,
    pattern_length: u64,
    patches: Vec<(u64, u8)>,
}
#[test]
fn matches_reference_original_source_conversion() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/source-conversion.json")).expect("fixtures");
    let data = include_bytes!("fixtures/source-conversion.bin");
    for case in fixtures["cases"].as_array().expect("cases") {
        let label = case["label"].as_str().expect("label");
        let model = Model::decode(blob(data, &case["model"])).expect("Model");
        let preparation =
            Preparation::decode(&model, blob(data, &case["preparation"])).expect("Preparation");
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
                period: blob(data, &f["period"]),
                start: f["start"].as_u64().expect("pattern offset"),
                pattern_length: f["pattern_length"].as_u64().expect("pattern length"),
                patches: f["patches"]
                    .as_array()
                    .expect("patches")
                    .iter()
                    .map(|p| {
                        (
                            p[0].as_u64().expect("offset"),
                            p[1].as_u64().expect("byte") as u8,
                        )
                    })
                    .collect(),
            })
            .collect();
        let names: Vec<_> = files.iter().map(|f| f.name).collect();
        let bytes_read = Cell::new(0u64);
        let read = |name: &str, offset: u64, out: &mut [u8]| {
            assert!(out.len() <= 65536);
            let f = files.iter().find(|f| f.name == name).ok_or(())?;
            let n = out
                .len()
                .min(f.length.saturating_sub(offset) as usize)
                .min(if label == "random 0" { 31 } else { 65536 });
            out[..n].fill(0);
            if offset < f.prefix.len() as u64 {
                let at = offset as usize;
                let copied = n.min(f.prefix.len() - at);
                out[..copied].copy_from_slice(&f.prefix[at..at + copied]);
            }
            if !f.period.is_empty() {
                for at in offset.max(f.start)..(offset + n as u64).min(f.start + f.pattern_length) {
                    out[(at - offset) as usize] =
                        f.period[((at - f.start) % f.period.len() as u64) as usize];
                }
            }
            for &(at, byte) in &f.patches {
                if offset <= at && at - offset < n as u64 {
                    out[(at - offset) as usize] = byte;
                }
            }
            bytes_read.set(bytes_read.get() + n as u64);
            Ok::<_, ()>(n)
        };
        let package = SourcePackage::read_from(
            preparation.map(),
            &source,
            &assets,
            &names,
            1 << 24,
            1 << 26,
            read,
        )
        .expect("complete original package");
        bytes_read.set(0);
        let required = Conversion::required_cache_bytes(&model, &package).expect("cache geometry");
        let mut output = Vec::new();
        let result = Conversion::write_to(&model, &preparation, &package, required, read, |raw| {
            assert!(!raw.is_empty() && raw.len() <= 65536);
            output.extend_from_slice(raw);
            Ok::<_, ()>(raw.len())
        });
        if let Some(error) = case["error"].as_str() {
            let expected = match error {
                "Nonfinite" => Error::SourceNonfinite,
                "Overflow" => Error::ConversionOverflow,
                _ => unreachable!(),
            };
            assert_eq!(result.err(), Some(expected), "{label}");
            assert!(
                output.is_empty(),
                "{label}: must reject before the first write"
            );
            continue;
        }
        let conversion = result.expect(label);
        if label.starts_with("transposed chunk stride") {
            // A resource control on raw-byte reuse, not a timing benchmark.
            assert!(
                bytes_read.get()
                    <= 32 * source.total_length()
                        + 6 * 65536 * u64::from(model.shape().record_count())
            );
        }
        assert_eq!(output, blob(data, &case["artifact"]), "{label}");
        assert_eq!(
            conversion.scales().encode().expect("Scales"),
            blob(data, &case["scales"]),
            "{label}"
        );
        assert_eq!(conversion.source_identity(), source.identity());
        assert_eq!(conversion.assets_identity(), assets.identity());
        assert_eq!(
            conversion.artifact().preparation_identity(),
            preparation.identity()
        );
        assert_eq!(
            conversion.artifact().identity(),
            *blake3::hash(&output).as_bytes()
        );
        let stored = Artifact::decode(&model, &preparation, conversion.scales(), &output)
            .expect("actual stored bytes");
        assert_eq!(&stored, conversion.artifact());
        let mut calls = 0;
        assert_eq!(
            Conversion::write_to(
                &model,
                &preparation,
                &package,
                required - 1,
                |_, _, _| {
                    calls += 1;
                    Ok::<_, ()>(0)
                },
                |_| Ok::<_, ()>(0)
            )
            .err(),
            Some(Error::Capacity)
        );
        assert_eq!(calls, 0);
        let other_model = Model::decode(blob(data, &case["other_model"])).expect("other Model");
        let other_preparation =
            Preparation::decode(&model, blob(data, &case["other_preparation"])).expect("other Map");
        for (m, p) in [(&other_model, &preparation), (&model, &other_preparation)] {
            assert_eq!(
                Conversion::write_to(
                    m,
                    p,
                    &package,
                    required,
                    |_, _, _| {
                        calls += 1;
                        Ok::<_, ()>(0)
                    },
                    |_| Ok::<_, ()>(0)
                )
                .err(),
                Some(Error::Identity)
            );
        }
        assert_eq!(calls, 0);
        if label == "random 0" {
            let layout = ArtifactLayout::new(&model).expect("layout");
            let at = layout
                .records()
                .iter()
                .find(|r| r.bits() == 16)
                .expect("vector")
                .payload_offset() as usize;
            let mut changed_output = output.clone();
            changed_output[at] ^= 1;
            assert_eq!(
                Artifact::decode_expected(
                    &model,
                    &preparation,
                    conversion.scales(),
                    &conversion.artifact().identity(),
                    &changed_output
                )
                .err(),
                Some(Error::Identity)
            );
            assert_eq!(
                Conversion::write_to(&model, &preparation, &package, required, read, |raw| Ok::<
                    _,
                    (),
                >(
                    raw.len() - 1
                ))
                .err(),
                Some(Error::Write)
            );
            assert_eq!(
                Conversion::write_to(&model, &preparation, &package, required, read, |_| Err::<
                    usize,
                    _,
                >(
                    ()
                ))
                .err(),
                Some(Error::Write)
            );
            assert_eq!(
                Conversion::write_to(
                    &model,
                    &preparation,
                    &package,
                    required,
                    |_, _, _| Err::<usize, _>(()),
                    |raw| Ok::<_, ()>(raw.len())
                )
                .err(),
                Some(Error::Read)
            );
            // Original source bytes change after package validation, before conversion.
            let tensor = package.tensor(0).expect("token");
            let changed = tensor.offset();
            let mut written = 0;
            assert_eq!(
                Conversion::write_to(
                    &model,
                    &preparation,
                    &package,
                    required,
                    |name, at, out| {
                        let n = read(name, at, out)?;
                        if name == tensor.file().name() && at <= changed && changed - at < n as u64
                        {
                            out[(changed - at) as usize] ^= 1;
                        }
                        Ok::<_, ()>(n)
                    },
                    |raw| {
                        written += raw.len();
                        Ok::<_, ()>(raw.len())
                    }
                )
                .err(),
                Some(Error::SnapshotData)
            );
            assert_eq!(written, 0);
            // A change during emission must preserve SnapshotData, even though
            // the generic Artifact payload reader normally maps errors to Read.
            let emission = Cell::new(false);
            let mut written = 0;
            assert_eq!(
                Conversion::write_to(
                    &model,
                    &preparation,
                    &package,
                    required,
                    |name, at, out| {
                        let n = read(name, at, out)?;
                        if emission.get()
                            && name == tensor.file().name()
                            && at <= changed
                            && changed - at < n as u64
                        {
                            out[(changed - at) as usize] ^= 1;
                        }
                        Ok::<_, ()>(n)
                    },
                    |raw| {
                        emission.set(true);
                        written += raw.len();
                        Ok::<_, ()>(raw.len())
                    }
                )
                .err(),
                Some(Error::SnapshotData)
            );
            assert!(written > 0);
            assert_eq!(
                Conversion::write_to(&model, &preparation, &package, required, read, |raw| Ok::<
                    _,
                    (),
                >(
                    raw.len() + 1
                ))
                .err(),
                Some(Error::Write)
            );
        }
    }
}
