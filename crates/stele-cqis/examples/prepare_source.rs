//! RFC-0025 source/conversion and encoding §6: complete disk-backed preparation.
//! Manual qualification adapter; no publisher authority, inference or proof admission.
#![forbid(unsafe_code)]
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use stele_cqis::model::{
    Artifact, Assets, Bounds, Conversion, Error, Model, NumericalIdentity, Preparation, Registry,
    Source, SourceConfig, SourcePackage,
};

fn cq<T>(result: Result<T, Error>) -> Result<T, String> {
    result.map_err(|e| format!("{e:?}"))
}
fn io<T>(result: std::io::Result<T>) -> Result<T, String> {
    result.map_err(|e| e.to_string())
}
fn frame(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = io(File::open(path))?;
    let length = io(file.metadata())?.len();
    if length > limit {
        return Err("metadata frame exceeds capacity".into());
    }
    let length = usize::try_from(length).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(length).map_err(|e| e.to_string())?;
    raw.resize(length, 0);
    io(file.read_exact(&mut raw))?;
    if io(file.read(&mut [0; 1]))? != 0 {
        return Err("metadata file changed length".into());
    }
    Ok(raw)
}
fn write_frame(directory: &Path, name: &str, raw: &[u8]) -> Result<(), String> {
    let mut file = io(File::create_new(directory.join(name)))?;
    io(file.write_all(raw))?;
    io(file.sync_all())
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 7 {
        return Err("usage: prepare_source MODEL PREPARATION SOURCE ASSETS LAYOUT SOURCE_DIR NEW_OUTPUT_DIR".into());
    }
    let model_raw = frame(Path::new(&args[0]), 1 << 20)?;
    let preparation_raw = frame(Path::new(&args[1]), 17 << 20)?;
    let source_raw = frame(Path::new(&args[2]), 1 << 29)?;
    let assets_raw = frame(Path::new(&args[3]), 1 << 29)?;
    let layout: u8 = args[4]
        .to_str()
        .ok_or("layout must be an integer")?
        .parse()
        .map_err(|_| "layout must be an integer")?;
    let source_dir = Path::new(&args[5]);
    let output_dir = Path::new(&args[6]);
    let model = cq(Model::decode(&model_raw))?;
    let preparation = cq(Preparation::decode(&model, &preparation_raw))?;
    let source = cq(Source::decode(&source_raw))?;
    let assets = cq(Assets::decode(&assets_raw))?;
    let descriptions: Vec<_> = source
        .files()
        .iter()
        .chain(source.index())
        .chain(core::iter::once(assets.config()))
        .chain(assets.tokenizers())
        .chain(assets.generation())
        .collect();
    // Adapter resource allowance, separate from the canonical source domain.
    if descriptions.len() > 4096 {
        return Err("file-descriptor allowance exceeded".into());
    }
    let names: Vec<_> = descriptions.iter().map(|f| f.name()).collect();
    let mut files = BTreeMap::new();
    for name in &names {
        files.insert(*name, io(File::open(source_dir.join(name)))?);
    }
    let mut read_at = |name: &str, offset: u64, out: &mut [u8]| {
        let file = files.get_mut(name).ok_or(std::io::ErrorKind::NotFound)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    };
    let package = cq(SourcePackage::read_from(
        preparation.map(),
        &source,
        &assets,
        &names,
        32 << 20,
        64 << 20,
        &mut read_at,
    ))?;
    let config = cq(SourceConfig::read_from(
        &model,
        &package,
        layout,
        64 << 20,
        &mut read_at,
    ))?;
    eprintln!("complete original package and SourceConfig validated");
    let cache = cq(Conversion::required_cache_bytes(&model, &package))?;
    if cache > 64 << 20 {
        return Err("source-cache allowance exceeded".into());
    }
    io(fs::create_dir(output_dir))?;
    let mut artifact_file = io(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output_dir.join("artifact.bin")))?;
    let conversion = cq(Conversion::write_to(
        &model,
        &preparation,
        &package,
        cache,
        &mut read_at,
        |raw| {
            artifact_file.write_all(raw)?;
            Ok::<_, std::io::Error>(raw.len())
        },
    ))?;
    io(artifact_file.sync_all())?;
    io(artifact_file.seek(SeekFrom::Start(0)))?;
    let stored = cq(Artifact::read_from_expected(
        &model,
        &preparation,
        conversion.scales(),
        &conversion.artifact().identity(),
        |out| artifact_file.read(out),
    ))?;
    eprintln!("complete converted Artifact reread and validated");
    let registry = cq(Registry::new(&model))?;
    let mut bounds_file = io(File::create_new(output_dir.join("bounds.bin")))?;
    let bounds = cq(Bounds::write_to(
        &model,
        conversion.scales(),
        &registry,
        |raw| bounds_file.write_all(raw),
    ))?;
    io(bounds_file.sync_all())?;
    let identity = cq(NumericalIdentity::new(
        &model,
        conversion.scales(),
        &registry,
        &bounds,
    ))?;
    for (name, raw) in [
        ("model.bin", model_raw.as_slice()),
        ("preparation.bin", preparation_raw.as_slice()),
        ("source.bin", source_raw.as_slice()),
        ("assets.bin", assets_raw.as_slice()),
        ("source-config.bin", config.as_bytes()),
        ("registry.bin", registry.as_bytes()),
        ("identity.bin", identity.as_bytes()),
    ] {
        write_frame(output_dir, name, raw)?;
    }
    write_frame(output_dir, "scales.bin", &cq(conversion.scales().encode())?)?;
    // Written last: a failed run's partial directory is not a completed result.
    let result = serde_json::json!({
        "status": "prepared", "layout": layout, "physical_records": model.shape().record_count(),
        "source_bytes": source.total_length(), "assets_bytes": assets.total_length(),
        "source_identity": hex(&conversion.source_identity()), "assets_id": hex(&assets.identity()),
        "source_config_id": hex(&config.identity()), "model_id": hex(&model.identity()),
        "quantiser_id": hex(&preparation.identity()), "scales_id": hex(&conversion.scales().identity()),
        "digest_cqis": hex(&stored.identity()), "artifact_bytes": stored.byte_length(),
        "registry_id": hex(&registry.identity()), "bounds_id": hex(&bounds.identity()),
        "bounds_bytes": bounds.byte_length(), "bound_records": bounds.record_count(),
        "cqis_id": hex(&identity.identity()), "source_cache_allowance_bytes": cache,
        "boundary": "Numerical preparation only; no publisher authority, inference, fidelity or proof admission."
    });
    write_frame(output_dir, "result.json", result.to_string().as_bytes())?;
    println!("{result}");
    Ok(())
}
