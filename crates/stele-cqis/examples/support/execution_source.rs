//! RFC-0025 source: independently rederive runtime SourceConfig from original files.
use super::{frame, result};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
use stele_cqis::model::{Assets, Model, Preparation, Source, SourceConfig, SourcePackage};

pub fn validate(
    directory: &Path,
    originals: &Path,
    model: &Model,
    preparation: &Preparation<'_>,
    layout: u8,
    expected: &[u8],
) -> Result<(), String> {
    let source_raw = frame(&directory.join("source.bin"), 1 << 29)?;
    let assets_raw = frame(&directory.join("assets.bin"), 1 << 29)?;
    let source = result(Source::decode(&source_raw))?;
    let assets = result(Assets::decode(&assets_raw))?;
    let descriptions: Vec<_> = source
        .files()
        .iter()
        .chain(source.index())
        .chain(core::iter::once(assets.config()))
        .chain(assets.tokenizers())
        .chain(assets.generation())
        .collect();
    if descriptions.len() > 4096 {
        return Err("file-descriptor allowance exceeded".into());
    }
    let names: Vec<_> = descriptions.iter().map(|f| f.name()).collect();
    let mut files = BTreeMap::new();
    for name in &names {
        files.insert(
            *name,
            File::open(originals.join(name)).map_err(|e| e.to_string())?,
        );
    }
    let mut read_at = |name: &str, offset: u64, out: &mut [u8]| {
        let file = files.get_mut(name).ok_or(std::io::ErrorKind::NotFound)?;
        file.seek(SeekFrom::Start(offset))?;
        file.read(out)
    };
    let package = result(SourcePackage::read_from(
        preparation.map(),
        &source,
        &assets,
        &names,
        32 << 20,
        64 << 20,
        &mut read_at,
    ))?;
    let config = result(SourceConfig::read_from(
        model,
        &package,
        layout,
        64 << 20,
        &mut read_at,
    ))?;
    result(config.verify(expected))?;
    eprintln!("complete original package and runtime SourceConfig independently matched");
    Ok(())
}
