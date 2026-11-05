//! RFC-0025 §2.1/conversion §§1–3: complete original-source numerical conversion.
use super::{codec::reserved, Artifact, Error, Model, Preparation, Scales, SourcePackage};
mod payload;
mod scalar;
mod view;
use scalar::Scalar;
use view::{Cache, Tensor};

/// Completed exact conversion, retaining Scales and the full emitted Artifact
/// identity. The sink must still be read and validated to establish its storage
/// contents. SourceConfig, original publisher/passport authority, inference and
/// proof admission remain separate requirements.
/// ```compile_fail
/// fn change(c: &mut stele_cqis::model::Conversion) { c.source_identity = [0; 33]; }
/// ```
pub struct Conversion {
    source_identity: [u8; 33],
    assets_identity: [u8; 32],
    scales: Scales,
    artifact: Artifact,
}
impl Conversion {
    /// Conservative requested raw-cache allowance for this checked package:
    /// chunk slots plus up to 65536 owned bytes each. Scales (<=64 MiB), small
    /// record metadata, bounded stream buffers, input package storage and allocator
    /// overhead are separate.
    /// This derives the full geometry, without reading source data or using a
    /// former element-count cap. No whole decoded matrix or row-maxima array exists.
    pub fn required_cache_bytes(
        model: &Model,
        package: &SourcePackage<'_>,
    ) -> Result<usize, Error> {
        Cache::bytes(Self::slots(model, package)?)
    }
    fn slots(model: &Model, package: &SourcePackage<'_>) -> Result<usize, Error> {
        if model.shape() != package.source_map().shape() {
            return Err(Error::Shape);
        }
        let mut maximum = 1;
        for ordinal in 0..model.shape().record_count() {
            let physical = model.shape().physical(ordinal).ok_or(Error::Physical)?;
            maximum = maximum.max(Tensor::new(package, physical)?.slots());
        }
        Ok(maximum)
    }
    /// Derive minimal scales and validate every selected scalar/vector before
    /// the first write. Emit only canonical metadata and continuously packed
    /// codes. Short/overreported/error writes reject; discard any partial sink.
    /// Reads use authenticated package views, with bounded immutable chunk reuse.
    /// No result escapes until the entire emitted Artifact has been hashed.
    pub fn write_to<R, W>(
        model: &Model,
        preparation: &Preparation<'_>,
        package: &SourcePackage<'_>,
        max_cache_bytes: usize,
        mut read_at: impl FnMut(&str, u64, &mut [u8]) -> Result<usize, R>,
        mut write: impl FnMut(&[u8]) -> Result<usize, W>,
    ) -> Result<Self, Error> {
        if preparation.model_identity() != model.identity()
            || preparation.map().as_bytes() != package.source_map().as_bytes()
        {
            return Err(Error::Identity);
        }
        let slots = Self::slots(model, package)?;
        if Cache::bytes(slots)? > max_cache_bytes {
            return Err(Error::Capacity);
        }
        Scales::encoded_length(model)?;
        let mut cache = Cache::new(slots)?;
        let count = (0..model.shape().record_count())
            .filter(|i| {
                model
                    .shape()
                    .physical(*i)
                    .is_some_and(|p| p.dimensions().len() == 2)
            })
            .count();
        let mut values = reserved(count)?;
        for ordinal in 0..model.shape().record_count() {
            let physical = model.shape().physical(ordinal).ok_or(Error::Physical)?;
            let tensor = Tensor::new(package, physical)?;
            let format = model.formats()[usize::from(ordinal)];
            if format.bits() == 16 {
                for k in 0..tensor.count {
                    tensor
                        .scalar(k, &mut cache, &mut read_at)?
                        .vector(format.parameter())?;
                }
            } else {
                let mut peak = Scalar::ZERO;
                for k in 0..tensor.count {
                    peak = peak.maximum(tensor.scalar(k, &mut cache, &mut read_at)?);
                }
                let exponent = peak.exponent(format.bits())?;
                let mut mantissas =
                    reserved(usize::try_from(tensor.rows).map_err(|_| Error::Capacity)?)?;
                for row in 0..tensor.rows {
                    let mut peak = Scalar::ZERO;
                    for column in 0..tensor.columns {
                        peak = peak.maximum(tensor.scalar(
                            row * tensor.columns + column,
                            &mut cache,
                            &mut read_at,
                        )?);
                    }
                    mantissas.push(peak.mantissa(exponent, format.bits())?);
                }
                values.push((exponent, mantissas));
            }
        }
        let scales = Scales::from_derived(model, values)?;
        let mut payload = payload::Payload::new(model, package, &scales);
        let mut failure = None;
        let artifact = Artifact::write_to(
            model,
            preparation,
            &scales,
            |ordinal, out| {
                payload
                    .read(ordinal, out, &mut cache, &mut read_at)
                    .map_err(|error| {
                        failure = Some(error);
                    })
            },
            |raw| {
                let n = write(raw).map_err(|_| Error::Write)?;
                if n != raw.len() {
                    return Err(Error::Write);
                }
                Ok(())
            },
        )
        .map_err(|error| failure.unwrap_or(error))?;
        Ok(Self {
            source_identity: package.source().identity(),
            assets_identity: package.assets().identity(),
            scales,
            artifact,
        })
    }
    /// Original typed checkpoint identity; numerical equality does not replace it.
    pub fn source_identity(&self) -> [u8; 33] {
        self.source_identity
    }
    /// Complete original auxiliary-file identity, separate from config semantics.
    pub fn assets_identity(&self) -> [u8; 32] {
        self.assets_identity
    }
    /// Complete minimal source-derived matrix exponents and channel mantissas.
    pub fn scales(&self) -> &Scales {
        &self.scales
    }
    /// Completed emitted Artifact. Actual stored-byte validation is still required.
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
}
