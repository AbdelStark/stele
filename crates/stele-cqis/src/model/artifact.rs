//! RFC-0025 encoding §3: complete bounded Artifact streams, not source conversion.
use super::{Error, Model, Preparation, Scales};
mod layout;
pub use layout::{ArtifactLayout, ArtifactRecord};
mod stream;
use stream::{Digest, Part};

const PREFIX: &[u8] = b"cqis-weights-v1";
const TENSOR: &[u8] = b"stele/v0.1/cqis/tensor";
const HEADER: usize = PREFIX.len() + 32 + 2;
const CHUNK: usize = 65536;
const LIMIT: u64 = 1 << 39;

/// Completed canonical Artifact validation or emission, without retained payloads.
/// Structural validity does not establish source conversion, minimal scales,
/// storage integrity after emission, publisher authority or proof admission.
/// ```compile_fail
/// fn change(a: &mut stele_cqis::model::Artifact) { a.identity = [0; 32]; }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    model_identity: [u8; 32],
    preparation_identity: [u8; 32],
    scales_identity: [u8; 32],
    identity: [u8; 32],
    byte_length: u64,
    record_count: u16,
}
impl Artifact {
    /// Check exact metadata, every code/padding byte and complete stream exhaustion.
    /// Reads use at most 65536 bytes; short reads are accumulated without seeking.
    pub fn read_from<E>(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        let layout = context(model, preparation, scales)?;
        let mut buffer = stream::buffer()?;
        let mut digest = Digest::new();
        stream::walk(&layout, preparation, scales, |part| match part {
            Part::Metadata(raw) => stream::expected(raw, &mut buffer, &mut read, &mut digest),
            Part::Payload(record) => {
                stream::payload(record, &mut buffer, &mut read, |raw| digest.update(raw))
            }
        })?;
        stream::eof(&mut read)?;
        Self::complete(model, preparation, scales, &layout, digest)
    }
    /// Complete streamed validation before comparing an independently expected digest.
    pub fn read_from_expected<E>(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        expected: &[u8; 32],
        read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> Result<Self, Error> {
        Self::read_from(model, preparation, scales, read)?.check_identity(expected)
    }
    /// Validate an existing byte slice without making a whole-Artifact copy.
    pub fn decode(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        mut raw: &[u8],
    ) -> Result<Self, Error> {
        if raw.len() as u64 >= LIMIT {
            return Err(Error::Capacity);
        }
        Self::read_from(model, preparation, scales, |out| {
            let n = raw.len().min(out.len());
            out[..n].copy_from_slice(&raw[..n]);
            raw = &raw[n..];
            Ok::<_, core::convert::Infallible>(n)
        })
    }
    /// Complete validation followed by an independently expected digest_cqis check.
    pub fn decode_expected(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        expected: &[u8; 32],
        raw: &[u8],
    ) -> Result<Self, Error> {
        Self::decode(model, preparation, scales, raw)?.check_identity(expected)
    }
    /// Emit canonical metadata and checked payloads in chunks of at most 65536 bytes.
    /// The payload callback receives each expected physical ordinal in order and
    /// must report EOF after that record's exact payload extent. A failed read or
    /// write leaves an unusable partial sink and returns no completed Artifact.
    pub fn write_to<R, W>(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        mut read_payload: impl FnMut(u16, &mut [u8]) -> Result<usize, R>,
        mut write: impl FnMut(&[u8]) -> Result<(), W>,
    ) -> Result<Self, Error> {
        let layout = context(model, preparation, scales)?;
        let mut buffer = stream::buffer()?;
        let mut digest = Digest::new();
        stream::walk(&layout, preparation, scales, |part| match part {
            Part::Metadata(raw) => {
                write(raw).map_err(|_| Error::Write)?;
                digest.update(raw)
            }
            Part::Payload(record) => {
                let mut read = |out: &mut [u8]| read_payload(record.ordinal(), out);
                stream::payload(record, &mut buffer, &mut read, |raw| {
                    write(raw).map_err(|_| Error::Write)?;
                    digest.update(raw)
                })?;
                stream::eof(&mut read)
            }
        })?;
        Self::complete(model, preparation, scales, &layout, digest)
    }

    fn complete(
        model: &Model,
        preparation: &Preparation<'_>,
        scales: &Scales,
        layout: &ArtifactLayout,
        digest: Digest,
    ) -> Result<Self, Error> {
        if digest.length != layout.byte_length() {
            return Err(Error::Artifact);
        }
        Ok(Self {
            model_identity: model.identity(),
            preparation_identity: preparation.identity(),
            scales_identity: scales.identity(),
            identity: *digest.hash.finalize().as_bytes(),
            byte_length: digest.length,
            record_count: model.shape().record_count(),
        })
    }
    fn check_identity(self, expected: &[u8; 32]) -> Result<Self, Error> {
        if &self.identity != expected {
            return Err(Error::Identity);
        }
        Ok(self)
    }
    /// Complete Model against which the physical configuration was checked.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// quantiser_id of the complete checked Preparation, also in the Artifact header.
    pub fn preparation_identity(&self) -> [u8; 32] {
        self.preparation_identity
    }
    /// Complete expected Scales identity, retaining every original channel value.
    pub fn scales_identity(&self) -> [u8; 32] {
        self.scales_identity
    }
    /// digest_cqis of all successfully checked or emitted bytes, including payloads.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Complete validated extent; no prefix digest can construct this result.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    /// Exact number of physical records checked or emitted.
    pub fn record_count(&self) -> u16 {
        self.record_count
    }
}

fn context(
    model: &Model,
    preparation: &Preparation<'_>,
    scales: &Scales,
) -> Result<ArtifactLayout, Error> {
    if preparation.model_identity() != model.identity()
        || scales.model_identity() != model.identity()
    {
        return Err(Error::Identity);
    }
    ArtifactLayout::new(model)
}
