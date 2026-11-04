//! RFC-0025 encoding §§1–6 and collection §§1–4: checked model and preparation artifacts.
//! Source/passport authority and inference/proof admission remain separate.
use crate::functions::{self, Representation};
use alloc::vec::Vec;
mod codec;
mod shape;
pub use shape::{Physical, Role, Shape};
mod rotation;
pub use rotation::Rotation;
mod block;
mod registry;
mod rotary;
pub use block::{Block, Policy};
pub use registry::Registry;
mod decoding;
use codec::{reserved, Reader, Writer};
pub use decoding::{Decoding, Sampling};
mod scales;
pub use scales::{MatrixScale, Scales};
mod bounds;
pub use bounds::Bounds;
mod source_map;
pub use source_map::{SourceEntry, SourceMap};
mod preparation;
pub use preparation::Preparation;
mod artifact;
pub use artifact::{Artifact, ArtifactLayout, ArtifactRecord};

const PREFIX: &[u8] = b"stele/v0.1/cqis/model";
const LIMIT: usize = 1 << 20;

/// Rejected canonical configuration; failure returns no partial checked metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid prefix, truncation, inactive bytes or suffix.
    Encoding,
    /// Unsupported shape, family or inconsistent head dimensions.
    Shape,
    /// A physical ordinal, rank, dimension, format or channel axis is incorrect.
    Physical,
    /// Inner function/representation validation failed.
    Function(functions::Error),
    /// Wrong normalization kind or dimension.
    Norm,
    /// A gain/bias fraction differs from its consuming normalization function.
    NormSource,
    /// Unsupported or inconsistent numerical units.
    Units,
    /// Invalid complete-row conversion policy.
    Policy,
    /// Invalid score multiplier or configured accumulation/drop.
    Attention,
    /// Wrong FFN activation family.
    Activation,
    /// An exp role selected a different function kind.
    Exponential,
    /// Incomplete or inconsistent rotation parameters.
    Rotation,
    /// Invalid sampled/greedy mode or rational policy.
    Decoding,
    /// The same FunctionId has distinct descriptors or selected representations.
    RepresentationConflict,
    /// The complete canonical bytes do not match an independently expected digest.
    Identity,
    /// A matrix scale exponent is outside [-1099,1024].
    ScaleExponent,
    /// A matrix scale mantissa is zero.
    ScaleMantissa,
    /// The stream reader failed or returned more bytes than the supplied buffer.
    Read,
    /// Native coefficient/table generation could not certify a complete result.
    Generation(crate::tables::Error),
    /// Registry length, ordered references or canonical metadata differs from Model.
    Registry,
    /// A component digest differs from complete native table regeneration.
    TableData,
    /// A rotation digest differs from complete native coefficient regeneration.
    RotationData,
    /// The complete ordered Bounds frame differs from deterministic derivation.
    Bounds,
    /// A static arithmetic record cannot be derived from the checked configuration.
    ArithmeticBounds(crate::bounds::arithmetic::Error),
    /// The output sink failed; no completed result is returned.
    Write,
    /// A source tensor name is empty, too long, contains NUL or is invalid UTF-8.
    SourceName,
    /// A selected source scalar format is outside F16/BF16/F32/F64.
    SourceDtype,
    /// Source rank, dimensions or full byte length disagree with the physical role.
    SourceShape,
    /// A source transform or fused part is not permitted at its physical role.
    SourceTransform,
    /// Fused Q/K/V uses do not form one complete matching layer-local partition.
    SourcePartition,
    /// A source name is reused or an optional GPT-2 token/head alias is invalid.
    SourceAlias,
    /// Ignored names are repeated, unsorted or overlap selected/alias names.
    SourceIgnored,
    /// Artifact framing, expected metadata, extent or exact exhaustion differs.
    Artifact,
    /// An Artifact payload contains the forbidden int4 -8 or int8 -128 code.
    ArtifactCode,
    /// An odd int4 payload has a nonzero final high nibble.
    ArtifactPadding,
    /// A byte/allocation bound cannot be satisfied.
    Capacity,
}

/// Checked physical precision. Its owning Model determines ordinal and shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalFormat {
    bits: u8,
    parameter: u8,
}
impl PhysicalFormat {
    /// Matrix int4/int8 or vector int16.
    pub fn bits(self) -> u8 {
        self.bits
    }
    /// Matrix channel axis (zero), or the vector's configured fractional bits.
    pub fn parameter(self) -> u8 {
        self.parameter
    }
}

/// Immutable complete structural metadata. A matching hash is a content join only.
/// ```compile_fail
/// fn change(model: &mut stele_cqis::model::Model) { model.initial_fraction = 0; }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Model {
    shape: Shape,
    formats: Vec<PhysicalFormat>,
    initial_fraction: u8,
    blocks: Vec<Block>,
    final_norm: Representation,
    final_policy: Policy,
    logits_fraction: u8,
    decoding: Decoding,
    identity: [u8; 32],
}
impl Model {
    /// Check the entire Model before returning metadata. Dimensions, physical order,
    /// units, functions and policies are closed; table/rotation data and static
    /// Bounds must additionally validate before any numerical operation admission.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let mut r = Reader(raw);
        r.prefix(PREFIX)?;
        let shape = Shape::decode(r.blob(21)?)?;
        let mut configuration_bytes = 0usize;
        for i in 0..shape.record_count() {
            let physical = shape.physical(i).ok_or(Error::Physical)?;
            configuration_bytes += 5 + 4 * physical.dimensions().len();
        }
        if configuration_bytes > r.0.len() {
            return Err(Error::Encoding);
        }
        let mut formats = reserved(usize::from(shape.record_count()))?;
        for i in 0..shape.record_count() {
            let physical = shape.physical(i).ok_or(Error::Physical)?;
            let dimensions = physical.dimensions();
            if r.u16()? != i || usize::from(r.u8()?) != dimensions.len() {
                return Err(Error::Physical);
            }
            for expected in dimensions {
                if r.u32()? != *expected {
                    return Err(Error::Physical);
                }
            }
            let bits = r.u8()?;
            let parameter = r.u8()?;
            if (dimensions.len() == 2 && (!matches!(bits, 4 | 8) || parameter != 0))
                || (dimensions.len() == 1 && (bits != 16 || parameter > 30))
            {
                return Err(Error::Physical);
            }
            formats.push(PhysicalFormat { bits, parameter });
        }
        let initial_fraction = block::fraction(&mut r)?;
        let mut current = initial_fraction;
        let mut blocks = reserved(usize::from(shape.layers()))?;
        for _ in 0..shape.layers() {
            let b = Block::read(&mut r, shape, current)?;
            current = b.output_fraction();
            blocks.push(b);
        }
        let final_norm = block::selection(&mut r)?;
        block::norm(&final_norm, shape, current)?;
        let final_policy = Policy::read(&mut r, false)?;
        let logits_fraction = block::fraction(&mut r)?;
        let decoding = Decoding::read(r.blob(345)?)?;
        r.end()?;
        let mut model = Self {
            shape,
            formats,
            initial_fraction,
            blocks,
            final_norm,
            final_policy,
            logits_fraction,
            decoding,
            identity: [0; 32],
        };
        model.check_norm_sources()?;
        model.check_function_selections()?;
        if model.encode()? != raw {
            return Err(Error::Encoding);
        }
        model.identity = *blake3::hash(raw).as_bytes();
        Ok(model)
    }
    /// Complete validation followed by an externally expected content-identity check.
    /// The expected hash still requires independent source/passport authority.
    pub fn decode_expected(expected: &[u8; 32], raw: &[u8]) -> Result<Self, Error> {
        let model = Self::decode(raw)?;
        if &model.identity != expected {
            return Err(Error::Identity);
        }
        Ok(model)
    }
    fn check_norm_sources(&self) -> Result<(), Error> {
        use Role::*;
        for (i, format) in self.formats.iter().enumerate() {
            let physical = self
                .shape
                .physical(u16::try_from(i).map_err(|_| Error::Physical)?)
                .ok_or(Error::Physical)?;
            let selected = match physical.role() {
                FirstGain | FirstBias | SecondGain | SecondBias => {
                    let b = self
                        .blocks
                        .get(usize::from(physical.layer().ok_or(Error::Physical)?))
                        .ok_or(Error::Physical)?;
                    if matches!(physical.role(), FirstGain | FirstBias) {
                        b.first_norm()
                    } else {
                        b.second_norm()
                    }
                }
                FinalGain | FinalBias => &self.final_norm,
                _ => continue,
            };
            let bias = matches!(physical.role(), FirstBias | SecondBias | FinalBias);
            if format.parameter != selected.function().parameters()[if bias { 5 } else { 3 }] {
                return Err(Error::NormSource);
            }
        }
        Ok(())
    }
    fn check_function_selections(&self) -> Result<(), Error> {
        let mut functions = reserved(self.function_roles().count())?;
        for r in self.function_roles() {
            functions.push((r.function().identity().map_err(Error::Function)?, r));
        }
        functions.sort_unstable_by_key(|v| v.0);
        if functions
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return Err(Error::RepresentationConflict);
        }
        Ok(())
    }
    /// Re-encode all checked fields. The shape-derived reservation is below 220000
    /// bytes over the complete domain (encoding §4); no append grows the buffer.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let capacity = 64
            + 13 * usize::from(self.shape.record_count())
            + 1494 * usize::from(self.shape.layers())
            + 800;
        if capacity > LIMIT {
            return Err(Error::Capacity);
        }
        let mut w = Writer::new(capacity)?;
        w.push(PREFIX)?;
        w.blob(&self.shape.encode())?;
        for (i, f) in self.formats.iter().enumerate() {
            let ordinal = u16::try_from(i).map_err(|_| Error::Physical)?;
            let p = self.shape.physical(ordinal).ok_or(Error::Physical)?;
            w.push(&ordinal.to_le_bytes())?;
            w.push(&[p.dimensions().len() as u8])?;
            for d in p.dimensions() {
                w.push(&d.to_le_bytes())?;
            }
            w.push(&[f.bits, f.parameter])?;
        }
        w.push(&[self.initial_fraction])?;
        for b in &self.blocks {
            b.write(&mut w)?;
        }
        block::write_selection(&mut w, &self.final_norm)?;
        self.final_policy.write(&mut w)?;
        w.push(&[self.logits_fraction])?;
        w.blob(&self.decoding.encode()?)?;
        Ok(w.finish())
    }
    /// Complete Model hash, not the four-artifact cqis_id or a passport identity.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Complete checked Shape.
    pub fn shape(&self) -> Shape {
        self.shape
    }
    /// Physical precisions in derived record order, including every gain/bias.
    pub fn formats(&self) -> &[PhysicalFormat] {
        &self.formats
    }
    /// First residual fraction, after complete token/position gathering.
    pub fn initial_fraction(&self) -> u8 {
        self.initial_fraction
    }
    /// Every block in execution order.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }
    /// Final normalization selection.
    pub fn final_norm(&self) -> &Representation {
        &self.final_norm
    }
    /// Whole-row final conversion policy.
    pub fn final_policy(&self) -> Policy {
        self.final_policy
    }
    /// Common output fraction of all vocabulary logits.
    pub fn logits_fraction(&self) -> u8 {
        self.logits_fraction
    }
    /// Complete explicit greedy/sampled configuration.
    pub fn decoding(&self) -> &Decoding {
        &self.decoding
    }
    /// Ordered neural roles: first norm, attention exp, second norm, activation for
    /// every block, then final norm and sampled exp. Repeated functions retain roles.
    pub fn function_roles(&self) -> impl Iterator<Item = &Representation> {
        self.blocks
            .iter()
            .flat_map(|b| {
                [
                    b.first_norm(),
                    b.exponential(),
                    b.second_norm(),
                    b.activation(),
                ]
            })
            .chain(core::iter::once(&self.final_norm))
            .chain(self.decoding.sampling().map(Sampling::exponential))
    }
}
