//! RFC-0025 encoding §3: independently derived full-u64 Artifact addresses.
use super::{HEADER, LIMIT, TENSOR};
use crate::model::{
    codec::{configuration, reserved},
    Error, Model,
};
use alloc::vec::Vec;

/// One physical record's expected addresses; no source or payload is admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRecord {
    ordinal: u16,
    bits: u8,
    elements: u64,
    record_offset: u64,
    payload_offset: u64,
    payload_length: u64,
    record_length: u64,
    pub(super) configuration: [u8; 13],
    pub(super) configuration_length: usize,
    pub(super) channels: Option<u32>,
}
impl ArtifactRecord {
    /// Physical ordinal in Model order; GPT-2 has no additional head record.
    pub fn ordinal(&self) -> u16 {
        self.ordinal
    }
    /// Expected int4, int8 or int16 physical encoding width.
    pub fn bits(&self) -> u8 {
        self.bits
    }
    /// Complete physical element count, without a former research element cap.
    pub fn elements(&self) -> u64 {
        self.elements
    }
    /// Artifact-global start of R_i, immediately after its u64 length field.
    pub fn record_offset(&self) -> u64 {
        self.record_offset
    }
    /// Artifact-global first payload byte; all header and scale bytes are retained.
    pub fn payload_offset(&self) -> u64 {
        self.payload_offset
    }
    /// Exact continuous packed payload length, with no per-row nibble padding.
    pub fn payload_length(&self) -> u64 {
        self.payload_length
    }
    /// Complete R_i length, excluding the preceding u64 length field.
    pub fn record_length(&self) -> u64 {
        self.record_length
    }
}

/// Complete expected layout from Model, without reading or admitting an Artifact.
#[derive(Debug, Eq, PartialEq)]
pub struct ArtifactLayout {
    model_identity: [u8; 32],
    records: Vec<ArtifactRecord>,
    byte_length: u64,
}
impl ArtifactLayout {
    /// Derive every dimension, C_i and checked address before any stream is read.
    pub fn new(model: &Model) -> Result<Self, Error> {
        let mut records = reserved(usize::from(model.shape().record_count()))?;
        let mut offset = HEADER as u64;
        for ordinal in 0..model.shape().record_count() {
            let physical = model.shape().physical(ordinal).ok_or(Error::Physical)?;
            let bits = model
                .formats()
                .get(usize::from(ordinal))
                .ok_or(Error::Physical)?
                .bits();
            let (configuration, configuration_length) = configuration(model, ordinal)?;
            let elements = physical.dimensions().iter().try_fold(1u64, |n, d| {
                n.checked_mul(u64::from(*d)).ok_or(Error::Capacity)
            })?;
            let payload_length = elements
                .checked_mul(u64::from(bits))
                .and_then(|n| n.checked_add(7))
                .ok_or(Error::Capacity)?
                / 8;
            let channels = (physical.dimensions().len() == 2).then_some(physical.dimensions()[0]);
            let scale_length = match channels {
                Some(n) => u64::from(n)
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(Error::Capacity)?,
                None => 0,
            };
            let header = (TENSOR.len() as u64)
                .checked_add(4)
                .and_then(|n| n.checked_add(configuration_length as u64))
                .and_then(|n| n.checked_add(8))
                .and_then(|n| n.checked_add(scale_length))
                .ok_or(Error::Capacity)?;
            let record_offset = offset.checked_add(8).ok_or(Error::Capacity)?;
            let payload_offset = record_offset.checked_add(header).ok_or(Error::Capacity)?;
            let record_length = header.checked_add(payload_length).ok_or(Error::Capacity)?;
            offset = record_offset
                .checked_add(record_length)
                .filter(|n| *n < LIMIT)
                .ok_or(Error::Capacity)?;
            records.push(ArtifactRecord {
                ordinal,
                bits,
                elements,
                record_offset,
                payload_offset,
                payload_length,
                record_length,
                configuration,
                configuration_length,
                channels,
            });
        }
        Ok(Self {
            model_identity: model.identity(),
            records,
            byte_length: offset,
        })
    }
    /// Model from which all addresses and physical formats were derived.
    pub fn model_identity(&self) -> [u8; 32] {
        self.model_identity
    }
    /// Complete physical record order, including all vectors and scale extents.
    pub fn records(&self) -> &[ArtifactRecord] {
        &self.records
    }
    /// Exact total extent; strictly below 2^39 over the accepted domain.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
}
