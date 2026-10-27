//! Canonical transcript registry governed by RFC-0012 A1.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

/// A registry validation failure; invalid registries cannot be used for transcripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Label bytes are not versioned ASCII of length 1..255.
    InvalidLabel,
    /// Two registered meanings have identical label bytes.
    DuplicateLabel,
    /// Only challenge labels may carry a soundness-accounting line.
    InvalidAccounting,
}
/// Operation class of a registered label (RFC-0012 A1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelKind {
    /// The mandatory, once-only public-input absorb.
    Constructor,
    /// A caller-scheduled message absorb.
    Absorb,
    /// A field challenge request and its state update.
    Challenge,
}
/// Soundness line owned by a challenge label (RFC-0012 §4, A1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossLine {
    /// One sumcheck round; instance degree/round counts are supplied by the consumer.
    Sc,
}
/// Registered label metadata; validation does not authorize a caller-supplied registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryEntry<'a> {
    /// Exact ASCII bytes, without a terminator.
    pub label: &'a str,
    /// Operation class, separate from the label's byte identity.
    pub kind: LabelKind,
    /// Algebraic soundness line, in addition to the existing FS/H assumptions.
    pub loss: Option<LossLine>,
}
const REGISTRY: [RegistryEntry<'static>; 5] = [
    RegistryEntry {
        label: "stele/v0.1/public",
        kind: LabelKind::Constructor,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/instance",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/round",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/final",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/challenge",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::Sc),
    },
];

/// Validate names, uniqueness and accounting at the production registry boundary.
/// The public validator supports configuration controls; callers cannot replace REGISTRY.
pub fn validate_registry(entries: &[RegistryEntry<'_>]) -> Result<(), Error> {
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index]
            .iter()
            .any(|other| other.label == entry.label)
        {
            return Err(Error::DuplicateLabel);
        }
        if !(1..=255).contains(&entry.label.len())
            || !entry.label.is_ascii()
            || !entry.label.starts_with("stele/v0.1/")
        {
            return Err(Error::InvalidLabel);
        }
        if (entry.kind == LabelKind::Challenge) != entry.loss.is_some() {
            return Err(Error::InvalidAccounting);
        }
    }
    Ok(())
}

/// Return the fixed production registry only after its validation succeeds.
/// This is metadata, not an API for importing alternate labels or transcript state.
pub fn registry() -> Result<&'static [RegistryEntry<'static>; 5], Error> {
    validate_registry(&REGISTRY)?;
    Ok(&REGISTRY)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
