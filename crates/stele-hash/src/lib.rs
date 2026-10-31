//! Canonical transcript and registry governed by RFC-0012 A1.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(feature = "wrapper"),
    doc = r#"
The wrapper permutation is absent unless explicitly enabled:
```compile_fail
use stele_hash::poseidon2::permute;
```
"#
)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;

/// Canonical Merkle authentication (RFC-0012 A3).
pub mod merkle;
mod pcs;

mod usage;
pub use usage::HashUsage;

use stele_field::{M31, OM31, QM31};

/// A transcript or registry validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Label bytes are not versioned ASCII of length 1..255.
    InvalidLabel,
    /// Two registered meanings have identical label bytes.
    DuplicateLabel,
    /// Only challenge labels may carry a soundness-accounting line.
    InvalidAccounting,
    /// Construction requires nonempty canonical public-input bytes.
    EmptyPublicInput,
    /// A frame length cannot be represented without truncation.
    LengthOverflow,
    /// Fewer than d canonical coefficients were found in 64 words; abort the proof.
    SamplingExhausted,
    /// A local work counter would overflow; abort before unrecorded work.
    UsageOverflow,
    /// Column domains must be powers of two in [2, 2^30].
    InvalidColumnDomain,
    /// All 64 outer column candidates were rejected; abort the attempt.
    ColumnSamplingExhausted,
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
    /// One ordered batching coefficient (RFC-0012 A4).
    Rlc,
    /// Certificate row-weight error, conditional on RFC-0010 A8/A9 hypotheses.
    PcsTensor,
    /// Certificate/opening column miss term, separate from FS/H (RFC-0012 A10).
    PcsQuery,
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
const REGISTRY: [RegistryEntry<'static>; 21] = [
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
    RegistryEntry {
        label: "stele/v0.1/sumcheck/batch",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/batch-final",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/batch-coefficient",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::Rlc),
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/zero",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/zero-weight",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::Sc),
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/zero-skip",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/sumcheck/zero-final",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/lookup/fraction",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/lookup/layer",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/lookup/gamma",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::Rlc),
    },
    RegistryEntry {
        label: "stele/v0.1/lookup/fold",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::Rlc),
    },
    RegistryEntry {
        label: "stele/v0.1/lookup/leaf",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/pcs/certificate-weight",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::PcsTensor),
    },
    RegistryEntry {
        label: "stele/v0.1/pcs/certificate-row",
        kind: LabelKind::Absorb,
        loss: None,
    },
    RegistryEntry {
        label: "stele/v0.1/pcs/certificate-column",
        kind: LabelKind::Challenge,
        loss: Some(LossLine::PcsQuery),
    },
    RegistryEntry {
        label: "stele/v0.1/pcs/certificate-columns",
        kind: LabelKind::Absorb,
        loss: None,
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
pub fn registry() -> Result<&'static [RegistryEntry<'static>; 21], Error> {
    validate_registry(&REGISTRY)?;
    Ok(&REGISTRY)
}

// RFC-0012 A1: only the two canonical extension fields can be challenge targets.
mod sealed {
    pub trait Target {
        const DEGREE: usize;
        fn from_limbs(limbs: [stele_field::M31; 8]) -> Self;
    }
}
/// Closed challenge targets: QM31 and OM31, selected from a verified profile.
///
/// ```compile_fail
/// use stele_hash::Transcript;
/// use stele_field::M31;
/// let transcript = Transcript::<M31>::new(b"public");
/// ```
pub trait ChallengeField: sealed::Target + stele_field::Field {}
impl sealed::Target for QM31 {
    const DEGREE: usize = 4;
    fn from_limbs(l: [M31; 8]) -> Self {
        Self(stele_field::CM31(l[0], l[1]), stele_field::CM31(l[2], l[3]))
    }
}
impl ChallengeField for QM31 {}
impl sealed::Target for OM31 {
    const DEGREE: usize = 8;
    fn from_limbs(l: [M31; 8]) -> Self {
        Self(
            QM31(stele_field::CM31(l[0], l[1]), stele_field::CM31(l[2], l[3])),
            QM31(stele_field::CM31(l[4], l[5]), stele_field::CM31(l[6], l[7])),
        )
    }
}
impl ChallengeField for OM31 {}

/// Closed message labels from RFC-0012 A1; public input is constructor-only.
#[derive(Clone, Copy, Debug)]
pub enum AbsorbLabel {
    /// Canonical instance description, encoded by the consuming protocol.
    Instance,
    /// Canonical sumcheck round polynomial.
    Round,
    /// Canonical final claims, before the next dependent challenge.
    Final,
    /// Complete ordered batch descriptor (A4).
    Batch,
    /// Complete batched final claims (A4).
    BatchFinal,
    /// Complete zerocheck descriptor (A5).
    Zero,
    /// Initial univariate skip polynomial (A5).
    ZeroSkip,
    /// Every original tensor slice final (A5).
    ZeroFinal,
    /// Conditional tree descriptor and roots (A9).
    Fraction,
    /// Tree id, level and current evaluation claims (A9).
    FractionLayer,
    /// Selected-product descriptor, sources and incoming claims (A9).
    FractionLeaf,
    /// Complete canonical certificate row before query sampling (A10).
    CertificateRow,
    /// Complete ordered response block before continuation (A10).
    CertificateColumns,
}
impl AbsorbLabel {
    fn entry(self) -> &'static RegistryEntry<'static> {
        &REGISTRY[match self {
            Self::Instance => 1,
            Self::Round => 2,
            Self::Final => 3,
            Self::Batch => 5,
            Self::BatchFinal => 6,
            Self::Zero => 8,
            Self::ZeroSkip => 10,
            Self::ZeroFinal => 11,
            Self::Fraction => 12,
            Self::FractionLayer => 13,
            Self::FractionLeaf => 16,
            Self::CertificateRow => 18,
            Self::CertificateColumns => 20,
        }]
    }
}
/// Closed random-challenge labels from RFC-0012 A1.
#[derive(Clone, Copy, Debug)]
pub enum ChallengeLabel {
    /// Sumcheck round challenge, accounted under SC plus FS/H.
    Sumcheck,
    /// Ordered batch coefficient, accounted under RLC plus FS/H (A4).
    BatchCoefficient,
    /// Zerocheck tail weight, SC phase 0 (A5).
    ZeroWeight,
    /// Pair combination after current claims (A9), RLC.
    FractionGamma,
    /// Child interpolation after all A1 finals (A9), RLC.
    FractionFold,
    /// Source-bound certificate row coordinate, PCS tensor term (A10).
    CertificateWeight,
    /// Full K draw for a certificate column attempt, PCS query term (A10).
    CertificateColumn,
}
impl ChallengeLabel {
    fn entry(self) -> &'static RegistryEntry<'static> {
        &REGISTRY[match self {
            Self::Sumcheck => 4,
            Self::BatchCoefficient => 7,
            Self::ZeroWeight => 9,
            Self::FractionGamma => 14,
            Self::FractionFold => 15,
            Self::CertificateWeight => 17,
            Self::CertificateColumn => 19,
        }]
    }
}

/// Deterministic BLAKE3 transcript with mandatory public-input absorption (RFC-0012 A1).
/// The caller validates the public input/profile and follows its protocol's message schedule.
/// No state import, alternate registry or external random-byte source is accepted.
pub struct Transcript<K: ChallengeField> {
    state: [u8; 32],
    usage: HashUsage,
    field: core::marker::PhantomData<K>,
}
impl<K: ChallengeField> Transcript<K> {
    /// Validate the fixed registry and absorb nonempty canonical public-input bytes.
    pub fn new(public: &[u8]) -> Result<Self, Error> {
        registry()?;
        if public.is_empty() {
            return Err(Error::EmptyPublicInput);
        }
        // A10: constructor errors have no transcript from which to observe work.
        // Preflight all frame lengths before the first hash; fresh counters fit.
        frame_lengths(REGISTRY[0].label.len(), public.len())?;
        let mut usage = HashUsage::default();
        usage.hashes(1)?;
        let initial = *blake3::hash(b"stele/v0.1/transcript/init").as_bytes();
        Ok(Self {
            state: *frame(&initial, 0, REGISTRY[0].label, public, &mut usage)?
                .finalize()
                .as_bytes(),
            usage,
            field: core::marker::PhantomData,
        })
    }
    /// Snapshot of this attempt's work, including work before an error.
    /// Observation does not authorize retry, continuation or a soundness budget.
    pub fn usage(&self) -> HashUsage {
        self.usage
    }
    /// Absorb a registered message; encoding/schedule checks belong to its consumer.
    pub fn absorb(&mut self, label: AbsorbLabel, bytes: &[u8]) -> Result<(), Error> {
        self.state = *frame(&self.state, 0, label.entry().label, bytes, &mut self.usage)?
            .finalize()
            .as_bytes();
        Ok(())
    }
    /// Sample exactly d canonical coefficients, then commit the result into the state.
    /// Errors leave the state unchanged; exhaustion requires aborting the proof attempt.
    pub fn challenge(&mut self, label: ChallengeLabel) -> Result<K, Error> {
        let degree = K::DEGREE as u8;
        let mut raw = [0; 256];
        frame(
            &self.state,
            1,
            label.entry().label,
            &[degree],
            &mut self.usage,
        )?
        .finalize_xof()
        .fill(&mut raw);
        let (limbs, consumed) = sample::<K>(&raw, &mut self.usage)?;
        let value = K::from_limbs(limbs);
        let canonical = value.to_le_bytes();
        let mut payload = [0; 37];
        payload[0] = degree;
        payload[1..5].copy_from_slice(&consumed.to_le_bytes());
        payload[5..5 + 4 * K::DEGREE].copy_from_slice(canonical.as_ref());
        // RFC-0012 A1/A10: errors preserve state, but not the work observations.
        self.state = *frame(
            &self.state,
            2,
            label.entry().label,
            &payload[..5 + 4 * K::DEGREE],
            &mut self.usage,
        )?
        .finalize()
        .as_bytes();
        Ok(value)
    }
}

fn frame(
    state: &[u8; 32],
    tag: u8,
    label: &str,
    payload: &[u8],
    usage: &mut HashUsage,
) -> Result<blake3::Hasher, Error> {
    let (label_length, payload_length) = frame_lengths(label.len(), payload.len())?;
    usage.add(if tag == 1 {
        HashUsage {
            xof_requests: 1,
            xof_bytes: 256,
            ..HashUsage::default()
        }
    } else {
        HashUsage {
            hash_evaluations: 1,
            state_updates: 1,
            ..HashUsage::default()
        }
    })?;
    let mut h = blake3::Hasher::new();
    for part in [
        state.as_slice(),
        &[tag],
        &label_length.to_le_bytes(),
        label.as_bytes(),
        &payload_length.to_le_bytes(),
        payload,
    ] {
        h.update(part);
    }
    Ok(h)
}

fn frame_lengths(label: usize, payload: usize) -> Result<(u32, u64), Error> {
    Ok((
        u32::try_from(label).map_err(|_| Error::LengthOverflow)?,
        u64::try_from(payload).map_err(|_| Error::LengthOverflow)?,
    ))
}

// RFC-0012 A1: pure decoder for forced-rejection tests, never an injectable RNG.
fn sample<K: ChallengeField>(
    raw: &[u8; 256],
    usage: &mut HashUsage,
) -> Result<([M31; 8], u32), Error> {
    let mut limbs = [M31::ZERO; 8];
    let mut accepted = 0;
    for (index, word) in raw.chunks_exact(4).enumerate() {
        usage.add(HashUsage {
            candidate_words: 1,
            ..HashUsage::default()
        })?;
        let candidate = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) & 0x7fff_ffff;
        if let Some(limb) = M31::from_canonical(candidate) {
            limbs[accepted] = limb;
            accepted += 1;
            if accepted == K::DEGREE {
                return Ok((limbs, (index + 1) as u32));
            }
        }
    }
    Err(Error::SamplingExhausted)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod transcript_tests;

#[cfg(test)]
mod usage_tests;

#[cfg(feature = "wrapper")]
pub mod poseidon2;
