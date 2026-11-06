//! Closed code registry and fail-closed PCS parameter resolution, RFC-0010 A1
//! (acceptance resolution) and RFC-0012 A7.
//!
//! Parameters are derived from a validated identity, never accepted as input. No
//! proximity radius, query count or profile is admitted yet (RFC-0010 A3, Q12), so
//! [`resolve_pcs`] has no success value: [`ProximityParams`] is uninhabited.
use super::{Code, Encoder, Error};

/// Immutable evidence identifier for the A2 Circle distance bound.
pub const CIRCLE_DISTANCE_EVIDENCE: &str = "rfc-0010-a2/root-bound-v1";
/// Immutable evidence identifier for the v2 finite expander distance bound.
pub const EXPANDER_DISTANCE_EVIDENCE: &str = "rfc-0010-a1/finite-v2";
/// Immutable evidence identifier for the A7 all-seed setup event.
pub const EXPANDER_SETUP_EVIDENCE: &str = "rfc-0012-a7/2^256-all-seeds-v2";
/// A7 event count: the setup loss is this numerator over 2^160.
pub const EXPANDER_SETUP_LOSS_NUMERATOR: u64 = 200_431_782;
/// A7 setup loss denominator exponent.
pub const EXPANDER_SETUP_LOSS_LOG2_DENOMINATOR: u32 = 160;

/// The registry export, byte for byte; `research/code-provenance/codes.toml` must equal it.
pub const CATALOG_EXPORT: &str = include_str!("registry/codes.toml");

/// Code parameters derived from a validated identity (RFC-0010 A1, code-identity.md §2).
///
/// These are symbol-distance and setup facts, not proximity radii or query counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeParameters {
    /// Number of message symbols.
    pub message_len: u64,
    /// Number of codeword symbols.
    pub codeword_len: u64,
    /// Certified minimum symbol distance lower bound under the evidence premises.
    pub distance_lower_bound: u64,
    /// Evidence identifier for the distance bound.
    pub distance_evidence: &'static str,
    /// Setup failure bound numerator (zero when no sampled setup is involved).
    pub setup_loss_numerator: u64,
    /// Setup failure bound denominator exponent: the loss is numerator / 2^this.
    pub setup_loss_log2_denominator: u32,
    /// Evidence identifier for the setup bound, when one is charged.
    pub setup_evidence: Option<&'static str>,
}

/// Inference profile requesting PCS parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Standard profile.
    Standard,
    /// Treaty profile.
    Treaty,
}

/// Admitted PCS parameters. No set is admitted, so no value of this type exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProximityParams {}

/// Derive the parameters of a validated code; the identity is the only authority.
pub fn parameters(code: &Encoder) -> CodeParameters {
    let id = code.code_id();
    let info = code.info();
    let (k, n) = (info.message_len, info.codeword_len);
    if id.len() == 21 {
        // Circle: N if k = 1, otherwise N - k (RFC-0010 A2).
        let distance = if k == 1 { n } else { n - k };
        return CodeParameters {
            message_len: k,
            codeword_len: n,
            distance_lower_bound: distance,
            distance_evidence: CIRCLE_DISTANCE_EVIDENCE,
            setup_loss_numerator: 0,
            setup_loss_log2_denominator: 0,
            setup_evidence: None,
        };
    }
    // Expander v2: the base-only size J = 3 is the circle base, with deterministic distance.
    let base_only = k == 64;
    CodeParameters {
        message_len: k,
        codeword_len: n,
        distance_lower_bound: if base_only { 64 } else { k / 25 + 1 },
        distance_evidence: EXPANDER_DISTANCE_EVIDENCE,
        setup_loss_numerator: if base_only {
            0
        } else {
            EXPANDER_SETUP_LOSS_NUMERATOR
        },
        setup_loss_log2_denominator: if base_only {
            0
        } else {
            EXPANDER_SETUP_LOSS_LOG2_DENOMINATOR
        },
        setup_evidence: if base_only {
            None
        } else {
            Some(EXPANDER_SETUP_EVIDENCE)
        },
    }
}

/// Resolve PCS parameters for a code identity, field degree and profile.
///
/// Validates the identity (`InvalidCodeId`) and field degree 1, 4 or 8
/// (`FieldMismatch`), then fails closed with `UnsupportedParameters`: no proximity
/// radius, exceptional-combination bound or query count is admitted (RFC-0010 A3, Q12).
pub fn resolve_pcs(
    code_id: &[u8],
    field_degree: u8,
    profile: Profile,
) -> Result<ProximityParams, Error> {
    let _ = (Encoder::from_code_id(code_id)?, profile);
    if !matches!(field_degree, 1 | 4 | 8) {
        return Err(Error::FieldMismatch);
    }
    Err(Error::UnsupportedParameters)
}

/// Check a registry export; anything but the exact compiled bytes is `InvalidRegistry`.
pub fn check_export(bytes: &[u8]) -> Result<(), Error> {
    if bytes == CATALOG_EXPORT.as_bytes() {
        Ok(())
    } else {
        Err(Error::InvalidRegistry)
    }
}
