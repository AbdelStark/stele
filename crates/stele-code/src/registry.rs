//! Closed code registry and fail-closed PCS parameter resolution, RFC-0010 A1
//! (acceptance resolution) and RFC-0012 A7.
//!
//! Parameters are derived from a validated identity, never accepted as input. Only
//! RFC-0010 A14's Policy 2 is admitted, and only for the standard profile with QM31
//! or OM31 challenges; every other request fails closed.
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
    /// RFC-0026 A10: the development tier's Policy 2 counts, with `proven: false`.
    /// Ungated by `standard-unproven`, because it admits nothing (ADR-110).
    Development,
}

/// Admitted PCS parameters (RFC-0010 A14 item 6); constructed only by [`resolve_pcs`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProximityParams {
    /// Source policy byte (A14 item 1): always 2.
    pub policy: u8,
    /// Least q_c with `2^92·(N−e−1)^q_c ≤ N^q_c` (A14 item 2).
    pub certificate_queries: u16,
    /// Least q_o with `2^92·(N−D+e)^q_o ≤ N^q_o` (A14 item 2).
    pub opening_queries: u16,
    /// Grinding bits k_q of every certificate and opening column round (A14 item 3).
    pub column_grind_bits: u8,
    /// A14 item 6: true for standard under Policy 2; treaty is never admitted;
    /// false for the development tier (RFC-0026 A10), which claims no level.
    pub proven: bool,
}

/// RFC-0010 A14 item 2 column grinding bits k_q.
pub const POLICY2_COLUMN_GRIND_BITS: u8 = 16;
// RFC-0010 A14 item 2: (q_c, q_o) per Circle m (b = 1, b = 2) and v2 J (J−3).
const POLICY2_HALF: [(u16, u16); 30] = {
    let mut t = [(350, 158); 30];
    let head = [
        (92, 1),
        (222, 92),
        (222, 136),
        (308, 136),
        (308, 152),
        (339, 152),
        (339, 156),
        (347, 156),
        (347, 157),
        (350, 157),
    ];
    let mut i = 0;
    while i < head.len() {
        t[i] = head[i];
        i += 1;
    }
    t
};
const POLICY2_QUARTER: [(u16, u16); 29] = {
    let mut t = [(222, 92); 29];
    let head = [
        (92, 46),
        (222, 66),
        (222, 78),
        (222, 85),
        (222, 88),
        (222, 90),
        (222, 91),
    ];
    let mut i = 0;
    while i < head.len() {
        t[i] = head[i];
        i += 1;
    }
    t
};
const POLICY2_V2: [(u16, u16); 12] = [
    (339, 156),
    (8131, 4050),
    (9297, 4633),
    (9467, 4718),
    (9510, 4739),
    (9532, 4748),
    (9532, 4751),
    (9533, 4751),
    (9534, 4751),
    (9534, 4751),
    (9534, 4751),
    (9534, 4751),
];

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
/// (`FieldMismatch`). A standard request with QM31 or OM31 challenges returns the
/// RFC-0010 A14 Policy 2 parameters; every other request (treaty, M31 challenges,
/// v2 J = 15) fails closed with `UnsupportedParameters`. A development request
/// (RFC-0026 A10) returns the same counts with `proven: false`.
pub fn resolve_pcs(
    code_id: &[u8],
    field_degree: u8,
    profile: Profile,
) -> Result<ProximityParams, Error> {
    Encoder::from_code_id(code_id)?;
    if !matches!(field_degree, 1 | 4 | 8) {
        return Err(Error::FieldMismatch);
    }
    if profile == Profile::Treaty || field_degree == 1 {
        return Err(Error::UnsupportedParameters);
    }
    let proven = profile == Profile::Standard;
    // ADR-108: no production build resolves a standard profile before E8-05's
    // composed (C1)-(C3) check; tests and controls opt in with `standard-unproven`.
    // The development tier is not gated: it gets `proven: false` (ADR-110).
    if proven && cfg!(not(feature = "standard-unproven")) {
        return Err(Error::UnsupportedParameters);
    }
    // The factory validated the identity: Circle m <= 30 - b, v2 J in 3..=15.
    let (certificate_queries, opening_queries) = if code_id.len() == 21 {
        let m = usize::from(code_id[19]);
        if code_id[20] == 1 {
            POLICY2_HALF[m]
        } else {
            POLICY2_QUARTER[m]
        }
    } else {
        let j = usize::from(code_id[22]);
        *POLICY2_V2.get(j - 3).ok_or(Error::UnsupportedParameters)?
    };
    Ok(ProximityParams {
        policy: 2,
        certificate_queries,
        opening_queries,
        column_grind_bits: POLICY2_COLUMN_GRIND_BITS,
        proven,
    })
}

/// Check a registry export; anything but the exact compiled bytes is `InvalidRegistry`.
pub fn check_export(bytes: &[u8]) -> Result<(), Error> {
    if bytes == CATALOG_EXPORT.as_bytes() {
        Ok(())
    } else {
        Err(Error::InvalidRegistry)
    }
}
