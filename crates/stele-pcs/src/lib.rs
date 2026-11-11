//! Conditional Circle and v2 field sources, certificates and functional openings,
//! RFC-0010 A3/A6/A9/A10/A15, with RFC-0013 A2 hiding sources.
//!
//! Verification retains conditional obligations; A1 closure and profiles remain separate.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
mod certificate;
mod expansion;
mod hiding;
mod opening;
mod preparation;
mod producer;
mod source;
mod work;
pub use certificate::{
    verify_certificate, verify_certificate_measured, CertificateRecord, Failure, Usage,
    VerifiedCertificate,
};
pub use expansion::{expand, Embedding, Value};
pub use hiding::hiding_message;
pub use opening::{
    verify_opening, verify_opening_measured, verify_point, verify_point_measured, Functional,
    OpeningRecord, RetainedRow, RetainedRowWork,
};
pub use preparation::{PreparationWork, PreparedColumn, PreparedSource};
pub use producer::CertificateFailure;
pub use source::{Error, Parameters, Policy, ProofKind, Response, Source, SourceBytes, Wire};
// A1 registry validator: stele-code is reachable only through this crate (deny.toml).
pub use stele_code::{registry, CodeField};
pub use work::{ProverWork, VerifierWork};
