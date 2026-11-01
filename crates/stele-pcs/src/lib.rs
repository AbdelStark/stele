//! Conditional Circle field sources, certificates and functional openings, RFC-0010 A9/A10.
//!
//! Verification retains conditional obligations; A1 closure and profiles remain separate.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
mod certificate;
mod opening;
mod preparation;
mod producer;
mod source;
mod work;
pub use certificate::{
    verify_certificate, verify_certificate_measured, CertificateRecord, Failure, Usage,
    VerifiedCertificate,
};
pub use opening::{
    verify_opening, verify_opening_measured, verify_point, verify_point_measured, Functional,
    OpeningRecord, RetainedRow, RetainedRowWork,
};
pub use preparation::{PreparationWork, PreparedColumn, PreparedSource};
pub use producer::CertificateFailure;
pub use source::{Error, Parameters, ProofKind, Response, Source, Wire};
pub use stele_code::CodeField;
pub use work::{ProverWork, VerifierWork};
