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
pub use certificate::{verify_certificate, CertificateRecord, Failure, Usage, VerifiedCertificate};
pub use opening::{
    verify_opening, verify_point, Functional, OpeningRecord, RetainedRow, RetainedRowWork,
};
pub use preparation::{PreparationWork, PreparedColumn, PreparedSource};
pub use producer::CertificateFailure;
pub use source::{Error, Parameters, ProofKind, Response, Source, Wire};
pub use stele_code::CodeField;
