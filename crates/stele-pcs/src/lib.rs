//! Conditional Circle field sources and certificates, RFC-0010 A9.
//!
//! Certificate verification is conditional; functional openings and profiles remain separate.
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

extern crate alloc;
mod certificate;
mod preparation;
mod producer;
mod source;
pub use certificate::{verify_certificate, CertificateRecord, Failure, Usage, VerifiedCertificate};
pub use preparation::{PreparationWork, PreparedColumn, PreparedSource};
pub use producer::CertificateFailure;
pub use source::{Error, Parameters, ProofKind, Response, Source, Wire};
