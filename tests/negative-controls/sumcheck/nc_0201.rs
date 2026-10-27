//! RFC-0006 A1: one-value production control NC-0201.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0201() {
    stele_negative_controls::sumcheck::run(201).expect("exact rejection in both fields");
}
