//! RFC-0006 A1: one-value production control NC-0200.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0200() {
    stele_negative_controls::sumcheck::run(200).expect("exact rejection in both fields");
}
