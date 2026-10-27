//! RFC-0006 A1: one-value production control NC-0205.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0205() {
    stele_negative_controls::sumcheck::run(205).expect("exact rejection in both fields");
}
