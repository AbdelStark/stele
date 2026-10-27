//! RFC-0006 A1: one-value production control NC-0800.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0800() {
    stele_negative_controls::sumcheck::run(800).expect("exact rejection in both fields");
}
