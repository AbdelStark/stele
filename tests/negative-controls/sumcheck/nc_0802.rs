//! RFC-0006 A1: one-value production control NC-0802.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0802() {
    stele_negative_controls::sumcheck::run(802).expect("exact rejection in both fields");
}
