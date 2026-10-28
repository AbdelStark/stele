//! RFC-0006 A3: one-value production control NC-0209.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0209() {
    stele_negative_controls::zerocheck::run(209).expect("exact rejection in both fields");
}
