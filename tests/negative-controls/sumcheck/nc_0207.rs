//! RFC-0006 A3: one-value production control NC-0207.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0207() {
    stele_negative_controls::zerocheck::run(207).expect("exact rejection in both fields");
}
