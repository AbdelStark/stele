//! RFC-0006 A3: one-value production control NC-0208.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0208() {
    stele_negative_controls::zerocheck::run(208).expect("exact rejection in both fields");
}
