//! RFC-0006 A2: both-mode, both-field production control.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0206() {
    stele_negative_controls::batching::run(206).expect("exact rejection in both fields");
}
