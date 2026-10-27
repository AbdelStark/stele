//! RFC-0006 A2: instance-mode control; full two-mode credit awaits E3-02 completion.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0202() {
    stele_negative_controls::batching::run(202).expect("exact rejection in both fields");
}
