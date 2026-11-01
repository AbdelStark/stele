//! RFC-0008 A5 §7: complete conditional lookup control NC-0403.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0403() {
    stele_negative_controls::lookup::run(403).expect("exact rejection in both fields");
}
