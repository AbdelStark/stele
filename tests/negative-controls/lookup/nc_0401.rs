//! RFC-0008 A5 §7: complete conditional lookup control NC-0401.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0401() {
    stele_negative_controls::lookup::run(401).expect("exact rejection in both fields");
}
