//! RFC-0008 A5 §7: complete conditional lookup control NC-0400.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0400() {
    stele_negative_controls::lookup::run(400).expect("exact rejection in both fields");
}
