//! RFC-0008 A5 §7: complete conditional lookup control NC-0419.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0419() {
    stele_negative_controls::lookup::run(419).expect("exact rejection in both fields");
}
