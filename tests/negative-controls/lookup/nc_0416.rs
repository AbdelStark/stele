//! RFC-0008 A5 §7: complete conditional lookup control NC-0416.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0416() {
    stele_negative_controls::lookup::run(416).expect("exact rejection in both fields");
}
