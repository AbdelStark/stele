//! RFC-0008 A5 §7: complete conditional lookup control NC-0418.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0418() {
    stele_negative_controls::lookup::run(418).expect("exact rejection in both fields");
}
