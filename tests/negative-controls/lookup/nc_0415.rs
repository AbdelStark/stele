//! RFC-0008 A5 §7: complete conditional lookup control NC-0415.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0415() {
    stele_negative_controls::lookup::run(415).expect("exact rejection in both fields");
}
