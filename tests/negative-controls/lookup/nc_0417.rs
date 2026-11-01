//! RFC-0008 A5 §7: complete conditional lookup control NC-0417.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0417() {
    stele_negative_controls::lookup::run(417).expect("exact rejection in both fields");
}
