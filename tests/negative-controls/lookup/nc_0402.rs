//! RFC-0008 A5 §7: complete conditional lookup control NC-0402.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0402() {
    stele_negative_controls::lookup::run(402).expect("exact rejection in both fields");
}
