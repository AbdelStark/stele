//! RFC-0023 §6: actual native Requant binding NC-0308.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0308() {
    stele_negative_controls::requant::run(308).expect("exact rejection in both fields");
}
