//! RFC-0023 §6: actual native Requant binding NC-0314.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0314() {
    stele_negative_controls::requant::run(314).expect("exact rejection in both fields");
}
