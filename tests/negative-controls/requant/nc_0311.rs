//! RFC-0023 §6: actual native Requant binding NC-0311.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0311() {
    stele_negative_controls::requant::run(311).expect("exact rejection in both fields");
}
