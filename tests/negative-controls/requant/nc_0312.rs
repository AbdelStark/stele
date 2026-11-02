//! RFC-0023 §6: actual native Requant binding NC-0312.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0312() {
    stele_negative_controls::requant::run(312).expect("exact rejection in both fields");
}
