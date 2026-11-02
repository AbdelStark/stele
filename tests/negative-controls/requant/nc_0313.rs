//! RFC-0023 §6: actual native Requant binding NC-0313.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0313() {
    stele_negative_controls::requant::run(313).expect("exact rejection in both fields");
}
