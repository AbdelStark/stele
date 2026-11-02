//! RFC-0023 §6: actual native Requant binding NC-0310.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0310() {
    stele_negative_controls::requant::run(310).expect("exact rejection in both fields");
}
