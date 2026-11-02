//! RFC-0023 §6: actual native Requant binding NC-0309.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0309() {
    stele_negative_controls::requant::run(309).expect("exact rejection in both fields");
}
