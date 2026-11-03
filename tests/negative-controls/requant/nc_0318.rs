//! RFC-0024 §6: one raw original opening-row cell changed to its signed value.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0318() {
    stele_negative_controls::integer_linear::run(318).expect("exact rejection in both fields");
}
