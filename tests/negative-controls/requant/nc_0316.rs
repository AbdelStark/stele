//! RFC-0024 §6: one high-cap-only scalar A3 final.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0316() {
    stele_negative_controls::integer_linear::run(316).expect("exact rejection in both fields");
}
