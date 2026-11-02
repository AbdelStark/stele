//! RFC-0024 §6: original byte authority is required for X and W under zero factors.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0315() {
    stele_negative_controls::lookup::run(315).expect("exact false-byte rejection in both fields");
}
