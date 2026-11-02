//! RFC-0024 §6: one signed matmul final under a nonzero opposite factor.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0317() {
    stele_negative_controls::integer_linear::run(317).expect("exact rejection in both fields");
}
