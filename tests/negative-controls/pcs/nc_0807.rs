//! RFC-0010 A14 / RFC-0012 A17: a k_q - 1 prover under the k_q context (NC-0807).
#[test]
fn rejects_nc_0807() {
    stele_negative_controls::pcs_policy2::run(807).expect("GrindMismatch");
}
