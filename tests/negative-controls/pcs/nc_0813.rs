//! RFC-0010 A14 item 4 / RFC-0012 A17: the tensor nonce is absorbed (NC-0813).
#[test]
fn rejects_nc_0813() {
    stele_negative_controls::pcs_policy2::run(813).expect("GrindMismatch");
}
