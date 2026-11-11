//! RFC-0010 A14 / RFC-0012 A17: Policy 2 nonces failing the predicate (NC-0806).
#[test]
fn rejects_nc_0806() {
    stele_negative_controls::pcs_policy2::run(806).expect("GrindMismatch");
}
