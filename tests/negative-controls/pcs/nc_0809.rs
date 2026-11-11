//! RFC-0010 A14 item 2: a query count below the Policy 2 count (NC-0809).
#[test]
fn rejects_nc_0809() {
    stele_negative_controls::pcs_policy2::run(809).expect("ProofShape");
}
