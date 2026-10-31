//! RFC-0010 A9: actual native query control NC-0803.
#[test]
fn rejects_nc_0803() {
    stele_negative_controls::pcs::run(803).expect("native query binding must reject");
    stele_negative_controls::pcs_opening::run(803).expect("native opening must reject");
}
