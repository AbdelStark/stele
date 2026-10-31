//! RFC-0010 A9: actual native query control NC-0601.
#[test]
fn rejects_nc_0601() {
    stele_negative_controls::pcs::run(601).expect("native query binding must reject");
    stele_negative_controls::pcs_opening::run(601).expect("native opening must reject");
}
