//! RFC-0010 A9 §4: scalar binding with all other proof bytes unchanged.
#[test]
fn rejects_nc_0610() {
    stele_negative_controls::pcs_opening::run(610).expect("wrong scalar must reject");
}
