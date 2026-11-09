//! RFC-0010 A3 items 8-9: NC-0612 under the actual version-2 consumers.
#[test]
fn rejects_nc_0612() {
    stele_negative_controls::pcs_expander::run(612).expect("every variant rejects as stated");
}
