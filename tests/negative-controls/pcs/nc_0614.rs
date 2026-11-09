//! RFC-0010 A6 item 4: NC-0614 storage-to-message expansion at the actual certificate.
#[test]
fn rejects_nc_0614() {
    stele_negative_controls::pcs_expander::run(614).expect("both expansion variants reject");
}
