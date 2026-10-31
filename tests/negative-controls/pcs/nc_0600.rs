//! RFC-0010 A9: actual native certificate control NC-0600.
#[test]
fn rejects_nc_0600() {
    stele_negative_controls::pcs::run(600)
        .expect("native certificate must reject the stated tamper");
}
