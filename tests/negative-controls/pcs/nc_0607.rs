//! RFC-0010 A9: actual native certificate control NC-0607.
#[test]
fn rejects_nc_0607() {
    stele_negative_controls::pcs::run(607)
        .expect("native certificate must reject the stated tamper");
}
