//! RFC-0010 A9: actual native certificate control NC-0608.
#[test]
fn rejects_nc_0608() {
    stele_negative_controls::pcs::run(608)
        .expect("native certificate must reject the stated tamper");
}
