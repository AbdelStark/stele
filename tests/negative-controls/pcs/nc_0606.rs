//! RFC-0010 A9: actual native certificate control NC-0606.
#[test]
fn rejects_nc_0606() {
    stele_negative_controls::pcs::run(606)
        .expect("native certificate must reject the stated tamper");
}
