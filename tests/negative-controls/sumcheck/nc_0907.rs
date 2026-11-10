//! RFC-0013 A3: NC-0907.
#[test]
fn rejects_nc_0907() {
    stele_negative_controls::zk::run(907).expect("a substituted mask source moves alpha");
}
