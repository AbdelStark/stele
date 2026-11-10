//! RFC-0008 A7: NC-0919.
#[test]
fn rejects_nc_0919() {
    stele_negative_controls::zk::run(919).expect("a top h other than p/q is rejected");
}
