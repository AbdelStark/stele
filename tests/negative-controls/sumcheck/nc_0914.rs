//! RFC-0008 A7: NC-0914.
#[test]
fn rejects_nc_0914() {
    stele_negative_controls::zk::run(914).expect("a changed layer block does not authenticate");
}
