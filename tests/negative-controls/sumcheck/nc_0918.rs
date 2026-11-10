//! RFC-0008 A7: NC-0918.
#[test]
fn rejects_nc_0918() {
    stele_negative_controls::zk::run(918).expect("a changed selector final is rejected");
}
