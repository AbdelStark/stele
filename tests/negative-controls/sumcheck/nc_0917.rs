//! RFC-0008 A7: NC-0917.
#[test]
fn rejects_nc_0917() {
    stele_negative_controls::zk::run(917).expect("a changed head final is rejected");
}
