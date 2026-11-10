//! RFC-0013 A5 item 5a: NC-0916.
#[test]
fn rejects_nc_0916() {
    stele_negative_controls::zk::run(916).expect("a relation's solved mu fails the shared batch");
}
