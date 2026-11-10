//! RFC-0008 A7: NC-0913.
#[test]
fn rejects_nc_0913() {
    stele_negative_controls::zk::run(913)
        .expect("a changed masked layer value fails the next step");
}
