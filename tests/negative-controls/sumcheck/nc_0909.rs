//! RFC-0013 A5: NC-0909.
#[test]
fn rejects_nc_0909() {
    stele_negative_controls::zk::run(909).expect("a changed masked claim fails its batch");
}
