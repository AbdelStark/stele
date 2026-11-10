//! RFC-0013 A5: NC-0915.
#[test]
fn rejects_nc_0915() {
    stele_negative_controls::zk::run(915).expect("batch weight on the mask rows fails the final");
}
