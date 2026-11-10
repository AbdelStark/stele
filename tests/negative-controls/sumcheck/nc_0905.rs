//! RFC-0013 A2 item 2: NC-0905.
#[test]
fn rejects_nc_0905() {
    stele_negative_controls::zk::run(905).expect("a changed mask final rejects");
}
