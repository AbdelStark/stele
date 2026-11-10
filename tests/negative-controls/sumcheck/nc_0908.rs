//! RFC-0013 A3: NC-0908.
#[test]
fn rejects_nc_0908() {
    stele_negative_controls::zk::run(908).expect("a forged mask final fails the mask opening");
}
