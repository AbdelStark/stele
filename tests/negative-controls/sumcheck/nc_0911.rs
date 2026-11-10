//! RFC-0013 A5: NC-0911.
#[test]
fn rejects_nc_0911() {
    stele_negative_controls::zk::run(911)
        .expect("a changed claim-mask block does not authenticate");
}
