//! RFC-0013 A2, RFC-0010 A14: NC-0902.
#[test]
fn rejects_nc_0902() {
    stele_negative_controls::zk::run(902).expect("one changed salt byte rejects as RootMismatch");
}
