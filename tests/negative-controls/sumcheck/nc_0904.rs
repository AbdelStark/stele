//! RFC-0013 A2 item 2: NC-0904.
#[test]
fn rejects_nc_0904() {
    stele_negative_controls::zk::run(904).expect("a changed mask sum rejects at the first round");
}
