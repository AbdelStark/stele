//! RFC-0013 A2, RFC-0010 A14: NC-0903.
#[test]
fn rejects_nc_0903() {
    stele_negative_controls::zk::run(903).expect("a version-3 context outside admission rejects");
}
