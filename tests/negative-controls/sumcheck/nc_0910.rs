//! RFC-0013 A5, RFC-0026 A9: NC-0910.
#[test]
fn rejects_nc_0910() {
    stele_negative_controls::zk::run(910).expect("a matmul with a sent out~ has the wrong shape");
}
