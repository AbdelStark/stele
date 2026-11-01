//! RFC-0007 A2: actual closed matmul control NC-0611.
#[test]
fn rejects_nc_0611() {
    stele_negative_controls::matmul::run(611).expect("actual consumer rejection in both fields");
}
