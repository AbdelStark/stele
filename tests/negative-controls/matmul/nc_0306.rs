//! RFC-0007 A2: actual closed matmul control NC-0306.
#[test]
fn rejects_nc_0306() {
    stele_negative_controls::matmul::run(306).expect("actual consumer rejection in both fields");
}

#[test]
fn rejects_integer_linear_wrong_source_point() {
    stele_negative_controls::integer_linear::run(306).expect("both centered original points");
}
