//! RFC-0007 A1 item 7: fused W opening serializes the wrong row B' that drove the sumcheck.
#[test]
fn rejects_nc_0305() {
    stele_negative_controls::matmul::run(305).expect("ColumnMismatch in both fields");
}
