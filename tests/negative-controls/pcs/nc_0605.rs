//! RFC-0007 A1 item 7: fused W opening serializes a row other than the retained row.
#[test]
fn rejects_nc_0605() {
    // (a) eq(r_j')^T M_W for r_j' != r_j, signed embedding.
    stele_negative_controls::matmul::run(605).expect("ValueMismatch in both fields");
}

#[test]
fn rejects_integer_linear_centered_opening_row() {
    // (b) offset embedding: centered B instead of the raw retained row.
    stele_negative_controls::integer_linear::run(605).expect("ValueMismatch in both fields");
}
