//! RFC-0007 A2: actual closed matmul control NC-0307.
#[test]
fn rejects_nc_0307() {
    stele_negative_controls::matmul::run(307).expect("actual consumer rejection in both fields");
}

#[test]
fn rejects_wrong_coefficient_at_actual_a7() {
    stele_negative_controls::matmul::run_coefficient()
        .expect("independent coefficient consumer in both fields");
}
