//! RFC-0006 A4 §6: complete certified stacked controls.
#[test]
fn rejects_wrong_restored_point_at_actual_opening() {
    stele_negative_controls::stacked_certified::run_point().expect("NC-0211");
}
#[test]
fn rejects_substituted_verified_certificate_at_actual_opening() {
    stele_negative_controls::stacked_certified::run_root().expect("NC-0213");
}
