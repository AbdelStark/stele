//! RFC-0006 A4: actual coefficient, original-coordinate and frame consumers.
#[test]
fn rejects_wrong_layer_coefficient() {
    stele_negative_controls::stacked::run(203).expect("NC-0203");
}
#[test]
fn rejects_changed_onehot_and_exact_table_source() {
    stele_negative_controls::stacked::run(212).expect("NC-0212");
}
#[test]
fn rejects_unused_original_at_draw_order_point() {
    stele_negative_controls::stacked::run_public_original().expect("public NC-0211 variant");
}
#[test]
fn rejects_missing_stack_or_sources_before_successor() {
    stele_negative_controls::stacked::run_continuation().expect("NC-0802 stacked frames");
}
