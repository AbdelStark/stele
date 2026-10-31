//! RFC-0010 A9 §5: an unused original still requires its actual opening.
#[test]
fn rejects_unused_original_final() {
    stele_negative_controls::pcs_a1::run().expect("unused final rejects at its opening");
}
