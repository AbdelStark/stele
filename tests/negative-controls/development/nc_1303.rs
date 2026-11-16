//! RFC-0026 §9: one noncanonical certificate row limb in an actual window proof.
#[test]
fn rejects_nc_1303() {
    stele_negative_controls::development_messages::run(1303).expect("NC-1303 must reject");
}
