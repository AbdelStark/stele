//! RFC-0026 §4 step 6, §9: one changed matmul output claim in an actual window proof.
#[test]
fn rejects_nc_1307() {
    stele_negative_controls::development_messages::run(1307).expect("NC-1307 must reject");
}
