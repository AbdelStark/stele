//! RFC-0006 A1: one-value production control NC-0802.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0802() {
    stele_negative_controls::pcs_opening_continuation::run()
        .expect("opening response continuation");
    stele_negative_controls::sumcheck::run(802).expect("exact rejection in both fields");
    stele_negative_controls::batching::run(802).expect("instance-batch extension");
    stele_negative_controls::zerocheck::run(802).expect("zerocheck extension");
    stele_negative_controls::lookup::run(802).expect("complete lookup extension");
    stele_negative_controls::matmul::run(802).expect("closed matmul extension");
    stele_negative_controls::requant::run(802).expect("closed Requant extension");
}
