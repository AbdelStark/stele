//! RFC-0010 A6 item 4: NC-0603 through the actual RFC-0024 §1.1 byte-range verifier.
#[test]
fn rejects_nc_0603() {
    stele_negative_controls::lookup::run(603)
        .expect("byte-range verifier must reject the decomposition-preserving pair");
}
