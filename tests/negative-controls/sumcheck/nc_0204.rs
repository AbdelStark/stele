//! RFC-0006 A5: actual small-strategy original-value binding.
#[test]
fn rejects_nc_0204() {
    stele_negative_controls::small::run().expect("ClaimMismatch in both fields");
}
