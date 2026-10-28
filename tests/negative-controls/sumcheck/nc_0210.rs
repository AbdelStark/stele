//! RFC-0006 A6: one changed source value, unchanged original public consumer.
#[test]
fn rejects_nc_0210() {
    stele_negative_controls::streaming::run().expect("actual file-source control");
}
