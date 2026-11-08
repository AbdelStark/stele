//! RFC-0008 A2 item 2: plan admission control NC-0424, before any transcript work.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0424() {
    stele_negative_controls::lookup::run(424).expect("exact admission rejection");
}
