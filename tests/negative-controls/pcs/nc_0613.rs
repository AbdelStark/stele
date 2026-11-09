//! RFC-0010 A3 item 9: NC-0613 rejects before any transcript work.
#[test]
fn rejects_nc_0613() {
    stele_negative_controls::pcs_expander::run(613).expect("unsupported v2 source rejects");
}
