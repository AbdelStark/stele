//! RFC-0012 A17 item 5: the column nonce is absorbed before the draws (NC-0808).
#[test]
fn rejects_nc_0808() {
    stele_negative_controls::pcs_policy2::run(808).expect("RootMismatch");
}
