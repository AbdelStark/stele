//! RFC-0013 A2 item 1: NC-0906, a producer refusal.
#[test]
fn rejects_nc_0906() {
    stele_negative_controls::zk::run(906)
        .expect("a second opening of one hiding source is refused");
}
