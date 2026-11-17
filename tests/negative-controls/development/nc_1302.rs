//! RFC-0026 §§2.3, 4, 9: composed NC-1302 on actual L0/L1 window proofs.
#[test]
fn rejects_nc_1302() {
    let control = stele_negative_controls::CONTROLS
        .iter()
        .find(|control| control.id == 1302)
        .expect("NC-1302 must be registered");
    assert_eq!((control.run)(), Ok(()), "NC-1302 must reject exactly");
}
