//! RFC-0023 §6: actual native Requant binding NC-0312.
#![forbid(unsafe_code)]
#[test]
fn rejects_nc_0312() {
    stele_negative_controls::requant::run(312).expect("exact rejection in both fields");
}

#[test]
fn rejects_integer_linear_wrong_output_plane() {
    stele_negative_controls::integer_linear::run(312).expect("embedded physical output plane");
}
