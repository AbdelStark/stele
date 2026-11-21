//! M31 scalar property suite (RFC-0003 §§1,6).
use stele_field::M31 as Scalar;
const P: u64 = (1 << 31) - 1;

#[path = "common/scalar.rs"]
mod scalar;

#[test]
fn matches_reference_integer_embedding_at_the_range_edges() {
    use stele_field::Field;
    // `from_i64` adds once inside (-p, p) and divides outside: both sides of each edge.
    let p = P as i64;
    for value in [
        0,
        1,
        -1,
        p - 1,
        p,
        p + 1,
        -(p - 1),
        -p,
        -(p + 1),
        i64::MAX,
        i64::MIN,
        1 << 40,
        -(1 << 40),
    ] {
        assert_eq!(
            i64::from(Scalar::from_i64(value).as_u32()),
            value.rem_euclid(p),
            "{value}"
        );
    }
}
