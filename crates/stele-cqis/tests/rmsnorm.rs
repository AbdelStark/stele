//! RFC-0021 §2.3,§6: exact RMSNorm arithmetic, not inference or a field proof.
use stele_cqis::functions::{Descriptor, NormError};

fn descriptor(d: u16, f: u8, g: u8, e: u8, en: u32, ed: u32) -> Descriptor {
    let mut p = d.to_le_bytes().to_vec();
    p.extend([f, g, e]);
    p.extend(en.to_le_bytes());
    p.extend(ed.to_le_bytes());
    Descriptor::new("rmsnorm_q", 1, &p).expect("norm descriptor")
}

#[test]
fn accepts_zero_endpoint_and_preserved_normalization_remainders() {
    let f = descriptor(3, 8, 14, 8, 1, 100000);
    let row = f
        .evaluate_rmsnorm(&[256, 256, 1], &[16384; 3])
        .expect("row");
    assert_eq!(row.statistic(), 131073);
    let (a, d, r) = row.normalized_ratio();
    assert_eq!(a, u128::from(row.mantissa()) * d + r);
    assert!(0 < r && r < d);
    let zero = f.evaluate_rmsnorm(&[0; 3], &[i16::MIN; 3]).expect("zero");
    assert_eq!(zero.outputs(), &[0; 3]);
    let edge = descriptor(1, 8, 14, 8, 1, 100000)
        .evaluate_rmsnorm(&[i16::MIN], &[i16::MIN])
        .expect("wide product");
    assert_eq!(edge.reciprocal(), 16384);
    assert_eq!(edge.outputs(), &[512]);
    let tiny = descriptor(1, 30, 30, 0, u32::MAX, 1)
        .evaluate_rmsnorm(&[i16::MIN], &[i16::MIN])
        .expect("wide shift");
    assert_eq!(tiny.shift(), 89);
    assert_eq!(tiny.outputs(), &[0]);
    let left = descriptor(4, 0, 0, 14, 1, u32::MAX)
        .evaluate_rmsnorm(&[-1, 0, 0, 0], &[1, 0, 0, 0])
        .expect("exact negative shift");
    assert_eq!(left.shift(), -1);
    assert_eq!(left.outputs(), &[i16::MIN, 0, 0, 0]);
}

#[test]
fn rejects_wrong_function_shapes_and_whole_row_overflow() {
    let f = descriptor(2, 0, 0, 14, 1, 100000);
    let input = [0, 32767];
    let gains = [0, 32767];
    assert_eq!(f.evaluate_rmsnorm(&input, &gains), Err(NormError::Overflow));
    assert_eq!(input, [0, 32767]);
    assert_eq!(gains, [0, 32767]);
    assert_eq!(f.evaluate_rmsnorm(&[], &[]), Err(NormError::Shape));
    assert_eq!(f.evaluate_rmsnorm(&input, &[0]), Err(NormError::Shape));
    assert_eq!(
        Descriptor::new("range_8", 1, &[])
            .expect("other function")
            .evaluate_rmsnorm(&[], &[]),
        Err(NormError::Function)
    );
}

#[test]
fn accepts_maximum_shape_and_parameter_boundaries() {
    let input = vec![i16::MIN; 16384];
    for (f, g, e, en, ed) in [(0, 30, 0, u32::MAX, 1), (30, 30, 14, 1, u32::MAX)] {
        let row = descriptor(16384, f, g, e, en, ed)
            .evaluate_rmsnorm(&input, &input)
            .expect("bounded exact arithmetic");
        assert_eq!(row.statistic(), 1 << 44);
        assert_eq!(row.outputs().len(), 16384);
        let (a, d, r) = row.normalized_ratio();
        assert_eq!(a, u128::from(row.mantissa()) * d + r);
        assert!(r < d);
    }
}
