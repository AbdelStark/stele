//! Tower checks against a schoolbook power-basis oracle (RFC-0003 §2, A1).
use stele_field::{Field, Inverse, Serialize, CM31, OM31, QM31};
const P: u64 = (1 << 31) - 1;
const CASES: usize = 1_000_000;

fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

// Independent bases: i; u with i=u^2-2; v with u=v^2 and i=v^4-2.
fn to_power(limbs: &[u64]) -> Vec<u64> {
    let n = limbs.len();
    if n == 2 {
        return limbs.to_vec();
    }
    let mut out = vec![0; n];
    for k in 0..n / 2 {
        let index = if n == 4 { k } else { 2 * (k % 2) + k / 2 };
        out[index] = (limbs[2 * k] + 2 * P - 2 * limbs[2 * k + 1]) % P;
        out[index + n / 2] = limbs[2 * k + 1];
    }
    out
}

fn multiply(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len();
    let mut c = vec![0u64; 2 * n - 1];
    for i in 0..n {
        for j in 0..n {
            c[i + j] = ((u128::from(c[i + j]) + u128::from(a[i]) * u128::from(b[j]))
                % u128::from(P)) as u64;
        }
    }
    for i in (n..c.len()).rev() {
        let value = c[i];
        if n == 2 {
            c[i - n] = (c[i - n] + P - value) % P;
        } else {
            c[i - n] = (c[i - n] + 5 * P - 5 * value) % P;
            c[i - n / 2] = (c[i - n / 2] + 4 * value) % P;
        }
    }
    c.truncate(n);
    c
}

fn power(mut a: Vec<u64>, mut e: u64) -> Vec<u64> {
    let mut out = vec![0; a.len()];
    out[0] = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = multiply(&out, &a);
        }
        a = multiply(&a, &a);
        e >>= 1;
    }
    out
}

fn limbs(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(4)
        .map(|x| u64::from(u32::from_le_bytes(x.try_into().expect("four bytes"))))
        .collect()
}

macro_rules! suite {
    ($module:ident, $field:ty, $n:expr) => {
        mod $module {
            use super::*;
            type F = $field;
            fn random(seed: &mut u64) -> F {
                let mut bytes = [0; $n * 4];
                for chunk in bytes.chunks_exact_mut(4) {
                    chunk.copy_from_slice(&((next(seed) % P) as u32).to_le_bytes());
                }
                F::from_le_bytes(bytes).expect("canonical limbs")
            }
            fn poly(a: F) -> Vec<u64> {
                to_power(&limbs(&a.to_le_bytes()))
            }

            #[test]
            #[allow(clippy::eq_op)] // Commutativity is under test.
            fn matches_reference_million_tower_cases() {
                let images: Vec<_> = (0..$n)
                    .map(|i| {
                        let mut basis = vec![0; $n];
                        basis[i] = 1;
                        power(basis, P)
                    })
                    .collect();
                let mut seed = 0x5354_454c_4500_0003;
                for _ in 0..CASES {
                    let a = random(&mut seed);
                    let b = random(&mut seed);
                    let c = random(&mut seed);
                    assert_eq!(poly(a * b), multiply(&poly(a), &poly(b)));
                    assert_eq!(a + b, b + a);
                    assert_eq!(a * b, b * a);
                    assert_eq!((a + b) + c, a + (b + c));
                    assert_eq!((a * b) * c, a * (b * c));
                    assert_eq!(a * (b + c), a * b + a * c);
                    assert_eq!((a - b) + b, a);
                    assert_eq!(a + (-a), F::ZERO);
                    assert_eq!(a + F::ZERO, a);
                    assert_eq!(a * F::ONE, a);
                    assert_eq!(a * F::ZERO, F::ZERO);
                    if a != F::ZERO {
                        let inv = a.inverse().expect("nonzero tower element");
                        assert_eq!(multiply(&poly(a), &poly(inv)), poly(F::ONE));
                    }
                    let input = poly(a);
                    let expected: Vec<_> = (0..$n)
                        .map(|j| {
                            (input
                                .iter()
                                .zip(&images)
                                .map(|(x, im)| u128::from(*x) * u128::from(im[j]))
                                .sum::<u128>()
                                % u128::from(P)) as u64
                        })
                        .collect();
                    assert_eq!(poly(a.frobenius()), expected);
                    assert_eq!(F::from_le_bytes(a.to_le_bytes()), Some(a));
                    let signed = (next(&mut seed) % P) as i64 - (P / 2) as i64;
                    assert_eq!(F::from_i64(signed).to_i64_signed(), Some(signed));
                }
            }

            #[test]
            fn rejects_noncanonical_limbs_and_nonconstant_signed_recovery() {
                for index in 0..$n {
                    let mut bytes = [0; $n * 4];
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&(P as u32).to_le_bytes());
                    assert_eq!(F::from_le_bytes(bytes), None);
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&1u32.to_le_bytes());
                    let value = F::from_le_bytes(bytes).expect("basis element");
                    assert_eq!(
                        value.to_i64_signed(),
                        if index == 0 { Some(1) } else { None }
                    );
                    assert_eq!(value.frobenius(), value.pow(u128::from(P)));
                    let mut conjugate = value;
                    for _ in 0..$n {
                        conjugate = conjugate.frobenius();
                    }
                    assert_eq!(conjugate, value);
                }
                assert_eq!(F::ZERO.inverse(), None);
                assert_eq!(F::ZERO.pow(0), F::ONE);
                assert_eq!(F::ZERO.pow(1), F::ZERO);
            }
        }
    };
}
suite!(cm31, CM31, 2);
suite!(qm31, QM31, 4);
suite!(om31, OM31, 8);

#[test]
fn accepts_irreducible_tower_moduli() {
    use stele_field::M31;
    let i = CM31(M31::ZERO, M31::ONE);
    let t = CM31(M31::from_i64(2), M31::ONE);
    let u = QM31(CM31::ZERO, CM31::ONE);
    let v = OM31(QM31::ZERO, QM31::ONE);
    assert_eq!(i * i, -CM31::ONE);
    assert_eq!(u * u, QM31(t, CM31::ZERO));
    assert_eq!(v * v, OM31(u, QM31::ZERO));
    assert_eq!(t.pow((u128::from(P).pow(2) - 1) / 2), -CM31::ONE);
    assert_eq!(u.pow((u128::from(P).pow(4) - 1) / 2), -QM31::ONE);
    assert_ne!(
        QM31::from_i64(4).pow((u128::from(P).pow(4) - 1) / 2),
        -QM31::ONE
    );
}

#[test]
fn matches_reference_canonical_basis_order() {
    use stele_field::M31;
    let pair = |a, b| CM31(M31::from_i64(a), M31::from_i64(b));
    let value = OM31(QM31(pair(1, 2), pair(3, 4)), QM31(pair(5, 6), pair(7, 8)));
    assert_eq!(limbs(&value.to_le_bytes()), (1..=8).collect::<Vec<_>>());
    assert_eq!(limbs(&value.0.to_le_bytes()), (1..=4).collect::<Vec<_>>());
    assert_eq!(limbs(&value.0 .0.to_le_bytes()), vec![1, 2]);
}
