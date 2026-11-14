//! E8-02c parity for the Circle code. The checks are:
//! - the twelve shared canonical vectors, which `stele-code`'s own test and
//!   `research/circle-code/check_circle.py` also check;
//! - the RFC-0010 A2 basis evaluated point by point (`direct`, the same formula as the
//!   Python vector generator, so not an independent formulation), for `m ≤ 7` at both
//!   rates;
//! - a matrix-solve oracle: interpolation by Gaussian elimination over M31, then
//!   evaluation in the basis, for `m ≤ 5` at both rates. It shares no step with the
//!   transforms;
//! - extension elements encoded limb by limb;
//! - the size and field rules.
use stele_field::{Field, KoalaBear, Serialize, M31, QM31};
use stele_verifier::circle::{Circle, Error};

const P: u64 = (1 << 31) - 1;

fn m31(x: u64) -> M31 {
    M31::from_i64((x % P) as i64)
}

fn mul(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    (
        (a.0 * b.0 + (P - a.1) * b.1) % P,
        (a.0 * b.1 + a.1 * b.0) % P,
    )
}

fn power(mut a: (u64, u64), mut n: u64) -> (u64, u64) {
    let mut r = (1, 0);
    while n > 0 {
        if n & 1 == 1 {
            r = mul(r, a);
        }
        a = mul(a, a);
        n >>= 1;
    }
    r
}

/// The coset point `g^{(2i+1)·2^(30−log)}`.
fn point(log: u32, i: u64) -> (u64, u64) {
    power((1_717_986_917, 1_288_490_189), (2 * i + 1) << (30 - log))
}

/// `Σ_j c_j · Π_{bit k of j} f_k(x, y)` with `f_0 = y`, `f_1 = x`, `f_k = π^{k−1}(x)`.
fn direct(coefficients: &[u64], (x, y): (u64, u64)) -> u64 {
    let bits = coefficients.len().trailing_zeros() as usize;
    let mut factors = vec![y];
    let mut x = x;
    for _ in 1..bits {
        factors.push(x);
        x = (2 * x * x + P - 1) % P;
    }
    let mut total = 0;
    for (j, c) in coefficients.iter().enumerate() {
        let mut v = *c;
        for (k, f) in factors.iter().enumerate() {
            if (j >> k) & 1 == 1 {
                v = v * f % P;
            }
        }
        total = (total + v) % P;
    }
    total
}

#[test]
fn matches_reference_shared_circle_vectors() {
    let parse = |s: &str| -> Vec<M31> {
        s.split(',')
            .map(|v| m31(v.parse().expect("value")))
            .collect()
    };
    let mut count = 0;
    for line in include_str!("../../../research/circle-code/vectors.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let code = Circle::new(f[0].parse().expect("m"), f[1].parse().expect("b")).expect("code");
        assert_eq!(
            code.encode(&parse(f[2])).expect("encode"),
            parse(f[3]),
            "{line}"
        );
        count += 1;
    }
    assert_eq!(count, 12);
}

#[test]
fn matches_direct_evaluation_of_the_basis() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % P
    };
    for m in 0..=7u32 {
        let coefficients: Vec<u64> = (0..1u64 << m).map(|_| next()).collect();
        let row: Vec<M31> = (0..1u64 << m)
            .map(|i| m31(direct(&coefficients, point(m, i))))
            .collect();
        for b in 1..=2 {
            let word: Vec<M31> = (0..1u64 << (m + b))
                .map(|i| m31(direct(&coefficients, point(m + b, i))))
                .collect();
            let code = Circle::new(m, b).expect("code");
            assert_eq!(code.encode(&row).expect("encode"), word, "m {m} b {b}");
            let columns = [0, word.len() - 1, word.len() / 2, 0];
            assert_eq!(
                code.eval_row(&row, &columns).expect("columns"),
                columns.iter().map(|c| word[*c]).collect::<Vec<_>>()
            );
        }
    }
}

/// `a^(p−2)`, the inverse of a nonzero `a` modulo p.
fn inverse(a: u64) -> u64 {
    let (mut r, mut b, mut e) = (1u64, a % P, P - 2);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % P;
        }
        b = b * b % P;
        e >>= 1;
    }
    r
}

/// Solve `B·c = r` modulo p by Gauss–Jordan elimination; `B` is square and invertible.
fn solve(mut b: Vec<Vec<u64>>, mut r: Vec<u64>) -> Vec<u64> {
    let n = r.len();
    for col in 0..n {
        let pivot = (col..n).find(|&i| b[i][col] != 0).expect("invertible");
        b.swap(col, pivot);
        r.swap(col, pivot);
        let inv = inverse(b[col][col]);
        for j in 0..n {
            b[col][j] = b[col][j] * inv % P;
        }
        r[col] = r[col] * inv % P;
        for i in 0..n {
            if i != col && b[i][col] != 0 {
                let f = b[i][col];
                for j in 0..n {
                    b[i][j] = (b[i][j] + P - f * b[col][j] % P) % P;
                }
                r[i] = (r[i] + P - f * r[col] % P) % P;
            }
        }
    }
    r
}

#[test]
fn matches_matrix_solve_interpolation() {
    for m in 0..=5u32 {
        let n = 1usize << m;
        let unit = |j: usize| -> Vec<u64> { (0..n).map(|k| u64::from(k == j)).collect() };
        // B[i][j] is basis function j at the i-th point of D_m.
        let basis: Vec<Vec<u64>> = (0..n as u64)
            .map(|i| (0..n).map(|j| direct(&unit(j), point(m, i))).collect())
            .collect();
        let row: Vec<u64> = (0..n as u64).map(|i| (i * i * 7919 + 13) % P).collect();
        let coefficients = solve(basis, row.clone());
        for b in 1..=2 {
            let word: Vec<M31> = (0..1u64 << (m + b))
                .map(|i| m31(direct(&coefficients, point(m + b, i))))
                .collect();
            let row: Vec<M31> = row.iter().map(|v| m31(*v)).collect();
            assert_eq!(
                Circle::new(m, b)
                    .expect("code")
                    .encode(&row)
                    .expect("encode"),
                word,
                "m {m} b {b}"
            );
        }
    }
}

#[test]
fn encodes_extension_elements_limb_by_limb() {
    let code = Circle::new(4, 2).expect("code");
    let row: Vec<QM31> = (0..16)
        .map(|i| {
            let bytes: Vec<u8> = (0..4u32)
                .flat_map(|l| ((i * 7 + l * 1_000_003 + 11) % 2_147_483_647).to_le_bytes())
                .collect();
            QM31::from_le_bytes(bytes.try_into().expect("16 bytes")).expect("canonical")
        })
        .collect();
    let word = code.encode(&row).expect("encode");
    for limb in 0..4 {
        let part = |v: &QM31| {
            m31(u64::from(u32::from_le_bytes(
                v.to_le_bytes().as_ref()[4 * limb..4 * limb + 4]
                    .try_into()
                    .expect("limb"),
            )))
        };
        let lane: Vec<M31> = row.iter().map(part).collect();
        assert_eq!(
            code.encode(&lane).expect("lane"),
            word.iter().map(part).collect::<Vec<_>>()
        );
    }
}

/// RFC-0010 A2: a field of another characteristic is FieldMismatch.
#[test]
fn rejects_other_characteristics() {
    let code = Circle::new(2, 1).expect("code");
    let row = [KoalaBear::from_i64(1); 4];
    assert_eq!(code.encode(&row), Err(Error::FieldMismatch));
    assert_eq!(code.eval_row(&row, &[0]), Err(Error::FieldMismatch));
}

#[test]
fn rejects_sizes_rows_and_columns() {
    assert_eq!(Circle::new(1, 0), Err(Error::InvalidSize));
    assert_eq!(Circle::new(1, 3), Err(Error::InvalidSize));
    assert_eq!(Circle::new(29, 2), Err(Error::InvalidSize));
    assert!(Circle::new(28, 2).is_ok() && Circle::new(29, 1).is_ok());
    let code = Circle::new(2, 1).expect("code");
    assert_eq!(code.encode(&[m31(1); 3]), Err(Error::RowShape));
    assert_eq!(code.eval_row(&[m31(1); 4], &[8]), Err(Error::Column));
    let mut id = [0; 21];
    id[..19].copy_from_slice(b"stele/circle-m31/v1");
    id[19..].copy_from_slice(&[2, 1]);
    assert_eq!(code.code_id(), id);
}
