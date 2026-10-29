//! RFC-0021 §6 test oracle: explicit Boolean equality weights, not native folding.
use core::fmt::Debug;
use stele_cqis::tables::{Descriptor, Table, TableField};
use stele_field::{Field, CM31, M31, OM31, QM31};

pub trait TestField: TableField + Eq + Debug {
    fn random(state: &mut u64) -> Self;
    fn lift(value: i32) -> Self;
}

fn next(state: &mut u64) -> M31 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    M31::from_u64(*state)
}

fn lift(value: i32) -> M31 {
    let p = i64::from(M31::MODULUS);
    let canonical = ((i64::from(value) % p) + p) % p;
    M31::from_canonical(u32::try_from(canonical).expect("canonical limb")).expect("M31")
}

impl TestField for QM31 {
    fn random(state: &mut u64) -> Self {
        Self(
            CM31(next(state), next(state)),
            CM31(next(state), next(state)),
        )
    }
    fn lift(value: i32) -> Self {
        Self(CM31(lift(value), M31::ZERO), CM31::ZERO)
    }
}
impl TestField for OM31 {
    fn random(state: &mut u64) -> Self {
        Self(QM31::random(state), QM31::random(state))
    }
    fn lift(value: i32) -> Self {
        Self(QM31::lift(value), QM31::ZERO)
    }
}

pub const CASES: [(&str, &[u8]); 14] = [
    ("exp_q/hi", &[31, 30, 14, 16]),
    ("exp_q/lo", &[16, 10, 12, 16]),
    ("exp_q/direct", &[15, 10, 12]),
    ("exp_q/correction", &[15, 10, 12, 7]),
    ("sigmoid_q", &[8, 8]),
    ("silu_q", &[8, 8]),
    ("softcap_q", &[8, 8, 30, 0, 0]),
    ("gelu_q", &[8, 8]),
    ("gelu_tanh_q", &[8, 8]),
    ("rsqrt_q", &[]),
    ("range_8", &[]),
    ("range_12", &[]),
    ("range_16", &[]),
    ("exp_q/hi", &[16, 10, 12, 16]), // two-row high component, one coordinate
];

pub fn generate(case: (&str, &[u8])) -> Table {
    Table::generate(Descriptor::new(case.0, 1, case.1).expect("descriptor"))
        .expect("complete definition")
}

pub struct BooleanOracle<K> {
    weights: Vec<K>,
}

impl<K: TestField> BooleanOracle<K> {
    pub fn new(table: &Table) -> Self {
        Self {
            weights: vec![K::from_i64(0); table.descriptor().shape().padded() as usize],
        }
    }

    pub fn evaluate(&mut self, table: &Table, point: &[K]) -> (Vec<K>, K) {
        self.weights[0] = K::from_i64(1);
        let mut length = 1;
        // Expand the literal Boolean eq table in MSB order. This constructs
        // weights independently of native recursive interpolation of value rows.
        for r in point {
            for i in (0..length).rev() {
                let w = self.weights[i];
                self.weights[2 * i] = w * (K::from_i64(1) - *r);
                self.weights[2 * i + 1] = w * *r;
            }
            length *= 2;
        }
        assert_eq!(length, self.weights.len());
        let width = usize::from(table.descriptor().shape().columns());
        let mut result = vec![K::from_i64(0); width];
        let mut valid = K::from_i64(0);
        for (i, (row, w)) in table
            .entries()
            .chunks_exact(width)
            .zip(&self.weights)
            .enumerate()
        {
            for (out, v) in result.iter_mut().zip(row) {
                *out = *out + *w * K::lift(*v);
            }
            if i < table.descriptor().shape().rows() as usize {
                valid = valid + *w;
            }
        }
        (result, valid)
    }
}
