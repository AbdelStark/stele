//! RFC-0006 A1 (task E20-03): the sumcheck call sites of the host kernels against loops
//! written here, from the E20-03 slice 1 review (F3): `parallel::fold`,
//! `parallel::mul_assign`, `parallel::layer_round_kernel` and the all-extension `Dense` round
//! (block-wise where the host has kernels), on random instances with repeated factors,
//! zero-factor terms, zero coefficients and no terms.
use stele_field::{Field, Serialize, CM31, M31, OM31, QM31};
use stele_hash::ChallengeField;
use stele_sumcheck::{parallel, Dense, Instance, Summand, Term};

const P: u32 = (1 << 31) - 1;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn m31(&mut self, edge: bool) -> M31 {
        const EDGE: [u32; 5] = [0, 1, P - 1, P - 2, 1 << 30];
        let limb = if edge {
            EDGE[self.below(5) as usize]
        } else {
            (self.next() % u64::from(P)) as u32
        };
        M31::from_canonical(limb).expect("canonical")
    }
    fn qm31(&mut self, edge: bool) -> QM31 {
        QM31(
            CM31(self.m31(edge), self.m31(edge)),
            CM31(self.m31(edge), self.m31(edge)),
        )
    }
    fn om31(&mut self, edge: bool) -> OM31 {
        OM31(self.qm31(edge), self.qm31(edge))
    }
}

fn fnv(h: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *h = (*h ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
    }
}

fn evaluate<K: ChallengeField>(i: &Instance<K>, values: &[K]) -> K {
    i.terms.iter().fold(K::from_i64(0), |sum, term| {
        sum + term
            .factors
            .iter()
            .fold(term.coefficient, |product, f| product * values[*f as usize])
    })
}

#[test]
fn matches_reference_fold_loop_for_both_challenge_fields() {
    let mut rng = Rng(0x5354_454c_4552_0101);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for vars in 0..=14u32 {
        for variant in 0..4 {
            let edge = variant == 1;
            let len = 1usize << vars;
            let table: Vec<QM31> = (0..len).map(|_| rng.qm31(edge)).collect();
            let r = rng.qm31(variant >= 2);
            let half = len / 2;
            let naive: Vec<QM31> = (0..half)
                .map(|j| table[j] + r * (table[j + half] - table[j]))
                .collect();
            let mut folded = table.clone();
            parallel::fold(&mut folded, r);
            assert_eq!(folded, naive, "QM31 vars={vars} variant={variant}");
            for value in &folded {
                fnv(&mut h, value.to_le_bytes().as_ref());
            }
            if vars <= 9 {
                let table: Vec<OM31> = (0..len).map(|_| rng.om31(edge)).collect();
                let r = rng.om31(variant >= 2);
                let naive: Vec<OM31> = (0..half)
                    .map(|j| table[j] + r * (table[j + half] - table[j]))
                    .collect();
                let mut folded = table.clone();
                parallel::fold(&mut folded, r);
                assert_eq!(folded, naive, "OM31 vars={vars}");
            }
        }
    }
}

#[test]
fn matches_reference_product_and_layer_round_loops() {
    let mut rng = Rng(0x5354_454c_4552_0102);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for case in 0..3000usize {
        let n = rng.below(150) as usize;
        let edge = case % 4 == 0;
        let a: Vec<QM31> = (0..n).map(|_| rng.qm31(edge)).collect();
        let b: Vec<QM31> = (0..n).map(|_| rng.qm31(edge)).collect();
        let mut product = a.clone();
        parallel::mul_assign(&mut product, &b);
        assert!((0..n).all(|j| product[j] == a[j] * b[j] && product[j] == a[j].karatsuba(b[j])));
        for value in &product {
            fnv(&mut h, value.to_le_bytes().as_ref());
        }
        let half = n / 2;
        let t: Vec<Vec<QM31>> = (0..4)
            .map(|_| (0..2 * half).map(|_| rng.qm31(edge)).collect())
            .collect();
        let e: Vec<QM31> = (0..half).map(|_| rng.qm31(edge)).collect();
        let gamma = rng.qm31(case % 8 == 0);
        let start = rng.below(half as u64 + 1) as usize;
        let end = start + rng.below((half - start) as u64 + 1) as usize;
        let term = |p0: QM31, q0: QM31, p1: QM31, q1: QM31| q1 * (p0 + gamma * q0) + p1 * q0;
        let mut naive = [QM31::ZERO; 3];
        for (x, &weight) in e.iter().enumerate().take(end).skip(start) {
            let y = x + half;
            naive[0] = naive[0] + weight * term(t[0][x], t[1][x], t[2][x], t[3][x]);
            naive[1] = naive[1] + weight * term(t[0][y], t[1][y], t[2][y], t[3][y]);
            naive[2] = naive[2]
                + weight
                    * term(
                        t[0][y] - t[0][x],
                        t[1][y] - t[1][x],
                        t[2][y] - t[2][x],
                        t[3][y] - t[3][x],
                    );
        }
        let sums = parallel::layer_round_kernel(
            [&t[0][..], &t[1][..], &t[2][..], &t[3][..]],
            &e,
            gamma,
            start..end,
        )
        .expect("QM31 has a layer kernel entry");
        assert_eq!(sums, naive, "case {case} half={half} {start}..{end}");
        for value in &sums {
            fnv(&mut h, value.to_le_bytes().as_ref());
        }
    }
    // OM31: no kernel, the callers keep their loops.
    let o: Vec<OM31> = (0..6).map(|_| rng.om31(false)).collect();
    assert!(
        parallel::layer_round_kernel([&o[..], &o[..], &o[..], &o[..]], &o[..3], o[0], 0..3)
            .is_none()
    );
    assert!(!parallel::kernels_available::<OM31>());
    let mut product = o.clone();
    parallel::mul_assign(&mut product, &o);
    assert!((0..6).all(|j| product[j] == o[j] * o[j]));
}

/// A random instance: 0..=5 inputs, 0..=6 terms of 0..=4 factors (repeats allowed).
fn instance(rng: &mut Rng, id: u64, num_vars: u32) -> Instance<QM31> {
    let inputs = rng.below(6) as usize;
    let terms = (0..rng.below(7))
        .map(|_| {
            let factors = if inputs == 0 {
                Vec::new()
            } else {
                (0..rng.below(5))
                    .map(|_| rng.below(inputs as u64) as u32)
                    .collect()
            };
            let coefficient = match rng.below(6) {
                0 => QM31::ZERO,
                1 => QM31::ONE,
                2 => QM31::from_i64(-1),
                3 => rng.qm31(true),
                _ => rng.qm31(false),
            };
            Term {
                coefficient,
                factors,
            }
        })
        .collect();
    Instance {
        id,
        num_vars,
        inputs: (0..inputs as u64).map(|j| 100 + j).collect(),
        terms,
        claimed_sum: QM31::ZERO,
    }
}

/// A pool range that is not a multiple of a block of columns leaves a partial block after
/// a full one. That never happens at 1, 2, 4, 8 or 16 threads, so the same instances also
/// run on three.
#[test]
fn matches_reference_dense_round_loop_on_random_instances_and_on_three_threads() {
    dense_rounds();
    parallel::with_threads(3, dense_rounds);
}

fn dense_rounds() {
    let mut rng = Rng(0x5354_454c_4552_0103);
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let (mut repeated, mut constant, mut empty) = (0, 0, 0);
    for case in 0..700usize {
        // Mostly small (partial blocks), some large (full blocks, a tail, pool splits).
        let num_vars = match case % 70 {
            0 => 13,
            1 => 12,
            2 | 3 => 10,
            _ => 1 + rng.below(8) as u32,
        };
        let i = instance(&mut rng, case as u64, num_vars);
        let degree = i.terms.iter().map(|t| t.factors.len()).max().unwrap_or(0);
        repeated += i
            .terms
            .iter()
            .filter(|t| (1..t.factors.len()).any(|k| t.factors[..k].contains(&t.factors[k])))
            .count();
        constant += i.terms.iter().filter(|t| t.factors.is_empty()).count();
        empty += usize::from(i.terms.is_empty());
        let edge = case % 5 == 0;
        let mut tables: Vec<Vec<QM31>> = (0..i.inputs.len())
            .map(|_| (0..1usize << num_vars).map(|_| rng.qm31(edge)).collect())
            .collect();
        let mut dense = Dense::new(&i, tables.clone()).expect("dense");
        for _ in 0..num_vars {
            let values = dense.round(&i).expect("round");
            assert_eq!(values.len(), degree + 1);
            if !tables.is_empty() {
                let half = tables[0].len() / 2;
                for (node, value) in values.iter().enumerate() {
                    let x = QM31::from_i64(node as i64);
                    let mut expected = QM31::ZERO;
                    let mut point = vec![QM31::ZERO; tables.len()];
                    for column in 0..half {
                        for (v, t) in point.iter_mut().zip(&tables) {
                            *v = t[column] + x * (t[column + half] - t[column]);
                        }
                        expected = expected + evaluate(&i, &point);
                    }
                    assert_eq!(*value, expected, "case {case} vars={num_vars} node {node}");
                }
            }
            for value in &values {
                fnv(&mut h, value.to_le_bytes().as_ref());
            }
            let r = rng.qm31(case % 9 == 0);
            dense.fold(r).expect("fold");
            for t in &mut tables {
                let half = t.len() / 2;
                *t = (0..half).map(|j| t[j] + r * (t[j + half] - t[j])).collect();
            }
        }
        let finals = dense.final_values().expect("finals");
        assert_eq!(finals, tables.iter().map(|t| t[0]).collect::<Vec<_>>());
        for value in &finals {
            fnv(&mut h, value.to_le_bytes().as_ref());
        }
    }
    assert!(repeated > 100 && constant > 100 && empty > 20);
}
