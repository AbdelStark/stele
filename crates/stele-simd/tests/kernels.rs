//! RFC-0003 §§2,6 (task E20-03): every kernel against arithmetic written from the definition,
//! and the bounds its safe entry checks before the unsafe loads. From the slice 1 review (F1, F6).
//! Adversarial parity of the stele-simd slice kernels against (a) the scalar references and
//! (b) arithmetic written here from the QM31 definition, independent of stele-field's product.
use std::panic::{catch_unwind, AssertUnwindSafe};
use stele_field::{CM31, M31, QM31};
use stele_simd::{
    butterflies_reference, fold_reference, layer_round_reference, mul_assign_reference, Backend,
};

const P: u32 = (1 << 31) - 1;
type L = [u32; 4];

fn m(v: u32) -> M31 {
    M31::from_canonical(v).expect("canonical limb")
}
fn q(l: L) -> QM31 {
    QM31(CM31(m(l[0]), m(l[1])), CM31(m(l[2]), m(l[3])))
}
fn limbs(x: QM31) -> L {
    [
        x.0 .0.as_u32(),
        x.0 .1.as_u32(),
        x.1 .0.as_u32(),
        x.1 .1.as_u32(),
    ]
}

/// (a + b·u)(c + d·u) with u² = 2 + i, i² = −1, limbs (a0, a1, b0, b1): from the definition.
fn schoolbook(x: L, y: L) -> L {
    let p = i128::from(P);
    let [a0, a1, b0, b1] = x.map(i128::from);
    let [c0, c1, d0, d1] = y.map(i128::from);
    let ac = (a0 * c0 - a1 * c1, a0 * c1 + a1 * c0);
    let bd = (b0 * d0 - b1 * d1, b0 * d1 + b1 * d0);
    let ad = (a0 * d0 - a1 * d1, a0 * d1 + a1 * d0);
    let bc = (b0 * c0 - b1 * c1, b0 * c1 + b1 * c0);
    // (2 + i)(e0 + e1·i) = (2e0 − e1) + (e0 + 2e1)·i
    let r = (ac.0 + 2 * bd.0 - bd.1, ac.1 + bd.0 + 2 * bd.1);
    let s = (ad.0 + bc.0, ad.1 + bc.1);
    [r.0, r.1, s.0, s.1].map(|v| v.rem_euclid(p) as u32)
}
fn add4(x: L, y: L) -> L {
    std::array::from_fn(|i| ((u64::from(x[i]) + u64::from(y[i])) % u64::from(P)) as u32)
}
fn sub4(x: L, y: L) -> L {
    std::array::from_fn(|i| {
        ((u64::from(x[i]) + u64::from(P) - u64::from(y[i])) % u64::from(P)) as u32
    })
}

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
    fn limb(&mut self, edge: bool) -> u32 {
        if edge {
            EDGE[self.below(EDGE.len() as u64) as usize]
        } else {
            (self.next() % u64::from(P)) as u32
        }
    }
    fn element(&mut self, edge: bool) -> L {
        std::array::from_fn(|_| self.limb(edge))
    }
}

/// Limbs at and next to every boundary the kernels' bounds argue about.
const EDGE: [u32; 7] = [0, 1, 2, P - 1, P - 2, 1 << 30, (1 << 30) + 1];

fn backends() -> Vec<Backend> {
    let all = [
        Backend::Scalar,
        Backend::Neon,
        Backend::Avx2,
        Backend::Avx512,
    ];
    let available: Vec<_> = all.into_iter().filter(|b| b.available()).collect();
    eprintln!(
        "executed backends: {available:?} detect {:?}",
        Backend::detect()
    );
    if let Ok(required) = std::env::var("STELE_REQUIRE_SIMD") {
        for name in required.split(',') {
            assert!(
                available
                    .iter()
                    .any(|b| format!("{b:?}").eq_ignore_ascii_case(name)),
                "required backend unavailable: {name}"
            );
        }
    }
    available
}

fn fnv(h: &mut u64, v: u32) {
    for byte in v.to_le_bytes() {
        *h = (*h ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
}

/// Every pair of elements whose eight limbs come from EDGE: 7^8 = 5 764 801 products per
/// backend and operand order, each compared with the definition. Includes all limbs p − 1.
#[test]
fn matches_reference_definition_of_the_product_on_every_edge_limb_combination() {
    let backends = backends();
    let n = EDGE.len();
    let all: Vec<L> = (0..n.pow(4))
        .map(|i| {
            [
                EDGE[i % n],
                EDGE[i / n % n],
                EDGE[i / n / n % n],
                EDGE[i / n / n / n % n],
            ]
        })
        .collect();
    let xs: Vec<QM31> = all.iter().map(|l| q(*l)).collect();
    let mut products = 0u64;
    for (j, y) in all.iter().enumerate() {
        let ys = vec![q(*y); xs.len()];
        let expected: Vec<QM31> = all.iter().map(|x| q(schoolbook(*x, *y))).collect();
        let mut reference = xs.clone();
        mul_assign_reference(&mut reference, &ys);
        assert_eq!(reference, expected, "reference vs definition, y={y:?}");
        // The independent Karatsuba product of stele-field agrees as well.
        assert!(xs
            .iter()
            .zip(&expected)
            .all(|(x, e)| x.karatsuba(q(*y)) == *e));
        // A moving start shifts which operand lands in which lane and leaves a tail.
        let off = j % 5;
        for backend in &backends {
            let mut a = xs[off..].to_vec();
            backend.mul_assign(&mut a, &ys[off..]).expect("available");
            assert_eq!(a, expected[off..], "{backend:?} x varying, y={y:?}");
            let mut b = ys[off..].to_vec();
            backend.mul_assign(&mut b, &xs[off..]).expect("available");
            assert_eq!(b, expected[off..], "{backend:?} y varying, y={y:?}");
            assert!(a.iter().all(|e| limbs(*e).iter().all(|l| *l < P)));
        }
        products += xs.len() as u64;
    }
    assert_eq!(products, 5_764_801);
    eprintln!("edge products per backend and order: {products}");
}

/// RFC-0003 §6 asks 10^6 random cases per op per backend: 4·10^6 uniform products here.
#[test]
fn matches_reference_definition_of_the_product_on_four_million_random_pairs() {
    let backends = backends();
    let mut rng = Rng(0x5354_454c_4552_0001);
    let mut done = 0usize;
    while done < 4_000_000 {
        let n = rng.below(130) as usize;
        let edge = rng.below(16) == 0;
        let x: Vec<L> = (0..n).map(|_| rng.element(edge)).collect();
        let y: Vec<L> = (0..n).map(|_| rng.element(false)).collect();
        let expected: Vec<QM31> = x
            .iter()
            .zip(&y)
            .map(|(a, b)| q(schoolbook(*a, *b)))
            .collect();
        let (xq, yq): (Vec<QM31>, Vec<QM31>) = (
            x.iter().map(|l| q(*l)).collect(),
            y.iter().map(|l| q(*l)).collect(),
        );
        for backend in &backends {
            let mut a = xq.clone();
            backend.mul_assign(&mut a, &yq).expect("available");
            assert_eq!(a, expected, "{backend:?} n={n}");
        }
        let mut a = xq.clone();
        stele_simd::mul_assign(&mut a, &yq);
        assert_eq!(a, expected, "detected backend n={n}");
        done += n;
    }
    // Unequal lengths: only the common prefix is multiplied.
    let a: Vec<QM31> = (0..11).map(|_| q(rng.element(false))).collect();
    let b: Vec<QM31> = (0..7).map(|_| q(rng.element(false))).collect();
    for backend in &backends {
        let mut left = a.clone();
        backend.mul_assign(&mut left, &b).expect("available");
        assert!((0..7).all(|i| limbs(left[i]) == schoolbook(limbs(a[i]), limbs(b[i]))));
        assert_eq!(left[7..], a[7..]);
        let mut short = b.clone();
        backend.mul_assign(&mut short, &a).expect("available");
        assert!((0..7).all(|i| limbs(short[i]) == schoolbook(limbs(a[i]), limbs(b[i]))));
    }
}

/// The eight elements whose products drive the largest and smallest lanes.
fn specials() -> Vec<L> {
    let e = P - 1;
    vec![
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [e, e, e, e],
        [1, 1, 1, 1],
        [e, 0, 0, 0],
        [0, e, 0, 0],
        [0, 0, e, 0],
        [0, 0, 0, e],
    ]
}

#[test]
fn matches_reference_definition_of_the_fold_on_special_edge_and_random_tables() {
    let backends = backends();
    let naive = |lo: &[L], hi: &[L], c: L| -> Vec<QM31> {
        lo.iter()
            .zip(hi)
            .map(|(a, b)| q(add4(*a, schoolbook(c, sub4(*b, *a)))))
            .collect()
    };
    let check = |lo: &[L], hi: &[L], c: L, what: &str| {
        let expected = naive(lo, hi, c);
        let (loq, hiq): (Vec<QM31>, Vec<QM31>) = (
            lo.iter().map(|l| q(*l)).collect(),
            hi.iter().map(|l| q(*l)).collect(),
        );
        let mut reference = loq.clone();
        fold_reference(&mut reference, &hiq, q(c));
        assert_eq!(reference, expected, "reference {what}");
        for backend in &backends {
            let mut folded = loq.clone();
            backend.fold(&mut folded, &hiq, q(c)).expect("available");
            assert_eq!(folded, expected, "{backend:?} {what}");
        }
        let mut folded = loq.clone();
        stele_simd::fold(&mut folded, &hiq, q(c));
        assert_eq!(folded, expected, "detected {what}");
    };
    // Every (lo, hi, c) of the specials, at every lane position (three rotations).
    let s = specials();
    for c in &s {
        for rotation in 0..3 {
            let mut lo = Vec::new();
            let mut hi = Vec::new();
            for a in &s {
                for b in &s {
                    lo.push(*a);
                    hi.push(*b);
                }
            }
            lo.rotate_left(rotation);
            hi.rotate_left(rotation);
            let n = lo.len() - rotation;
            check(&lo[..n], &hi[..n], *c, "specials");
        }
    }
    let mut rng = Rng(0x5354_454c_4552_0002);
    for case in 0..30_000usize {
        let n = rng.below(38) as usize;
        let edge = case % 3 == 0;
        let lo: Vec<L> = (0..n).map(|_| rng.element(edge)).collect();
        let hi: Vec<L> = (0..n).map(|_| rng.element(edge)).collect();
        let c = rng.element(case % 5 == 0);
        check(&lo, &hi, c, "random");
    }
}

fn naive_layer(t: [&[L]; 4], e: &[L], g: L, range: std::ops::Range<usize>) -> [QM31; 3] {
    let half = e.len();
    let term = |p0: L, q0: L, p1: L, q1: L| {
        add4(
            schoolbook(q1, add4(p0, schoolbook(g, q0))),
            schoolbook(p1, q0),
        )
    };
    let mut sums = [[0u32; 4]; 3];
    for x in range {
        let y = x + half;
        let at = |i: usize| [t[0][i], t[1][i], t[2][i], t[3][i]];
        let (a, b) = (at(x), at(y));
        let d: [L; 4] = std::array::from_fn(|k| sub4(b[k], a[k]));
        sums[0] = add4(sums[0], schoolbook(e[x], term(a[0], a[1], a[2], a[3])));
        sums[1] = add4(sums[1], schoolbook(e[x], term(b[0], b[1], b[2], b[3])));
        sums[2] = add4(sums[2], schoolbook(e[x], term(d[0], d[1], d[2], d[3])));
    }
    sums.map(q)
}

#[test]
fn matches_reference_definition_of_the_layer_round_and_rejects_ranges_outside_the_tables() {
    let backends = backends();
    let mut rng = Rng(0x5354_454c_4552_0003);
    let mut ranges = 0;
    for half in 0..=14usize {
        for variant in 0..3 {
            let edge = variant == 1;
            let mut table = |n: usize| -> Vec<L> {
                (0..n)
                    .map(|i| {
                        if variant == 2 {
                            specials()[(i * 5 + n) % 8]
                        } else {
                            rng.element(edge)
                        }
                    })
                    .collect()
            };
            let t: Vec<Vec<L>> = (0..4).map(|_| table(2 * half)).collect();
            let e = table(half);
            let g = if variant == 2 {
                [P - 1; 4]
            } else {
                rng.element(edge)
            };
            let tq: Vec<Vec<QM31>> = t
                .iter()
                .map(|c| c.iter().map(|l| q(*l)).collect())
                .collect();
            let eq: Vec<QM31> = e.iter().map(|l| q(*l)).collect();
            let view = [&tq[0][..], &tq[1][..], &tq[2][..], &tq[3][..]];
            for start in 0..=half {
                for end in start..=half {
                    let expected = naive_layer([&t[0], &t[1], &t[2], &t[3]], &e, g, start..end);
                    assert_eq!(
                        layer_round_reference(view, &eq, q(g), start..end),
                        expected,
                        "reference half={half} {start}..{end}"
                    );
                    for backend in &backends {
                        assert_eq!(
                            backend
                                .layer_round(view, &eq, q(g), start..end)
                                .expect("available"),
                            expected,
                            "{backend:?} half={half} {start}..{end} variant={variant}"
                        );
                    }
                    assert_eq!(
                        stele_simd::layer_round(view, &eq, q(g), start..end),
                        expected
                    );
                    ranges += 1;
                }
            }
        }
    }
    eprintln!("layer ranges: {ranges}");

    // Bounds: what the kernel must never read. A half of 8 is whole vectors on every
    // backend (no reference tail to panic in the kernel's place); 9 leaves a tail.
    for half in [8usize, 9] {
        layer_bounds(&backends, &mut rng, half);
    }
}

fn layer_bounds(backends: &[Backend], rng: &mut Rng, half: usize) {
    let t: Vec<Vec<QM31>> = (0..4)
        .map(|_| (0..2 * half).map(|_| q(rng.element(false))).collect())
        .collect();
    let e: Vec<QM31> = (0..half).map(|_| q(rng.element(false))).collect();
    let g = q(rng.element(false));
    let view = [&t[0][..], &t[1][..], &t[2][..], &t[3][..]];
    let zero = [QM31::ZERO; 3];
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = [
        8..0,
        8..3,
        half..0,
        usize::MAX..0,
        usize::MAX..usize::MAX - 1,
        5..4,
    ];
    for backend in backends {
        // A reversed range is empty: no kernel work, and no wrapped length.
        for range in reversed.clone() {
            assert_eq!(
                backend
                    .layer_round(view, &e, g, range.clone())
                    .expect("available"),
                zero,
                "{backend:?} reversed {range:?}"
            );
            assert_eq!(layer_round_reference(view, &e, g, range), zero);
        }
        // A range past the half: the reference panics on its index, and so must the backend.
        for range in [0..half + 1, half..half + 4, 0..4 * half] {
            let r = range.clone();
            assert!(
                catch_unwind(AssertUnwindSafe(|| layer_round_reference(view, &e, g, r))).is_err()
            );
            let r = range.clone();
            assert!(
                catch_unwind(AssertUnwindSafe(|| backend.layer_round(view, &e, g, r))).is_err(),
                "{backend:?} must not read past the half for {range:?}"
            );
        }
        // One table one element short: in-bounds ranges still agree, the last index panics.
        for short in 0..4 {
            let mut cut = view;
            cut[short] = &t[short][..2 * half - 1];
            assert_eq!(
                backend
                    .layer_round(cut, &e, g, 0..half - 1)
                    .expect("available"),
                layer_round_reference(cut, &e, g, 0..half - 1),
                "{backend:?} short table {short}"
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| backend.layer_round(
                    cut,
                    &e,
                    g,
                    0..half
                )))
                .is_err(),
                "{backend:?} must not read past a short table {short}"
            );
            // A table of the lower half only: every `x + half` is out of bounds.
            let mut lower = view;
            lower[short] = &t[short][..half];
            assert!(catch_unwind(AssertUnwindSafe(|| backend.layer_round(
                lower,
                &e,
                g,
                0..half
            )))
            .is_err());
        }
        // Longer tables than `2·half` are read in their first `2·half` only.
        let long: Vec<Vec<QM31>> = t
            .iter()
            .map(|c| {
                let mut c = c.clone();
                c.extend((0..5).map(|_| q([7, 7, 7, 7])));
                c
            })
            .collect();
        let long_view = [&long[0][..], &long[1][..], &long[2][..], &long[3][..]];
        assert_eq!(
            backend
                .layer_round(long_view, &e, g, 0..half)
                .expect("available"),
            layer_round_reference(view, &e, g, 0..half)
        );
    }
}

#[test]
fn matches_reference_definition_of_the_butterflies_on_every_edge_triple_and_random_rows() {
    let backends = backends();
    const E: [u32; 10] = [
        0,
        1,
        2,
        P - 1,
        P - 2,
        1 << 30,
        (1 << 30) + 1,
        (1 << 16) + 1,
        0x5555_5555,
        0x2aaa_aaaa,
    ];
    let naive = |a: u32, b: u32, w: u32| -> (u32, u32) {
        let p = u64::from(P);
        let t = u64::from(b) * u64::from(w) % p;
        (
            ((u64::from(a) + t) % p) as u32,
            ((u64::from(a) + p - t) % p) as u32,
        )
    };
    let check = |low: &[u32], high: &[u32], tw: &[u32], what: &str| {
        let n = low.len().min(high.len()).min(tw.len());
        let mut want_low: Vec<M31> = low.iter().map(|v| m(*v)).collect();
        let mut want_high: Vec<M31> = high.iter().map(|v| m(*v)).collect();
        for i in 0..n {
            let (x, y) = naive(low[i], high[i], tw[i]);
            (want_low[i], want_high[i]) = (m(x), m(y));
        }
        let (l0, h0, t0): (Vec<M31>, Vec<M31>, Vec<M31>) = (
            low.iter().map(|v| m(*v)).collect(),
            high.iter().map(|v| m(*v)).collect(),
            tw.iter().map(|v| m(*v)).collect(),
        );
        let (mut l, mut h) = (l0.clone(), h0.clone());
        butterflies_reference(&mut l, &mut h, &t0);
        assert_eq!((&l, &h), (&want_low, &want_high), "reference {what}");
        for backend in &backends {
            let (mut l, mut h) = (l0.clone(), h0.clone());
            backend.butterflies(&mut l, &mut h, &t0).expect("available");
            assert_eq!((&l, &h), (&want_low, &want_high), "{backend:?} {what}");
        }
        let (mut l, mut h) = (l0.clone(), h0.clone());
        stele_simd::butterflies(&mut l, &mut h, &t0);
        assert_eq!((&l, &h), (&want_low, &want_high), "detected {what}");
    };
    // All 1000 edge triples; 19 starts move each triple through every lane and leave
    // tails, on pointers that are not vector-aligned.
    let (mut low, mut high, mut tw) = (Vec::new(), Vec::new(), Vec::new());
    for a in E {
        for b in E {
            for w in E {
                low.push(a);
                high.push(b);
                tw.push(w);
            }
        }
    }
    for start in 0..19 {
        check(&low[start..], &high[start..], &tw[start..], "edge triples");
    }
    let mut rng = Rng(0x5354_454c_4552_0004);
    for case in 0..40_000usize {
        let edge = case % 4 == 0;
        let mut row = |n: usize| -> Vec<u32> {
            (0..n)
                .map(|_| {
                    if edge {
                        E[rng.below(10) as usize]
                    } else {
                        (rng.next() % u64::from(P)) as u32
                    }
                })
                .collect()
        };
        let n = case % 71;
        // Every tenth case has three lengths, each of the three the shortest in turn: only
        // the common prefix moves.
        let k = case / 10;
        let (a, b, c) = if case % 10 == 0 {
            (n + k % 3, n + k % 5, n + k % 2)
        } else {
            (n, n, n)
        };
        let (low, high, tw) = (row(a), row(b), row(c));
        check(&low, &high, &tw, "random");
    }
}

/// One digest per backend over fixed inputs: equal on a host, and compared across hosts.
#[test]
fn matches_reference_digest_on_every_backend() {
    let backends = backends();
    let mut digests = Vec::new();
    for backend in &backends {
        let mut rng = Rng(0x5354_454c_4552_0005);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for case in 0..2000usize {
            let edge = case % 4 == 0;
            let n = case % 53;
            let mut a: Vec<QM31> = (0..n).map(|_| q(rng.element(edge))).collect();
            let b: Vec<QM31> = (0..n).map(|_| q(rng.element(edge))).collect();
            let c = q(rng.element(case % 8 == 0));
            let mut f = a.clone();
            backend.mul_assign(&mut a, &b).expect("available");
            backend.fold(&mut f, &b, c).expect("available");
            let half = n / 2;
            let t: Vec<Vec<QM31>> = (0..4)
                .map(|_| (0..2 * half).map(|_| q(rng.element(edge))).collect())
                .collect();
            let e: Vec<QM31> = (0..half).map(|_| q(rng.element(edge))).collect();
            let sums = backend
                .layer_round([&t[0][..], &t[1][..], &t[2][..], &t[3][..]], &e, c, 0..half)
                .expect("available");
            let mut low: Vec<M31> = (0..n).map(|_| m(rng.limb(edge))).collect();
            let mut high: Vec<M31> = (0..n).map(|_| m(rng.limb(edge))).collect();
            let tw: Vec<M31> = (0..n).map(|_| m(rng.limb(edge))).collect();
            backend
                .butterflies(&mut low, &mut high, &tw)
                .expect("available");
            for x in a.iter().chain(&f).chain(&sums) {
                for l in limbs(*x) {
                    fnv(&mut h, l);
                }
            }
            for x in low.iter().chain(&high) {
                fnv(&mut h, x.as_u32());
            }
        }
        eprintln!("digest simd {backend:?} {h:016x}");
        digests.push(h);
    }
    assert!(digests.windows(2).all(|w| w[0] == w[1]), "{digests:x?}");
}
