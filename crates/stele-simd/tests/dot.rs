//! RFC-0004 A15, RFC-0014 §2 (task E20-03): the int8 dot kernel against the exact sum, on every
//! byte pair and on rows whose sum wraps. From the slice 1 review (F1, F6).
//! The int8 dot kernel against its reference and against an exact i64 sum: every byte pair
//! in every lane, random rows across both vector widths, rows whose sum leaves i32 (the
//! kernel must wrap as the reference does), unequal lengths and unaligned starts.
use stele_simd::{dot_i8_reference, Backend};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

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
            assert!(available
                .iter()
                .any(|b| format!("{b:?}").eq_ignore_ascii_case(name)));
        }
    }
    available
}

/// The integer dot product, exact; the kernel and the reference return it modulo 2^32.
fn exact(x: &[i8], w: &[u8]) -> i64 {
    x.iter()
        .zip(w)
        .map(|(x, w)| i64::from(*x) * i64::from(*w as i8))
        .sum()
}

fn check(backends: &[Backend], x: &[i8], w: &[u8], what: &str) -> i32 {
    let expected = exact(x, w) as i32; // truncation is reduction modulo 2^32
    assert_eq!(dot_i8_reference(x, w), expected, "reference {what}");
    for backend in backends {
        assert_eq!(
            backend.dot_i8(x, w).expect("available"),
            expected,
            "{backend:?} {what} n={}",
            x.len().min(w.len())
        );
    }
    assert_eq!(stele_simd::dot_i8(x, w), expected, "detected {what}");
    expected
}

#[test]
fn matches_reference_exact_sum_of_the_int8_dot_and_its_wrap() {
    let backends = backends();
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut note = |v: i32| {
        for byte in v.to_le_bytes() {
            h = (h ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    // Every pair of bytes, at 67 starts: each pair visits every lane of both widths, on
    // unaligned pointers, with a tail.
    let mut x = Vec::with_capacity(1 << 16);
    let mut w = Vec::with_capacity(1 << 16);
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            x.push(a as i8);
            w.push(b);
        }
    }
    for start in 0..67 {
        note(check(&backends, &x[start..], &w[start..], "all byte pairs"));
        note(check(
            &backends,
            &x[start..start + 3 * start + 5],
            &w[start..start + 3 * start + 5],
            "short run",
        ));
    }
    // One product alone in every position of a row of 97 zeros.
    for position in 0..97 {
        for (a, b) in [
            (-128i8, 0x80u8),
            (-128, 0x7f),
            (127, 0x80),
            (127, 0x7f),
            (-1, 0xff),
        ] {
            let mut x = vec![0i8; 97];
            let mut w = vec![0u8; 97];
            (x[position], w[position]) = (a, b);
            let sum = check(&backends, &x, &w, "one product");
            assert_eq!(sum, i32::from(a) * i32::from(b as i8));
        }
    }
    // Rows of the largest products: exact up to 2^17 - 1 terms, then the sum leaves i32
    // and both the reference and the kernel wrap.
    for (n, a, b) in [
        (16_384usize, -127i8, 0x80u8), // the executor's widest row: 16384·127·128 < 2^28
        (65_536, -128, 0x80),          // 2^30
        (131_071, -128, 0x80),         // 2^31 - 2^14: the last exact length
        (131_072, -128, 0x80),         // 2^31: wraps to -2^31
        (300_001, -128, 0x80),
        (300_001, -128, 0x7f),
        (262_147, 127, 0x7f),
    ] {
        let sum = check(&backends, &vec![a; n], &vec![b; n], "extreme row");
        let integer = n as i64 * i64::from(a) * i64::from(b as i8);
        assert_eq!(sum, integer as i32);
        if n <= 131_071 {
            assert_eq!(i64::from(sum), integer, "exact below 2^17 terms");
        }
        note(sum);
    }
    // Random rows: lengths across both widths, three lengths apart in a tenth of them.
    let mut rng = Rng(0x5354_454c_4552_0401);
    for case in 0..60_000usize {
        let n = (rng.next() % 200) as usize;
        let k = case / 10;
        let (nx, nw) = if case % 10 == 0 {
            (n + k % 3, n + k % 5)
        } else {
            (n, n)
        };
        let edge = case % 4 == 0;
        let byte = |rng: &mut Rng| -> u8 {
            let raw = rng.next();
            if edge {
                [0x80, 0x81, 0x7f, 0x00, 0x01, 0xff][(raw % 6) as usize]
            } else {
                raw as u8
            }
        };
        let x: Vec<i8> = (0..nx).map(|_| byte(&mut rng) as i8).collect();
        let w: Vec<u8> = (0..nw).map(|_| byte(&mut rng)).collect();
        note(check(&backends, &x, &w, "random"));
    }
    eprintln!("digest dot {h:016x}");
}
