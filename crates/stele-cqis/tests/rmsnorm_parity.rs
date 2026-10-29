//! RFC-0021 §2.3,§6: deterministic full-row corpus against independent Python.
use stele_cqis::functions::{Descriptor, NormError};

struct Rng(u64);
impl Rng {
    fn word(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
}

#[test]
fn matches_reference_ten_thousand_rmsnorm_rows_and_numpy_rounding() {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../research/cqis-tables/native-rmsnorm.json"
    ))
    .expect("exact Python fixture");
    let mut rng = Rng(2602038);
    let mut digest = blake3::Hasher::new();
    let (mut accepted, mut overflow) = (0u64, 0u64);
    for i in 0..11000 {
        let (mut d, f, mut g, e) = (
            1 + rng.word() % 32,
            rng.word() % 31,
            rng.word() % 31,
            rng.word() % 15,
        );
        let (mut en, mut ed) = (rng.word().max(1), rng.word().max(1));
        let (mut a, mut b) = (en, ed);
        while b != 0 {
            (a, b) = (b, a % b);
        }
        en /= a;
        ed /= a;
        if i % 4 == 0 {
            (en, ed) = (1, u32::MAX);
        }
        if i % 4 == 1 {
            (en, ed) = (u32::MAX, 1);
        }
        if i % 997 == 0 {
            d = 16384;
        }
        if i < 10000 {
            let bits = if d == 1 { 0 } else { (d - 1).ilog2() + 1 };
            g = g.max(e + bits.div_ceil(2) + 1);
        }
        let mut xs: Vec<i16> = (0..d).map(|_| rng.word() as u16 as i16).collect();
        let mut gs: Vec<i16> = (0..d).map(|_| rng.word() as u16 as i16).collect();
        if i % 5 == 0 {
            gs.fill(0);
        }
        if i == 0 {
            xs.fill(0);
        }
        let mut parameters = (d as u16).to_le_bytes().to_vec();
        parameters.extend([f as u8, g as u8, e as u8]);
        parameters.extend(en.to_le_bytes());
        parameters.extend(ed.to_le_bytes());
        digest.update(&parameters);
        for row in [&xs, &gs] {
            for v in row {
                digest.update(&v.to_le_bytes());
            }
        }
        match Descriptor::new("rmsnorm_q", 1, &parameters)
            .expect("descriptor")
            .evaluate_rmsnorm(&xs, &gs)
        {
            Err(NormError::Overflow) => {
                digest.update(&[0]);
                overflow += 1;
            }
            result => {
                let row = result.expect("supported row arithmetic or checked output overflow");
                accepted += 1;
                digest.update(&[1]);
                digest.update(&row.statistic().to_le_bytes());
                let (n, p) = row.ratio();
                let (a, d, r) = row.normalized_ratio();
                assert_eq!(a, u128::from(row.mantissa()) * d + r);
                assert!(r < d);
                for v in [n, p, a, d, r] {
                    digest.update(&v.to_le_bytes());
                }
                digest.update(&row.exponent().to_le_bytes());
                digest.update(&row.mantissa().to_le_bytes());
                digest.update(&row.reciprocal().to_le_bytes());
                digest.update(&i8::try_from(row.shift()).expect("shift").to_le_bytes());
                for y in row.outputs() {
                    digest.update(&y.to_le_bytes());
                }
            }
        }
    }
    assert_eq!(accepted, expected["accepted"].as_u64().expect("accepted"));
    assert_eq!(overflow, expected["overflow"].as_u64().expect("overflow"));
    assert!(accepted >= 10000 && overflow > 0);
    assert_eq!(accepted + overflow, 11000);
    assert_eq!(
        digest.finalize().to_hex().as_str(),
        expected["digest"].as_str().expect("digest")
    );
}
