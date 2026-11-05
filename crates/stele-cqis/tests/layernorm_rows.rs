//! RFC-0025 §2.3/6: exact-mean affine LayerNorm, independent NumPy row corpus.
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

fn descriptor(d: u16, units: [u8; 4], en: u32, ed: u32) -> Descriptor {
    let mut p = d.to_le_bytes().to_vec();
    p.extend(units);
    p.extend(en.to_le_bytes());
    p.extend(ed.to_le_bytes());
    Descriptor::new("layernorm_q", 1, &p).expect("LayerNorm")
}

#[test]
fn matches_reference_ten_thousand_exact_mean_affine_rows() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/layernorm-rows.json")).expect("NumPy receipt");
    let mut rng = Rng(50423);
    let mut digest = blake3::Hasher::new();
    let (mut accepted, mut overflow) = (0u64, 0u64);
    for i in 0..11000 {
        let (mut d, f, mut g, e, mut gb) = (
            1 + rng.word() % 32,
            rng.word() % 31,
            rng.word() % 31,
            rng.word() % 15,
            rng.word() % 31,
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
            g = g.max(e + bits.div_ceil(2) + 3);
            gb = gb.max(e + 2);
        }
        let mut x: Vec<_> = (0..d).map(|_| rng.word() as u16 as i16).collect();
        let mut h: Vec<_> = (0..d).map(|_| rng.word() as u16 as i16).collect();
        let b: Vec<_> = (0..d).map(|_| rng.word() as u16 as i16).collect();
        if i % 5 == 0 {
            h.fill(0);
        }
        if i % 7 == 0 {
            let first = x[0];
            x.fill(first);
        }
        let f = descriptor(d as u16, [f as u8, g as u8, e as u8, gb as u8], en, ed);
        digest.update(f.parameters());
        for row in [&x, &h, &b] {
            for v in row {
                digest.update(&v.to_le_bytes());
            }
        }
        match f.evaluate_layernorm(&x, &h, &b) {
            Err(NormError::Overflow) => {
                overflow += 1;
                digest.update(&[0]);
            }
            result => {
                let row = result.expect("exact arithmetic or checked overflow");
                accepted += 1;
                digest.update(&[1]);
                for v in row {
                    digest.update(&v.to_le_bytes());
                }
            }
        }
    }
    assert!(accepted >= 10000 && overflow > 0);
    assert_eq!(accepted, expected["accepted"].as_u64().expect("accepted"));
    assert_eq!(overflow, expected["overflow"].as_u64().expect("overflow"));
    assert_eq!(
        digest.finalize().to_hex().as_str(),
        expected["digest"].as_str().expect("digest")
    );
}

#[test]
fn accepts_constant_rows_singletons_and_single_bias_rounding() {
    let f = descriptor(3, [0, 0, 0, 1], 1, 1);
    // A rounded mean or a separately rounded half-unit bias changes these outputs.
    assert_eq!(
        f.evaluate_layernorm(&[0, 0, 1], &[1; 3], &[1; 3]),
        Ok(vec![0, 0, 1])
    );
    assert_eq!(
        f.evaluate_layernorm(&[0, 0, 1], &[1; 3], &[2; 3]),
        Ok(vec![1, 1, 2])
    );
    let f = descriptor(1, [30, 30, 0, 1], 1, u32::MAX);
    assert_eq!(
        f.evaluate_layernorm(&[-32768], &[32767], &[-3]),
        Ok(vec![-2])
    );
    let f = descriptor(3, [0, 0, 0, 0], u32::MAX, 1);
    assert_eq!(
        f.evaluate_layernorm(&[7; 3], &[-32768; 3], &[1, -2, 3]),
        Ok(vec![1, -2, 3])
    );
    assert_eq!(f.evaluate_layernorm(&[], &[], &[]), Err(NormError::Shape));
    let rms =
        Descriptor::new("rmsnorm_q", 1, &[1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]).expect("RMSNorm");
    assert_eq!(
        rms.evaluate_layernorm(&[0], &[0], &[0]),
        Err(NormError::Function)
    );
    let f = descriptor(1, [0, 0, 14, 0], 1, 1);
    assert_eq!(
        f.evaluate_layernorm(&[0], &[0], &[2]),
        Err(NormError::Overflow)
    );
}
