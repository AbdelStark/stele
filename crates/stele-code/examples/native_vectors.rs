//! RFC-0010 A4 — deterministic native bytes for the independent Python consumer.
use stele_code::{Code, CodeId, Element};
use stele_field::{Field, CM31, M31, OM31, QM31};
fn emit<K: Element>(d: usize, j: u8, seed: u8, value: impl Fn(usize) -> K) {
    let mut raw = b"stele/expander-seed/v2".to_vec();
    raw.push(j);
    raw.extend([seed; 32]);
    let code = CodeId::parse(&raw)
        .expect("id")
        .prepare(1 << 24)
        .expect("setup");
    let row: Vec<_> = (0..code.parameters().message_len).map(value).collect();
    let word = code.encode(&row).expect("encode");
    print!("{d} {j} {seed} {} ", code.setup_hash_blocks());
    for value in word {
        for b in value.to_le_bytes().as_ref() {
            print!("{b:02x}");
        }
    }
    println!();
}
fn main() {
    let m = |i: usize, k: usize| M31::from_i64((i * 37 + k * 17 + 9) as i64);
    let q = |i: usize, k: usize| QM31(CM31(m(i, k), m(i, k + 1)), CM31(m(i, k + 2), m(i, k + 3)));
    for seed in [0, 1] {
        for j in 3..=5 {
            emit(1, j, seed, |i| m(i, 0));
            emit(4, j, seed, |i| q(i, 0));
            emit(8, j, seed, |i| OM31(q(i, 0), q(i, 4)));
        }
    }
}
