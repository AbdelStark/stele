//! RFC-0021 §6: mandatory full-shape public MLE correctness gate, not a benchmark.
#[path = "../tests/support/table_mle.rs"]
mod oracle;
use oracle::{BooleanOracle, TestField};
use stele_cqis::tables::Table;
use stele_field::{OM31, QM31};

fn check<K: TestField>(table: &Table, field: &str, seed: u64) {
    let d = table.descriptor();
    let dimension = d.shape().padded().ilog2() as usize;
    let mut oracle = BooleanOracle::<K>::new(table);
    let mut state = seed;
    let mut digest = blake3::Hasher::new();
    for index in 0..10000 {
        let point: Vec<K> = (0..dimension).map(|_| K::random(&mut state)).collect();
        let expected = oracle.evaluate(table, &point);
        let actual = table.evaluate(&point).expect("native evaluation");
        assert_eq!(
            actual.columns(),
            expected.0,
            "{} {field} point {index}",
            d.name()
        );
        assert_eq!(
            actual.valid_rows(),
            expected.1,
            "{} {field} selector {index}",
            d.name()
        );
        for value in actual
            .columns()
            .iter()
            .chain(core::iter::once(&actual.valid_rows()))
        {
            digest.update(value.to_le_bytes().as_ref());
        }
        if (index + 1) % 1000 == 0 {
            println!(
                "{} {:?} {field}: {}/10000 points",
                d.name(),
                d.parameters(),
                index + 1
            );
        }
    }
    println!(
        "PASS {} {:?} {field} N={} L={} digest={}",
        d.name(),
        d.parameters(),
        d.shape().rows(),
        d.shape().padded(),
        digest.finalize().to_hex()
    );
}

fn main() {
    // A shard is one complete case/field pair with the original seed and
    // 10000 points. CI schedules all 28; no arguments still runs all pairs.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let shard = match args.as_slice() {
        [] => None,
        [flag, value] if flag == "--shard" => {
            let index: usize = value.parse().expect("integer shard index");
            assert!(index < 2 * oracle::CASES.len(), "shard index out of range");
            Some(index)
        }
        _ => panic!("usage: table_mle_parity [--shard 0..27]"),
    };
    for (index, case) in oracle::CASES.into_iter().enumerate() {
        if shard.is_some_and(|part| part / 2 != index) {
            continue;
        }
        let table = oracle::generate(case);
        if shard.is_none_or(|part| part % 2 == 0) {
            check::<QM31>(&table, "QM31", 0x21c0_0001 + index as u64);
        }
        if shard.is_none_or(|part| part % 2 == 1) {
            check::<OM31>(&table, "OM31", 0x21c0_1001 + index as u64);
        }
    }
    if let Some(part) = shard {
        println!("PASS shard {part}: 10000 full-extension points");
    } else {
        println!("PASS: 280000 full-extension points; all thirteen kinds plus two-row high, in both fields");
    }
}
