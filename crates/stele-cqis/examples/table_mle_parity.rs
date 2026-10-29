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
    assert_eq!(
        std::env::args_os().len(),
        1,
        "this gate always runs its complete fixed corpus"
    );
    for (index, case) in oracle::CASES.into_iter().enumerate() {
        let table = oracle::generate(case);
        check::<QM31>(&table, "QM31", 0x21c0_0001 + index as u64);
        check::<OM31>(&table, "OM31", 0x21c0_1001 + index as u64);
    }
    println!(
        "PASS: 280000 full-extension points; all thirteen kinds plus two-row high, in both fields"
    );
}
