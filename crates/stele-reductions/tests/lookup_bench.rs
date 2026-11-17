//! RFC-0008 A7 items 2/3: the benchmark adapter preserves actual tree semantics.
#![cfg(feature = "bench")]
use stele_reductions::stele_field::{Field, CM31, M31, QM31};
use stele_reductions::zk::claims::{bench::LookupCase, Column, Lookup, Public, Read, Statement};
use stele_reductions::zk::Error;

fn case() -> (Statement<QM31>, Vec<Vec<M31>>) {
    let s = Statement {
        sources: 1,
        columns: vec![
            Column {
                source: 0,
                log_len: 1,
            },
            Column {
                source: 0,
                log_len: 2,
            },
        ],
        relations: vec![],
        lookups: vec![Lookup::single(
            &[0],
            1,
            1,
            vec![vec![1], vec![2], vec![3], vec![0]],
            3,
        )],
    };
    (
        s,
        vec![
            vec![M31::from_i64(1), M31::from_i64(2)],
            vec![M31::from_i64(4), M31::from_i64(4), M31::ZERO, M31::ZERO],
        ],
    )
}

#[test]
fn matches_reference_lookup_padding_and_top() {
    let (s, columns) = case();
    let c = LookupCase::new(&s, &columns, 0).expect("lookup");
    let (beta, alpha) = (QM31::from_i64(7), QM31::from_i64(11));
    let input = c.inputs(beta, alpha);
    assert_eq!(input.top_variables, 3);
    assert_eq!(
        input.tuples,
        vec![(0..8)
            .map(|j| QM31::from_i64(1 + j % 2))
            .collect::<Vec<_>>()]
    );
    assert_eq!(input.selector, vec![1; 8]);
    assert_eq!(input.table, [10, 9, 8, 1, 1, 1, 1, 1].map(QM31::from_i64));
    assert_eq!(input.multiplicity, [4, 4, 0, 0].map(QM31::from_i64));
    assert_eq!(input.powers, vec![QM31::ONE]);
    assert_eq!(input.alpha, alpha);
    let tree = c.reference(beta, alpha).expect("nonzero top denominators");
    assert_eq!(
        tree.layers.iter().map(Vec::len).collect::<Vec<_>>(),
        [1, 2, 4, 8, 16]
    );
    let leaf = &tree.layers[4];
    for x in 0..8 {
        assert_eq!(
            leaf[2 * x],
            [QM31::ONE, QM31::from_i64(10 - (x % 2) as i64)]
        );
        assert_eq!(
            leaf[2 * x + 1],
            [QM31::from_i64(if x < 2 { -4 } else { 0 }), input.table[x]]
        );
        let [p, q] = tree.layers[3][x];
        assert_eq!(tree.top[0][x], p);
        assert_eq!(tree.top[1][x], q);
        assert_eq!(tree.top[2][x] * q, p);
    }
    assert_eq!(tree.layers[0][0][0], QM31::ZERO, "honest fraction sum");
    let mut changed = columns.clone();
    changed[1][0] = changed[1][0] + M31::ONE;
    let near = LookupCase::new(&s, &changed, 0)
        .expect("near-miss input shape")
        .reference(beta, alpha)
        .expect("near-miss denominators");
    assert_ne!(
        near.layers[0][0][0],
        QM31::ZERO,
        "one multiplicity near miss"
    );
}

#[test]
fn matches_reference_lookup_members_selector_and_shift() {
    let (mut s, mut columns) = case();
    let mut member = s.lookups[0].members[0].clone();
    member.shifts[0] = 1;
    member.selector = Some(Public {
        vars: vec![0],
        values: vec![1, 0],
    });
    s.lookups[0].members.push(member);
    columns[1][1] = M31::from_i64(8);
    let c = LookupCase::new(&s, &columns, 0).expect("valid lookup");
    let input = c.inputs(QM31::from_i64(7), QM31::from_i64(11));
    assert_eq!(&input.selector[..8], &[1; 8]);
    assert_eq!(&input.selector[8..], &[1, 0, 1, 0, 1, 0, 1, 0]);
    assert_eq!(
        &input.tuples[0][8..],
        &[2, 3, 2, 3, 2, 3, 2, 3].map(QM31::from_i64)
    );
    let tree = c
        .reference(QM31::from_i64(7), QM31::from_i64(11))
        .expect("nonzero denominators");
    assert_eq!(tree.layers[0][0][0], QM31::ZERO);
    assert_eq!(
        tree.layers.last().expect("leaf layer")[18],
        [QM31::ZERO, QM31::from_i64(11)],
        "unselected lookup denominator is alpha"
    );
}

#[test]
fn rejects_lookup_bench_invalid_input() {
    let (mut s, columns) = case();
    assert!(matches!(
        LookupCase::new(&s, &columns, 1),
        Err(Error::Statement)
    ));
    assert!(matches!(
        LookupCase::new(&s, &columns[..1], 0),
        Err(Error::Statement)
    ));
    let mut short = columns.clone();
    short[0].pop();
    assert!(matches!(
        LookupCase::new(&s, &short, 0),
        Err(Error::Statement)
    ));
    s.lookups[0].members[0].selector = Some(Public {
        vars: vec![0],
        values: vec![1, 2],
    });
    assert!(matches!(
        LookupCase::new(&s, &columns, 0),
        Err(Error::Statement)
    ));
}

#[test]
fn matches_reference_lookup_extension_compression() {
    let (mut s, mut columns) = case();
    s.columns.push(Column {
        source: 0,
        log_len: 1,
    });
    columns.push(vec![M31::from_i64(4), M31::from_i64(5)]);
    s.lookups[0].members[0].tuple.push(Read {
        column: 2,
        vars: vec![0],
    });
    s.lookups[0].members[0].shifts.push(-1);
    s.lookups[0].table = vec![vec![1, 3], vec![2, 4], vec![3, 5], vec![0, 0]];
    let c = LookupCase::new(&s, &columns, 0).expect("tuple lookup");
    let beta = QM31(CM31(M31::from_i64(7), M31::ONE), CM31(M31::ZERO, M31::ONE));
    let alpha = QM31::from_i64(19);
    let input = c.inputs(beta, alpha);
    let denominator = alpha - (QM31::ONE + beta * QM31::from_i64(3));
    assert_eq!(input.powers, [QM31::ONE, beta]);
    assert_eq!(
        input.tuples[1],
        [3, 4, 3, 4, 3, 4, 3, 4].map(QM31::from_i64)
    );
    assert_eq!(input.table[0], denominator);
    let tree = c.reference(beta, alpha).expect("extension denominators");
    assert_eq!(
        tree.layers.last().expect("leaves")[0],
        [QM31::ONE, denominator]
    );
    assert_eq!(tree.layers[0][0][0], QM31::ZERO);
}

#[test]
fn rejects_lookup_bench_zero_denominator() {
    let (s, columns) = case();
    let c = LookupCase::new(&s, &columns, 0).expect("valid lookup");
    assert!(matches!(
        c.reference(QM31::from_i64(7), QM31::ONE),
        Err(Error::DenominatorZero)
    ));
}
