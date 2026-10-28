//! RFC-0010 A4 — native factory/encoder tests; no PCS admission.
use stele_code::{Code, CodeId, Error, Profile};
use stele_field::{Field, CM31, M31, OM31, QM31};
fn identity(j: u8, seed: u8) -> Vec<u8> {
    let mut bytes = b"stele/expander-seed/v2".to_vec();
    bytes.push(j);
    bytes.extend([seed; 32]);
    bytes
}
#[test]
fn accepts_all_identities_without_setup_allocation() {
    for b in 1..=2u8 {
        for m in 0..=30 - b {
            let mut raw = b"stele/circle-m31/v1".to_vec();
            raw.extend([m, b]);
            let id = CodeId::parse(&raw).expect("circle");
            assert_eq!(id.to_bytes().expect("id"), raw);
            let p = id.parameters();
            assert_eq!(p.message_len, 1usize << m);
            assert_eq!(p.codeword_len, 1usize << (m + b));
            assert_eq!(
                p.distance_lower_bound,
                if m == 0 {
                    p.codeword_len as u64
                } else {
                    (p.codeword_len - p.message_len) as u64
                }
            );
            assert_eq!(p.setup_loss_numerator, 0);
            assert!(!p.proven);
        }
    }
    let expected_edges: [u64; 13] = [
        0,
        9728,
        41984,
        156672,
        615424,
        2384896,
        9462784,
        36725760,
        145777664,
        581985280,
        2393924608,
        9641681920,
        38632711168,
    ];
    for j in 3..=15 {
        let raw = identity(j, 19);
        let id = CodeId::parse(&raw).expect("expander");
        assert_eq!(id.to_bytes().expect("id"), raw);
        let p = id.parameters();
        assert_eq!(p.message_len, 1usize << (2 * j));
        assert_eq!(p.codeword_len, 2 * p.message_len);
        assert_eq!(
            p.distance_lower_bound,
            if j == 3 {
                64
            } else {
                p.message_len as u64 / 25 + 1
            }
        );
        assert_eq!(p.setup_loss_numerator, if j == 3 { 0 } else { 200431782 });
        assert_eq!(p.edge_count, expected_edges[usize::from(j - 3)]);
        assert_eq!(p.raw_setup_bytes, 43 + 8 * p.edge_count);
        assert!(!p.proven);
        for profile in [Profile::Standard, Profile::Treaty] {
            assert_eq!(
                id.pcs_parameters(profile),
                Err(Error::UnsupportedParameters)
            );
        }
        if j > 3 {
            assert_eq!(id.prepare(0).err(), Some(Error::Capacity));
        }
    }
}
#[test]
fn rejects_identity_row_column_and_budget_errors() {
    let raw = identity(4, 0);
    for end in 0..raw.len() {
        assert_eq!(CodeId::parse(&raw[..end]).err(), Some(Error::InvalidCodeId));
    }
    for bad in [
        identity(2, 0),
        identity(16, 0),
        [raw.clone(), vec![0]].concat(),
        raw.iter()
            .enumerate()
            .map(|(i, b)| if i == 21 { b'1' } else { *b })
            .collect(),
    ] {
        assert_eq!(CodeId::parse(&bad).err(), Some(Error::InvalidCodeId));
    }
    let id = CodeId::parse(&raw).expect("id");
    let bytes = id.parameters().edge_count as usize * 8;
    assert_eq!(id.prepare(bytes - 1).err(), Some(Error::Capacity));
    let code = id.prepare(bytes).expect("exact graph budget");
    assert_eq!(code.graph_capacity_bytes(), bytes);
    assert_eq!(code.setup_hash_blocks(), 3162);
    let row = vec![M31::ONE; 256];
    assert_eq!(code.encode(&row[..255]), Err(Error::RowShape));
    assert_eq!(code.eval_row(&row[..255], &[]), Err(Error::RowShape));
    assert_eq!(code.eval_row(&row, &[0, 512]), Err(Error::Column));
    assert!(code.eval_row(&row, &[]).expect("empty").is_empty());
}
fn linearity<K: stele_code::Element + Eq + core::fmt::Debug>(values: impl Fn(usize) -> K) {
    for j in 3..=5 {
        let id = CodeId::parse(&identity(j, 0)).expect("id");
        let code = id.prepare(1 << 22).expect("setup");
        let n = code.parameters().message_len;
        let x: Vec<_> = (0..n).map(&values).collect();
        let y: Vec<_> = (0..n).map(|i| values(i + 3)).collect();
        let a = values(7);
        let combined: Vec<_> = x.iter().zip(&y).map(|(x, y)| *x + a * *y).collect();
        let first = code.encode(&x).expect("x");
        let second = code.encode(&y).expect("y");
        assert_eq!(
            code.encode(&combined).expect("linear"),
            first
                .iter()
                .zip(&second)
                .map(|(x, y)| *x + a * *y)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            code.eval_row(&x, &[2 * n - 1, 0, n, 0]).expect("queries"),
            vec![first[2 * n - 1], first[0], first[n], first[0]]
        );
        if j > 3 {
            assert_eq!(&first[..n], x);
        }
    }
}
#[test]
fn matches_reference_linearity_all_fields_and_seed_separation() {
    let q = |i| {
        QM31(
            CM31(M31::from_i64(i as i64), M31::from_i64(3 * i as i64 + 1)),
            CM31(
                M31::from_i64(5 * i as i64 + 2),
                M31::from_i64(7 * i as i64 + 3),
            ),
        )
    };
    linearity(|i| M31::from_i64(i as i64 - 19));
    linearity(q);
    linearity(|i| OM31(q(i), q(i + 11)));
    let codes: Vec<_> = [0, 1]
        .into_iter()
        .map(|seed| {
            CodeId::parse(&identity(4, seed))
                .expect("id")
                .prepare(1 << 20)
                .expect("setup")
        })
        .collect();
    assert_eq!(codes[0].parameters(), codes[1].parameters());
    let mut row = vec![M31::ZERO; 256];
    row[0] = M31::ONE;
    assert_ne!(codes[0].encode(&row), codes[1].encode(&row));
}

#[test]
fn matches_reference_live_capacity_including_query_overlap() {
    fn check<K: stele_code::Element + Eq + core::fmt::Debug>() {
        for j in 3..=6 {
            let code = CodeId::parse(&identity(j, 0))
                .expect("id")
                .prepare(1 << 24)
                .expect("setup");
            let n = code.parameters().message_len;
            let row = vec![K::from_i64(7); n];
            let report = code.encode_with_memory(&row).expect("encode");
            // Independent liveness recurrence: base output + max(transform buffers),
            // or top-level output and child z after y is released. Actual capacities
            // are exact on the pinned toolchain; this detects omitted overlap/stale y.
            let expected = code.graph_capacity_bytes()
                + if j == 3 {
                    128 * size_of::<K>() + 7 * size_of::<Vec<M31>>() + 127 * size_of::<M31>()
                } else {
                    5 * n / 2 * size_of::<K>()
                };
            assert_eq!(report.peak_owned_heap_bytes, expected);
            let query = code
                .eval_row_with_memory(&row, &[0, n, 2 * n - 1, 0])
                .expect("query");
            assert_eq!(
                query.peak_owned_heap_bytes,
                expected + query.word.capacity() * size_of::<K>()
            );
            assert_eq!(
                query.word,
                vec![
                    report.word[0],
                    report.word[n],
                    report.word[2 * n - 1],
                    report.word[0]
                ]
            );
            assert_eq!(
                code.eval_row_with_memory(&row, &[])
                    .expect("empty")
                    .peak_owned_heap_bytes,
                code.graph_capacity_bytes()
            );
        }
    }
    check::<M31>();
    check::<QM31>();
    check::<OM31>();
}
