//! RFC-0010 A5 — observations must describe the actual unchanged encoding path.
use core::fmt::Debug;
use stele_code::{Circle, Code, CodeField, Encoder, Error};
use stele_field::{M31, OM31, QM31};

fn manifest(j: u8) -> [u8; 55] {
    let mut id = [0; 55];
    id[..22].copy_from_slice(b"stele/expander-seed/v2");
    id[22] = j;
    id
}
fn check<K: CodeField + Eq + Debug>() {
    let w = size_of::<K>();
    for j in 3..=6 {
        let code = Encoder::from_code_id(&manifest(j)).expect("identity");
        let n = 4usize.pow(u32::from(j));
        let row = vec![K::from_i64(7); n];
        let measured = code.encode_measured(&row).expect("encode");
        assert_eq!(measured.values, code.encode(&row).expect("ordinary"));
        let zero = code
            .encode_measured(&vec![K::from_i64(0); n])
            .expect("zero");
        assert_eq!(zero.work, measured.work);
        assert!(zero.values.iter().all(|value| *value == K::from_i64(0)));
        // Independent allocation liveness: outer word/scratch stay live through
        // the base temporary and its larger forward-twiddle allocation.
        let expected =
            (2 * n + (n - 64) / 3 + 128) * w + 127 * size_of::<M31>() + 7 * size_of::<Vec<M31>>();
        assert_eq!(measured.work.peak_owned_bytes, expected);
        assert_eq!(measured.work.generated_rows, code.info().row_count);
        assert_eq!(
            measured.work.sparse_limb_additions,
            code.info().sparse_edges * u64::from(K::DEGREE)
        );
        assert_eq!(
            measured.work.sparse_limb_products,
            measured.work.sparse_limb_additions
        );
        assert_eq!(
            measured.work.initialized_symbols,
            (2 * n + (n - 64) / 3 + 64) as u64
        );
        assert_eq!(
            measured.work.copied_symbols,
            (4..=j).map(|l| 4u64.pow(u32::from(l))).sum::<u64>() + 192
        );
        assert_eq!(measured.work.circle_calls, 1);
        assert_eq!(measured.work.circle_transform_additions, 1280);
        assert_eq!(measured.work.circle_transform_products, 704);
        assert_eq!(measured.work.twiddle_elements, 190);
        assert_eq!(measured.work.inverse_prefix_elements, 63);
        assert_eq!(measured.work.max_recursive_frames, j - 2);
        if j == 3 {
            assert_eq!(measured.work.hash_blocks, 0);
        }
        if j == 4 {
            assert_eq!(measured.work.hash_blocks, 3162);
        }
        let columns = [2 * n - 1, 0, n, 0];
        let query = code.eval_row_measured(&row, &columns).expect("query");
        assert_eq!(query.values, columns.map(|c| measured.values[c]));
        let mut expected_work = measured.work;
        expected_work.peak_owned_bytes += query.values.capacity() * w;
        expected_work.copied_symbols += columns.len() as u64;
        assert_eq!(query.work, expected_work);
        let empty = code.eval_row_measured(&row, &[]).expect("empty");
        assert!(empty.values.is_empty());
        assert_eq!(empty.work, Default::default());
        assert_eq!(
            code.encode_measured(&row[..n - 1]).err(),
            Some(Error::RowShape)
        );
        assert_eq!(
            code.eval_row_measured(&row, &[2 * n]).err(),
            Some(Error::Column)
        );
    }
    for m in 0..=7 {
        for b in [1, 2] {
            let circle = Circle::new(m, b).expect("circle");
            let code = Encoder::from_code_id(&circle.code_id()).expect("id");
            let row = vec![K::from_i64(-1); 1 << m];
            let result = code.encode_measured(&row).expect("measured circle");
            assert_eq!(result.values, circle.encode(&row).expect("reference"));
            let big = circle.codeword_len();
            let expected = big * w + (big - 1) * 4 + (m + b) as usize * size_of::<Vec<M31>>();
            assert_eq!(result.work.peak_owned_bytes, expected);
            assert_eq!(result.work.generated_rows, 0);
            assert_eq!(result.work.hash_blocks, 0);
        }
    }
}
#[test]
fn matches_reference_complete_work_and_capacity_all_fields() {
    check::<M31>();
    check::<QM31>();
    check::<OM31>();
}
