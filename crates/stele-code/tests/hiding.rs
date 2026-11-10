//! Algebraic evidence for the hiding-source design, formal/zk-development.md §3
//! (Q29, task E12-10). Tests only: no source, profile or privacy credit.
use stele_code::{Circle, Code, Encoder};
use stele_field::{Inverse, M31};

/// Rank over M31 by Gaussian elimination (rows are consumed).
fn rank(mut rows: Vec<Vec<M31>>) -> usize {
    let columns = rows.first().map_or(0, Vec::len);
    let mut rank = 0;
    for c in 0..columns {
        let Some(p) = (rank..rows.len()).find(|&i| rows[i][c] != M31::ZERO) else {
            continue;
        };
        rows.swap(rank, p);
        let inverse = rows[rank][c].inverse().expect("nonzero pivot");
        let pivot: Vec<M31> = rows[rank].iter().map(|v| *v * inverse).collect();
        for (i, row) in rows.iter_mut().enumerate() {
            if i != rank && row[c] != M31::ZERO {
                let f = row[c];
                for (value, p) in row.iter_mut().zip(&pivot) {
                    *value = *value - f * *p;
                }
            }
        }
        rows[rank] = pivot;
        rank += 1;
    }
    rank
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed >> 33
}

/// Codewords of the unit messages on the mask half (indices C..2C).
fn mask_map(code: &Circle, k: usize) -> Vec<Vec<M31>> {
    (k / 2..k)
        .map(|j| {
            let mut unit = vec![M31::ZERO; k];
            unit[j] = M31::ONE;
            code.encode(&unit).expect("encode")
        })
        .collect()
}

fn restrict(map: &[Vec<M31>], query: &[usize]) -> Vec<Vec<M31>> {
    map.iter()
        .map(|row| query.iter().map(|&c| row[c]).collect())
        .collect()
}

/// §3.2 Lemma 1: up to C-1 distinct queried positions, the mask half alone
/// reaches every value (so the queried symbols are uniform for any data half).
#[test]
fn matches_reference_mask_half_rank_below_budget() {
    let mut seed = 7;
    for m in 1..=6u32 {
        for b in 1..=2u32 {
            let code = Circle::new(m + 1, b).expect("code");
            let (k, n) = (code.message_len(), code.codeword_len());
            let map = mask_map(&code, k);
            for _ in 0..64 {
                let mut positions: Vec<usize> = (0..n).collect();
                let q = k / 2 - 1;
                for i in 0..q {
                    let j = i + next(&mut seed) as usize % (n - i);
                    positions.swap(i, j);
                }
                assert_eq!(rank(restrict(&map, &positions[..q])), q, "m={m} b={b}");
            }
        }
    }
}

/// The budget is sharp: some C distinct positions are not reached by the mask
/// half (the FFT span is one dimension short of the degree-C/2 circle space).
#[test]
fn rejects_query_budget_at_mask_width() {
    let code = Circle::new(2, 1).expect("code");
    let (k, n) = (code.message_len(), code.codeword_len());
    let map = mask_map(&code, k);
    let deficient = (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| [a, b]))
        .find(|q| rank(restrict(&map, q)) < 2);
    assert!(deficient.is_some());
}

/// §2: the v2 expander code copies its message into the codeword prefix, so a
/// mask placed anywhere in the message cannot hide a queried data position.
#[test]
fn rejects_systematic_expander_mask() {
    let mut id = [0; 55];
    id[..22].copy_from_slice(b"stele/expander-seed/v2");
    id[22] = 4;
    let code = Encoder::from_code_id(&id).expect("identity");
    let k = usize::try_from(code.info().message_len).expect("small");
    let data: Vec<M31> = (0..k / 2).map(|i| M31::from_u64(i as u64 + 3)).collect();
    for mask in [1u64, 99] {
        let message: Vec<M31> = data
            .iter()
            .copied()
            .chain((0..k / 2).map(|i| M31::from_u64(mask * (i as u64 + 1))))
            .collect();
        let word = code.encode(&message).expect("word");
        assert_eq!(word[..k / 2], data[..]);
    }
}
