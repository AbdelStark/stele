//! RFC-0008 A7: ZK-GKR over the A5 fraction tree through the actual verifier, in
//! both fields: the committed top, masked layer steps and masked leaves.
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::CodeField;
use stele_reductions::zk::claims::{self, Column, Lookup, Statement};
use stele_reductions::zk::{Error, Seed};

/// `n = c_D + 2`: one masked layer between the committed top and the leaves.
fn bits<K: CodeField>() -> u32 {
    (<K as CodeField>::DEGREE as u32).trailing_zeros() + 2
}

/// One source: the tuple column `x` and its multiplicities, into a table of
/// `3j + 1` with the last quarter padding.
fn statement<K: ChallengeField + CodeField>() -> Statement<K> {
    let n = bits::<K>();
    let rows = 1usize << n;
    Statement {
        sources: 1,
        columns: vec![
            Column {
                source: 0,
                log_len: n,
            },
            Column {
                source: 0,
                log_len: n,
            },
        ],
        relations: Vec::new(),
        lookups: vec![Lookup {
            columns: vec![0],
            multiplicity: 1,
            table: (0..rows as i64).map(|j| vec![3 * j + 1]).collect(),
            valid: 3 * rows / 4,
        }],
    }
}

/// Lookups of valid rows chosen by `pick`, and their counts.
fn witness<K: CodeField>(pick: impl Fn(usize) -> usize) -> Vec<Vec<M31>> {
    let rows = 1usize << bits::<K>();
    let valid = 3 * rows / 4;
    let mut counts = vec![0i64; rows];
    let x: Vec<M31> = (0..rows)
        .map(|i| {
            let j = pick(i) % valid;
            counts[j] += 1;
            M31::from_i64(3 * j as i64 + 1)
        })
        .collect();
    vec![x, counts.into_iter().map(M31::from_i64).collect()]
}

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"dev-zk lookup").expect("transcript")
}

fn seed(n: u8) -> Seed {
    let mut bytes = [5; 32];
    bytes[0] = n;
    Seed::new(bytes)
}

/// The tree layer `k` of the test's lookup, recomputed from the witness and the
/// public `β, α` (the verifier never sees it).
fn layer<K: ChallengeField>(
    s: &Statement<K>,
    w: &[Vec<M31>],
    beta: K,
    alpha: K,
    k: usize,
) -> Vec<[K; 2]> {
    let lookup = &s.lookups[0];
    let value = |v: i64| K::from_i64(v);
    let mut layer = Vec::new();
    for (i, row) in lookup.table.iter().enumerate() {
        let x = K::from_i64(i64::from(w[0][i].as_u32()));
        layer.push([value(1), alpha - x]);
        let q = if i < lookup.valid {
            alpha - value(row[0])
        } else {
            value(1)
        };
        layer.push([value(0) - K::from_i64(i64::from(w[1][i].as_u32())), q]);
    }
    let _ = beta; // c = 1: Σ β^i x_i = x.
    while layer.len() > 1 << k {
        layer = layer
            .chunks_exact(2)
            .map(|p| [p[0][0] * p[1][1] + p[1][0] * p[0][1], p[0][1] * p[1][1]])
            .collect();
    }
    layer
}

fn mle<K: ChallengeField>(values: impl Iterator<Item = K>, point: &[K]) -> K {
    let eq = stele_poly::eq_table(point).expect("eq");
    values.zip(&eq).fold(K::from_i64(0), |s, (v, e)| s + v * *e)
}

fn round_trip<K: ChallengeField + CodeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let s = statement::<K>();
    let w = witness::<K>(|i| 5 * i + 2);
    let proof = claims::prove(&s, &w, seed(1), &mut transcript()).expect("proof");
    let verified = claims::verify(&s, &proof, &mut transcript()).expect("accepted");
    // Two top relations, two GKR steps, two source batches and the shared batch.
    assert_eq!(proof.relations.len(), 2);
    assert_eq!(proof.gkr.len(), 2);
    assert_eq!(verified.reductions.len(), 7);
    // Declared degrees (A7 implementation notes): the first step 7 (`q0·q1`, `v ∈ u`), the
    // leaf step 4.
    assert_eq!(verified.reductions[2].sc.degree, 7);
    assert_eq!(verified.reductions[3].sc.degree, 4);
    // The first step reveals the masked layer below the top: never its true value.
    let [beta, alpha] = verified.lookups[0];
    let k0 = bits::<K>() as usize - 1;
    let point = &verified.reductions[2].point;
    let below = layer(&s, &w, beta, alpha, k0 + 1);
    let mut at = point.clone();
    at.push(K::from_i64(0));
    let exact = mle(below.iter().map(|v| v[0]), &at);
    assert_ne!(proof.gkr[0].final_values[3], exact);
    assert_eq!(
        claims::prove(&s, &w, seed(1), &mut transcript()).expect("proof"),
        proof
    );
}

#[test]
fn accepts_masked_gkr_lookup() {
    round_trip::<QM31>();
    round_trip::<OM31>();
}

/// A5 soundness is kept: a tuple outside the table cannot be counted, so the tree
/// sum is not zero and `Σ h = 0` fails in the prover's own rounds.
#[test]
fn rejects_tuple_outside_table() {
    let s = statement::<QM31>();
    let mut w = witness::<QM31>(|i| i);
    w[0][3] = M31::from_i64(2); // not 3j + 1
    assert_eq!(
        claims::prove(&s, &w, seed(1), &mut transcript()).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    );
}

/// Wrong multiplicities are rejected the same way.
#[test]
fn rejects_wrong_multiplicity() {
    let s = statement::<QM31>();
    let mut w = witness::<QM31>(|i| i);
    w[1][0] = w[1][0] + M31::ONE;
    assert!(claims::prove(&s, &w, seed(1), &mut transcript()).is_err());
}

/// An honest proof against a statement with one table row changed: the leaf
/// step's public table final disagrees.
#[test]
fn rejects_changed_table() {
    let s = statement::<QM31>();
    let proof =
        claims::prove(&s, &witness::<QM31>(|i| i), seed(1), &mut transcript()).expect("proof");
    let mut other = s.clone();
    other.lookups[0].table[1][0] += 1;
    assert_eq!(
        claims::verify(&other, &proof, &mut transcript()).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::ClaimMismatch))
    );
}

/// Pearson statistic of the top three bits against the uniform distribution.
fn chi_square(values: &[u32]) -> u64 {
    let mut counts = [0u64; 8];
    for value in values {
        counts[(*value >> 28) as usize] += 1;
    }
    let n = values.len() as u64;
    counts
        .iter()
        .map(|count| (8 * count).abs_diff(n).pow(2) / (8 * n))
        .sum()
}

fn first_limb(value: QM31) -> u32 {
    let bytes = stele_field::Serialize::to_le_bytes(value);
    u32::from_le_bytes(bytes.as_ref()[..4].try_into().expect("limb"))
}

/// Lemma 6′ for layer blocks (check_gkr.py): over seeds and two witnesses, the
/// masked part `V̇ − Ṽ` of a revealed layer value, the revealed `q` value and the
/// leaf step's claim on `x` are uniform (χ², 7 dof, threshold 30).
#[test]
fn accepts_uniform_layer_values() {
    let s = statement::<QM31>();
    for shift in [1usize, 7] {
        let w = witness::<QM31>(|i| 3 * i + shift);
        let (mut residuals, mut values, mut leaves) = (Vec::new(), Vec::new(), Vec::new());
        for n in 0..96u8 {
            let proof = claims::prove(&s, &w, seed(n), &mut transcript()).expect("proof");
            let verified = claims::verify(&s, &proof, &mut transcript()).expect("accepted");
            let [beta, alpha] = verified.lookups[0];
            let mut at = verified.reductions[2].point.clone();
            at.push(QM31::from_i64(0));
            let below = layer(&s, &w, beta, alpha, 4);
            let exact = mle(below.iter().map(|v| v[0]), &at);
            residuals.push(first_limb(proof.gkr[0].final_values[3] - exact));
            values.push(first_limb(proof.gkr[0].final_values[5]));
            leaves.push(first_limb(proof.gkr[1].final_values[6]));
        }
        for v in [&residuals, &values, &leaves] {
            assert!(chi_square(v) < 30, "{}", chi_square(v));
        }
    }
}

/// RFC-0008 A7 item 4: the `s = 1` half's block finals are claims on the committed
/// blocks. An adversary that moves both block finals of the leaf step while
/// keeping its final check (and `μ`) intact is rejected by the shared batch only.
#[test]
fn rejects_unbound_block_finals() {
    let s = statement::<QM31>();
    let w = witness::<QM31>(|i| i);
    let forged = claims::forge_block(&s, &w, seed(3), &mut transcript(), 1).expect("forgery");
    assert_eq!(
        claims::verify(&s, &forged, &mut transcript()).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    );
}
