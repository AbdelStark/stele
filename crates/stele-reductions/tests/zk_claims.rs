//! RFC-0013 A5 items 1–6 and RFC-0026 A9: masked claims, an identity, a padded
//! identity and a matmul zero-sum through the actual verifier, in both fields.
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::CodeField;
use stele_reductions::zk::claims::{self, Column, Read, Relation, Statement};
use stele_reductions::zk::{Error, Seed};
use stele_sumcheck::Term;

fn term<K: ChallengeField>(coefficient: i64, factors: &[u32]) -> Term<K> {
    Term {
        coefficient: K::from_i64(coefficient),
        factors: factors.to_vec(),
    }
}

/// Source 0: `a·b = c` on 3 variables and `d² = d` on 1 (padded). Source 1:
/// `out = lhs·rhs` with 1 row bit, 3 inner bits and 1 column bit.
fn statement<K: ChallengeField>() -> Statement<K> {
    let column = |source, log_len| Column { source, log_len };
    Statement {
        sources: 2,
        columns: vec![
            column(0, 3), // a
            column(0, 3), // b
            column(0, 3), // c
            column(0, 1), // d
            column(1, 4), // lhs
            column(1, 4), // rhs
            column(1, 2), // out
        ],
        relations: vec![
            Relation::Identity {
                num_vars: 3,
                reads: (0..3)
                    .map(|column| Read {
                        column,
                        vars: vec![0, 1, 2],
                    })
                    .collect(),
                terms: vec![term(1, &[0, 1]), term(-1, &[2])],
            },
            Relation::Identity {
                num_vars: 1,
                reads: vec![Read {
                    column: 3,
                    vars: vec![0],
                }],
                terms: vec![term(1, &[0, 0]), term(-1, &[0])],
            },
            Relation::Matmul {
                lhs: 4,
                rhs: 5,
                out: 6,
                rows: 1,
                inner: 3,
                cols: 1,
            },
        ],
    }
}

fn witness(shift: i64) -> Vec<Vec<M31>> {
    let a: Vec<i64> = (0..8).map(|n| n + shift).collect();
    let b: Vec<i64> = (0..8).map(|n| 3 - 2 * n).collect();
    let c = a.iter().zip(&b).map(|(x, y)| x * y).collect();
    let lhs: Vec<i64> = (0..16).map(|n| (n * 7 + shift) % 11 - 5).collect();
    let rhs: Vec<i64> = (0..16).map(|n| (n * 5) % 9 - 4).collect();
    // out(i, j) = Σ_k lhs(i, k)·rhs(k, j); lhs is (i ‖ k), rhs (k ‖ j).
    let out = (0..4)
        .map(|ij| {
            let (i, j) = (ij >> 1, ij & 1);
            (0..8).map(|k| lhs[i * 8 + k] * rhs[k * 2 + j]).sum()
        })
        .collect();
    [a, b, c, vec![0, 1], lhs, rhs, out]
        .into_iter()
        .map(|v: Vec<i64>| v.into_iter().map(M31::from_i64).collect())
        .collect()
}

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"dev-zk claims").expect("transcript")
}

fn seed(n: u8) -> Seed {
    let mut bytes = [9; 32];
    bytes[0] = n;
    Seed::new(bytes)
}

fn mle<K: ChallengeField>(column: &[M31], point: &[K]) -> K {
    let eq = stele_poly::eq_table(point).expect("eq");
    column.iter().zip(&eq).fold(K::from_i64(0), |s, (x, e)| {
        s + *e * K::from_i64(i64::from(x.as_u32()))
    })
}

fn round_trip<K: ChallengeField + CodeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let s = statement::<K>();
    let w = witness(1);
    let proof = claims::prove(&s, &w, seed(1), &mut transcript()).expect("proof");
    let verified = claims::verify(&s, &proof, &mut transcript()).expect("accepted");
    // Three relations, two source batches and the shared batch, each masked.
    assert_eq!(verified.reductions.len(), 6);
    assert_eq!(verified.masks.len(), 6);
    // A5 item 3: identity a·b − c at degree 4 (eq·a·b with a's vanishing
    // variable), d² − d at 5 (repeated factor), matmul at 3; batches at 2.
    let degrees: Vec<u8> = verified.reductions.iter().map(|r| r.sc.degree).collect();
    assert_eq!(degrees, [4, 5, 3, 2, 2, 2]);
    // The identity's claim on `a` is masked: it is not a's MLE at the point.
    let point = &verified.reductions[0].point;
    assert_ne!(proof.relations[0].final_values[1], mle(&w[0], point));
    // Deterministic for a seed (INV-8); another seed moves every mask.
    assert_eq!(
        claims::prove(&s, &w, seed(1), &mut transcript()).expect("proof"),
        proof
    );
    assert_ne!(
        claims::prove(&s, &w, seed(2), &mut transcript()).expect("proof"),
        proof
    );
}

#[test]
fn accepts_masked_identity_and_matmul_zero_sum() {
    round_trip::<QM31>();
    round_trip::<OM31>();
}

/// A false witness (`c` off by one entry) fails in the prover's own rounds.
#[test]
fn rejects_false_identity_witness() {
    let s = statement::<QM31>();
    let mut w = witness(1);
    w[2][5] = w[2][5] + M31::ONE;
    assert_eq!(
        claims::prove(&s, &w, seed(1), &mut transcript()).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    );
}

/// A false matmul output fails the zero-sum.
#[test]
fn rejects_false_matmul_output() {
    let s = statement::<QM31>();
    let mut w = witness(1);
    w[6][2] = w[6][2] + M31::ONE;
    assert!(claims::prove(&s, &w, seed(1), &mut transcript()).is_err());
}

/// Bad statements are refused by both sides before any transcript work.
#[test]
fn rejects_invalid_statement() {
    let mut s = statement::<QM31>();
    s.columns[6].log_len = 3;
    let honest =
        claims::prove(&statement(), &witness(1), seed(1), &mut transcript()).expect("proof");
    assert_eq!(
        claims::verify(&s, &honest, &mut transcript()).err(),
        Some(Error::Statement)
    );
    let mut s = statement::<QM31>();
    s.relations[0] = Relation::Identity {
        num_vars: 3,
        reads: vec![Read {
            column: 0,
            vars: vec![0, 0, 1],
        }],
        terms: vec![term(1, &[0])],
    };
    assert_eq!(
        claims::prove(&s, &witness(1), seed(1), &mut transcript()).err(),
        Some(Error::Statement)
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

/// Lemma 6′ and Lemma 4 evidence over seeds, for two witnesses: the masked part
/// `c − x̃(ρ)` of a claim on `a`, the matmul's claim on `out` and a round value
/// are uniform (χ², 7 degrees of freedom, 0.999 quantile 24.3).
#[test]
fn accepts_uniform_claims_and_rounds() {
    let s = statement::<QM31>();
    for shift in [1, 40] {
        let w = witness(shift);
        let (mut residuals, mut outs, mut rounds) = (Vec::new(), Vec::new(), Vec::new());
        for n in 0..96u8 {
            let proof = claims::prove(&s, &w, seed(n), &mut transcript()).expect("proof");
            let verified = claims::verify(&s, &proof, &mut transcript()).expect("accepted");
            let point = &verified.reductions[0].point;
            residuals.push(first_limb(
                proof.relations[0].final_values[1] - mle(&w[0], point),
            ));
            outs.push(first_limb(proof.relations[2].final_values[2]));
            rounds.push(first_limb(proof.relations[2].rounds[0][2]));
        }
        for values in [&residuals, &outs, &rounds] {
            assert!(chi_square(values) < 30, "{}", chi_square(values));
        }
    }
}
