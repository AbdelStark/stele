//! RFC-0013 A2 item 2: masked A1 sumcheck through the actual verifier, and
//! evidence that the round messages are masked.
use core::fmt::Debug;
use stele_field::{Field, Inverse, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_sumcheck::masked::{self, Mask};
use stele_sumcheck::{prove, Dense, Error, Instance, Term};

/// Stand-in mask binding; the RFC-0013 A4 consumer binds real source bytes.
const BINDING: &[u8] = b"test mask binding";

fn table<K: ChallengeField>(m: u32, f: impl Fn(i64) -> i64) -> Vec<K> {
    (0..1i64 << m).map(|n| K::from_i64(f(n))).collect()
}

fn mle<K: ChallengeField>(table: &[K], point: &[K]) -> K {
    let weights = stele_poly::eq_table(point).expect("eq");
    table
        .iter()
        .zip(&weights)
        .fold(K::from_i64(0), |s, (x, w)| s + *x * *w)
}

/// `Σ a·b` over the cube with the claimed sum; degree 2.
fn product<K: ChallengeField>(a: &[K], b: &[K], m: u32) -> Instance<K> {
    Instance {
        id: 5,
        num_vars: m,
        inputs: vec![11, 12],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: a
            .iter()
            .zip(b)
            .fold(K::from_i64(0), |s, (x, y)| s + *x * *y),
    }
}

fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"masked A1").expect("transcript")
}

fn round_trip<K: ChallengeField + Eq + Debug>() {
    let m = 4;
    let (a, b) = (table::<K>(m, |n| n + 3), table::<K>(m, |n| 2 * n - 7));
    let i = product(&a, &b, m);
    let mask = Mask::derive(&[1; 32], &i).expect("mask");
    let proof = masked::prove(
        &i,
        Dense::new(&i, vec![a.clone(), b.clone()]).expect("dense"),
        &mask,
        BINDING,
        &mut transcript(),
    )
    .expect("proof")
    .0;
    assert_eq!(proof.mask_sum, mask.sum());
    let result = masked::verify(&i, &proof, BINDING, &mut transcript()).expect("accepted");
    let point = &result.reduction.point;
    assert_eq!(result.reduction.claims[0].1, mle(&a, point));
    assert_eq!(result.reduction.claims[1].1, mle(&b, point));
    assert_eq!(result.mask_final, mask.evaluate(point).expect("g(ρ)"));
    assert_eq!(result.reduction.sc.numerator, 8);
    assert_eq!(result.mask.id, i.id);

    // NC-0904 shape: G changed in an honest proof; the running claim moves by α·ΔG.
    let mut changed = proof.clone();
    changed.mask_sum = changed.mask_sum + K::from_i64(1);
    assert_eq!(
        masked::verify(&i, &changed, BINDING, &mut transcript()).err(),
        Some(Error::RoundSumMismatch)
    );
    // NC-0905 shape: μ changed.
    let mut changed = proof.clone();
    changed.mask_final = changed.mask_final + K::from_i64(1);
    assert_eq!(
        masked::verify(&i, &changed, BINDING, &mut transcript()).err(),
        Some(Error::FinalEvaluationMismatch)
    );
    // A false claim is rejected.
    let mut false_claim = i.clone();
    false_claim.claimed_sum = i.claimed_sum + K::from_i64(1);
    let mask = Mask::derive(&[1; 32], &false_claim).expect("mask");
    let forged = masked::prove(
        &false_claim,
        Dense::new(&false_claim, vec![a, b]).expect("dense"),
        &mask,
        BINDING,
        &mut transcript(),
    );
    assert_eq!(forged.err(), Some(Error::RoundSumMismatch));
}

#[test]
fn accepts_masked_sumcheck() {
    round_trip::<QM31>();
    round_trip::<OM31>();
}

/// A zerocheck in A1 form: `Σ eq(τ, x)·(a·b − c) = 0` with `c = a·b`.
#[test]
fn accepts_masked_zerocheck_in_a1_form() {
    let m = 3;
    let tau: Vec<QM31> = (0..m).map(|k| QM31::from_i64(17 + k as i64)).collect();
    let eq = stele_poly::eq_table(&tau).expect("eq");
    let (a, b) = (table::<QM31>(m, |n| n - 4), table::<QM31>(m, |n| 3 * n + 1));
    let c: Vec<QM31> = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
    let i = Instance {
        id: 9,
        num_vars: m,
        inputs: vec![1, 2, 3, 4],
        terms: vec![
            Term {
                coefficient: QM31::from_i64(1),
                factors: vec![0, 1, 2],
            },
            Term {
                coefficient: QM31::from_i64(-1),
                factors: vec![0, 3],
            },
        ],
        claimed_sum: QM31::from_i64(0),
    };
    let mask = Mask::derive(&[2; 32], &i).expect("mask");
    let tables = vec![eq.clone(), a, b, c];
    let proof = masked::prove(
        &i,
        Dense::new(&i, tables.clone()).expect("dense"),
        &mask,
        BINDING,
        &mut transcript(),
    )
    .expect("proof")
    .0;
    let result = masked::verify(&i, &proof, BINDING, &mut transcript()).expect("accepted");
    for (table, (_, value)) in tables.iter().zip(&result.reduction.claims) {
        assert_eq!(mle(table, &result.reduction.point), *value);
    }
    // One wrong entry of c breaks the zero sum: the honest prover cannot finish.
    let mut wrong = tables;
    wrong[3][5] = wrong[3][5] + QM31::from_i64(1);
    let forged = masked::prove(
        &i,
        Dense::new(&i, wrong).expect("dense"),
        &mask,
        BINDING,
        &mut transcript(),
    );
    assert_eq!(forged.err(), Some(Error::RoundSumMismatch));
}

#[test]
fn rejects_unmaskable_instances() {
    let i = Instance::<QM31> {
        id: 1,
        num_vars: 0,
        inputs: vec![],
        terms: vec![],
        claimed_sum: QM31::from_i64(0),
    };
    assert_eq!(
        Mask::derive(&[0; 32], &i).err(),
        Some(Error::InvalidInstance)
    );
}

/// First limb of `p_1(2)`, the first round value not fixed by the claim.
fn first_free_value(a: &[QM31], b: &[QM31], seed: Option<[u8; 32]>) -> u32 {
    let i = product(a, b, 4);
    let dense = Dense::new(&i, vec![a.to_vec(), b.to_vec()]).expect("dense");
    let value = match seed {
        Some(seed) => {
            let mask = Mask::derive(&seed, &i).expect("mask");
            masked::prove(&i, dense, &mask, BINDING, &mut transcript())
                .expect("proof")
                .0
                .rounds[0][2]
        }
        None => prove(&i, dense, &mut transcript()).expect("proof").rounds[0][2],
    };
    let bytes = stele_field::Serialize::to_le_bytes(value);
    u32::from_le_bytes(bytes.as_ref()[..4].try_into().expect("limb"))
}

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

/// Lemma 4: a round value that consistency does not fix is uniform over seeds,
/// for two different witnesses. Without the mask it is a fixed function of the
/// witness, and the test detects it.
#[test]
fn accepts_masked_rounds_and_rejects_unmasked() {
    let (a, b) = (table::<QM31>(4, |n| n), table::<QM31>(4, |n| n * n - 3));
    let (a2, b2) = (table::<QM31>(4, |n| 5 - n), table::<QM31>(4, |n| 1 + n));
    for (x, y) in [(&a, &b), (&a2, &b2)] {
        let values: Vec<u32> = (0..256u16)
            .map(|s| {
                let mut seed = [0; 32];
                seed[..2].copy_from_slice(&s.to_le_bytes());
                first_free_value(x, y, Some(seed))
            })
            .collect();
        // 7 degrees of freedom: 30 is beyond the 0.999 quantile (24.3).
        assert!(chi_square(&values) < 30, "{}", chi_square(&values));
    }
    let unmasked = first_free_value(&a, &b, None);
    assert!((0..8).all(|_| first_free_value(&a, &b, None) == unmasked));
    assert_ne!(unmasked, first_free_value(&a2, &b2, None));
}

/// The open gap R2, made visible: nothing binds `g`, so a prover that picks `μ`
/// after `ρ` passes the verifier with a false claimed sum. This is why the
/// module is hidden and no consumer may accept a masked reduction.
#[test]
fn accepts_forged_mask_final_for_a_false_sum() {
    use stele_hash::{AbsorbLabel, ChallengeLabel};
    use stele_sumcheck::message_bytes;
    let m = 3;
    let (a, b) = (table::<QM31>(m, |n| n + 1), table::<QM31>(m, |n| n - 2));
    let mut i = product(&a, &b, m);
    i.claimed_sum = i.claimed_sum + QM31::from_i64(5); // false
    let mut t = transcript::<QM31>();
    let mask_sum = QM31::from_i64(11);
    t.absorb(AbsorbLabel::Instance, &i.encode().expect("instance"))
        .expect("absorb");
    t.absorb(AbsorbLabel::FieldSources, BINDING)
        .expect("absorb");
    t.absorb(
        AbsorbLabel::ZkMaskSum,
        &message_bytes(i.id, 0, &[mask_sum]).expect("bytes"),
    )
    .expect("absorb");
    let alpha = t.challenge(ChallengeLabel::ZkMaskWeight).expect("alpha");
    let mut running = i.claimed_sum + alpha * mask_sum;
    let half = QM31::from_i64(2).inverse().expect("1/2");
    let mut rounds = Vec::new();
    for index in 0..m {
        // p(t) = running*(1-t)(2-t)/2: p(0) + p(1) = running, degree 2.
        let values = vec![running, QM31::from_i64(0), QM31::from_i64(0)];
        t.absorb(
            AbsorbLabel::Round,
            &message_bytes(i.id, index, &values).expect("bytes"),
        )
        .expect("absorb");
        let r = t.challenge(ChallengeLabel::Sumcheck).expect("rho");
        running = running * (r - QM31::from_i64(1)) * (r - QM31::from_i64(2)) * half;
        rounds.push(values);
    }
    let finals = vec![QM31::from_i64(1), QM31::from_i64(1)];
    let mask_final = (running - finals[0] * finals[1]) * alpha.inverse().expect("alpha != 0");
    let forged = masked::Proof {
        mask_sum,
        rounds,
        final_values: finals,
        mask_final,
    };
    assert!(masked::verify(&i, &forged, BINDING, &mut transcript()).is_ok());
}
