//! RFC-0013 A4: the bound masked A1 sumcheck through the actual verifiers.
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, Transcript};
use stele_reductions::zk::{self, Error};
use stele_sumcheck::{Dense, Instance, Term};

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

fn product<K: ChallengeField>(a: &[K], b: &[K], m: u32) -> Instance<K> {
    Instance {
        id: 7,
        num_vars: m,
        inputs: vec![1, 2],
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
    Transcript::new(b"bound masked A1").expect("transcript")
}

fn round_trip<K: ChallengeField + stele_pcs::CodeField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let m = 4;
    let (a, b) = (table::<K>(m, |n| n + 3), table::<K>(m, |n| 2 * n - 7));
    let i = product(&a, &b, m);
    let dense = || Dense::new(&i, vec![a.clone(), b.clone()]).expect("dense");
    let proof = zk::prove(&i, dense(), zk::Seed::new([4; 32]), &mut transcript()).expect("proof");
    let (reduction, mask) = zk::verify(&i, &proof, &mut transcript()).expect("accepted");
    assert_eq!(reduction.claims[0].1, mle(&a, &reduction.point));
    assert_eq!(reduction.claims[1].1, mle(&b, &reduction.point));
    assert_eq!(mask.id, i.id);

    // NC-0907 shape: another seed's mask source and certificate substituted.
    let other = zk::prove(&i, dense(), zk::Seed::new([5; 32]), &mut transcript()).expect("proof");
    let mut swapped = proof.clone();
    swapped.source = other.source.clone();
    swapped.certificate = other.certificate.clone();
    assert_eq!(
        zk::verify(&i, &swapped, &mut transcript()).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    );
}

#[test]
fn accepts_bound_masked_sumcheck() {
    round_trip::<QM31>();
    round_trip::<OM31>();
}

/// The A2 forgery (rounds chosen freely, `μ` solved last for a false sum) now
/// needs an opening of the committed mask at `μ`: the actual opening verifier
/// rejects the honest row against the forged value (NC-0908 shape).
#[test]
fn rejects_forged_mask_final() {
    use stele_hash::{AbsorbLabel, ChallengeLabel};
    use stele_sumcheck::message_bytes;
    let m = 3;
    let (a, b) = (table::<QM31>(m, |n| n + 1), table::<QM31>(m, |n| n - 2));
    let honest_instance = product(&a, &b, m);
    let mut i = honest_instance.clone();
    i.claimed_sum = i.claimed_sum + QM31::from_i64(5); // false
    let honest = zk::prove(
        &i,
        Dense::new(&honest_instance, vec![a, b]).expect("dense"),
        zk::Seed::new([6; 32]),
        &mut transcript(),
    );
    // The honest prover cannot prove the false sum.
    assert!(honest.is_err());
    // Reuse a genuine mask source, certificate and opening for this instance id.
    let (c, d) = (table::<QM31>(m, |n| n), table::<QM31>(m, |n| n));
    let genuine_instance = product(&c, &d, m);
    let mut genuine = zk::prove(
        &genuine_instance,
        Dense::new(&genuine_instance, vec![c, d]).expect("dense"),
        zk::Seed::new([6; 32]),
        &mut transcript(),
    )
    .expect("genuine");
    let mut t = transcript::<QM31>();
    t.absorb(AbsorbLabel::Instance, &i.encode().expect("instance"))
        .expect("absorb");
    t.absorb(AbsorbLabel::FieldSources, &genuine.source)
        .expect("absorb");
    let mask_sum = genuine.sumcheck.mask_sum;
    t.absorb(
        AbsorbLabel::ZkMaskSum,
        &message_bytes(i.id, 0, &[mask_sum]).expect("bytes"),
    )
    .expect("absorb");
    let alpha = t.challenge(ChallengeLabel::ZkMaskWeight).expect("alpha");
    let mut running = i.claimed_sum + alpha * mask_sum;
    let half = stele_field::Inverse::inverse(QM31::from_i64(2)).expect("1/2");
    let mut rounds = Vec::new();
    for index in 0..m {
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
    let alpha_inverse = stele_field::Inverse::inverse(alpha).expect("alpha != 0");
    genuine.sumcheck.rounds = rounds;
    genuine.sumcheck.final_values = finals.clone();
    genuine.sumcheck.mask_final = (running - finals[0] * finals[1]) * alpha_inverse;
    assert_eq!(
        zk::verify(&i, &genuine, &mut transcript()).err(),
        Some(Error::Pcs(stele_pcs::Error::ValueMismatch))
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

/// A4 Lemma 5 evidence: the first round's free value and the first limb of the
/// mask opening row are uniform over seeds, for two different witnesses.
#[test]
fn accepts_masked_rounds_and_opening_row() {
    let witnesses = [
        (table::<QM31>(3, |n| n), table::<QM31>(3, |n| n * n - 3)),
        (table::<QM31>(3, |n| 5 - n), table::<QM31>(3, |n| 1 + n)),
    ];
    for (a, b) in &witnesses {
        let i = product(a, b, 3);
        let (mut rounds, mut rows) = (Vec::new(), Vec::new());
        for s in 0..128u8 {
            let mut seed = [0; 32];
            seed[0] = s;
            seed[1] = 1;
            let dense = Dense::new(&i, vec![a.clone(), b.clone()]).expect("dense");
            let proof =
                zk::prove(&i, dense, zk::Seed::new(seed), &mut transcript()).expect("proof");
            let value = stele_field::Serialize::to_le_bytes(proof.sumcheck.rounds[0][2]);
            rounds.push(u32::from_le_bytes(
                value.as_ref()[..4].try_into().expect("limb"),
            ));
            rows.push(u32::from_le_bytes(
                proof.opening[1..5].try_into().expect("limb"),
            ));
        }
        // 7 degrees of freedom: 30 is beyond the 0.999 quantile (24.3).
        assert!(chi_square(&rounds) < 30, "{}", chi_square(&rounds));
        assert!(chi_square(&rows) < 30, "{}", chi_square(&rows));
    }
}
