//! RFC-0013 A5 item 5: production batch preparation for device qualification.
#![cfg(feature = "bench")]
use stele_field::{Field, CM31, M31, QM31};
use stele_hash::{HashUsage, Transcript};
use stele_pcs::{Policy, PreparedSource};
use stele_reductions::zk::claims::{bench::BatchInputs, Claim};
use stele_reductions::zk::Error;
use stele_sumcheck::{Dense, Summand};

fn extension(n: i64) -> QM31 {
    QM31(CM31(M31::from_i64(n), M31::ONE), CM31::ONE)
}

fn message() -> Vec<M31> {
    let mut values: Vec<_> = (0..16 * 1024)
        .map(|i| M31::from_i64((17 * i) % 101 - 50))
        .collect();
    values[..3].copy_from_slice(&[M31::ZERO, M31::ONE, -M31::ONE]);
    values
}

fn prepared(message: &[M31]) -> PreparedSource<'_, QM31> {
    PreparedSource::hiding_with(
        71,
        3,
        9,
        2,
        message,
        &[4; 32],
        &mut HashUsage::default(),
        Policy::Two,
    )
    .expect("hiding source")
}

fn embed(value: M31) -> QM31 {
    QM31::from_i64(i64::from(value.as_u32()))
}

fn claims(message: &[M31]) -> Vec<Claim<QM31>> {
    [
        vec![(0, QM31::ONE), (0, extension(2)), (511, extension(-1))],
        vec![(1, -QM31::ONE), (512, QM31::ONE), (4095, extension(3))],
    ]
    .into_iter()
    .map(|weights| Claim {
        value: weights.iter().fold(QM31::ZERO, |sum, (position, weight)| {
            sum + *weight * embed(message[position / 512 * 1024 + position % 512])
        }),
        weights,
    })
    .collect()
}

#[test]
fn matches_reference_batch_tables_rounds_and_finals() {
    let message = message();
    let prepared = prepared(&message);
    let claims = claims(&message);
    let gammas = [extension(5), extension(7)];
    let input = BatchInputs::new(19, &prepared, &claims, &gammas).expect("batch inputs");
    assert_eq!(input.instance.id, 19);
    assert_eq!(input.instance.num_vars, 13);
    assert_eq!(input.instance.inputs, [0, 1]);
    assert_eq!(input.instance.terms.len(), 1);
    assert_eq!(input.instance.terms[0].coefficient, QM31::ONE);
    assert_eq!(input.instance.terms[0].factors, [0, 1]);
    let face: Vec<_> = (0..8192)
        .map(|i| embed(message[i / 512 * 1024 + i % 512]))
        .collect();
    assert_eq!(input.face, face, "Y=0 in every data and mask row");
    let mut weights = vec![QM31::ZERO; 8192];
    for (claim, gamma) in claims.iter().zip(gammas) {
        for (position, weight) in &claim.weights {
            weights[*position] = weights[*position] + gamma * *weight;
        }
    }
    assert_eq!(input.weights, weights);
    assert!(input.weights[4096..].iter().all(|w| *w == QM31::ZERO));
    let sum = weights
        .iter()
        .zip(&face)
        .fold(QM31::ZERO, |s, (w, x)| s + *w * *x);
    assert_eq!(input.instance.claimed_sum, sum);
    let mut tables = vec![weights, face];
    let mut dense = Dense::new(&input.instance, tables.clone()).expect("production dense");
    for round in 0..13 {
        let half = tables[0].len() / 2;
        let expected: Vec<_> = (0..=2)
            .map(|node| {
                let t = QM31::from_i64(node);
                (0..half).fold(QM31::ZERO, |sum, i| {
                    sum + tables.iter().fold(QM31::ONE, |product, table| {
                        product * ((QM31::ONE - t) * table[i] + t * table[i + half])
                    })
                })
            })
            .collect();
        assert_eq!(dense.round(&input.instance).expect("round"), expected);
        let t = extension(round + 11);
        dense.fold(t).expect("fold");
        for table in &mut tables {
            for i in 0..half {
                table[i] = (QM31::ONE - t) * table[i] + t * table[i + half];
            }
            table.truncate(half);
        }
    }
    assert_eq!(
        dense.final_values().expect("finals"),
        [tables[0][0], tables[1][0]]
    );

    let mut near = claims.clone();
    near[1].value = near[1].value + QM31::ONE;
    let changed = BatchInputs::new(19, &prepared, &near, &gammas).expect("same input shapes");
    assert_eq!(changed.weights, input.weights);
    assert_eq!(changed.face, input.face);
    assert_eq!(changed.instance.claimed_sum - sum, gammas[1]);
    assert_ne!(
        changed.instance.claimed_sum, sum,
        "one claimed value changed"
    );
    let dense =
        Dense::new(&changed.instance, vec![changed.weights, changed.face]).expect("near miss");
    assert_eq!(
        stele_sumcheck::prove(
            &changed.instance,
            dense,
            &mut Transcript::new(b"batch near miss").expect("transcript")
        )
        .err(),
        Some(stele_sumcheck::Error::RoundSumMismatch)
    );
}

#[test]
fn rejects_batch_bench_invalid_weights_and_source() {
    let message = message();
    let prepared = prepared(&message);
    let mut claims = claims(&message);
    assert!(matches!(
        BatchInputs::new(0, &prepared, &claims, &[QM31::ONE]),
        Err(Error::Statement)
    ));
    claims[0].weights.push((4096, QM31::ZERO));
    assert!(matches!(
        BatchInputs::new(0, &prepared, &claims, &[QM31::ONE; 2]),
        Err(Error::Statement)
    ));
    claims[0].weights.pop();
    claims[0].weights.push((usize::MAX, QM31::ONE));
    assert!(matches!(
        BatchInputs::new(0, &prepared, &claims, &[QM31::ONE; 2]),
        Err(Error::Statement)
    ));
    let plain = PreparedSource::<QM31>::new(72, 4, 10, 2, &message, &mut HashUsage::default())
        .expect("plain source");
    assert!(matches!(
        BatchInputs::new(0, &plain, &[], &[]),
        Err(Error::Statement)
    ));
}

#[test]
fn accepts_batch_bench_empty_claims_and_zero_coefficients() {
    let message = message();
    let prepared = prepared(&message);
    for (claims, gammas) in [(vec![], vec![]), (claims(&message), vec![QM31::ZERO; 2])] {
        let input = BatchInputs::new(0, &prepared, &claims, &gammas).expect("zero batch");
        assert_eq!(input.instance.claimed_sum, QM31::ZERO);
        assert!(input.weights.iter().all(|w| *w == QM31::ZERO));
        assert_eq!(input.face.len(), 8192);
    }
}
