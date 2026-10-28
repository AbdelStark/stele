//! RFC-0006 A1/A6: caller-owned buffers preserve all proof bytes and obligations.
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    message_bytes, message_bytes_into, message_size, prove, prove_into, verify_public, Dense,
    Error, Instance, Proof, Term,
};

fn fixture<K: ChallengeField>(m: u32, degree: usize, id: u64) -> (Instance<K>, Vec<Vec<K>>) {
    let c = Transcript::<K>::new(&id.to_le_bytes())
        .expect("domain")
        .challenge(ChallengeLabel::Sumcheck)
        .expect("fixture coefficient");
    let tables: Vec<Vec<K>> = (0..3)
        .map(|a| {
            (0..1usize << m)
                .map(|j| c * K::from_i64((a * 19 + j * 7) as i64 - 13))
                .collect()
        })
        .collect();
    let mut i = Instance {
        id,
        num_vars: m,
        inputs: vec![11, 12, 13],
        terms: vec![
            Term {
                coefficient: c,
                factors: (0..degree).map(|j| (j % 2) as u32).collect(),
            },
            Term {
                coefficient: K::from_i64(0),
                factors: vec![1; degree],
            },
            Term {
                coefficient: K::from_i64(-7),
                factors: vec![],
            },
        ],
        claimed_sum: K::from_i64(0),
    };
    for column in 0..1usize << m {
        for term in &i.terms {
            i.claimed_sum = i.claimed_sum
                + term
                    .factors
                    .iter()
                    .fold(term.coefficient, |product, input| {
                        product * tables[*input as usize][column]
                    });
        }
    }
    (i, tables)
}

fn buffers<K: ChallengeField>(m: u32, degree: usize, count: usize) -> Proof<K> {
    Proof {
        rounds: vec![vec![K::from_i64(0); degree + 1]; m as usize],
        final_values: vec![K::from_i64(0); count],
    }
}

fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    for degree in 0..=4 {
        for case in 0..1000 {
            let m = case % 4;
            let (i, tables) = fixture::<K>(m, degree, u64::from(case));
            let mut output = buffers::<K>(m, degree, 3);
            let pointers: Vec<_> = output
                .rounds
                .iter()
                .map(|v| (v.as_ptr(), v.capacity()))
                .collect();
            let outer = (output.rounds.as_ptr(), output.rounds.capacity());
            let finals = (output.final_values.as_ptr(), output.final_values.capacity());
            let mut bytes = vec![0xa5; i.encoded_len().expect("size") + 97];
            let bytes_pointer = (bytes.as_ptr(), bytes.capacity());
            let mut a = Transcript::<K>::new(b"buffer-parity").expect("domain");
            let mut b = Transcript::<K>::new(b"buffer-parity").expect("domain");
            let mut c = Transcript::<K>::new(b"buffer-parity").expect("domain");
            let mut state = Dense::new(&i, tables.clone()).expect("shape");
            prove_into(&i, &mut state, &mut output, &mut bytes, &mut a).expect("buffered proof");
            let reference = prove(&i, Dense::new(&i, tables.clone()).expect("shape"), &mut b)
                .expect("reference");
            assert_eq!(output, reference);
            let receipt = verify_public(&i, &output, &tables, &mut c).expect("original consumer");
            assert_eq!(receipt.claims.len(), 3);
            assert_eq!(receipt.sc.numerator, u64::from(m) * degree as u64);
            assert_eq!(receipt.sc.field_degree, K::DEGREE as u8);
            let next = a.challenge(ChallengeLabel::Sumcheck);
            assert_eq!(next, b.challenge(ChallengeLabel::Sumcheck));
            assert_eq!(next, c.challenge(ChallengeLabel::Sumcheck));
            assert_eq!(outer, (output.rounds.as_ptr(), output.rounds.capacity()));
            assert_eq!(
                finals,
                (output.final_values.as_ptr(), output.final_values.capacity())
            );
            assert_eq!(
                pointers,
                output
                    .rounds
                    .iter()
                    .map(|v| (v.as_ptr(), v.capacity()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(bytes_pointer, (bytes.as_ptr(), bytes.capacity()));
        }
    }
}

#[test]
fn matches_reference_buffered_qm31() {
    check::<QM31>();
}
#[test]
fn matches_reference_buffered_om31() {
    check::<OM31>();
}

#[test]
fn accepts_empty_inputs_and_reuses_proof_and_byte_buffers() {
    let mut a = Transcript::<QM31>::new(b"reuse").expect("domain");
    let mut b = Transcript::<QM31>::new(b"reuse").expect("domain");
    let mut output = buffers::<QM31>(3, 0, 0);
    let mut bytes = vec![0xff; 256];
    for id in 0..3 {
        let mut i = Instance {
            id,
            num_vars: 3,
            inputs: vec![],
            terms: vec![Term {
                coefficient: QM31::from_i64(9),
                factors: vec![],
            }],
            claimed_sum: QM31::from_i64(72),
        };
        if id == 1 {
            i.terms.clear();
            i.claimed_sum = QM31::from_i64(0);
        }
        let mut state = Dense::new(&i, vec![]).expect("shape");
        prove_into(&i, &mut state, &mut output, &mut bytes, &mut a).expect("buffered proof");
        assert_eq!(
            output,
            prove(&i, Dense::new(&i, vec![]).expect("shape"), &mut b).expect("reference")
        );
    }
    assert_eq!(
        a.challenge(ChallengeLabel::Sumcheck),
        b.challenge(ChallengeLabel::Sumcheck)
    );
}

#[test]
fn rejects_buffer_shapes_before_mutating_transcript() {
    let (i, tables) = fixture::<QM31>(2, 3, 7);
    let required = i
        .encoded_len()
        .expect("size")
        .max(message_size::<QM31>(4).expect("size"));
    for case in 0..4 {
        let mut output = buffers::<QM31>(2, 3, 3);
        let mut bytes = vec![0xa5; required];
        match case {
            0 => {
                output.rounds.pop();
            }
            1 => {
                output.rounds[0].pop();
            }
            2 => {
                output.final_values.pop();
            }
            _ => {
                bytes.pop();
            }
        }
        let mut state = Dense::new(&i, tables.clone()).expect("shape");
        let mut a = Transcript::<QM31>::new(b"preflight").expect("domain");
        let mut b = Transcript::<QM31>::new(b"preflight").expect("domain");
        assert_eq!(
            prove_into(&i, &mut state, &mut output, &mut bytes, &mut a),
            Err(if case == 3 {
                Error::Capacity
            } else {
                Error::ProofShape
            })
        );
        assert_eq!(
            a.challenge(ChallengeLabel::Sumcheck),
            b.challenge(ChallengeLabel::Sumcheck)
        );
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
    assert_eq!(message_size::<QM31>(usize::MAX), Err(Error::Capacity));
}

#[test]
fn matches_reference_payloads_and_rejects_short_buffers_without_partial_writes() {
    let (i, tables) = fixture::<OM31>(2, 4, 9);
    let expected = i.encode().expect("encode");
    assert_eq!(i.encoded_len(), Ok(expected.len()));
    let mut out = vec![0xa5; expected.len() + 11];
    assert_eq!(i.encode_into(&mut out), Ok(expected.len()));
    assert_eq!(&out[..expected.len()], expected);
    assert_eq!(&out[expected.len()..], &[0xa5; 11]);
    let mut short = vec![0xa5; expected.len() - 1];
    assert_eq!(i.encode_into(&mut short), Err(Error::Capacity));
    assert!(short.iter().all(|b| *b == 0xa5));
    let mut invalid = i.clone();
    invalid.inputs[1] = invalid.inputs[0];
    assert_eq!(invalid.encode_into(&mut out), Err(Error::InvalidInstance));
    let values = &tables[0];
    let expected = message_bytes(i.id, 3, values).expect("encode");
    let mut out = vec![0xa5; expected.len() + 11];
    assert_eq!(
        message_bytes_into(i.id, 3, values, &mut out),
        Ok(expected.len())
    );
    assert_eq!(&out[..expected.len()], expected);
    assert_eq!(&out[expected.len()..], &[0xa5; 11]);
    let mut short = vec![0xa5; expected.len() - 1];
    assert_eq!(
        message_bytes_into(i.id, 3, values, &mut short),
        Err(Error::Capacity)
    );
    assert!(short.iter().all(|b| *b == 0xa5));
}

#[test]
fn rejects_buffered_false_sum_and_invalid_descriptor() {
    for m in [0, 2] {
        let (mut i, tables) = fixture::<QM31>(m, 2, 17);
        let mut output = buffers::<QM31>(m, 2, 3);
        let mut bytes = vec![0; i.encoded_len().expect("size")];
        i.claimed_sum = i.claimed_sum + QM31::from_i64(1);
        let mut state = Dense::new(&i, tables).expect("shape");
        assert_eq!(
            prove_into(
                &i,
                &mut state,
                &mut output,
                &mut bytes,
                &mut Transcript::new(b"wrong-sum").expect("domain")
            ),
            Err(if m == 0 {
                Error::FinalEvaluationMismatch
            } else {
                Error::RoundSumMismatch
            })
        );
    }
    for invalid_ids in [false, true] {
        let (mut i, tables) = fixture::<QM31>(2, 2, 17);
        let mut state = Dense::new(&i, tables).expect("shape");
        let mut output = buffers::<QM31>(2, 2, 3);
        let mut bytes = vec![0xa5; 256];
        if invalid_ids {
            i.inputs[1] = i.inputs[0];
        } else {
            i.num_vars = 3;
        }
        let mut a = Transcript::new(b"descriptor").expect("domain");
        let mut b = Transcript::<QM31>::new(b"descriptor").expect("domain");
        assert_eq!(
            prove_into(&i, &mut state, &mut output, &mut bytes, &mut a),
            Err(if invalid_ids {
                Error::InvalidInstance
            } else {
                Error::PublicShape
            })
        );
        assert_eq!(
            a.challenge(ChallengeLabel::Sumcheck),
            b.challenge(ChallengeLabel::Sumcheck)
        );
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
}

fn unused_final<K: ChallengeField + Eq + core::fmt::Debug>() {
    let (i, tables) = fixture::<K>(3, 4, 29);
    let mut output = buffers::<K>(3, 4, 3);
    let mut bytes = vec![0; i.encoded_len().expect("size")];
    prove_into(
        &i,
        &mut Dense::new(&i, tables.clone()).expect("shape"),
        &mut output,
        &mut bytes,
        &mut Transcript::new(b"consumer").expect("domain"),
    )
    .expect("honest proof");
    let receipt = verify_public(
        &i,
        &output,
        &tables,
        &mut Transcript::new(b"consumer").expect("domain"),
    )
    .expect("honest acceptance");
    assert_eq!(receipt.claims.len(), tables.len());
    let mut changed = output.clone();
    changed.final_values[2] = changed.final_values[2] + K::from_i64(1);
    assert_eq!(changed.rounds, output.rounds);
    assert_eq!(
        changed
            .final_values
            .iter()
            .zip(&output.final_values)
            .filter(|(a, b)| a != b)
            .count(),
        1
    );
    assert_eq!(
        verify_public(
            &i,
            &changed,
            &tables,
            &mut Transcript::new(b"consumer").expect("domain")
        ),
        Err(Error::ClaimMismatch)
    );
}
#[test]
fn rejects_buffered_unused_final_value() {
    unused_final::<QM31>();
    unused_final::<OM31>();
}
