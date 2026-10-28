//! RFC-0006 A6: real source visits, bounded arena and original A1 consumers.
use stele_field::{Field, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    prove, prove_into, verify_public, Dense, Error, Instance, Proof, Source, Streaming, Summand,
    Term,
};

struct Rows<K> {
    ids: Vec<u64>,
    m: u32,
    rows: Vec<Vec<K>>,
    cursor: usize,
    visits: usize,
    reads: usize,
    fail_at: Option<usize>,
    changed_metadata: bool,
    fail_visit: Option<usize>,
    arena: Option<(usize, usize)>,
}
impl<K: Copy> Source<K> for Rows<K> {
    fn input_ids(&self) -> &[u64] {
        &self.ids
    }
    fn num_vars(&self) -> u32 {
        self.m
    }
    fn rewind(&mut self) -> Result<(), Error> {
        self.cursor = 0;
        self.visits += 1;
        if self.fail_visit == Some(self.visits) {
            return Err(Error::Source);
        }
        if self.changed_metadata {
            self.ids[0] += 1;
        }
        Ok(())
    }
    fn next_row(&mut self, out: &mut [K]) -> Result<bool, Error> {
        if self.fail_at == Some(self.cursor) {
            return Err(Error::Source);
        }
        let Some(row) = self.rows.get(self.cursor) else {
            return Ok(false);
        };
        if let Some((base, end)) = self.arena {
            let start = out.as_ptr() as usize;
            assert!(start >= base && start + core::mem::size_of_val(out) <= end);
        }
        out.copy_from_slice(row);
        self.cursor += 1;
        self.reads += 1;
        Ok(true)
    }
}
fn fixture<K: ChallengeField>(
    m: u32,
    degree: usize,
    seed: u64,
) -> (Instance<K>, Vec<Vec<K>>, Rows<K>) {
    let mut rng = Transcript::<K>::new(&seed.to_le_bytes()).expect("domain");
    let tables: Vec<Vec<K>> = (0..3)
        .map(|_| {
            (0..1usize << m)
                .map(|_| rng.challenge(ChallengeLabel::Sumcheck).expect("field"))
                .collect()
        })
        .collect();
    let terms = vec![
        Term {
            coefficient: K::from_i64(7),
            factors: (0..degree).map(|x| (x % 2) as u32).collect(),
        },
        Term {
            coefficient: K::from_i64(-3),
            factors: vec![],
        },
    ];
    let sum = (0..1usize << m).fold(K::from_i64(0), |sum, j| {
        sum + terms.iter().fold(K::from_i64(0), |s, t| {
            s + t
                .factors
                .iter()
                .fold(t.coefficient, |v, a| v * tables[*a as usize][j])
        })
    });
    let i = Instance {
        id: seed,
        num_vars: m,
        inputs: vec![1, 2, 3],
        terms,
        claimed_sum: sum,
    };
    let rows = (0..1usize << m)
        .map(|j| {
            let at = if m == 0 {
                0
            } else {
                j.reverse_bits() >> (usize::BITS - m)
            };
            tables.iter().map(|t| t[at]).collect()
        })
        .collect();
    let source = Rows {
        ids: i.inputs.clone(),
        m,
        rows,
        cursor: 0,
        visits: 0,
        reads: 0,
        fail_at: None,
        changed_metadata: false,
        fail_visit: None,
        arena: None,
    };
    (i, tables, source)
}
fn parity<K: ChallengeField + Eq + core::fmt::Debug>(
    m: u32,
    degree: usize,
    seed: u64,
    windows: &[u32],
) {
    let (i, tables, mut source) = fixture::<K>(m, degree, seed);
    let required = Streaming::<K, Rows<K>>::workspace_len(&i, windows).expect("plan");
    let mut work = Vec::with_capacity(required + 3);
    work.resize(required, K::from_i64(0));
    let capacity = work.capacity();
    let base = work.as_ptr() as usize;
    source.arena = Some((base, base + capacity * core::mem::size_of::<K>()));
    let mut state = Streaming::new(&i, source, windows, work, capacity).expect("source");
    let mut proof = Proof {
        rounds: vec![vec![K::from_i64(0); degree + 1]; m as usize],
        final_values: vec![K::from_i64(0); 3],
    };
    let mut bytes = vec![0; 512];
    let mut a = Transcript::new(b"stream").expect("domain");
    let mut b = Transcript::new(b"stream").expect("domain");
    let mut c = Transcript::new(b"stream").expect("domain");
    prove_into(&i, &mut state, &mut proof, &mut bytes, &mut a).expect("stream");
    assert_eq!(
        proof,
        prove(&i, Dense::new(&i, tables.clone()).expect("dense"), &mut b).expect("proof")
    );
    let receipt = verify_public(&i, &proof, &tables, &mut c).expect("original consumer");
    assert_eq!(receipt.claims.len(), 3);
    assert_eq!(receipt.sc.numerator, u64::from(m) * degree as u64);
    let next = a.challenge(ChallengeLabel::Sumcheck);
    assert_eq!(next, b.challenge(ChallengeLabel::Sumcheck));
    assert_eq!(next, c.challenge(ChallengeLabel::Sumcheck));
    assert_eq!(state.workspace_capacity(), capacity);
    assert_eq!(state.source().visits, windows.len() + 1);
    assert_eq!(state.source().reads, (windows.len() + 1) * (1usize << m));
}
fn cases<K: ChallengeField + Eq + core::fmt::Debug>() {
    let schedules: &[(u32, &[u32])] = &[
        (0, &[]),
        (3, &[]),
        (3, &[1]),
        (3, &[2]),
        (3, &[3]),
        (3, &[1, 1]),
        (3, &[1, 2]),
        (3, &[2, 1]),
        (3, &[1, 1, 1]),
    ];
    for degree in 0..=4 {
        for seed in 0..1000 {
            let (m, w) = schedules[seed as usize % schedules.len()];
            parity::<K>(m, degree, seed, w);
        }
    }
}
#[test]
fn matches_reference_streaming_qm31() {
    cases::<QM31>();
}
#[test]
fn matches_reference_streaming_om31() {
    cases::<OM31>();
}
#[test]
fn accepts_workspace_smaller_than_dense_input() {
    let (i, _, _) = fixture::<QM31>(10, 4, 1);
    let required =
        Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &[2, 2, 2, 2, 2]).expect("plan");
    assert_eq!(required, 43);
    assert!(required < 3 * (1 << 10));
    parity::<QM31>(10, 4, 1, &[2, 2, 2, 2, 2]);
}
#[test]
fn rejects_source_failures_and_capacity_overrun() {
    for case in 0..7 {
        let (i, _, mut source) = fixture::<QM31>(3, 2, 1);
        let need = Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &[1]).expect("plan");
        let mut work = vec![QM31::from_i64(0); need];
        let mut budget = work.capacity();
        let expected = match case {
            0 => {
                source.rows.pop();
                Error::Source
            }
            1 => {
                source.rows.push(source.rows[0].clone());
                Error::Source
            }
            2 => {
                source.fail_at = Some(3);
                Error::Source
            }
            3 => {
                source.ids[0] = 9;
                Error::PublicShape
            }
            4 => {
                source.changed_metadata = true;
                Error::PublicShape
            }
            5 => {
                work.pop();
                Error::Capacity
            }
            _ => {
                budget -= 1;
                Error::Capacity
            }
        };
        assert!(matches!(Streaming::new(&i,source,&[1],work,budget),Err(e) if e==expected));
    }
    let (i, _, _) = fixture::<QM31>(3, 2, 1);
    for windows in [&[0][..], &[4][..], &[2, 2][..]] {
        assert_eq!(
            Streaming::<QM31, Rows<QM31>>::workspace_len(&i, windows),
            Err(Error::InvalidStreaming)
        );
    }
    let mut i = i;
    i.num_vars = 64;
    assert_eq!(
        Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &[]),
        Err(Error::Capacity)
    );
}
#[test]
fn rejects_cached_instance_even_without_rounds() {
    for m in [0, 3] {
        let (i, _, source) = fixture::<QM31>(m, 2, 1);
        let n = Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &[]).expect("plan");
        let mut state =
            Streaming::new(&i, source, &[], vec![QM31::from_i64(0); n], n).expect("source");
        let mut other = i.clone();
        other.id += 1;
        let mut proof = Proof {
            rounds: vec![vec![QM31::from_i64(0); 3]; m as usize],
            final_values: vec![QM31::from_i64(0); 3],
        };
        let mut a = Transcript::new(b"cached").expect("domain");
        let mut b = Transcript::<QM31>::new(b"cached").expect("domain");
        assert_eq!(
            prove_into(&other, &mut state, &mut proof, &mut [0; 512], &mut a),
            Err(Error::InvalidStreaming)
        );
        assert_eq!(
            a.challenge(ChallengeLabel::Sumcheck),
            b.challenge(ChallengeLabel::Sumcheck)
        );
    }
}

#[test]
fn accepts_no_inputs_without_source_access() {
    for m in [0, 3, 63] {
        for windows in [vec![], if m == 0 { vec![] } else { vec![1, 2] }] {
            for constant in [0, 7] {
                let mut sum = QM31::from_i64(constant);
                for _ in 0..m {
                    sum = sum + sum;
                }
                let i = Instance {
                    id: 1,
                    num_vars: m,
                    inputs: vec![],
                    terms: if constant == 0 {
                        vec![]
                    } else {
                        vec![Term {
                            coefficient: QM31::from_i64(constant),
                            factors: vec![],
                        }]
                    },
                    claimed_sum: sum,
                };
                let source = Rows {
                    ids: vec![],
                    m,
                    rows: vec![],
                    cursor: 0,
                    visits: 0,
                    reads: 0,
                    fail_at: Some(0),
                    changed_metadata: false,
                    fail_visit: Some(1),
                    arena: None,
                };
                let n = Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &windows).expect("plan");
                let mut state = Streaming::new(&i, source, &windows, vec![QM31::from_i64(0); n], n)
                    .expect("no source reads");
                let mut out = Proof {
                    rounds: vec![vec![QM31::from_i64(0)]; m as usize],
                    final_values: vec![],
                };
                let mut a = Transcript::new(b"empty").expect("domain");
                let mut b = Transcript::new(b"empty").expect("domain");
                prove_into(&i, &mut state, &mut out, &mut [0; 512], &mut a).expect("empty proof");
                assert_eq!(
                    out,
                    prove(&i, Dense::new(&i, vec![]).expect("dense"), &mut b).expect("proof")
                );
                assert_eq!(state.source().visits, 0);
                assert_eq!(
                    a.challenge(ChallengeLabel::Sumcheck),
                    b.challenge(ChallengeLabel::Sumcheck)
                );
            }
        }
    }
}
#[test]
fn rejects_source_failure_during_window_transition() {
    let (i, _, mut source) = fixture::<QM31>(3, 2, 1);
    source.fail_visit = Some(2);
    let n = Streaming::<QM31, Rows<QM31>>::workspace_len(&i, &[1, 1]).expect("plan");
    let mut state =
        Streaming::new(&i, source, &[1, 1], vec![QM31::from_i64(0); n], n).expect("first visit");
    assert_eq!(state.fold(QM31::from_i64(0)), Err(Error::Source));
}
#[test]
fn matches_reference_zero_and_one_challenges() {
    let (i, tables, source) = fixture::<OM31>(4, 4, 1);
    let n = Streaming::<OM31, Rows<OM31>>::workspace_len(&i, &[1, 2]).expect("plan");
    let mut state =
        Streaming::new(&i, source, &[1, 2], vec![OM31::from_i64(0); n], n).expect("source");
    let mut dense = Dense::new(&i, tables).expect("dense");
    for r in [0, 1, 0, 1] {
        assert_eq!(state.round(&i), dense.round(&i));
        state.fold(OM31::from_i64(r)).expect("stream fold");
        dense.fold(OM31::from_i64(r)).expect("dense fold");
    }
    assert_eq!(state.final_values(), dense.final_values());
}

fn suffix_contributions<K: ChallengeField + Eq + core::fmt::Debug>() {
    for degree in 1..=4 {
        let (mut i, _, source) = fixture::<K>(4, degree, 71);
        i.terms.pop(); // Constant multiplicity has its own no-input test; here P(0)=0.
        i.claimed_sum = i.claimed_sum + K::from_i64(3 * 16);
        let n = Streaming::<K, Rows<K>>::workspace_len(&i, &[2]).expect("plan");
        let mut full = Streaming::new(&i, source, &[2], vec![K::from_i64(0); n], n).expect("full");
        let first = full.round(&i).expect("first round");
        full.fold(K::from_i64(17)).expect("non-Boolean challenge");
        let second = full.round(&i).expect("second round");
        let mut totals = [
            vec![K::from_i64(0); degree + 1],
            vec![K::from_i64(0); degree + 1],
        ];
        for suffix in 0..4 {
            let (_, _, mut source) = fixture::<K>(4, degree, 71);
            for (physical, row) in source.rows.iter_mut().enumerate() {
                let canonical = physical.reverse_bits() >> (usize::BITS - 4);
                if canonical & 3 != suffix {
                    row.fill(K::from_i64(0));
                }
            }
            let mut partial = i.clone();
            partial.claimed_sum = source.rows.iter().fold(K::from_i64(0), |sum, row| {
                sum + partial.terms[0]
                    .factors
                    .iter()
                    .fold(partial.terms[0].coefficient, |v, f| v * row[*f as usize])
            });
            let mut state = Streaming::new(&partial, source, &[2], vec![K::from_i64(0); n], n)
                .expect("one suffix");
            for total in &mut totals {
                for (sum, value) in total
                    .iter_mut()
                    .zip(state.round(&partial).expect("partial round"))
                {
                    *sum = *sum + value;
                }
                state.fold(K::from_i64(17)).expect("fold");
            }
        }
        assert_eq!(totals, [first, second]);
    }
}
#[test]
fn matches_reference_window_suffix_contributions() {
    suffix_contributions::<QM31>();
    suffix_contributions::<OM31>();
}
