//! RFC-0006 A1/A5: randomized byte identity of the base-field prover paths (task E20-01)
//! against the all-extension reference, on edge shapes. From the E20-01/E20-02 review (F4).
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    claim_batch::Batch, parallel, prove, zerocheck::Zerocheck, Dense, DenseTable, Instance, Term,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// Base-field value biased towards the edges 0, 1, p-1, p-2 and small negatives.
    fn m31(&mut self) -> M31 {
        match self.below(8) {
            0 => M31::ZERO,
            1 => M31::ONE,
            2 => M31::from_i64(-1),
            3 => M31::from_i64(-2),
            4 => M31::from_i64(-(self.below(40_000) as i64)),
            5 => M31::from_i64(self.below(70_000) as i64),
            _ => M31::from_i64((self.next() >> 1) as i64),
        }
    }
}

/// Genuine extension elements: transcript challenges (all coordinates populated).
struct Ext<K: ChallengeField>(Transcript<K>);
impl<K: ChallengeField> Ext<K> {
    fn new(seed: &[u8]) -> Self {
        Self(Transcript::new(seed).expect("t"))
    }
    fn k(&mut self) -> K {
        self.0.challenge(ChallengeLabel::Sumcheck).expect("c")
    }
}

fn embed<K: ChallengeField>(v: M31) -> K {
    K::from_i64(i64::from(v.as_u32()))
}

fn fold_base_matches<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(1);
    let mut ext = Ext::<K>::new(b"review/fold");
    for log in 1..=13u32 {
        for _ in 0..3 {
            let base: Vec<M31> = (0..1usize << log).map(|_| rng.m31()).collect();
            let mut reference: Vec<K> = base.iter().map(|v| embed(*v)).collect();
            let r = ext.k();
            parallel::fold(&mut reference, r);
            assert_eq!(parallel::fold_base(&base, r).expect("fold_base"), reference);
        }
    }
    // Shape errors instead of panics on a length-1 or non-power-of-two table.
    assert!(parallel::fold_base::<K>(&[M31::ONE], ext.k()).is_err());
    assert!(parallel::fold_base::<K>(&[M31::ONE; 3], ext.k()).is_err());
}

#[test]
fn matches_reference_fold_on_extension_challenges() {
    fold_base_matches::<QM31>();
    fold_base_matches::<OM31>();
}

fn dense_mixed_matches<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(7);
    let mut ext = Ext::<K>::new(b"review/dense");
    let mut cases = 0;
    for nv in 0..=12u32 {
        let n = 1usize << nv;
        let reps = if nv <= 6 { 40 } else { 4 };
        for _ in 0..reps {
            let inputs = rng.below(6) as usize; // 0..=5 tables, including none
            let mut mixed = Vec::new();
            let mut reference = Vec::new();
            // 0: all base, 1: all ext, otherwise mixed.
            let mode = rng.below(4);
            for _ in 0..inputs {
                let base = match mode {
                    0 => true,
                    1 => false,
                    _ => rng.below(2) == 0,
                };
                if base {
                    let t: Vec<M31> = (0..n).map(|_| rng.m31()).collect();
                    reference.push(t.iter().map(|v| embed::<K>(*v)).collect::<Vec<K>>());
                    mixed.push(DenseTable::Base(t));
                } else {
                    let t: Vec<K> = (0..n).map(|_| ext.k()).collect();
                    reference.push(t.clone());
                    mixed.push(DenseTable::Ext(t));
                }
            }
            let mut terms = Vec::new();
            for _ in 0..rng.below(6) {
                let factors: Vec<u32> = if inputs == 0 {
                    Vec::new()
                } else {
                    (0..rng.below(5))
                        .map(|_| rng.below(inputs as u64) as u32)
                        .collect()
                };
                let coefficient = match rng.below(5) {
                    0 => K::from_i64(0),
                    1 => K::from_i64(-3),
                    _ => ext.k(),
                };
                terms.push(Term {
                    coefficient,
                    factors,
                });
            }
            let mut instance = Instance {
                id: 4000 + u64::from(nv),
                num_vars: nv,
                inputs: (0..inputs as u64).map(|i| 900 + 7 * i).collect(),
                terms,
                claimed_sum: K::from_i64(0),
            };
            // Hypercube sum by direct evaluation of the reference tables.
            let mut sum = K::from_i64(0);
            for x in 0..n {
                for term in &instance.terms {
                    sum = sum
                        + term
                            .factors
                            .iter()
                            .fold(term.coefficient, |p, f| p * reference[*f as usize][x]);
                }
            }
            instance.claimed_sum = sum;
            let mut t_ref = Transcript::<K>::new(b"review/dense/t").expect("t");
            let mut t_mix = Transcript::<K>::new(b"review/dense/t").expect("t");
            let p_ref = prove(
                &instance,
                Dense::new(&instance, reference).expect("dense"),
                &mut t_ref,
            )
            .expect("reference");
            let p_mix = prove(
                &instance,
                Dense::new_mixed(&instance, mixed).expect("mixed"),
                &mut t_mix,
            )
            .expect("mixed");
            assert_eq!(p_mix, p_ref, "nv={nv} inputs={inputs} mode={mode}");
            assert_eq!(
                t_mix.challenge(ChallengeLabel::Sumcheck).expect("c"),
                t_ref.challenge(ChallengeLabel::Sumcheck).expect("c")
            );
            cases += 1;
        }
    }
    assert!(cases > 250);
}

#[test]
fn matches_reference_all_extension_rounds_on_random_mixed_instances() {
    dense_mixed_matches::<QM31>();
    dense_mixed_matches::<OM31>();
}

fn zerocheck_base_matches<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(11);
    let mut ext = Ext::<K>::new(b"review/zc");
    let mut cases = 0;
    for nv in 0..=9u32 {
        let n = 1usize << nv;
        for skip in 0..=nv.min(4) as u8 {
            // 0: full (degree 4), 1: degree 3, 2: degree 1 only, 3: degree 0 (constants only).
            for shape in 0..4 {
                if shape == 3 && skip != 0 {
                    continue; // A3: a degree-zero instance admits no skip.
                }
                let col = |rng: &mut Rng| -> Vec<M31> { (0..n).map(|_| rng.m31()).collect() };
                let (a, b, e, unused) =
                    (col(&mut rng), col(&mut rng), col(&mut rng), col(&mut rng));
                let c: Vec<M31> = (0..n).map(|i| a[i] * b[i]).collect();
                let d: Vec<M31> = (0..n).map(|i| a[i] * a[i] * b[i]).collect();
                let f: Vec<M31> = (0..n).map(|i| a[i] * b[i] * e[i]).collect();
                let h: Vec<M31> = (0..n).map(|i| a[i] * b[i] * e[i] * a[i]).collect();
                let ones = vec![M31::ONE; n];
                // ordinals: a0 b1 e2 c3 d4 f5 h6 ones7 unused8
                let base = vec![a, b, e, c, d, f, h, ones, unused];
                let (l1, l2, l3, l4, l5) = (ext.k(), ext.k(), ext.k(), ext.k(), ext.k());
                let term = |coefficient: K, factors: &[u32]| Term {
                    coefficient,
                    factors: factors.to_vec(),
                };
                let terms = match shape {
                    0 => vec![
                        term(l1, &[0, 1]),
                        term(-l1, &[3]),
                        term(l2, &[0, 0, 1]),
                        term(-l2, &[4]),
                        term(l3, &[0, 1, 2]),
                        term(-l3, &[5]),
                        term(l4, &[]),
                        term(-l4, &[7]),
                        term(K::from_i64(0), &[3, 4, 5]),
                        term(l5, &[0, 1, 2, 0]),
                        term(-l5, &[6]),
                    ],
                    1 => vec![
                        term(l1, &[1, 0]),
                        term(-l1, &[3]),
                        term(l3, &[2, 1, 0]),
                        term(-l3, &[5]),
                        term(K::from_i64(0), &[8, 8, 8]),
                    ],
                    2 => vec![term(l1, &[3]), term(-l1, &[3]), term(K::from_i64(0), &[8])],
                    _ => vec![term(l4, &[]), term(-l4, &[])],
                };
                let instance = Instance {
                    id: 5000 + u64::from(nv),
                    num_vars: nv,
                    inputs: (0..base.len() as u64).map(|i| 300 + 3 * i).collect(),
                    terms,
                    claimed_sum: K::from_i64(0),
                };
                let reference: Vec<Vec<K>> = base
                    .iter()
                    .map(|t| t.iter().map(|v| embed::<K>(*v)).collect())
                    .collect();
                let z = Zerocheck {
                    instance: &instance,
                    skip,
                };
                let mut t_ref = Transcript::<K>::new(b"review/zc/t").expect("t");
                let mut t_base = Transcript::<K>::new(b"review/zc/t").expect("t");
                let r = z.prove_with_point(&reference, &mut t_ref).expect("ref");
                let o = z.prove_base_with_point(&base, &mut t_base).expect("base");
                assert_eq!(o, r, "nv={nv} skip={skip} shape={shape}");
                assert_eq!(
                    t_base.challenge(ChallengeLabel::Sumcheck).expect("c"),
                    t_ref.challenge(ChallengeLabel::Sumcheck).expect("c")
                );
                // The unchanged verifier accepts the base-path proof.
                let mut t_v = Transcript::<K>::new(b"review/zc/t").expect("t");
                // Acceptance is the point; the reduction's claims are not opened here.
                let _ = z.verify_public(&o.0, &reference, &mut t_v).expect("verify");
                cases += 1;
            }
        }
    }
    assert!(cases > 100);
}

#[test]
fn matches_reference_zerocheck_for_every_skip_and_degree() {
    zerocheck_base_matches::<QM31>();
    zerocheck_base_matches::<OM31>();
}

fn batch_base_matches<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(23);
    let mut ext = Ext::<K>::new(b"review/batch");
    let mut cases = 0;
    // 16 and 17 variables: blocks at and above the size where a claim's own sums and fill
    // run on the pool, with short prefixes so that such blocks occur, and forty claims so
    // that small blocks fall in several windows, nested in the large ones and disjoint.
    for nv in (0..=13u32).chain([16, 17]) {
        let n = 1usize << nv;
        for count in if nv > 13 { [1usize, 5, 40] } else { [1, 2, 5] } {
            let base: Vec<M31> = (0..n).map(|_| rng.m31()).collect();
            let reference: Vec<K> = base.iter().map(|v| embed::<K>(*v)).collect();
            let mut claims: Vec<(Vec<K>, K)> = Vec::new();
            for j in 0..count {
                // Boolean prefixes of every length, fully Boolean points and duplicates.
                let prefix = if nv > 13 && j % 4 == 0 {
                    j / 4 % 3
                } else if nv > 13 {
                    rng.below(9) as usize
                } else {
                    rng.below(u64::from(nv) + 1) as usize
                };
                let point: Vec<K> = if j > 0 && rng.below(4) == 0 {
                    claims[0].0.clone()
                } else {
                    (0..nv as usize)
                        .map(|i| {
                            if i < prefix {
                                K::from_i64(rng.below(2) as i64)
                            } else {
                                ext.k()
                            }
                        })
                        .collect()
                };
                let eq = stele_poly::eq_table(&point).expect("eq");
                let value = reference
                    .iter()
                    .zip(eq)
                    .fold(K::from_i64(0), |s, (a, w)| s + *a * w);
                claims.push((point, value));
            }
            let batch = Batch {
                id: 6000 + u64::from(nv),
                tensor: 17,
                num_vars: nv,
                claims: &claims,
            };
            let mut t_ref = Transcript::<K>::new(b"review/batch/t").expect("t");
            let mut t_base = Transcript::<K>::new(b"review/batch/t").expect("t");
            let r = batch.prove_with_point(reference, &mut t_ref).expect("ref");
            let o = batch
                .prove_base_with_point(&base, &mut t_base)
                .expect("base");
            assert_eq!(o, r, "nv={nv} count={count}");
            assert_eq!(
                t_base.challenge(ChallengeLabel::Sumcheck).expect("c"),
                t_ref.challenge(ChallengeLabel::Sumcheck).expect("c")
            );
            let mut t_v = Transcript::<K>::new(b"review/batch/t").expect("t");
            let _ = batch.verify(&o.0, &mut t_v).expect("verify");
            cases += 1;
        }
    }
    assert!(cases == 48);
}

#[test]
fn matches_reference_claim_batch_with_boolean_prefixes() {
    batch_base_matches::<QM31>();
    batch_base_matches::<OM31>();
}
