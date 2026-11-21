//! RFC-0008 A3: randomized byte identity of the base-field tree and selected-product paths
//! (task E20-02) against the extension reference. From the E20-01/E20-02 review (F4).
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{BaseLeaves, Descriptor, Error, LeafDescriptor, SelectedProduct};

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
    /// Lookup value: inside small tables, on their edges, far outside and negative.
    fn value(&mut self) -> M31 {
        match self.below(10) {
            0 => M31::ZERO,
            1 => M31::from_i64(255),
            2 => M31::from_i64(256),
            3 => M31::from_i64(65_535),
            4 => M31::from_i64(65_536),
            5 => M31::from_i64(-1),
            6 => M31::from_i64((self.next() >> 1) as i64),
            _ => M31::from_i64(self.below(300) as i64),
        }
    }
    /// Selector: mostly 0/1; `wild` adds values that are neither.
    fn sigma(&mut self, wild: bool) -> M31 {
        match self.below(if wild { 6 } else { 2 }) {
            0 => M31::ZERO,
            1 => M31::ONE,
            2 => M31::from_i64(2),
            3 => M31::from_i64(-1),
            _ => M31::from_i64((self.next() >> 1) as i64),
        }
    }
}

fn embed<K: ChallengeField>(v: M31) -> K {
    K::from_i64(i64::from(v.as_u32()))
}

fn tree_parity<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(3);
    let mut ext = Transcript::<K>::new(b"review/tree").expect("t");
    let mut k = move || ext.challenge(ChallengeLabel::Sumcheck).expect("c");
    let one = K::from_i64(1);
    let mut cases = 0;
    for m in 0..=9u32 {
        let len = 1usize << m;
        // Every group boundary: b = 0 weights every layer, including the leaf layer.
        for b in 0..=m {
            for wild in [false, true] {
                for uniform in 0..3 {
                    let theta: Vec<K> = (0..m - b).map(|_| k()).collect();
                    let d = Descriptor::new(42 + u64::from(m), m, b, [10, 11], &theta)
                        .expect("descriptor");
                    let (alpha, beta) = (k(), k());
                    let sigma: Vec<M31> = (0..len)
                        .map(|_| match uniform {
                            1 => M31::ZERO,
                            2 => M31::ONE,
                            _ => rng.sigma(wild),
                        })
                        .collect();
                    let xs: Vec<Vec<M31>> = (0..3)
                        .map(|_| (0..len).map(|_| rng.value()).collect())
                        .collect();
                    for c in 1..=3usize {
                        let leaves: Vec<[K; 2]> = (0..len)
                            .map(|i| {
                                let s = embed::<K>(sigma[i]);
                                let row = xs[..c]
                                    .iter()
                                    .rev()
                                    .fold(K::from_i64(0), |v, x| v * beta + embed::<K>(x[i]));
                                [s, one - s + s * (alpha - row)]
                            })
                            .collect();
                        let mut t_ref = Transcript::<K>::new(b"review/tree/t").expect("t");
                        let reference = d.prove(&leaves, &mut t_ref).expect("reference");
                        let next = t_ref.challenge(ChallengeLabel::Sumcheck).expect("c");
                        // The prebuilt-tree prover over the same extension leaves.
                        let mut t_built = Transcript::<K>::new(b"review/tree/t").expect("t");
                        let built = d.build_levels(&leaves).expect("levels");
                        assert_eq!(
                            d.prove_built(built, &mut t_built).expect("built"),
                            reference,
                            "prove_built m={m} b={b}"
                        );
                        assert_eq!(
                            t_built.challenge(ChallengeLabel::Sumcheck).expect("c"),
                            next
                        );
                        let mut variants = vec![BaseLeaves::General {
                            sigma: &sigma,
                            xs: &xs[..c],
                            alpha,
                            beta,
                        }];
                        if c == 1 {
                            for table_size in [0usize, 1, 2, 16, 255, 256, 257, 300, 65_536, 70_000]
                            {
                                variants.push(BaseLeaves::SmallDomain {
                                    sigma: &sigma,
                                    values: &xs[0],
                                    alpha,
                                    table_size,
                                });
                            }
                        }
                        for (v, base) in variants.into_iter().enumerate() {
                            let mut t_opt = Transcript::<K>::new(b"review/tree/t").expect("t");
                            let optimised = d.prove_base_leaves(base, &mut t_opt).expect("base");
                            assert_eq!(
                                optimised, reference,
                                "m={m} b={b} wild={wild} uniform={uniform} c={c} variant={v}"
                            );
                            assert_eq!(t_opt.challenge(ChallengeLabel::Sumcheck).expect("c"), next);
                            cases += 1;
                        }
                        // The unchanged verifier closes the base-path proof on the original leaves.
                        let mut t_v = Transcript::<K>::new(b"review/tree/t").expect("t");
                        let closed = d
                            .verify_public(&reference.0, &leaves, &mut t_v)
                            .expect("verify");
                        assert_eq!(closed, reference.1);
                    }
                }
            }
        }
    }
    assert!(cases > 1000);
}

#[test]
fn matches_reference_tree_for_every_group_boundary() {
    tree_parity::<QM31>();
    tree_parity::<OM31>();
}

fn selected_parity<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Rng(5);
    let mut ext = Transcript::<K>::new(b"review/selected").expect("t");
    let mut k = move || ext.challenge(ChallengeLabel::Sumcheck).expect("c");
    let one = K::from_i64(1);
    let mut cases = 0;
    for m in 0..=9u32 {
        let len = 1usize << m;
        for c in 1..=3usize {
            for uniform in 0..3 {
                let ids: Vec<u64> = (0..c as u64).map(|j| 91 + j).collect();
                let d = Descriptor::new(79, m, m, [10, 11], &[]).expect("tree");
                let shape = LeafDescriptor::new(&d, &ids).expect("leaf");
                let (alpha, beta) = (k(), k());
                let sigma: Vec<M31> = (0..len)
                    .map(|_| match uniform {
                        1 => M31::ZERO,
                        2 => M31::ONE,
                        _ => rng.sigma(false),
                    })
                    .collect();
                let sigma_k: Vec<K> = sigma.iter().map(|s| embed::<K>(*s)).collect();
                let xs: Vec<Vec<M31>> = (0..c)
                    .map(|_| (0..len).map(|_| rng.value()).collect())
                    .collect();
                let xs_k: Vec<Vec<K>> = xs
                    .iter()
                    .map(|x| x.iter().map(|v| embed::<K>(*v)).collect())
                    .collect();
                let leaves: Vec<[K; 2]> = (0..len)
                    .map(|i| {
                        let s = sigma_k[i];
                        let row = xs_k
                            .iter()
                            .rev()
                            .fold(K::from_i64(0), |v, x| v * beta + x[i]);
                        [s, one - s + s * (alpha - row)]
                    })
                    .collect();
                let (_, original) = d
                    .prove(
                        &leaves,
                        &mut Transcript::new(b"review/sel/tree").expect("t"),
                    )
                    .expect("tree");
                let mut t_ref = Transcript::<K>::new(b"review/sel/t").expect("t");
                let reference = SelectedProduct::new(shape, &original, &sigma_k, alpha, beta)
                    .expect("new")
                    .prove(&xs_k, &mut t_ref)
                    .expect("prove");
                let next = t_ref.challenge(ChallengeLabel::Sumcheck).expect("c");
                // Base selector and base columns.
                let mut t_opt = Transcript::<K>::new(b"review/sel/t").expect("t");
                let optimised = SelectedProduct::new_base(shape, &original, &sigma, alpha, beta)
                    .expect("new_base")
                    .prove_base(&xs, &mut t_opt)
                    .expect("prove_base");
                assert_eq!(optimised, reference, "m={m} c={c} uniform={uniform}");
                assert_eq!(t_opt.challenge(ChallengeLabel::Sumcheck).expect("c"), next);
                // Extension selector with base columns, and base selector with extension columns.
                let mut t_a = Transcript::<K>::new(b"review/sel/t").expect("t");
                let a = SelectedProduct::new(shape, &original, &sigma_k, alpha, beta)
                    .expect("new")
                    .prove_base(&xs, &mut t_a)
                    .expect("prove_base");
                assert_eq!(a, reference);
                let mut t_b = Transcript::<K>::new(b"review/sel/t").expect("t");
                let b = SelectedProduct::new_base(shape, &original, &sigma, alpha, beta)
                    .expect("new_base")
                    .prove(&xs_k, &mut t_b)
                    .expect("prove");
                assert_eq!(b, reference);
                // The verifier built from the base selector decides as the extension one.
                let mut t_v = Transcript::<K>::new(b"review/sel/t").expect("t");
                let verified = SelectedProduct::new_base(shape, &original, &sigma, alpha, beta)
                    .expect("new_base")
                    .verify(&reference.0, &mut t_v)
                    .expect("verify");
                assert_eq!(verified, reference.1);
                assert_eq!(t_v.challenge(ChallengeLabel::Sumcheck).expect("c"), next);
                cases += 1;
            }
        }
    }
    assert!(cases == 90);
    // A selector that is neither 0 nor 1 is refused by both constructors, the same way.
    let d = Descriptor::<K>::new(79, 1, 1, [10, 11], &[]).expect("tree");
    let shape = LeafDescriptor::new(&d, &[91]).expect("leaf");
    let (alpha, beta) = (k(), k());
    let leaves = vec![[one, alpha], [one, alpha]];
    let (_, original) = d
        .prove(
            &leaves,
            &mut Transcript::new(b"review/sel/tree").expect("t"),
        )
        .expect("tree");
    for bad in [M31::from_i64(2), M31::from_i64(-1)] {
        let sigma = [M31::ONE, bad];
        let sigma_k = [one, embed::<K>(bad)];
        assert_eq!(
            SelectedProduct::new_base(shape, &original, &sigma, alpha, beta).err(),
            Some(Error::Selector)
        );
        assert_eq!(
            SelectedProduct::new(shape, &original, &sigma_k, alpha, beta).err(),
            Some(Error::Selector)
        );
    }
    // A wrong incoming selector evaluation is refused by both, the same way.
    let sigma = [M31::ONE, M31::ZERO];
    let sigma_k = [one, K::from_i64(0)];
    assert_eq!(
        SelectedProduct::new_base(shape, &original, &sigma, alpha, beta).err(),
        Some(Error::SelectorMismatch)
    );
    assert_eq!(
        SelectedProduct::new(shape, &original, &sigma_k, alpha, beta).err(),
        Some(Error::SelectorMismatch)
    );
}

#[test]
fn matches_reference_selected_product_and_rejects_the_same_selectors() {
    selected_parity::<QM31>();
    selected_parity::<OM31>();
}

/// A prebuilt tree of the right shape but other leaves: the prover must not emit a proof
/// the verifier accepts for the supplied leaves.
#[test]
fn rejects_proofs_from_a_prebuilt_tree_of_other_leaves() {
    type K = QM31;
    let mut ext = Transcript::<K>::new(b"review/mismatch").expect("t");
    let mut k = move || ext.challenge(ChallengeLabel::Sumcheck).expect("c");
    let one = K::from_i64(1);
    for m in 1..=4u32 {
        let len = 1usize << m;
        let d = Descriptor::<K>::new(7, m, m, [10, 11], &[]).expect("d");
        let alpha = k();
        let sigma = vec![M31::ONE; len];
        let honest: Vec<M31> = (0..len).map(|i| M31::from_i64(i as i64 % 4)).collect();
        let mut other = honest.clone();
        other[len - 1] = M31::from_i64(9);
        let leaves = |values: &'_ [M31]| -> Vec<[K; 2]> {
            values
                .iter()
                .map(|v| [one, alpha - embed::<K>(*v)])
                .collect()
        };
        let base = |values| BaseLeaves::SmallDomain {
            sigma: &sigma,
            values,
            alpha,
            table_size: 4,
        };
        let tree = d.build_base_levels(base(&other)).expect("tree");
        let mut t = Transcript::<K>::new(b"review/mismatch/t").expect("t");
        match d.prove_built_base(base(&honest), tree, &mut t) {
            Err(_) => {}
            Ok((proof, _)) => {
                let mut t_v = Transcript::<K>::new(b"review/mismatch/t").expect("t");
                assert!(d.verify_public(&proof, &leaves(&honest), &mut t_v).is_err());
                let mut t_v = Transcript::<K>::new(b"review/mismatch/t").expect("t");
                assert!(d.verify_public(&proof, &leaves(&other), &mut t_v).is_err());
            }
        }
    }
}
