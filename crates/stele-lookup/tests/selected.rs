//! Original selected-product consumers and scoped leaf loss, RFC-0008 A3.
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_lookup::fraction::{Descriptor, Error, LeafDescriptor, SelectedProduct};
fn check<K: ChallengeField + Eq + core::fmt::Debug>() {
    let mut rng = Transcript::<K>::new(b"selected-product 1000 full-field cases").expect("fixture");
    for case in 0..1000 {
        let m = case % 5;
        let c = 1 + case as usize % 3;
        let ids: Vec<_> = (0..c).map(|j| u64::MAX - j as u64).collect();
        let d = Descriptor::new(79, m, m, [11, 12], &[]).expect("tree");
        let shape = LeafDescriptor::new(&d, &ids).expect("leaf");
        let mut rand = || {
            rng.challenge(ChallengeLabel::Sumcheck)
                .expect("fixture draw")
        };
        let alpha = rand();
        let beta = if case % 7 == 0 {
            K::from_i64(0)
        } else {
            rand()
        };
        let sigma: Vec<_> = (0..1 << m)
            .map(|i| K::from_i64(i64::from((i + case) % 2)))
            .collect();
        let xs: Vec<Vec<_>> = (0..c)
            .map(|_| sigma.iter().map(|_| rand()).collect())
            .collect();
        let leaves: Vec<_> = sigma
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut z = K::from_i64(0);
                let mut power = K::from_i64(1);
                for x in &xs {
                    z = z + power * x[i];
                    power = power * beta;
                }
                [*s, K::from_i64(1) + *s * (alpha - K::from_i64(1) - z)]
            })
            .collect();
        let mut pt = Transcript::new(b"fixed original source context").expect("transcript");
        let mut vt = Transcript::new(b"fixed original source context").expect("transcript");
        let (tree, pr) = d.prove(&leaves, &mut pt).expect("tree prover");
        let original = d.verify(&tree, &mut vt).expect("conditional tree");
        let prover = SelectedProduct::new(shape, &pr, &sigma, alpha, beta).expect("valid selector");
        let verifier =
            SelectedProduct::new(shape, &original, &sigma, alpha, beta).expect("valid selector");
        let (proof, pr) = prover.prove(&xs, &mut pt).expect("selected product prover");
        let vr = verifier
            .verify_public(&proof, &xs, &mut vt)
            .expect("original source consumer");
        assert_eq!(pr, vr);
        assert_eq!(vr.claims.iter().map(|c| c.0).collect::<Vec<_>>(), ids);
        assert_eq!(
            (
                vr.tree_id,
                vr.sc.id,
                vr.sc.m,
                vr.sc.degree,
                vr.sc.field_degree,
                vr.sc.numerator
            ),
            (79, 79, m, 3, K::DEGREE as u8, 3 * u64::from(m))
        );
        assert_eq!(
            pt.challenge(ChallengeLabel::Sumcheck),
            vt.challenge(ChallengeLabel::Sumcheck)
        );
        let mut bad = proof.clone();
        bad.final_values.pop();
        let mut t = Transcript::new(b"preflight").expect("transcript");
        assert_eq!(
            verifier.verify(&bad, &mut t).expect_err("shape"),
            Error::ProofShape
        );
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck),
            Transcript::<K>::new(b"preflight")
                .expect("transcript")
                .challenge(ChallengeLabel::Sumcheck)
        );
        let mut nonboolean = sigma.clone();
        nonboolean[0] = K::from_i64(2);
        assert_eq!(
            SelectedProduct::new(shape, &original, &nonboolean, alpha, beta).err(),
            Some(Error::Selector)
        );
    }
}
#[test]
fn accepts_qm31_selected_product_original_consumers() {
    check::<QM31>();
}
#[test]
fn accepts_om31_selected_product_original_consumers() {
    check::<OM31>();
}

fn check_base_selected_parity<K: ChallengeField + Eq + core::fmt::Debug>() {
    use stele_field::{Field, M31};
    let one = K::from_i64(1);
    for m in [0u32, 1, 4] {
        let len = 1usize << m;
        let mut seed = Transcript::<K>::new(b"e20-02-sel-seed").expect("t");
        let alpha = seed.challenge(ChallengeLabel::Sumcheck).expect("alpha");
        let beta = seed.challenge(ChallengeLabel::Sumcheck).expect("beta");
        let d = Descriptor::new(79, m, m, [10, 11], &[]).expect("tree");
        let shape = LeafDescriptor::new(&d, &[91, 92]).expect("leaf");
        let sigma_m31: Vec<M31> = (0..len)
            .map(|i| if i % 3 == 0 { M31::ZERO } else { M31::ONE })
            .collect();
        let sigma_k: Vec<K> = sigma_m31.iter().map(|&s| one.mul_m31(s)).collect();
        let xs_m31 = vec![
            (0..len)
                .map(|i| M31::from_i64((i * 11 + 5) as i64 % 256))
                .collect::<Vec<_>>(),
            (0..len)
                .map(|i| M31::from_i64(((i * 7) % 19) as i64 - 9))
                .collect::<Vec<_>>(),
        ];
        let xs_k: Vec<Vec<K>> = xs_m31
            .iter()
            .map(|col| col.iter().map(|&v| one.mul_m31(v)).collect())
            .collect();
        let leaves: Vec<[K; 2]> = (0..len)
            .map(|i| {
                let s = sigma_k[i];
                let row = xs_k[0][i] + beta * xs_k[1][i];
                [s, one - s + s * (alpha - row)]
            })
            .collect();
        let (_, original) = d
            .prove(&leaves, &mut Transcript::new(b"tree").expect("t"))
            .expect("tree");
        let mut t_ref = Transcript::new(b"sel-parity").expect("t");
        let (p_ref, r_ref) = SelectedProduct::new(shape, &original, &sigma_k, alpha, beta)
            .expect("new")
            .prove(&xs_k, &mut t_ref)
            .expect("prove");
        let mut t_opt = Transcript::new(b"sel-parity").expect("t");
        let (p_opt, r_opt) = SelectedProduct::new_base(shape, &original, &sigma_m31, alpha, beta)
            .expect("new_base")
            .prove_base(&xs_m31, &mut t_opt)
            .expect("prove_base");
        assert_eq!(p_opt, p_ref);
        assert_eq!(r_opt, r_ref);
        assert_eq!(
            t_opt.challenge(ChallengeLabel::Sumcheck),
            t_ref.challenge(ChallengeLabel::Sumcheck)
        );
    }
}

#[test]
fn matches_reference_base_selected_product_qm31_and_om31() {
    check_base_selected_parity::<QM31>();
    check_base_selected_parity::<OM31>();
}

fn context_shapes<K: ChallengeField + Eq + core::fmt::Debug>() {
    let one = K::from_i64(1);
    let two = K::from_i64(2);
    let d = Descriptor::new(1, 0, 0, [11, 12], &[]).expect("tree");
    let shape = LeafDescriptor::new(&d, &[91]).expect("leaf");
    let (_, original) = d
        .prove(
            &[[one, one]],
            &mut Transcript::new(b"scalar source").expect("transcript"),
        )
        .expect("tree prover");
    let sigma = [one];
    let selected = SelectedProduct::new(shape, &original, &sigma, two, one).expect("selector");
    for wrong in [vec![], vec![vec![]], vec![vec![one, one]]] {
        let mut t = Transcript::new(b"preflight source").expect("transcript");
        assert_eq!(
            selected.prove(&wrong, &mut t).expect_err("original shape"),
            Error::SourceShape
        );
        assert_eq!(
            t.challenge(ChallengeLabel::Sumcheck),
            Transcript::<K>::new(b"preflight source")
                .expect("transcript")
                .challenge(ChallengeLabel::Sumcheck)
        );
    }
    for kind in 0..3 {
        let mut wrong = original.clone();
        match kind {
            0 => wrong.point.push(one),
            1 => wrong.claims[0].0 += 1,
            _ => wrong.claims[0].1 = two,
        };
        assert_eq!(
            SelectedProduct::new(shape, &wrong, &sigma, two, one).err(),
            Some(if kind < 2 {
                Error::SourceShape
            } else {
                Error::SelectorMismatch
            })
        );
    }
    assert_eq!(
        SelectedProduct::new(shape, &original, &[], two, one).err(),
        Some(Error::SourceShape)
    );
}
#[test]
fn rejects_selected_product_context_and_source_shapes() {
    context_shapes::<QM31>();
    context_shapes::<OM31>();
}
