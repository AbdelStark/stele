//! RFC-0029 & RFC-0010 A17 — recursive opening integration tests and NC-0630..0634 verification.
#![forbid(unsafe_code)]

use stele_field::{Field, Inverse, Serialize, M31, OM31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::recursive::{
    level_descriptor, policy3_certified_queries, policy3_fresh_queries, prove_joined_tail,
    verify_certified_level0, verify_certified_opening, verify_certified_registration,
    verify_fresh_at_point, verify_fresh_claims, verify_fresh_level0_claims, verify_joined_tail,
    CertifiedModelSource, CertifiedPlan, CertifiedSource, ColumnFunctional, JoinedTailPlan,
    LevelSpec, PreparedRecursive, RecursiveError, RecursivePlan, RecursiveSource,
    DEFAULT_TARGET_BITS,
};
use stele_pcs::{CircleCoeff, Source};

fn seeded_m31(len: usize, seed: u64) -> Vec<M31> {
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push(M31::from_i64(((x >> 33) % ((1u64 << 31) - 1)) as i64));
    }
    out
}

fn seeded_point<K: ChallengeField>(len: usize, seed: &[u8]) -> Vec<K> {
    let mut t = Transcript::<K>::new(seed).expect("seed transcript");
    (0..len)
        .map(|_| t.challenge(ChallengeLabel::Sumcheck).expect("coord"))
        .collect()
}

fn check_plan_roundtrip<K: ChallengeField + PartialEq + std::fmt::Debug>(
    levels: Vec<LevelSpec>,
    id: u64,
    seed: u64,
) where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let plan =
        RecursivePlan::new(levels.clone(), K::DEGREE as u8, DEFAULT_TARGET_BITS).expect("plan");
    let msg = seeded_m31(plan.level0_elements().expect("elems"), seed);
    let prepared = PreparedRecursive::<K>::commit(id, plan.clone(), msg).expect("commit");
    let source = prepared.source().clone();
    assert_eq!(
        RecursiveSource::<K>::from_bytes(&source.bytes().expect("bytes")).expect("parse"),
        source
    );

    // 1. Fresh point opening (`open_fresh_at_point` / `verify_fresh_at_point`).
    let mut tp = Transcript::<K>::new(b"e19-03-at-point").expect("t");
    tp.absorb(AbsorbLabel::FieldSources, &source.bytes().expect("bytes"))
        .expect("absorb root");
    let point: Vec<K> = (0..plan.level0_vars())
        .map(|_| tp.challenge(ChallengeLabel::Sumcheck).expect("r"))
        .collect();
    let value = prepared.evaluate(&point).expect("eval");
    let proof1 = prepared
        .open_fresh_at_point(&mut tp, id + 100, &point, value)
        .expect("prove");
    let cont_p = tp.challenge(ChallengeLabel::Sumcheck).expect("cont");
    assert_eq!(proof1.len(), plan.proof_size().expect("size"));

    // Determinism check: identical transcript produces bit-identical bytes.
    let mut tp2 = Transcript::<K>::new(b"e19-03-at-point").expect("t2");
    tp2.absorb(AbsorbLabel::FieldSources, &source.bytes().expect("bytes"))
        .expect("absorb root");
    let point2: Vec<K> = (0..plan.level0_vars())
        .map(|_| tp2.challenge(ChallengeLabel::Sumcheck).expect("r"))
        .collect();
    let proof2 = prepared
        .open_fresh_at_point(&mut tp2, id + 100, &point2, value)
        .expect("prove2");
    assert_eq!(proof1, proof2);

    // Independent verifier.
    let mut tv = Transcript::<K>::new(b"e19-03-at-point").expect("tv");
    tv.absorb(AbsorbLabel::FieldSources, &source.bytes().expect("bytes"))
        .expect("absorb root");
    let vpoint: Vec<K> = (0..plan.level0_vars())
        .map(|_| tv.challenge(ChallengeLabel::Sumcheck).expect("r"))
        .collect();
    let verified =
        verify_fresh_at_point(&mut tv, &source, id + 100, &vpoint, value, &proof1).expect("verify");
    assert_eq!(verified.source_id(), id);
    assert_eq!(verified.opening_id(), id + 100);
    assert_eq!(verified.point(), vpoint.as_slice());
    assert_eq!(verified.value(), value);
    assert_eq!(verified.ledger().levels.len(), levels.len());
    for (i, lvl) in verified.ledger().levels.iter().enumerate() {
        assert_eq!(lvl.level as usize, i);
        assert_eq!(lvl.queries, plan.queries()[i]);
        assert_eq!(
            lvl.beta_numerator,
            if i + 1 < levels.len() {
                u64::from(plan.queries()[i])
            } else {
                0
            }
        );
        assert_eq!(
            lvl.sumcheck_numerator,
            if i >= 1 {
                2 * u64::from(levels[i].ell)
            } else {
                0
            }
        );
    }
    assert_eq!(
        tv.challenge(ChallengeLabel::Sumcheck).expect("cont"),
        cont_p
    );

    // 2. Full fresh-mode claims batching + recursive opening (1 claim and 3 claims).
    for claim_count in [1usize, 3usize] {
        let mut pts = Vec::new();
        let mut vals = Vec::new();
        for c in 0..claim_count {
            let p = seeded_point::<K>(plan.level0_vars(), format!("claim-{id}-{c}").as_bytes());
            let v = prepared.evaluate(&p).expect("eval");
            pts.push(p);
            vals.push(v);
        }
        let claim_refs: Vec<(&[K], K)> = pts
            .iter()
            .zip(&vals)
            .map(|(p, &v)| (p.as_slice(), v))
            .collect();
        let mut tc_p = Transcript::<K>::new(b"e19-03-claims").expect("tc_p");
        let cproof = prepared
            .open_fresh_claims(&mut tc_p, id + 200 + claim_count as u64, &claim_refs)
            .expect("open claims");
        let cont_cp = tc_p.challenge(ChallengeLabel::Sumcheck).expect("cont_cp");

        let mut tc_v = Transcript::<K>::new(b"e19-03-claims").expect("tc_v");
        let cverified = verify_fresh_claims(
            &mut tc_v,
            &source,
            id + 200 + claim_count as u64,
            &claim_refs,
            &cproof,
        )
        .expect("verify claims");
        assert_eq!(
            cverified.ledger().batch_rlc_numerator,
            (claim_count - 1) as u64
        );
        assert_eq!(
            cverified.ledger().batch_sc_numerator,
            2 * plan.level0_vars() as u64
        );
        assert_eq!(
            tc_v.challenge(ChallengeLabel::Sumcheck).expect("cont_cv"),
            cont_cp
        );
    }
}

#[test]
fn accepts_recursive_opening_single_and_multi_level_qm31_and_om31() {
    let plans = vec![
        // L = 1 (blow-up 1)
        vec![LevelSpec::new(2, 3, 1)],
        // L = 2 (blow-up 2 & 3)
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 3)],
        // L = 3 (blow-up 2, 3, 4)
        vec![
            LevelSpec::new(2, 6, 2),
            LevelSpec::new(2, 4, 3),
            LevelSpec::new(2, 2, 4),
        ],
        // L = 4 (deep chain)
        vec![
            LevelSpec::new(2, 7, 2),
            LevelSpec::new(2, 5, 2),
            LevelSpec::new(2, 3, 3),
            LevelSpec::new(1, 2, 4),
        ],
    ];
    for (idx, levels) in plans.into_iter().enumerate() {
        check_plan_roundtrip::<QM31>(levels.clone(), 10 + idx as u64, 1000 + idx as u64);
        check_plan_roundtrip::<OM31>(levels, 20 + idx as u64, 2000 + idx as u64);
    }
}

#[test]
fn matches_reference_policy3_dp_and_version4_context() {
    // Exact pinned Policy 3 query counts (RFC-0010 A17, check_policy3.py --check).
    assert_eq!(policy3_fresh_queries(16, 1, 100).expect("b1").0, 381);
    assert_eq!(policy3_fresh_queries(16, 2, 100).expect("b2").0, 241);
    assert_eq!(policy3_fresh_queries(16, 3, 100).expect("b3").0, 202);
    assert_eq!(policy3_fresh_queries(16, 4, 100).expect("b4").0, 185);
    // Domain ceiling m + b <= 30 enforced.
    assert_eq!(
        policy3_fresh_queries(29, 2, 100),
        Err(RecursiveError::UnsupportedSource)
    );
    assert_eq!(
        policy3_fresh_queries(10, 5, 100),
        Err(RecursiveError::UnsupportedSource)
    );
    assert_eq!(
        policy3_fresh_queries(10, 0, 100),
        Err(RecursiveError::UnsupportedSource)
    );

    // Pinned E19-01 DP model body_bytes receipts (research/rfc0029-pcs/check_policy3.py & REPORT.md).
    let expected_qm31_capped_b234: &[(u8, usize)] = &[
        (20, 299_344),
        (24, 474_288),
        (28, 984_736),
        (30, 2_465_440),
        (32, 8_388_256),
    ];
    for &(bits, expected_bytes) in expected_qm31_capped_b234 {
        let plan = RecursivePlan::fresh_for_size(bits, 4, 100, true, &[2, 3, 4]).expect("dp");
        assert_eq!(
            plan.body_bytes().expect("body"),
            expected_bytes,
            "2^{bits} capped b>=2"
        );
    }
    let plan32_b1 = RecursivePlan::fresh_for_size(32, 4, 100, true, &[1, 2, 3, 4]).expect("b1");
    assert_eq!(plan32_b1.body_bytes().expect("body"), 3_810_608);
    let plan32_om31 = RecursivePlan::fresh_for_size(32, 8, 100, true, &[2, 3, 4]).expect("om31");
    assert_eq!(plan32_om31.body_bytes().expect("body"), 1_085_248);
    // Finding 2 regression: total_bits up to 40 respects `ell <= 30` and never aborts feasible plans.
    for bits in [35u8, 38, 40] {
        if let Ok(plan) = RecursivePlan::fresh_for_size(bits, 8, 100, true, &[2, 3, 4]) {
            assert!(plan.levels().iter().all(|l| l.ell <= 30 && l.m + l.b <= 30));
        }
    }

    // Version-4 context validation & ZK reservation (RFC-0029 §7).
    let valid_plan = RecursivePlan::new(
        vec![LevelSpec::new(3, 5, 2), LevelSpec::new(2, 3, 2)],
        4,
        100,
    )
    .expect("plan");
    let src = RecursiveSource::<QM31>::new(7, valid_plan.clone(), [0x5a; 32]).expect("src");
    let raw = src.bytes().expect("bytes");
    assert_eq!(raw[23], 4); // version 4
    assert_eq!(raw[78], 3); // policy 3
    assert_eq!(&raw[34..59], b"stele/circle-coeff-m31/v1");
    assert_eq!(RecursiveSource::<QM31>::from_bytes(&raw), Ok(src.clone()));

    // Mutate version, policy, degree, ZK reservation fields, or append trailing byte -> UnsupportedSource.
    for &(off, val) in &[
        (23usize, 3u8),
        (24, 8),
        (77, 1),
        (78, 2),
        (114 + 3, 1),
        (114 + 5, 1),
    ] {
        let mut bad = raw.clone();
        bad[off] = val;
        assert_eq!(
            RecursiveSource::<QM31>::from_bytes(&bad),
            Err(RecursiveError::UnsupportedSource),
            "byte offset {off}"
        );
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(
        RecursiveSource::<QM31>::from_bytes(&trailing),
        Err(RecursiveError::UnsupportedSource)
    );

    // Nonzero LevelSpec ZK fields rejected at construction.
    let mut bad_lvl = LevelSpec::new(3, 5, 2);
    bad_lvl.randomisers = 1;
    assert_eq!(
        RecursivePlan::new(vec![bad_lvl], 4, 100),
        Err(RecursiveError::UnsupportedSource)
    );
    let mut bad_lvl2 = LevelSpec::new(3, 5, 2);
    bad_lvl2.mask_rows = 1;
    assert_eq!(
        RecursivePlan::new(vec![bad_lvl2], 4, 100),
        Err(RecursiveError::UnsupportedSource)
    );

    // Broken level chain rejected.
    assert_eq!(
        RecursivePlan::new(
            vec![LevelSpec::new(3, 5, 2), LevelSpec::new(2, 2, 2)],
            4,
            100
        ),
        Err(RecursiveError::UnsupportedSource)
    );

    // NC-0613 preservation: version-1 A9 Source still rejects policy byte 3.
    let v1 = Source::<QM31>::new(1, 2, 3, 1, [0x11; 32]).expect("v1");
    let mut v1_bytes = v1.bytes().to_vec();
    let policy_off = 34 + 21 + 17;
    assert_eq!(v1_bytes[policy_off], 1);
    v1_bytes[policy_off] = 3;
    assert_eq!(
        Source::<QM31>::from_bytes(&v1_bytes).err(),
        Some(stele_pcs::Error::UnsupportedSource)
    );
}

// ---------- Malicious prover helpers for NC-0630..0634 (test-only; verifier has zero bypasses) ----------

fn commit_m31_raw(
    source_id: u64,
    spec: LevelSpec,
    message: &[M31],
) -> (Vec<u8>, merkle::Tree, merkle::Descriptor) {
    let rows = spec.rows().expect("test");
    let cols = spec.columns().expect("test");
    let n = spec.codeword_len().expect("test");
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).expect("test");
    let mut col_bytes = vec![0u8; n * rows * 4];
    for (r, row) in message.chunks_exact(cols).enumerate() {
        let enc = code.encode(row).expect("test");
        for (j, val) in enc.iter().enumerate() {
            let off = j * rows * 4 + r * 4;
            col_bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
    let desc = level_descriptor(source_id, 0, spec, 4).expect("test");
    let leaves: Vec<&[u8]> = col_bytes.chunks_exact(rows * 4).collect();
    let tree =
        merkle::Tree::new_with_usage(desc, &leaves, &mut HashUsage::default()).expect("test");
    (col_bytes, tree, desc)
}

fn commit_ext_raw<K: ChallengeField>(
    source_id: u64,
    level: u8,
    spec: LevelSpec,
    message: &[K],
) -> (Vec<u8>, merkle::Tree, merkle::Descriptor) {
    let rows = spec.rows().expect("test");
    let cols = spec.columns().expect("test");
    let n = spec.codeword_len().expect("test");
    let elem = 4 * K::DEGREE;
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).expect("test");
    let mut col_bytes = vec![0u8; n * rows * elem];
    for (r, row) in message.chunks_exact(cols).enumerate() {
        let enc = code.encode(row).expect("test");
        for (j, val) in enc.iter().enumerate() {
            let off = j * rows * elem + r * elem;
            col_bytes[off..off + elem].copy_from_slice(val.to_le_bytes().as_ref());
        }
    }
    let desc = level_descriptor(source_id, level, spec, elem).expect("test");
    let leaves: Vec<&[u8]> = col_bytes.chunks_exact(rows * elem).collect();
    let tree =
        merkle::Tree::new_with_usage(desc, &leaves, &mut HashUsage::default()).expect("test");
    (col_bytes, tree, desc)
}

fn append_col(col_bytes: &[u8], tree: &merkle::Tree, width: usize, idx: u64, out: &mut Vec<u8>) {
    let j = idx as usize;
    out.extend_from_slice(&col_bytes[j * width..(j + 1) * width]);
    for sib in tree.path(idx).expect("test") {
        out.extend_from_slice(&sib);
    }
}

fn absorb_open_stmt<K: ChallengeField>(
    t: &mut Transcript<K>,
    opening_id: u64,
    source: &RecursiveSource<K>,
    point: &[K],
    value: K,
) {
    let sb = source.bytes().expect("test");
    let mut frame = Vec::new();
    frame.extend_from_slice(&opening_id.to_le_bytes());
    frame.extend_from_slice(&sb);
    for p in point {
        frame.extend_from_slice(p.to_le_bytes().as_ref());
    }
    frame.extend_from_slice(value.to_le_bytes().as_ref());
    t.absorb(AbsorbLabel::Opening, &frame).expect("test");
}

fn write_plan_header(plan: &RecursivePlan, out: &mut Vec<u8>) {
    out.push(4);
    out.push(plan.levels().len() as u8);
    for s in plan.levels() {
        out.push(s.ell);
        out.push(s.m);
        out.push(s.b);
    }
}

fn interp2<K: Field>(y: [K; 3], r: K) -> K {
    let one = K::from_i64(1);
    let two = K::from_i64(2);
    let inv2 = M31::from_i64(1 << 30);
    (y[0] * ((r - one) * (r - two))).mul_m31(inv2) - y[1] * (r * (r - two))
        + (y[2] * (r * (r - one))).mul_m31(inv2)
}

#[test]
fn rejects_nc_0630_through_nc_0634_through_actual_verifier() {
    // --- NC-0630 (L = 1 AND L = 2): commit u_1 differing from a^T M_0 in one entry -> ColumnMismatch ---
    {
        // L = 1 direct final check.
        let plan = RecursivePlan::new(vec![LevelSpec::new(2, 3, 2)], 4, 100).expect("test");
        let msg = seeded_m31(plan.level0_elements().expect("test"), 6301);
        let (col0, tree0, desc0) = commit_m31_raw(630, plan.levels()[0], &msg);
        let source = RecursiveSource::<QM31>::new(630, plan.clone(), tree0.root()).expect("test");
        let prepared =
            PreparedRecursive::<QM31>::commit(630, plan.clone(), msg.clone()).expect("test");
        assert_eq!(prepared.source().root(), source.root());

        let point = seeded_point::<QM31>(5, b"nc-0630-l1");
        let value = prepared.evaluate(&point).expect("test");
        let eq_row = stele_poly::eq_table(&point[..2]).expect("test");
        let mut u1 = vec![QM31::from_i64(0); 8];
        for (row, &a) in msg.chunks_exact(8).zip(&eq_row) {
            for (dst, &v) in u1.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(v);
            }
        }
        // Corrupt entry 0 of u_1 by +1 BEFORE Step 3 draws queries so all Merkle paths stay valid!
        u1[0] = u1[0] + QM31::from_i64(1);

        let mut tp = Transcript::<QM31>::new(b"nc-0630-t").expect("test");
        absorb_open_stmt(&mut tp, 1, &source, &point, value);
        let mut forged = Vec::new();
        write_plan_header(&plan, &mut forged);
        let u_start = forged.len();
        for v in &u1 {
            forged.extend_from_slice(v.to_le_bytes().as_ref());
        }
        tp.absorb(AbsorbLabel::PcsLevelRoot, &forged[u_start..])
            .expect("test");
        let r_start = forged.len();
        for _ in 0..plan.queries()[0] {
            let idx = tp.opening_column(desc0.count).expect("test");
            append_col(&col0, &tree0, desc0.width as usize, idx, &mut forged);
        }
        tp.absorb(AbsorbLabel::OpeningColumns, &forged[r_start..])
            .expect("test");

        let mut tv = Transcript::<QM31>::new(b"nc-0630-t").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv, &source, 1, &point, value, &forged),
            Err(RecursiveError::ColumnMismatch)
        );
    }

    {
        // L = 2: genuine residual-propagating malicious prover parameterized by u_1_cand
        // (proves non-vacuity when uncorrupted and tests PcsLevelBeta cross-level binding!).
        let plan = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            100,
        )
        .expect("test");
        let msg = seeded_m31(plan.level0_elements().expect("test"), 6302);
        let (col0, tree0, desc0) = commit_m31_raw(6302, plan.levels()[0], &msg);
        let source = RecursiveSource::<QM31>::new(6302, plan.clone(), tree0.root()).expect("test");
        let prepared =
            PreparedRecursive::<QM31>::commit(6302, plan.clone(), msg.clone()).expect("test");
        let point = seeded_point::<QM31>(6, b"nc-0630-l2");
        let value = prepared.evaluate(&point).expect("test");
        let eq_row0 = stele_poly::eq_table(&point[..2]).expect("test");
        let eq_col0 = stele_poly::eq_table(&point[2..]).expect("test");
        let code0 = CircleCoeff::new(4, 2).expect("test");
        let mut u1_honest = vec![QM31::from_i64(0); 16];
        for (row, &a) in msg.chunks_exact(16).zip(&eq_row0) {
            for (dst, &v) in u1_honest.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(v);
            }
        }

        let build_l2 = |u1_cand: &[QM31], forge_u2_scalar: bool, tag: &[u8]| -> Vec<u8> {
            let (col1, tree1, desc1) = commit_ext_raw(6302, 1, plan.levels()[1], u1_cand);
            let mut tp = Transcript::<QM31>::new(tag).expect("test");
            absorb_open_stmt(&mut tp, 2, &source, &point, value);
            let mut out = Vec::new();
            write_plan_header(&plan, &mut out);
            let root1 = tree1.root();
            out.extend_from_slice(&root1);
            tp.absorb(AbsorbLabel::PcsLevelRoot, &root1).expect("test");

            let r0_start = out.len();
            let mut queried0 = Vec::new();
            let mut ys0 = Vec::new();
            for _ in 0..plan.queries()[0] {
                let idx = tp.opening_column(desc0.count).expect("test");
                let width = desc0.width as usize;
                let pay = &col0[idx as usize * width..(idx as usize + 1) * width];
                let mut y = QM31::from_i64(0);
                for (&w, ch) in eq_row0.iter().zip(pay.chunks_exact(4)) {
                    let m = M31::from_le_bytes(ch.try_into().expect("test")).expect("test");
                    y = y + w.mul_m31(m);
                }
                queried0.push(idx);
                ys0.push(y);
                append_col(&col0, &tree0, width, idx, &mut out);
            }
            tp.absorb(AbsorbLabel::OpeningColumns, &out[r0_start..])
                .expect("test");

            let beta0 = tp.challenge(ChallengeLabel::PcsLevelBeta).expect("test");
            let mut w1 = eq_col0.clone();
            let mut v1 = value;
            let mut bp = beta0;
            for (&idx, &y) in queried0.iter().zip(&ys0) {
                v1 = v1 + bp * y;
                let mut factors = code0.basis_factors(idx as usize).expect("test");
                factors.reverse();
                let mut btbl = vec![M31::ZERO; 16];
                btbl[0] = M31::ONE;
                let mut width = 1usize;
                for f in factors {
                    for i in (0..width).rev() {
                        let parent = btbl[i];
                        btbl[2 * i] = parent;
                        btbl[2 * i + 1] = parent * f;
                    }
                    width *= 2;
                }
                for (dst, &bv) in w1.iter_mut().zip(&btbl) {
                    *dst = *dst + bp.mul_m31(bv);
                }
                bp = bp * beta0;
            }

            let mut actual_dot = QM31::from_i64(0);
            for (&w, &u) in w1.iter().zip(u1_cand) {
                actual_dot = actual_dot + w * u;
            }
            let mut delta = v1 - actual_dot;

            let mut inst = Vec::new();
            inst.extend_from_slice(&2u64.to_le_bytes());
            inst.push(1);
            inst.push(2);
            inst.push(2);
            inst.extend_from_slice(v1.to_le_bytes().as_ref());
            tp.absorb(AbsorbLabel::Instance, &inst).expect("test");

            let one = QM31::from_i64(1);
            let two = QM31::from_i64(2);
            let inv2 = M31::from_i64(1 << 30);
            let mut cur_w = w1;
            let mut cur_m = u1_cand.to_vec();
            let mut rows = 4usize;
            let cols = 4usize;
            for rnd in 0..2u32 {
                let half = rows / 2;
                let stride = half * cols;
                let (w_lo, w_hi) = cur_w.split_at(stride);
                let (m_lo, m_hi) = cur_m.split_at(stride);
                let (mut y0, mut y1, mut y2) =
                    (QM31::from_i64(0), QM31::from_i64(0), QM31::from_i64(0));
                for i in 0..stride {
                    let (w0, w1_v, m0, m1) = (w_lo[i], w_hi[i], m_lo[i], m_hi[i]);
                    y0 = y0 + w0 * m0;
                    y1 = y1 + w1_v * m1;
                    y2 = y2 + (w1_v + w1_v - w0) * (m1 + m1 - m0);
                }
                let vals = [y0 + delta, y1, y2];
                for v in vals {
                    out.extend_from_slice(v.to_le_bytes().as_ref());
                }
                let mut rbuf = Vec::new();
                rbuf.extend_from_slice(&2u64.to_le_bytes());
                rbuf.extend_from_slice(&rnd.to_le_bytes());
                for v in vals {
                    rbuf.extend_from_slice(v.to_le_bytes().as_ref());
                }
                tp.absorb(AbsorbLabel::Round, &rbuf).expect("test");
                let r = tp.challenge(ChallengeLabel::Sumcheck).expect("test");
                let _ = interp2(vals, r);
                delta = delta * (((r - one) * (r - two)).mul_m31(inv2));
                let mut nw = Vec::with_capacity(stride);
                let mut nm = Vec::with_capacity(stride);
                for i in 0..stride {
                    nw.push(w_lo[i] + r * (w_hi[i] - w_lo[i]));
                    nm.push(m_lo[i] + r * (m_hi[i] - m_lo[i]));
                }
                cur_w = nw;
                cur_m = nm;
                rows = half;
            }

            let mut u2 = cur_m;
            if forge_u2_scalar && delta != QM31::from_i64(0) {
                let (k, wk) = cur_w
                    .iter()
                    .enumerate()
                    .find(|&(_, &w)| w != QM31::from_i64(0))
                    .expect("nonzero w_2");
                u2[k] = u2[k] + delta * wk.inverse().expect("inv");
            }
            let u2_start = out.len();
            for v in &u2 {
                out.extend_from_slice(v.to_le_bytes().as_ref());
            }
            tp.absorb(AbsorbLabel::PcsLevelRoot, &out[u2_start..])
                .expect("test");
            let r1_start = out.len();
            for _ in 0..plan.queries()[1] {
                let idx = tp.opening_column(desc1.count).expect("test");
                append_col(&col1, &tree1, desc1.width as usize, idx, &mut out);
            }
            tp.absorb(AbsorbLabel::OpeningColumns, &out[r1_start..])
                .expect("test");
            out
        };

        // Non-vacuity: uncorrupted u_1 passes!
        let ok_proof = build_l2(&u1_honest, true, b"nc-0630-l2-honest");
        let mut tv_ok = Transcript::<QM31>::new(b"nc-0630-l2-honest").expect("test");
        verify_fresh_at_point(&mut tv_ok, &source, 2, &point, value, &ok_proof)
            .expect("uncorrupted builder must accept");

        // Single-entry tamper u_1'[3] += 1: scalar-forged u_2 -> ColumnMismatch; honest u_2 -> ValueMismatch.
        let mut u1_single = u1_honest.clone();
        u1_single[3] = u1_single[3] + QM31::from_i64(1);
        let forged_col = build_l2(&u1_single, true, b"nc-0630-l2-col");
        let mut tv_col = Transcript::<QM31>::new(b"nc-0630-l2-col").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv_col, &source, 2, &point, value, &forged_col),
            Err(RecursiveError::ColumnMismatch)
        );
        let forged_val = build_l2(&u1_single, false, b"nc-0630-l2-val");
        let mut tv_val = Transcript::<QM31>::new(b"nc-0630-l2-val").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv_val, &source, 2, &point, value, &forged_val),
            Err(RecursiveError::ValueMismatch)
        );

        // PcsLevelBeta-only tamper: ⟨eq(r_col0), u_1''⟩ == value holds identically!
        let mut u1_beta = u1_honest;
        u1_beta[0] = u1_beta[0] + eq_col0[1];
        u1_beta[1] = u1_beta[1] - eq_col0[0];
        let dot_check: QM31 = eq_col0
            .iter()
            .zip(&u1_beta)
            .fold(QM31::from_i64(0), |acc, (&e, &u)| acc + e * u);
        assert_eq!(dot_check, value);
        let forged_beta = build_l2(&u1_beta, true, b"nc-0630-l2-beta");
        let mut tv_beta = Transcript::<QM31>::new(b"nc-0630-l2-beta").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv_beta, &source, 2, &point, value, &forged_beta),
            Err(RecursiveError::ColumnMismatch)
        );
    }

    // --- NC-0631: answer a level-i query with the column of another index -> Merkle(RootMismatch) ---
    {
        let plan = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            100,
        )
        .expect("test");
        let msg = seeded_m31(plan.level0_elements().expect("test"), 631);
        let (col0, tree0, desc0) = commit_m31_raw(631, plan.levels()[0], &msg);
        let source = RecursiveSource::<QM31>::new(631, plan.clone(), tree0.root()).expect("test");
        let prepared = PreparedRecursive::<QM31>::commit(631, plan.clone(), msg).expect("test");
        let point = seeded_point::<QM31>(6, b"nc-0631-p");
        let value = prepared.evaluate(&point).expect("test");

        let mut tp = Transcript::<QM31>::new(b"nc-0631-t").expect("test");
        let mut proof = prepared
            .open_fresh_at_point(&mut tp, 3, &point, value)
            .expect("test");

        // Replace query 0 at level 0 with the valid column+path of another index (`(idx0 + 1) % N_0`).
        let mut ts = Transcript::<QM31>::new(b"nc-0631-t").expect("test");
        absorb_open_stmt(&mut ts, 3, &source, &point, value);
        let hlen = plan.header_bytes();
        ts.absorb(AbsorbLabel::PcsLevelRoot, &proof[hlen..hlen + 32])
            .expect("test");
        let idx0 = ts.opening_column(desc0.count).expect("test");
        let other = (idx0 + 1) % desc0.count;
        let mut replacement = Vec::new();
        append_col(&col0, &tree0, desc0.width as usize, other, &mut replacement);
        let q0_off = hlen + 32;
        proof[q0_off..q0_off + replacement.len()].copy_from_slice(&replacement);

        let mut tv = Transcript::<QM31>::new(b"nc-0631-t").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv, &source, 3, &point, value, &proof),
            Err(RecursiveError::Merkle(merkle::Error::RootMismatch))
        );
    }

    // --- NC-0632: final vector u_L with one entry changed -> ValueMismatch / ColumnMismatch ---
    {
        // Case A: forged u_L' differs by +1 in entry 1 (sent before Step 3 queries) -> ColumnMismatch.
        let plan = RecursivePlan::new(vec![LevelSpec::new(2, 3, 2)], 4, 100).expect("test");
        let msg = seeded_m31(plan.level0_elements().expect("test"), 632);
        let prepared =
            PreparedRecursive::<QM31>::commit(632, plan.clone(), msg.clone()).expect("test");
        let source = prepared.source().clone();
        let point = seeded_point::<QM31>(5, b"nc-0632-p");
        let value = prepared.evaluate(&point).expect("test");

        // Case B: honest u_L matches every queried column (`Enc(u_L)[j_t] == y_t`),
        // but claimed scalar `v_0` disagrees -> ValueMismatch!
        let (col0, tree0, desc0) = commit_m31_raw(632, plan.levels()[0], &msg);
        let eq_row = stele_poly::eq_table(&point[..2]).expect("test");
        let mut u_honest = vec![QM31::from_i64(0); 8];
        for (row, &a) in msg.chunks_exact(8).zip(&eq_row) {
            for (dst, &v) in u_honest.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(v);
            }
        }
        let wrong_value = value + QM31::from_i64(1);
        let mut tp = Transcript::<QM31>::new(b"nc-0632-val").expect("test");
        absorb_open_stmt(&mut tp, 4, &source, &point, wrong_value);
        let mut forged_val = Vec::new();
        write_plan_header(&plan, &mut forged_val);
        let us = forged_val.len();
        for v in &u_honest {
            forged_val.extend_from_slice(v.to_le_bytes().as_ref());
        }
        tp.absorb(AbsorbLabel::PcsLevelRoot, &forged_val[us..])
            .expect("test");
        let rs = forged_val.len();
        for _ in 0..plan.queries()[0] {
            let idx = tp.opening_column(desc0.count).expect("test");
            append_col(&col0, &tree0, desc0.width as usize, idx, &mut forged_val);
        }
        tp.absorb(AbsorbLabel::OpeningColumns, &forged_val[rs..])
            .expect("test");
        let mut tv = Transcript::<QM31>::new(b"nc-0632-val").expect("test");
        assert_eq!(
            verify_fresh_at_point(&mut tv, &source, 4, &point, wrong_value, &forged_val),
            Err(RecursiveError::ValueMismatch)
        );
    }

    // --- NC-0633: present a level count or (ell, m, b) other than the plan's -> ProofShape ---
    {
        let plan_a = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            100,
        )
        .expect("test");
        let plan_b = RecursivePlan::new(vec![LevelSpec::new(2, 4, 2)], 4, 100).expect("test");
        let plan_c = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(1, 3, 2)],
            4,
            100,
        )
        .expect("test");
        let msg = seeded_m31(64, 633);
        let prep_a =
            PreparedRecursive::<QM31>::commit(633, plan_a.clone(), msg.clone()).expect("test");
        let prep_b =
            PreparedRecursive::<QM31>::commit(633, plan_b.clone(), msg.clone()).expect("test");
        let prep_c = PreparedRecursive::<QM31>::commit(633, plan_c.clone(), msg).expect("test");
        let point = seeded_point::<QM31>(6, b"nc-0633-p");
        let value = prep_a.evaluate(&point).expect("test");

        let mut t1 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let proof_b = prep_b
            .open_fresh_at_point(&mut t1, 5, &point, value)
            .expect("test");
        let mut t2 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let proof_c = prep_c
            .open_fresh_at_point(&mut t2, 5, &point, value)
            .expect("test");

        // Offer 1-level proof to 2-level verifier -> ProofShape before transcript work.
        let mut tv1 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let before1 = tv1.usage();
        assert_eq!(
            verify_fresh_at_point(&mut tv1, prep_a.source(), 5, &point, value, &proof_b),
            Err(RecursiveError::ProofShape)
        );
        assert_eq!(tv1.usage(), before1);

        // Offer different (ell_1, m_1) split to plan_a verifier -> ProofShape before transcript work.
        let mut tv2 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let before2 = tv2.usage();
        assert_eq!(
            verify_fresh_at_point(&mut tv2, prep_a.source(), 5, &point, value, &proof_c),
            Err(RecursiveError::ProofShape)
        );
        assert_eq!(tv2.usage(), before2);

        // Same-length proof with tampered header byte -> ProofShape before transcript work.
        let mut t3 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let mut proof_a = prep_a
            .open_fresh_at_point(&mut t3, 5, &point, value)
            .expect("test");
        proof_a[4] ^= 1;
        let mut tv3 = Transcript::<QM31>::new(b"nc-0633").expect("test");
        let before3 = tv3.usage();
        assert_eq!(
            verify_fresh_at_point(&mut tv3, prep_a.source(), 5, &point, value, &proof_a),
            Err(RecursiveError::ProofShape)
        );
        assert_eq!(tv3.usage(), before3);
    }

    // --- NC-0634: fresh mode: open at a point that is not the batching sumcheck's -> RoundSumMismatch ---
    {
        let plan = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            100,
        )
        .expect("test");
        let msg = seeded_m31(plan.level0_elements().expect("test"), 634);
        let prepared = PreparedRecursive::<QM31>::commit(634, plan.clone(), msg).expect("test");
        let source = prepared.source().clone();
        let p_claim = seeded_point::<QM31>(6, b"nc-0634-claim");
        let v_claim = prepared.evaluate(&p_claim).expect("test");

        // Honest batching proof.
        let mut tp = Transcript::<QM31>::new(b"nc-0634-t").expect("test");
        let honest = prepared
            .open_fresh_claims(&mut tp, 6, &[(&p_claim, v_claim)])
            .expect("test");
        let mut tv_ok = Transcript::<QM31>::new(b"nc-0634-t").expect("test");
        verify_fresh_claims(&mut tv_ok, &source, 6, &[(&p_claim, v_claim)], &honest)
            .expect("honest passes");

        // Malicious prover substitutes an opening at a DIFFERENT point r' != r* (changing v* to M_0(r')
        // and producing a valid recursive opening at r' instead of the batching sumcheck's r*).
        let vars = plan.level0_vars();
        let elem = 4 * 4;
        let sc_bytes = vars * 3 * elem;
        let mut forged = honest[..sc_bytes].to_vec();
        let r_other = seeded_point::<QM31>(6, b"nc-0634-other-point");
        let v_other = prepared.evaluate(&r_other).expect("test");
        forged.extend_from_slice(v_other.to_le_bytes().as_ref());
        // Replay transcript up to Final, then open at r_other (not r*!).
        let mut tf = Transcript::<QM31>::new(b"nc-0634-t").expect("test");
        let sb = source.bytes().expect("test");
        tf.absorb(AbsorbLabel::FieldSources, &sb).expect("test");
        let mut chdr = Vec::new();
        chdr.extend_from_slice(&6u64.to_le_bytes());
        chdr.extend_from_slice(&1u32.to_le_bytes());
        for c in &p_claim {
            chdr.extend_from_slice(c.to_le_bytes().as_ref());
        }
        chdr.extend_from_slice(v_claim.to_le_bytes().as_ref());
        tf.absorb(AbsorbLabel::Batch, &chdr).expect("test");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&6u64.to_le_bytes());
        ihdr.push(0xff);
        ihdr.push(vars as u8);
        ihdr.push(2);
        ihdr.extend_from_slice(v_claim.to_le_bytes().as_ref());
        tf.absorb(AbsorbLabel::Instance, &ihdr).expect("test");
        for rnd in 0..vars {
            let slice = &honest[rnd * 3 * elem..(rnd + 1) * 3 * elem];
            let mut rb = Vec::new();
            rb.extend_from_slice(&6u64.to_le_bytes());
            rb.extend_from_slice(&(rnd as u32).to_le_bytes());
            rb.extend_from_slice(slice);
            tf.absorb(AbsorbLabel::Round, &rb).expect("test");
            let _ = tf.challenge(ChallengeLabel::Sumcheck).expect("test");
        }
        tf.absorb(AbsorbLabel::Final, v_other.to_le_bytes().as_ref())
            .expect("test");
        let rec_other = prepared
            .open_fresh_at_point(&mut tf, 6, &r_other, v_other)
            .expect("test");
        forged.extend_from_slice(&rec_other);

        let mut tv_bad = Transcript::<QM31>::new(b"nc-0634-t").expect("test");
        assert_eq!(
            verify_fresh_claims(&mut tv_bad, &source, 6, &[(&p_claim, v_claim)], &forged),
            Err(RecursiveError::RoundSumMismatch)
        );
    }
}

#[test]
fn accepts_certified_model_source_general_functional_and_streaming_memory() {
    // 1. Exact Policy 3 certified query counts match E19-01 check_policy3.py receipts.
    //    2^33 model source: (ell=9, m=24, b=2), e_c = 262_143 -> q_cert = 17_710, q_open = 51.
    let (qc_33, qo_33, n_33, d_33) =
        policy3_certified_queries(24, 2, 262_143, 100).expect("2^33 cert queries");
    assert_eq!((qc_33, qo_33, n_33, d_33), (17_710, 51, 1 << 26, 3 << 24));
    // Unconditional single-round registration proximity cap enforced: e_c = 1_000_000 at ell = 9
    // gives 2 * 9 * 1_000_001 = 18_000_018 > QM31_CAP_100 = 16_777_215 -> UnsupportedSource.
    assert_eq!(
        CertifiedPlan::new(vec![LevelSpec::new(9, 24, 2)], 4, 100, 1_000_000),
        Err(RecursiveError::UnsupportedSource)
    );
    assert!(CertifiedPlan::new(vec![LevelSpec::new(9, 24, 2)], 4, 100, 262_143).is_ok());

    // 2. Round-trip certified registration & opening for BOTH Tensor and arbitrary Dense column
    //    functionals across L = 1, 2, 3 and BOTH QM31 and OM31.
    fn run_certified<K: ChallengeField + PartialEq + std::fmt::Debug>(
        levels: Vec<LevelSpec>,
        e_c: u64,
        id: u64,
        seed: u64,
    ) where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let plan = CertifiedPlan::new(levels.clone(), K::DEGREE as u8, 100, e_c).expect("plan");
        let l0 = levels[0];
        let rows = l0.rows().expect("rows");
        let cols = l0.columns().expect("cols");
        let msg = seeded_m31(rows * cols, seed);
        let model = CertifiedModelSource::<K>::register(id, plan.clone(), &msg).expect("register");
        assert_eq!(model.stored_codeword_bytes(), 0);
        let src = model.source().clone();
        assert_eq!(
            CertifiedSource::<K>::from_bytes(&src.bytes().expect("bytes")).expect("parse"),
            src
        );

        let verified_cert =
            verify_certified_registration(src.clone(), model.certificate_proof()).expect("cert");
        assert_eq!(verified_cert.id(), model.certificate_id());
        assert_eq!(verified_cert.ledger().certified_radius, e_c);
        assert_eq!(verified_cert.ledger().cert_queries, plan.cert_queries());
        assert!(verified_cert.ledger().transcript_usage.state_updates > 0);
        assert!(verified_cert.ledger().transcript_usage.xof_bytes > 0);
        assert!(
            verified_cert.ledger().transcript_usage.column_attempts
                >= u64::from(plan.cert_queries())
        );
        assert!(verified_cert.ledger().non_transcript_usage.hash_evaluations > 0);

        // Arbitrary non-tensor row functional `a` (not an eq vector!).
        let row_weights = seeded_point::<K>(rows, format!("cert-row-{id}").as_bytes());
        // (a) Tensor column functional `b = eq(·, r_col)`.
        let col_pt = seeded_point::<K>(usize::from(l0.m), format!("cert-col-t-{id}").as_bytes());
        let val_t = model
            .evaluate_functional(&msg, &row_weights, ColumnFunctional::Tensor(&col_pt))
            .expect("eval_t");
        let mut tp = Transcript::<K>::new(b"e19-05-tensor").expect("tp");
        let (proof_t, work_t) = model
            .open_certified_measured(
                &msg,
                &mut tp,
                id + 10,
                &row_weights,
                ColumnFunctional::Tensor(&col_pt),
                val_t,
            )
            .expect("open_t");
        let cont_p = tp.challenge(ChallengeLabel::Sumcheck).expect("cont");
        assert_eq!(work_t.stored_codeword_bytes, 0);
        assert_eq!(
            work_t.recomputed_columns,
            usize::from(plan.level_queries()[0])
        );
        assert_eq!(proof_t.len(), plan.opening_proof_size().expect("sz"));

        let mut tv = Transcript::<K>::new(b"e19-05-tensor").expect("tv");
        let opened_t = verify_certified_opening(
            &mut tv,
            &verified_cert,
            &src,
            id + 10,
            &row_weights,
            ColumnFunctional::Tensor(&col_pt),
            val_t,
            &proof_t,
        )
        .expect("verify_t");
        assert_eq!(opened_t.certificate_id(), verified_cert.id());
        assert_eq!(opened_t.value(), val_t);
        assert_eq!(opened_t.ledger().levels[0].proximity_numerator, 0);
        assert_eq!(opened_t.ledger().levels[0].radius, e_c);
        assert_eq!(
            tv.challenge(ChallengeLabel::Sumcheck).expect("cont"),
            cont_p
        );

        // (b) Arbitrary non-tensor Dense column functional `b ∈ K^{C_0}`.
        let col_dense = seeded_point::<K>(cols, format!("cert-col-d-{id}").as_bytes());
        let val_d = model
            .evaluate_functional(&msg, &row_weights, ColumnFunctional::Dense(&col_dense))
            .expect("eval_d");
        let mut tpd = Transcript::<K>::new(b"e19-05-dense").expect("tpd");
        let proof_d = model
            .open_certified(
                &msg,
                &mut tpd,
                id + 20,
                &row_weights,
                ColumnFunctional::Dense(&col_dense),
                val_d,
            )
            .expect("open_d");
        let cont_pd = tpd.challenge(ChallengeLabel::Sumcheck).expect("cont_pd");
        let mut tvd = Transcript::<K>::new(b"e19-05-dense").expect("tvd");
        let opened_d = verify_certified_opening(
            &mut tvd,
            &verified_cert,
            &src,
            id + 20,
            &row_weights,
            ColumnFunctional::Dense(&col_dense),
            val_d,
            &proof_d,
        )
        .expect("verify_d");
        assert_eq!(opened_d.value(), val_d);
        assert_eq!(
            tvd.challenge(ChallengeLabel::Sumcheck).expect("cont_vd"),
            cont_pd
        );
    }

    // L = 1, L = 2, L = 3 certified sources (QM31 & OM31).
    run_certified::<QM31>(vec![LevelSpec::new(2, 4, 2)], 12, 501, 5001);
    run_certified::<OM31>(vec![LevelSpec::new(2, 4, 2)], 12, 502, 5002);
    run_certified::<QM31>(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        24,
        503,
        5003,
    );
    run_certified::<OM31>(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        24,
        504,
        5004,
    );
    run_certified::<QM31>(
        vec![
            LevelSpec::new(2, 6, 2),
            LevelSpec::new(2, 4, 3),
            LevelSpec::new(2, 2, 4),
        ],
        48,
        505,
        5005,
    );

    // 3. Memory invariant test (E19-05): full codeword is NEVER resident during certified opening.
    //    R_0 = 256 (ell = 8), C_0 = 1024 (m = 10), b = 2 -> N_0 = 4096, full codeword = 4,194,304 B.
    //    At e_c = 128 (q_open = 55): peak scratch = 1 row (16 KiB) + 55 cols (56 KiB) = 72 KiB (< 1/50 full!).
    let mem_plan = CertifiedPlan::new(
        vec![LevelSpec::new(8, 10, 2), LevelSpec::new(5, 5, 3)],
        4,
        100,
        128,
    )
    .expect("mem plan");
    let mem_msg = seeded_m31(256 * 1024, 5999);
    let mem_model =
        CertifiedModelSource::<QM31>::register(599, mem_plan.clone(), &mem_msg).expect("reg");
    assert_eq!(mem_model.stored_codeword_bytes(), 0);
    let mem_cert =
        verify_certified_registration(mem_model.source().clone(), mem_model.certificate_proof())
            .expect("mem cert");
    let rw = seeded_point::<QM31>(256, b"mem-rw");
    let cp = seeded_point::<QM31>(10, b"mem-cp");
    let mv = mem_model
        .evaluate_functional(&mem_msg, &rw, ColumnFunctional::Tensor(&cp))
        .expect("mv");
    let mut tm = Transcript::<QM31>::new(b"e19-05-mem").expect("tm");
    let (mem_proof, work) = mem_model
        .open_certified_measured(
            &mem_msg,
            &mut tm,
            599,
            &rw,
            ColumnFunctional::Tensor(&cp),
            mv,
        )
        .expect("open mem");
    assert_eq!(work.stored_codeword_bytes, 0);
    assert_eq!(work.full_codeword_bytes, 256 * 4096 * 4);
    assert!(
        work.peak_codeword_bytes * 32 < work.full_codeword_bytes,
        "peak={} vs full={}",
        work.peak_codeword_bytes,
        work.full_codeword_bytes
    );
    let mut tmv = Transcript::<QM31>::new(b"e19-05-mem").expect("tmv");
    verify_certified_opening(
        &mut tmv,
        &mem_cert,
        mem_model.source(),
        599,
        &rw,
        ColumnFunctional::Tensor(&cp),
        mv,
        &mem_proof,
    )
    .expect("verify mem");

    // 4. NC-0635: certificate for another radius offered for the expected source -> CertificateContext.
    let plan_r1 = CertifiedPlan::new(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        4,
        100,
        24,
    )
    .expect("plan r1");
    let plan_r2 = CertifiedPlan::new(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        4,
        100,
        16,
    )
    .expect("plan r2");
    let msg_c = seeded_m31(4 * 32, 635);
    let m_r1 = CertifiedModelSource::<QM31>::register(635, plan_r1, &msg_c).expect("r1");
    let m_r2 = CertifiedModelSource::<QM31>::register(635, plan_r2, &msg_c).expect("r2");
    assert_eq!(m_r1.source().root(), m_r2.source().root());
    // (a) Offering raw cert_proof registered for radius 16 to expected source with radius 24 -> CertificateContext.
    assert_eq!(
        verify_certified_registration(m_r1.source().clone(), m_r2.certificate_proof()),
        Err(RecursiveError::CertificateContext)
    );
    // (b) Offering VerifiedCertifiedSource for radius 16 to verify_certified_opening expecting radius 24 -> CertificateContext.
    let cert_r2 =
        verify_certified_registration(m_r2.source().clone(), m_r2.certificate_proof()).expect("c2");
    let rw_c = seeded_point::<QM31>(4, b"nc-0635-rw");
    let cp_c = seeded_point::<QM31>(5, b"nc-0635-cp");
    let val_c = m_r1
        .evaluate_functional(&msg_c, &rw_c, ColumnFunctional::Tensor(&cp_c))
        .expect("vc");
    let mut tp_c = Transcript::<QM31>::new(b"nc-0635").expect("tpc");
    let pr_r1 = m_r1
        .open_certified(
            &msg_c,
            &mut tp_c,
            635,
            &rw_c,
            ColumnFunctional::Tensor(&cp_c),
            val_c,
        )
        .expect("pr1");
    let mut tv_c = Transcript::<QM31>::new(b"nc-0635").expect("tvc");
    let before = tv_c.usage();
    assert_eq!(
        verify_certified_opening(
            &mut tv_c,
            &cert_r2,
            m_r1.source(),
            635,
            &rw_c,
            ColumnFunctional::Tensor(&cp_c),
            val_c,
            &pr_r1,
        ),
        Err(RecursiveError::CertificateContext)
    );
    assert_eq!(tv_c.usage(), before);

    // 5. CertifiedPlan cap enforcement on higher fresh levels (i >= 1) and non-final PcsLevelBeta (q_i).
    // (a) Level 0 clears 2*9*(262143+1) = 4,718,592 <= 16,777,215, but level 1 has 2*4*(5242879+1) = 41,943,040 > cap.
    assert_eq!(
        CertifiedPlan::new(
            vec![LevelSpec::new(9, 24, 2), LevelSpec::new(4, 20, 4)],
            4,
            100,
            262_143,
        ),
        Err(RecursiveError::UnsupportedSource)
    );
    // (b) T=120 on QM31 has cap=15: level 0 clears 2*1*(1+1)=4 <= 15, but level-0 PcsLevelBeta q_open=63 > 15
    //     and level-1 proximity 2*2*(3+1)=16 > 15.
    assert_eq!(
        CertifiedPlan::new(
            vec![LevelSpec::new(1, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            120,
            1,
        ),
        Err(RecursiveError::UnsupportedSource)
    );
    // (c) Pure PcsLevelBeta-only cap failure: level-0 proximity 2*1*2=4 <= 15 AND level-1 proximity 2*1*2=4 <= 15,
    //     while level-0 q_open > 15 at T=120.
    assert_eq!(
        CertifiedPlan::new(
            vec![LevelSpec::new(1, 3, 2), LevelSpec::new(1, 2, 1)],
            4,
            120,
            1,
        ),
        Err(RecursiveError::UnsupportedSource)
    );
}

#[test]
fn accepts_zero_zk_reservation_pinned_bytes_and_rejects_nonzero() {
    // RFC-0029 §7 (E19-06): randomisers and mask_rows are fields of every level in the source
    // context, zero by default; nonzero values are rejected until RFC-0013 A3; zero values
    // produce byte-identical pinned source contexts and opening proofs.
    let s0 = LevelSpec::new(2, 5, 2);
    let s1 = LevelSpec::new(2, 3, 2);
    assert_eq!(s0.randomisers, 0);
    assert_eq!(s0.mask_rows, 0);
    assert_eq!(s1.randomisers, 0);
    assert_eq!(s1.mask_rows, 0);

    // Reject nonzero randomisers or mask_rows at any level in both fresh and certified plans.
    for bad in [
        vec![
            LevelSpec {
                randomisers: 1,
                ..s0
            },
            s1,
        ],
        vec![LevelSpec { mask_rows: 1, ..s0 }, s1],
        vec![
            s0,
            LevelSpec {
                randomisers: 2,
                ..s1
            },
        ],
        vec![s0, LevelSpec { mask_rows: 3, ..s1 }],
    ] {
        assert_eq!(
            RecursivePlan::new(bad.clone(), 4, DEFAULT_TARGET_BITS),
            Err(RecursiveError::UnsupportedSource)
        );
        assert_eq!(
            CertifiedPlan::new(bad, 4, DEFAULT_TARGET_BITS, 24),
            Err(RecursiveError::UnsupportedSource)
        );
    }

    // Fresh source context & opening proof byte-layout pin.
    let fresh_plan = RecursivePlan::new(vec![s0, s1], 4, DEFAULT_TARGET_BITS).expect("fresh plan");
    let msg = seeded_m31(fresh_plan.level0_elements().expect("elems"), 1906);
    let prep = PreparedRecursive::<QM31>::commit(1906, fresh_plan.clone(), msg.clone())
        .expect("fresh commit");
    let fresh_src_bytes = prep.source().bytes().expect("fresh src bytes");
    // Level 0 bytes sit at offset 114..121: (ell, m, b, randomisers: u16le, mask_rows: u16le).
    assert_eq!(&fresh_src_bytes[117..121], &[0, 0, 0, 0]);
    assert_eq!(&fresh_src_bytes[124..128], &[0, 0, 0, 0]);
    // Flipping either reserved u16le byte in wire form must reject on parse.
    for off in [117usize, 119, 124, 126] {
        let mut tampered = fresh_src_bytes.clone();
        tampered[off] = 1;
        assert_eq!(
            RecursiveSource::<QM31>::from_bytes(&tampered),
            Err(RecursiveError::UnsupportedSource)
        );
    }
    let pt = seeded_point::<QM31>(7, b"e19-06-fresh-pt");
    let val = prep.evaluate(&pt).expect("eval");
    let mut tf = Transcript::<QM31>::new(b"e19-06-fresh").expect("tf");
    let fresh_proof = prep
        .open_fresh_at_point(&mut tf, 1906, &pt, val)
        .expect("fresh open");
    let mut tfv = Transcript::<QM31>::new(b"e19-06-fresh").expect("tfv");
    verify_fresh_at_point(&mut tfv, prep.source(), 1906, &pt, val, &fresh_proof)
        .expect("fresh verify");

    // Certified source context, registration certificate & opening proof byte-layout pin.
    let cert_plan =
        CertifiedPlan::new(vec![s0, s1], 4, DEFAULT_TARGET_BITS, 24).expect("cert plan");
    let model = CertifiedModelSource::<QM31>::register(1906, cert_plan, &msg).expect("reg");
    let cert_src_bytes = model.source().bytes().expect("cert src bytes");
    // CertifiedSource level 0 starts at offset 122: (ell, m, b, randomisers: u16le, mask_rows: u16le).
    assert_eq!(&cert_src_bytes[125..129], &[0, 0, 0, 0]);
    assert_eq!(&cert_src_bytes[132..136], &[0, 0, 0, 0]);
    for off in [125usize, 127, 132, 134] {
        let mut tampered = cert_src_bytes.clone();
        tampered[off] = 1;
        assert_eq!(
            CertifiedSource::<QM31>::from_bytes(&tampered),
            Err(RecursiveError::UnsupportedSource)
        );
    }
    let verified_cert =
        verify_certified_registration(model.source().clone(), model.certificate_proof())
            .expect("verify cert");
    let rw = seeded_point::<QM31>(4, b"e19-06-cert-rw");
    let cp = seeded_point::<QM31>(5, b"e19-06-cert-cp");
    let cval = model
        .evaluate_functional(&msg, &rw, ColumnFunctional::Tensor(&cp))
        .expect("cval");
    let mut tc = Transcript::<QM31>::new(b"e19-06-cert").expect("tc");
    let cert_proof = model
        .open_certified(
            &msg,
            &mut tc,
            1906,
            &rw,
            ColumnFunctional::Tensor(&cp),
            cval,
        )
        .expect("cert open");
    let mut tcv = Transcript::<QM31>::new(b"e19-06-cert").expect("tcv");
    verify_certified_opening(
        &mut tcv,
        &verified_cert,
        model.source(),
        1906,
        &rw,
        ColumnFunctional::Tensor(&cp),
        cval,
        &cert_proof,
    )
    .expect("cert verify");

    const EXPECTED_FRESH_SRC: [u8; 32] = [
        0xd7, 0x0e, 0xf8, 0xdd, 0xc2, 0xcf, 0xbb, 0x50, 0xa0, 0xe8, 0xd3, 0xec, 0x57, 0x47, 0xa0,
        0x9d, 0x62, 0xac, 0x67, 0x5b, 0x94, 0x1b, 0x8a, 0x92, 0x78, 0x43, 0x75, 0xaf, 0x63, 0xfa,
        0xa1, 0x7e,
    ];
    const EXPECTED_FRESH_PRF: [u8; 32] = [
        0x3e, 0x7e, 0xfc, 0xe2, 0x61, 0x3c, 0x95, 0xe1, 0x97, 0x08, 0xbe, 0x72, 0xfe, 0xfa, 0xd9,
        0xc2, 0x28, 0xd1, 0xc2, 0xbc, 0x16, 0xc0, 0xb5, 0x48, 0x82, 0x49, 0x2e, 0xb4, 0xca, 0xb3,
        0x87, 0x0f,
    ];
    const EXPECTED_CERT_SRC: [u8; 32] = [
        0x59, 0xcd, 0xe0, 0x11, 0x4b, 0xf8, 0x2e, 0x10, 0xb8, 0xc9, 0x99, 0xb8, 0xaf, 0x24, 0xf1,
        0x16, 0xb9, 0x46, 0x0c, 0x34, 0xa3, 0xef, 0x6d, 0x56, 0x9a, 0xc5, 0x41, 0x76, 0x3f, 0x89,
        0x1a, 0x77,
    ];
    const EXPECTED_CERT_REG: [u8; 32] = [
        0x4d, 0x5e, 0xc7, 0x6f, 0x7e, 0xca, 0x39, 0x35, 0xfb, 0xa7, 0xc8, 0x04, 0x6b, 0xe2, 0x30,
        0x6b, 0xfe, 0xdd, 0x4a, 0xe1, 0x1a, 0x18, 0x3a, 0x2c, 0x85, 0x5a, 0xc3, 0x3c, 0x54, 0x6f,
        0xda, 0xd4,
    ];
    const EXPECTED_CERT_PRF: [u8; 32] = [
        0x8b, 0xd0, 0x62, 0xd4, 0x55, 0x9e, 0xde, 0x22, 0x5a, 0xb1, 0xd8, 0x77, 0x7e, 0xd5, 0x8a,
        0x07, 0xbc, 0xa7, 0xfb, 0xac, 0x9b, 0x6e, 0x4c, 0xca, 0xae, 0xda, 0xe7, 0x34, 0xda, 0x31,
        0x1d, 0x9a,
    ];
    assert_eq!(
        stele_hash::blake3_digest(&fresh_src_bytes),
        EXPECTED_FRESH_SRC
    );
    assert_eq!(stele_hash::blake3_digest(&fresh_proof), EXPECTED_FRESH_PRF);
    assert_eq!(
        stele_hash::blake3_digest(&cert_src_bytes),
        EXPECTED_CERT_SRC
    );
    assert_eq!(
        stele_hash::blake3_digest(model.certificate_proof()),
        EXPECTED_CERT_REG
    );
    assert_eq!(stele_hash::blake3_digest(&cert_proof), EXPECTED_CERT_PRF);
}

#[test]
fn accepts_joined_multi_source_recursion_and_rejects_composed_tampers() {
    fn run_mixed<K: ChallengeField + PartialEq + std::fmt::Debug>(
        tail_levels: Vec<LevelSpec>,
        seed: u64,
    ) where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        let l1 = tail_levels[0];
        let l1_bits = l1.ell + l1.m;
        // 5 heterogeneous sources joined into ONE recursion (non-power-of-two k=5 -> block_bits=3):
        //   0: fresh segment, 2 claims, m_0 = l1_bits
        //   1: fresh segment, 1 claim,  m_0 = l1_bits - 2 (tests pad_msb_zeros on Eq + Basis)
        //   2: certified model, Tensor, m_0 = l1_bits
        //   3: certified model, Dense,  m_0 = l1_bits - 1 (tests pad_msb_zeros on Dense + Basis)
        //   4: fresh segment, 2 claims, m_0 = l1_bits - 1
        let tail_plan =
            JoinedTailPlan::new(tail_levels.clone(), 5, K::DEGREE as u8, DEFAULT_TARGET_BITS)
                .expect("tail plan");

        let p0 = RecursivePlan::new(
            vec![LevelSpec::new(2, l1_bits, 2)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
        )
        .expect("p0");
        let p1 = RecursivePlan::new(
            vec![LevelSpec::new(3, l1_bits - 2, 2)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
        )
        .expect("p1");
        let p2 = CertifiedPlan::new(
            vec![LevelSpec::new(2, l1_bits, 2)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
            24,
        )
        .expect("p2");
        let p3 = CertifiedPlan::new(
            vec![LevelSpec::new(2, l1_bits - 1, 2)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
            12,
        )
        .expect("p3");
        let p4 = RecursivePlan::new(
            vec![LevelSpec::new(2, l1_bits - 1, 3)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
        )
        .expect("p4");

        let m0 = seeded_m31(p0.level0_elements().expect("e0"), seed + 1);
        let m1 = seeded_m31(p1.level0_elements().expect("e1"), seed + 2);
        let m2 = seeded_m31(
            p2.levels()[0].rows().expect("r2") * p2.levels()[0].columns().expect("c2"),
            seed + 3,
        );
        let m3 = seeded_m31(
            p3.levels()[0].rows().expect("r3") * p3.levels()[0].columns().expect("c3"),
            seed + 4,
        );
        let m4 = seeded_m31(p4.level0_elements().expect("e4"), seed + 5);

        let prep0 = PreparedRecursive::<K>::commit(100, p0, m0).expect("c0");
        let prep1 = PreparedRecursive::<K>::commit(101, p1, m1).expect("c1");
        let mod2 = CertifiedModelSource::<K>::register(102, p2, &m2).expect("reg2");
        let mod3 = CertifiedModelSource::<K>::register(103, p3, &m3).expect("reg3");
        let prep4 = PreparedRecursive::<K>::commit(104, p4, m4).expect("c4");

        let src0 = prep0.source().clone();
        let src1 = prep1.source().clone();
        let cert2 = verify_certified_registration(mod2.source().clone(), mod2.certificate_proof())
            .expect("vc2");
        let cert3 = verify_certified_registration(mod3.source().clone(), mod3.certificate_proof())
            .expect("vc3");
        let src4 = prep4.source().clone();

        let pt0a = seeded_point::<K>(usize::from(2 + l1_bits), b"j-p0a");
        let pt0b = seeded_point::<K>(usize::from(2 + l1_bits), b"j-p0b");
        let v0a = prep0.evaluate(&pt0a).expect("v0a");
        let v0b = prep0.evaluate(&pt0b).expect("v0b");

        let pt1a = seeded_point::<K>(usize::from(3 + l1_bits - 2), b"j-p1a");
        let v1a = prep1.evaluate(&pt1a).expect("v1a");

        let rw2 = seeded_point::<K>(4, b"j-rw2");
        let cp2 = seeded_point::<K>(usize::from(l1_bits), b"j-cp2");
        let v2 = mod2
            .evaluate_functional(&m2, &rw2, ColumnFunctional::Tensor(&cp2))
            .expect("v2");

        let rw3 = seeded_point::<K>(4, b"j-rw3");
        let cd3 = seeded_point::<K>(1 << (l1_bits - 1), b"j-cd3");
        let v3 = mod3
            .evaluate_functional(&m3, &rw3, ColumnFunctional::Dense(&cd3))
            .expect("v3");

        let pt4a = seeded_point::<K>(usize::from(2 + l1_bits - 1), b"j-p4a");
        let pt4b = seeded_point::<K>(usize::from(2 + l1_bits - 1), b"j-p4b");
        let v4a = prep4.evaluate(&pt4a).expect("v4a");
        let v4b = prep4.evaluate(&pt4b).expect("v4b");

        let mut tp = Transcript::<K>::new(b"e19-04-joined").expect("tp");
        let (pr0, pend0) = prep0
            .close_fresh_level0_claims(&mut tp, 1000, l1, &[(&pt0a, v0a), (&pt0b, v0b)])
            .expect("cl0");
        let (pr1, pend1) = prep1
            .close_fresh_level0_claims(&mut tp, 1001, l1, &[(&pt1a, v1a)])
            .expect("cl1");
        let (pr2, pend2, work2) = mod2
            .close_certified_level0(
                &m2,
                &mut tp,
                1002,
                l1,
                &rw2,
                ColumnFunctional::Tensor(&cp2),
                v2,
            )
            .expect("cl2");
        assert_eq!(work2.stored_codeword_bytes, 0);
        let (pr3, pend3, work3) = mod3
            .close_certified_level0(
                &m3,
                &mut tp,
                1003,
                l1,
                &rw3,
                ColumnFunctional::Dense(&cd3),
                v3,
            )
            .expect("cl3");
        assert_eq!(work3.stored_codeword_bytes, 0);
        let (pr4, pend4) = prep4
            .close_fresh_level0_claims(&mut tp, 1004, l1, &[(&pt4a, v4a), (&pt4b, v4b)])
            .expect("cl4");

        let pending_p = [pend0, pend1, pend2, pend3, pend4];
        let tail_proof = prove_joined_tail(&mut tp, 2000, &tail_plan, &pending_p).expect("tail");
        let cont_p = tp.challenge(ChallengeLabel::Sumcheck).expect("cont_p");

        // Verify full joined proof!
        let mut tv = Transcript::<K>::new(b"e19-04-joined").expect("tv");
        let vp0 = verify_fresh_level0_claims(
            &mut tv,
            &src0,
            1000,
            l1,
            &[(&pt0a, v0a), (&pt0b, v0b)],
            &pr0,
        )
        .expect("vp0");
        let vp1 = verify_fresh_level0_claims(&mut tv, &src1, 1001, l1, &[(&pt1a, v1a)], &pr1)
            .expect("vp1");
        let vp2 = verify_certified_level0(
            &mut tv,
            &cert2,
            mod2.source(),
            1002,
            l1,
            &rw2,
            ColumnFunctional::Tensor(&cp2),
            v2,
            &pr2,
        )
        .expect("vp2");
        let vp3 = verify_certified_level0(
            &mut tv,
            &cert3,
            mod3.source(),
            1003,
            l1,
            &rw3,
            ColumnFunctional::Dense(&cd3),
            v3,
            &pr3,
        )
        .expect("vp3");
        let vp4 = verify_fresh_level0_claims(
            &mut tv,
            &src4,
            1004,
            l1,
            &[(&pt4a, v4a), (&pt4b, v4b)],
            &pr4,
        )
        .expect("vp4");

        let pending_v = [vp0, vp1, vp2, vp3, vp4];
        let verified_tail =
            verify_joined_tail(&mut tv, 2000, &tail_plan, &pending_v, &tail_proof).expect("vtail");
        assert_eq!(verified_tail.ledger().num_blocks, 5);
        assert_eq!(verified_tail.ledger().gamma_rlc_numerator, 4);
        assert_eq!(verified_tail.ledger().levels[0].blocks, 5);
        assert_eq!(
            verified_tail.ledger().levels[0].ell,
            tail_plan.effective_level1_ell()
        );
        assert_eq!(verified_tail.ledger().levels[0].gamma_numerator, 4);
        assert!(verified_tail.ledger().merkle_usage.hash_evaluations > 0);
        assert_eq!(
            tv.challenge(ChallengeLabel::Sumcheck).expect("cont_v"),
            cont_p
        );

        // Determinism check: repeating tail proof on identical state yields byte-identical bytes.
        let mut tp_det = Transcript::<K>::new(b"e19-04-det").expect("td1");
        let tail_a = prove_joined_tail(&mut tp_det, 2000, &tail_plan, &pending_p).expect("ta");
        let mut tp_det2 = Transcript::<K>::new(b"e19-04-det").expect("td2");
        let tail_b = prove_joined_tail(&mut tp_det2, 2000, &tail_plan, &pending_p).expect("tb");
        assert_eq!(tail_a, tail_b);

        // Composed NC-0631 on joined tail: tamper 1 byte in a level-1 queried column payload -> Merkle(RootMismatch).
        let mut bad_col = tail_a.clone();
        let hlen = tail_plan.header_bytes();
        let sc_bytes = usize::from(tail_plan.effective_level1_ell()) * 3 * (4 * K::DEGREE);
        let root_or_u = if tail_levels.len() > 1 {
            32
        } else {
            l1.columns().expect("c") * (4 * K::DEGREE)
        };
        let col_off = hlen + sc_bytes + root_or_u + 1;
        bad_col[col_off] ^= 1;
        let mut tv_bad_col = Transcript::<K>::new(b"e19-04-det").expect("tbc");
        assert_eq!(
            verify_joined_tail(&mut tv_bad_col, 2000, &tail_plan, &pending_v, &bad_col),
            Err(RecursiveError::Merkle(merkle::Error::RootMismatch))
        );

        // Composed NC-0632 on final u_L (1-level tail): flip 1 element of u_L -> rejected.
        if tail_levels.len() == 1 {
            let mut bad_u = tail_a.clone();
            let u_off = hlen + sc_bytes;
            let elem = 4 * K::DEGREE;
            let orig = K::from_le_bytes(bad_u[u_off..u_off + elem].try_into().ok().expect("slice"))
                .expect("k");
            let flipped = orig + K::from_i64(1);
            bad_u[u_off..u_off + elem].copy_from_slice(flipped.to_le_bytes().as_ref());
            let mut tv_u = Transcript::<K>::new(b"e19-04-det").expect("tvu");
            assert!(verify_joined_tail(&mut tv_u, 2000, &tail_plan, &pending_v, &bad_u).is_err());
        }

        // Composed NC-0633 on joined tail header: wrong block count in header -> ProofShape with 0 transcript work.
        let mut bad_hdr = tail_a.clone();
        bad_hdr[2] ^= 1;
        let mut tv_hdr = Transcript::<K>::new(b"e19-04-det").expect("tvh");
        let before = tv_hdr.usage();
        assert_eq!(
            verify_joined_tail(&mut tv_hdr, 2000, &tail_plan, &pending_v, &bad_hdr),
            Err(RecursiveError::ProofShape)
        );
        assert_eq!(tv_hdr.usage(), before);

        // Composed sumcheck tamper on level-1 joined row sumcheck -> RoundSumMismatch.
        let mut bad_sc = tail_a.clone();
        let sc_elem_off = hlen;
        let sc_orig = K::from_le_bytes(
            bad_sc[sc_elem_off..sc_elem_off + 4 * K::DEGREE]
                .try_into()
                .ok()
                .expect("sc"),
        )
        .expect("k");
        let sc_tampered = sc_orig + K::from_i64(1);
        bad_sc[sc_elem_off..sc_elem_off + 4 * K::DEGREE]
            .copy_from_slice(sc_tampered.to_le_bytes().as_ref());
        let mut tv_sc = Transcript::<K>::new(b"e19-04-det").expect("tvsc");
        assert_eq!(
            verify_joined_tail(&mut tv_sc, 2000, &tail_plan, &pending_v, &bad_sc),
            Err(RecursiveError::RoundSumMismatch)
        );

        // Composed NC-0634 on fresh level-0 closing batch sumcheck -> RoundSumMismatch.
        let mut bad_l0_sc = pr0.clone();
        let orig_l0 =
            K::from_le_bytes(bad_l0_sc[..4 * K::DEGREE].try_into().ok().expect("l0sc")).expect("k");
        let bad_l0 = orig_l0 + K::from_i64(1);
        bad_l0_sc[..4 * K::DEGREE].copy_from_slice(bad_l0.to_le_bytes().as_ref());
        let mut tv_l0_sc = Transcript::<K>::new(b"e19-04-joined").expect("tvl0");
        assert_eq!(
            verify_fresh_level0_claims(
                &mut tv_l0_sc,
                &src0,
                1000,
                l1,
                &[(&pt0a, v0a), (&pt0b, v0b)],
                &bad_l0_sc,
            )
            .err(),
            Some(RecursiveError::RoundSumMismatch)
        );

        // Composed NC-0635 on certified level-0 closing: wrong-radius certificate -> CertificateContext with 0 transcript work.
        let p2_wrong = CertifiedPlan::new(
            vec![LevelSpec::new(2, l1_bits, 2)],
            K::DEGREE as u8,
            DEFAULT_TARGET_BITS,
            16,
        )
        .expect("p2_wrong");
        let mod2_wrong = CertifiedModelSource::<K>::register(102, p2_wrong, &m2).expect("reg2w");
        let cert2_wrong = verify_certified_registration(
            mod2_wrong.source().clone(),
            mod2_wrong.certificate_proof(),
        )
        .expect("vc2w");
        let mut tv_c35 = Transcript::<K>::new(b"e19-04-c35").expect("tvc35");
        let before_c35 = tv_c35.usage();
        assert_eq!(
            verify_certified_level0(
                &mut tv_c35,
                &cert2_wrong,
                mod2.source(),
                1002,
                l1,
                &rw2,
                ColumnFunctional::Tensor(&cp2),
                v2,
                &pr2,
            )
            .err(),
            Some(RecursiveError::CertificateContext)
        );
        assert_eq!(tv_c35.usage(), before_c35);
    }

    // 1-level tail (L=2 total) in QM31 & OM31, and 2-level tail (L=3 total) in QM31.
    run_mixed::<QM31>(vec![LevelSpec::new(2, 4, 2)], 7001);
    run_mixed::<OM31>(vec![LevelSpec::new(2, 4, 2)], 7002);
    run_mixed::<QM31>(vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 3)], 7003);

    // k = 1 joined tail (no PcsLevelGamma draw, gamma_rlc_numerator == 0).
    {
        let l1 = LevelSpec::new(2, 3, 2);
        let tail_plan = JoinedTailPlan::new(vec![l1], 1, 4, DEFAULT_TARGET_BITS).expect("k1");
        assert_eq!(tail_plan.block_bits(), 0);
        let p0 =
            RecursivePlan::new(vec![LevelSpec::new(2, 5, 2)], 4, DEFAULT_TARGET_BITS).expect("p0");
        let msg = seeded_m31(p0.level0_elements().expect("e"), 7100);
        let prep = PreparedRecursive::<QM31>::commit(710, p0, msg).expect("c");
        let src = prep.source().clone();
        let pt = seeded_point::<QM31>(7, b"k1-pt");
        let val = prep.evaluate(&pt).expect("ev");
        let mut tp = Transcript::<QM31>::new(b"e19-04-k1").expect("tp");
        let (pr0, pend0) = prep
            .close_fresh_level0_claims(&mut tp, 710, l1, &[(&pt, val)])
            .expect("cl");
        let tail = prove_joined_tail(&mut tp, 711, &tail_plan, &[pend0]).expect("tail");
        let mut tv = Transcript::<QM31>::new(b"e19-04-k1").expect("tv");
        let vp0 =
            verify_fresh_level0_claims(&mut tv, &src, 710, l1, &[(&pt, val)], &pr0).expect("vp");
        let vt = verify_joined_tail(&mut tv, 711, &tail_plan, &[vp0], &tail).expect("vt");
        assert_eq!(vt.ledger().gamma_rlc_numerator, 0);
        assert_eq!(vt.ledger().levels[0].blocks, 1);
    }

    // Memory drop check: large level-0 segment (R_0=256, C_0=256, full codeword = 1 MiB) drops on close;
    // PendingLevel1Prover holds only u_1 (256 QM31 = 4 KiB) + encoded u_1 (16 KiB) << level-0 codeword.
    {
        let l0 = LevelSpec::new(8, 8, 2);
        let l1 = LevelSpec::new(4, 4, 2);
        let p0 = RecursivePlan::new(vec![l0], 4, DEFAULT_TARGET_BITS).expect("p0");
        let msg = seeded_m31(256 * 256, 7200);
        let full_l0_codeword = 256 * 1024 * 4;
        let prep = PreparedRecursive::<QM31>::commit(720, p0, msg).expect("c");
        let pt = seeded_point::<QM31>(16, b"drop-pt");
        let val = prep.evaluate(&pt).expect("ev");
        let mut tp = Transcript::<QM31>::new(b"e19-04-drop").expect("tp");
        let (_pr0, pend0) = prep
            .close_fresh_level0_claims(&mut tp, 720, l1, &[(&pt, val)])
            .expect("cl");
        assert!(
            pend0.resident_bytes() * 20 < full_l0_codeword,
            "resident={} vs full_l0={}",
            pend0.resident_bytes(),
            full_l0_codeword
        );
    }

    // JoinedTailPlan cap enforcement regressions:
    // (a) PcsLevelGamma cap: T=120 on QM31 has cap=15, so num_blocks=17 (gamma_num=16 > 15) must reject.
    assert_eq!(
        JoinedTailPlan::new(vec![LevelSpec::new(1, 2, 1)], 17, 4, 120),
        Err(RecursiveError::UnsupportedSource)
    );
    // (b) Logical level-1 proximity cap: single block (ell_1=2, m_1=20, b_1=4 -> e_1=5,242,879) has
    //     2*2*(e_1+1) = 20,971,520 > 16,777,215; even ell_1=1 (10,485,760 <= cap) fails once num_blocks=2
    //     raises eff_ell_1 = 1 + 1 = 2 (20,971,520 > cap)!
    assert!(JoinedTailPlan::new(vec![LevelSpec::new(1, 20, 4)], 1, 4, 100).is_ok());
    assert_eq!(
        JoinedTailPlan::new(vec![LevelSpec::new(1, 20, 4)], 2, 4, 100),
        Err(RecursiveError::UnsupportedSource)
    );
}
