//! RFC-0029 & RFC-0010 A17 — recursive opening integration tests and NC-0630..0634 verification.
#![forbid(unsafe_code)]

use stele_field::{Field, Inverse, Serialize, M31, OM31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::recursive::{
    level_descriptor, policy3_fresh_queries, verify_fresh_at_point, verify_fresh_claims, LevelSpec,
    PreparedRecursive, RecursiveError, RecursivePlan, RecursiveSource, DEFAULT_TARGET_BITS,
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
