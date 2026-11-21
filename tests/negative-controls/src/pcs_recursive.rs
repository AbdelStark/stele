//! RFC-0029 §6, RFC-0010 A17 — executable negative controls NC-0630..0634 through the actual
//! recursive opening verifiers (`verify_fresh_at_point` and `verify_fresh_claims`).
#![forbid(unsafe_code)]

use stele_field::{Field, Inverse, Serialize, M31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::recursive::{
    level_descriptor, verify_certified_opening, verify_certified_registration,
    verify_fresh_at_point, verify_fresh_claims, CertifiedModelSource, CertifiedPlan,
    ColumnFunctional, LevelSpec, PreparedRecursive, RecursiveError, RecursivePlan, RecursiveSource,
};
use stele_pcs::CircleCoeff;

fn dbg_err<E: core::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

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

fn seeded_point(len: usize, seed: &[u8]) -> Result<Vec<QM31>, String> {
    let mut t = Transcript::<QM31>::new(seed).map_err(dbg_err)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(t.challenge(ChallengeLabel::Sumcheck).map_err(dbg_err)?);
    }
    Ok(out)
}

fn commit_m31_raw(
    source_id: u64,
    spec: LevelSpec,
    message: &[M31],
) -> Result<(Vec<u8>, merkle::Tree, merkle::Descriptor), String> {
    let rows = spec.rows().map_err(dbg_err)?;
    let cols = spec.columns().map_err(dbg_err)?;
    let n = spec.codeword_len().map_err(dbg_err)?;
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).map_err(dbg_err)?;
    let mut col_bytes = vec![0u8; n * rows * 4];
    for (r, row) in message.chunks_exact(cols).enumerate() {
        let enc = code.encode(row).map_err(dbg_err)?;
        for (j, val) in enc.iter().enumerate() {
            let off = j * rows * 4 + r * 4;
            col_bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
    let desc = level_descriptor(source_id, 0, spec, 4).map_err(dbg_err)?;
    let leaves: Vec<&[u8]> = col_bytes.chunks_exact(rows * 4).collect();
    let tree =
        merkle::Tree::new_with_usage(desc, &leaves, &mut HashUsage::default()).map_err(dbg_err)?;
    Ok((col_bytes, tree, desc))
}

fn commit_ext_raw(
    source_id: u64,
    level: u8,
    spec: LevelSpec,
    message: &[QM31],
) -> Result<(Vec<u8>, merkle::Tree, merkle::Descriptor), String> {
    let rows = spec.rows().map_err(dbg_err)?;
    let cols = spec.columns().map_err(dbg_err)?;
    let n = spec.codeword_len().map_err(dbg_err)?;
    let elem = 16usize;
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).map_err(dbg_err)?;
    let mut col_bytes = vec![0u8; n * rows * elem];
    for (r, row) in message.chunks_exact(cols).enumerate() {
        let enc = code.encode(row).map_err(dbg_err)?;
        for (j, val) in enc.iter().enumerate() {
            let off = j * rows * elem + r * elem;
            col_bytes[off..off + elem].copy_from_slice(&val.to_le_bytes());
        }
    }
    let desc = level_descriptor(source_id, level, spec, elem).map_err(dbg_err)?;
    let leaves: Vec<&[u8]> = col_bytes.chunks_exact(rows * elem).collect();
    let tree =
        merkle::Tree::new_with_usage(desc, &leaves, &mut HashUsage::default()).map_err(dbg_err)?;
    Ok((col_bytes, tree, desc))
}

fn append_col(
    col_bytes: &[u8],
    tree: &merkle::Tree,
    width: usize,
    idx: u64,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let j = idx as usize;
    out.extend_from_slice(&col_bytes[j * width..(j + 1) * width]);
    for sib in tree.path(idx).map_err(dbg_err)? {
        out.extend_from_slice(&sib);
    }
    Ok(())
}

fn absorb_open_stmt(
    t: &mut Transcript<QM31>,
    opening_id: u64,
    source: &RecursiveSource<QM31>,
    point: &[QM31],
    value: QM31,
) -> Result<(), String> {
    let sb = source.bytes().map_err(dbg_err)?;
    let mut frame = Vec::new();
    frame.extend_from_slice(&opening_id.to_le_bytes());
    frame.extend_from_slice(&sb);
    for p in point {
        frame.extend_from_slice(&p.to_le_bytes());
    }
    frame.extend_from_slice(&value.to_le_bytes());
    t.absorb(AbsorbLabel::Opening, &frame).map_err(dbg_err)
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

fn interp2(y: [QM31; 3], r: QM31) -> QM31 {
    let one = QM31::from_i64(1);
    let two = QM31::from_i64(2);
    let inv2 = M31::from_i64(1 << 30);
    (y[0] * ((r - one) * (r - two))).mul_m31(inv2) - y[1] * (r * (r - two))
        + (y[2] * (r * (r - one))).mul_m31(inv2)
}

fn nc_0630() -> Result<(), String> {
    // 1. L = 1: honest passes, corrupted u_1 (1 entry +1) rejects with ColumnMismatch.
    let plan1 = RecursivePlan::new(vec![LevelSpec::new(2, 3, 2)], 4, 100).map_err(dbg_err)?;
    let msg1 = seeded_m31(plan1.level0_elements().map_err(dbg_err)?, 6301);
    let prepared1 =
        PreparedRecursive::<QM31>::commit(6301, plan1.clone(), msg1.clone()).map_err(dbg_err)?;
    let source1 = prepared1.source().clone();
    let point1 = seeded_point(5, b"nc-0630-l1")?;
    let value1 = prepared1.evaluate(&point1).map_err(dbg_err)?;

    let mut th = Transcript::<QM31>::new(b"nc-0630-h1").map_err(dbg_err)?;
    let honest1 = prepared1
        .open_fresh_at_point(&mut th, 1, &point1, value1)
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0630-h1").map_err(dbg_err)?;
    verify_fresh_at_point(&mut tvh, &source1, 1, &point1, value1, &honest1)
        .map_err(|e| format!("honest L=1 failed: {e:?}"))?;

    let (col0, tree0, desc0) = commit_m31_raw(6301, plan1.levels()[0], &msg1)?;
    let eq_row = stele_poly::eq_table(&point1[..2]).map_err(dbg_err)?;
    let mut u1 = vec![QM31::from_i64(0); 8];
    for (row, &a) in msg1.chunks_exact(8).zip(&eq_row) {
        for (dst, &v) in u1.iter_mut().zip(row) {
            *dst = *dst + a.mul_m31(v);
        }
    }
    u1[0] = u1[0] + QM31::from_i64(1);
    let mut tp = Transcript::<QM31>::new(b"nc-0630-f1").map_err(dbg_err)?;
    absorb_open_stmt(&mut tp, 1, &source1, &point1, value1)?;
    let mut forged1 = Vec::new();
    write_plan_header(&plan1, &mut forged1);
    let u_start = forged1.len();
    for v in &u1 {
        forged1.extend_from_slice(&v.to_le_bytes());
    }
    tp.absorb(AbsorbLabel::PcsLevelRoot, &forged1[u_start..])
        .map_err(dbg_err)?;
    let r_start = forged1.len();
    for _ in 0..plan1.queries()[0] {
        let idx = tp.opening_column(desc0.count).map_err(dbg_err)?;
        append_col(&col0, &tree0, desc0.width as usize, idx, &mut forged1)?;
    }
    tp.absorb(AbsorbLabel::OpeningColumns, &forged1[r_start..])
        .map_err(dbg_err)?;
    let mut tv = Transcript::<QM31>::new(b"nc-0630-f1").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv, &source1, 1, &point1, value1, &forged1) {
        Err(RecursiveError::ColumnMismatch) => {}
        other => return Err(format!("L=1 expected ColumnMismatch, got {other:?}")),
    }

    // 2. L = 2: honest passes, corrupted committed u_1' rejects with ColumnMismatch at final check.
    // 2. L = 2: genuine residual-propagating malicious prover parameterized by u_1_cand.
    //    - With uncorrupted u_1 (delta_0 == 0): verifies Ok (proves non-vacuity).
    //    - With single-entry tamper u_1'[3] += 1:
    //        * scalar-forged u_2 (matching ⟨w_2, u_2⟩ == running): rejects with ColumnMismatch.
    //        * honest u_2 = eq(r_1)^T u_1' (passing all column checks): rejects with ValueMismatch.
    //    - With PcsLevelBeta-only tamper u_1'' satisfying ⟨eq(r_col0), u_1''⟩ == value2:
    //        * rejects with ColumnMismatch / ValueMismatch purely via PcsLevelBeta column terms.
    let plan2 = RecursivePlan::new(
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
        4,
        100,
    )
    .map_err(dbg_err)?;
    let msg2 = seeded_m31(plan2.level0_elements().map_err(dbg_err)?, 6302);
    let prepared2 =
        PreparedRecursive::<QM31>::commit(6302, plan2.clone(), msg2.clone()).map_err(dbg_err)?;
    let source2 = prepared2.source().clone();
    let point2 = seeded_point(6, b"nc-0630-l2")?;
    let value2 = prepared2.evaluate(&point2).map_err(dbg_err)?;

    let (col0_2, tree0_2, desc0_2) = commit_m31_raw(6302, plan2.levels()[0], &msg2)?;
    let eq_row0 = stele_poly::eq_table(&point2[..2]).map_err(dbg_err)?;
    let eq_col0 = stele_poly::eq_table(&point2[2..]).map_err(dbg_err)?;
    let code0_2 = CircleCoeff::new(4, 2).map_err(dbg_err)?;
    let mut u1_honest = vec![QM31::from_i64(0); 16];
    for (row, &a) in msg2.chunks_exact(16).zip(&eq_row0) {
        for (dst, &v) in u1_honest.iter_mut().zip(row) {
            *dst = *dst + a.mul_m31(v);
        }
    }

    let build_l2 =
        |u1_cand: &[QM31], forge_u2_scalar: bool, tag: &[u8]| -> Result<Vec<u8>, String> {
            let (col1, tree1, desc1) = commit_ext_raw(6302, 1, plan2.levels()[1], u1_cand)?;
            let mut tp = Transcript::<QM31>::new(tag).map_err(dbg_err)?;
            absorb_open_stmt(&mut tp, 2, &source2, &point2, value2)?;
            let mut out = Vec::new();
            write_plan_header(&plan2, &mut out);
            let root1 = tree1.root();
            out.extend_from_slice(&root1);
            tp.absorb(AbsorbLabel::PcsLevelRoot, &root1)
                .map_err(dbg_err)?;

            let r0_start = out.len();
            let mut queried0 = Vec::new();
            let mut ys0 = Vec::new();
            for _ in 0..plan2.queries()[0] {
                let idx = tp.opening_column(desc0_2.count).map_err(dbg_err)?;
                let width = desc0_2.width as usize;
                let pay = &col0_2[idx as usize * width..(idx as usize + 1) * width];
                let mut y = QM31::from_i64(0);
                for (&w, ch) in eq_row0.iter().zip(pay.chunks_exact(4)) {
                    let arr: [u8; 4] = ch.try_into().map_err(dbg_err)?;
                    let m = M31::from_le_bytes(arr).ok_or_else(|| "noncanonical M31".to_owned())?;
                    y = y + w.mul_m31(m);
                }
                queried0.push(idx);
                ys0.push(y);
                append_col(&col0_2, &tree0_2, width, idx, &mut out)?;
            }
            tp.absorb(AbsorbLabel::OpeningColumns, &out[r0_start..])
                .map_err(dbg_err)?;

            let beta0 = tp
                .challenge(ChallengeLabel::PcsLevelBeta)
                .map_err(dbg_err)?;
            let mut w1 = eq_col0.clone();
            let mut v1 = value2;
            let mut bp = beta0;
            for (&idx, &y) in queried0.iter().zip(&ys0) {
                v1 = v1 + bp * y;
                let mut factors = code0_2.basis_factors(idx as usize).map_err(dbg_err)?;
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

            // Exact residual `delta = v1 - ⟨w1, u1_cand⟩`; identically 0 when u1_cand == u1_honest.
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
            inst.extend_from_slice(&v1.to_le_bytes());
            tp.absorb(AbsorbLabel::Instance, &inst).map_err(dbg_err)?;

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
                // Propagate residual through L_0(r) so `y0' + y1 == running` holds in every round.
                let vals = [y0 + delta, y1, y2];
                for v in vals {
                    out.extend_from_slice(&v.to_le_bytes());
                }
                let mut rb = Vec::new();
                rb.extend_from_slice(&2u64.to_le_bytes());
                rb.extend_from_slice(&rnd.to_le_bytes());
                for v in vals {
                    rb.extend_from_slice(&v.to_le_bytes());
                }
                tp.absorb(AbsorbLabel::Round, &rb).map_err(dbg_err)?;
                let r = tp.challenge(ChallengeLabel::Sumcheck).map_err(dbg_err)?;
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

            // cur_m is exact `u_2_honest = eq(r_1)^T u1_cand`; cur_w is exact `w_2`.
            let mut u2 = cur_m;
            if forge_u2_scalar && delta != QM31::from_i64(0) {
                let (k, wk) = cur_w
                    .iter()
                    .enumerate()
                    .find(|&(_, &w)| w != QM31::from_i64(0))
                    .ok_or_else(|| "all-zero w_2".to_owned())?;
                let inv_wk = wk
                    .inverse()
                    .ok_or_else(|| "non-invertible w_2".to_owned())?;
                u2[k] = u2[k] + delta * inv_wk;
            }

            let u2_start = out.len();
            for v in &u2 {
                out.extend_from_slice(&v.to_le_bytes());
            }
            tp.absorb(AbsorbLabel::PcsLevelRoot, &out[u2_start..])
                .map_err(dbg_err)?;
            let r1_start = out.len();
            for _ in 0..plan2.queries()[1] {
                let idx = tp.opening_column(desc1.count).map_err(dbg_err)?;
                append_col(&col1, &tree1, desc1.width as usize, idx, &mut out)?;
            }
            tp.absorb(AbsorbLabel::OpeningColumns, &out[r1_start..])
                .map_err(dbg_err)?;
            Ok(out)
        };

    // (a) Non-vacuity check: exact same builder with uncorrupted u_1 MUST be accepted!
    let honest_built = build_l2(&u1_honest, true, b"nc-0630-l2-honest")?;
    let mut tv_ok = Transcript::<QM31>::new(b"nc-0630-l2-honest").map_err(dbg_err)?;
    verify_fresh_at_point(&mut tv_ok, &source2, 2, &point2, value2, &honest_built)
        .map_err(|e| format!("non-vacuity L=2 check failed: {e:?}"))?;

    // (b) Single-entry tamper u_1'[3] += 1:
    let mut u1_single = u1_honest.clone();
    u1_single[3] = u1_single[3] + QM31::from_i64(1);
    let forged_col = build_l2(&u1_single, true, b"nc-0630-l2-single-col")?;
    let mut tv_col = Transcript::<QM31>::new(b"nc-0630-l2-single-col").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv_col, &source2, 2, &point2, value2, &forged_col) {
        Err(RecursiveError::ColumnMismatch) => {}
        other => {
            return Err(format!(
                "L=2 single-entry expected ColumnMismatch, got {other:?}"
            ))
        }
    }
    let forged_val = build_l2(&u1_single, false, b"nc-0630-l2-single-val")?;
    let mut tv_val = Transcript::<QM31>::new(b"nc-0630-l2-single-val").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv_val, &source2, 2, &point2, value2, &forged_val) {
        Err(RecursiveError::ValueMismatch) => {}
        other => {
            return Err(format!(
                "L=2 single-entry honest-u2 expected ValueMismatch, got {other:?}"
            ))
        }
    }

    // (c) PcsLevelBeta-only tamper: ⟨eq(r_col0), u_1''⟩ == value2 holds identically, so ONLY
    //     PcsLevelBeta's β_0^j column consistency terms detect the corruption!
    let mut u1_beta = u1_honest;
    u1_beta[0] = u1_beta[0] + eq_col0[1];
    u1_beta[1] = u1_beta[1] - eq_col0[0];
    let mut check_v0 = QM31::from_i64(0);
    for (&e, &u) in eq_col0.iter().zip(&u1_beta) {
        check_v0 = check_v0 + e * u;
    }
    if check_v0 != value2 {
        return Err("PcsLevelBeta-only tamper failed to preserve v_0".to_owned());
    }
    let forged_beta = build_l2(&u1_beta, true, b"nc-0630-l2-beta")?;
    let mut tv_beta = Transcript::<QM31>::new(b"nc-0630-l2-beta").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv_beta, &source2, 2, &point2, value2, &forged_beta) {
        Err(RecursiveError::ColumnMismatch) => Ok(()),
        other => Err(format!(
            "L=2 PcsLevelBeta-only expected ColumnMismatch, got {other:?}"
        )),
    }
}

fn nc_0631() -> Result<(), String> {
    let plan = RecursivePlan::new(
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
        4,
        100,
    )
    .map_err(dbg_err)?;
    let msg = seeded_m31(plan.level0_elements().map_err(dbg_err)?, 631);
    let (col0, tree0, desc0) = commit_m31_raw(631, plan.levels()[0], &msg)?;
    let prepared = PreparedRecursive::<QM31>::commit(631, plan.clone(), msg).map_err(dbg_err)?;
    let source = prepared.source().clone();
    let point = seeded_point(6, b"nc-0631-p")?;
    let value = prepared.evaluate(&point).map_err(dbg_err)?;

    let mut tp = Transcript::<QM31>::new(b"nc-0631-t").map_err(dbg_err)?;
    let honest = prepared
        .open_fresh_at_point(&mut tp, 3, &point, value)
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0631-t").map_err(dbg_err)?;
    verify_fresh_at_point(&mut tvh, &source, 3, &point, value, &honest)
        .map_err(|e| format!("honest failed: {e:?}"))?;

    // Swap query 0 at level 0 with the valid column+path of `(idx0 + 1) % N_0`.
    let mut tampered = honest.clone();
    let mut ts = Transcript::<QM31>::new(b"nc-0631-t").map_err(dbg_err)?;
    absorb_open_stmt(&mut ts, 3, &source, &point, value)?;
    let hlen = plan.header_bytes();
    ts.absorb(AbsorbLabel::PcsLevelRoot, &tampered[hlen..hlen + 32])
        .map_err(dbg_err)?;
    let idx0 = ts.opening_column(desc0.count).map_err(dbg_err)?;
    let other = (idx0 + 1) % desc0.count;
    let mut replacement = Vec::new();
    append_col(&col0, &tree0, desc0.width as usize, other, &mut replacement)?;
    let q0_off = hlen + 32;
    tampered[q0_off..q0_off + replacement.len()].copy_from_slice(&replacement);

    let mut tv = Transcript::<QM31>::new(b"nc-0631-t").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv, &source, 3, &point, value, &tampered) {
        Err(RecursiveError::Merkle(merkle::Error::RootMismatch)) => {}
        other => return Err(format!("level-0 swap expected RootMismatch, got {other:?}")),
    }

    // Also tamper level 1's first queried column payload byte -> RootMismatch at level 1.
    let mut tampered1 = honest;
    let q0_total = usize::from(plan.queries()[0])
        * (desc0.width as usize + plan.levels()[0].path_height() * 32);
    let l1_sc = usize::from(plan.levels()[1].ell) * 3 * 16;
    let l1_u_final = plan.levels()[1].columns().map_err(dbg_err)? * 16;
    let l1_q0_off = hlen + 32 + q0_total + l1_sc + l1_u_final;
    tampered1[l1_q0_off] ^= 1;
    let mut tv1 = Transcript::<QM31>::new(b"nc-0631-t").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv1, &source, 3, &point, value, &tampered1) {
        Err(RecursiveError::Merkle(merkle::Error::RootMismatch)) => Ok(()),
        other => Err(format!("level-1 swap expected RootMismatch, got {other:?}")),
    }
}

fn nc_0632() -> Result<(), String> {
    let plan = RecursivePlan::new(vec![LevelSpec::new(2, 3, 2)], 4, 100).map_err(dbg_err)?;
    let msg = seeded_m31(plan.level0_elements().map_err(dbg_err)?, 632);
    let prepared =
        PreparedRecursive::<QM31>::commit(632, plan.clone(), msg.clone()).map_err(dbg_err)?;
    let source = prepared.source().clone();
    let point = seeded_point(5, b"nc-0632-p")?;
    let value = prepared.evaluate(&point).map_err(dbg_err)?;

    let mut th = Transcript::<QM31>::new(b"nc-0632-h").map_err(dbg_err)?;
    let honest = prepared
        .open_fresh_at_point(&mut th, 4, &point, value)
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0632-h").map_err(dbg_err)?;
    verify_fresh_at_point(&mut tvh, &source, 4, &point, value, &honest)
        .map_err(|e| format!("honest failed: {e:?}"))?;

    let (col0, tree0, desc0) = commit_m31_raw(632, plan.levels()[0], &msg)?;
    let eq_row = stele_poly::eq_table(&point[..2]).map_err(dbg_err)?;
    let mut u_honest = vec![QM31::from_i64(0); 8];
    for (row, &a) in msg.chunks_exact(8).zip(&eq_row) {
        for (dst, &v) in u_honest.iter_mut().zip(row) {
            *dst = *dst + a.mul_m31(v);
        }
    }

    // Variant A: u_L with one entry changed BEFORE queries -> ColumnMismatch.
    let mut u_bad = u_honest.clone();
    u_bad[5] = u_bad[5] + QM31::from_i64(1);
    let mut tp_a = Transcript::<QM31>::new(b"nc-0632-a").map_err(dbg_err)?;
    absorb_open_stmt(&mut tp_a, 4, &source, &point, value)?;
    let mut forged_a = Vec::new();
    write_plan_header(&plan, &mut forged_a);
    let ua = forged_a.len();
    for v in &u_bad {
        forged_a.extend_from_slice(&v.to_le_bytes());
    }
    tp_a.absorb(AbsorbLabel::PcsLevelRoot, &forged_a[ua..])
        .map_err(dbg_err)?;
    let ra = forged_a.len();
    for _ in 0..plan.queries()[0] {
        let idx = tp_a.opening_column(desc0.count).map_err(dbg_err)?;
        append_col(&col0, &tree0, desc0.width as usize, idx, &mut forged_a)?;
    }
    tp_a.absorb(AbsorbLabel::OpeningColumns, &forged_a[ra..])
        .map_err(dbg_err)?;
    let mut tv_a = Transcript::<QM31>::new(b"nc-0632-a").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv_a, &source, 4, &point, value, &forged_a) {
        Err(RecursiveError::ColumnMismatch) => {}
        other => return Err(format!("Variant A expected ColumnMismatch, got {other:?}")),
    }

    // Variant B: u_L satisfies all queried columns (`Enc(u_L)[j] == y_j`), scalar disagrees -> ValueMismatch.
    let wrong_val = value + QM31::from_i64(1);
    let mut tp_b = Transcript::<QM31>::new(b"nc-0632-b").map_err(dbg_err)?;
    absorb_open_stmt(&mut tp_b, 4, &source, &point, wrong_val)?;
    let mut forged_b = Vec::new();
    write_plan_header(&plan, &mut forged_b);
    let ub = forged_b.len();
    for v in &u_honest {
        forged_b.extend_from_slice(&v.to_le_bytes());
    }
    tp_b.absorb(AbsorbLabel::PcsLevelRoot, &forged_b[ub..])
        .map_err(dbg_err)?;
    let rb = forged_b.len();
    for _ in 0..plan.queries()[0] {
        let idx = tp_b.opening_column(desc0.count).map_err(dbg_err)?;
        append_col(&col0, &tree0, desc0.width as usize, idx, &mut forged_b)?;
    }
    tp_b.absorb(AbsorbLabel::OpeningColumns, &forged_b[rb..])
        .map_err(dbg_err)?;
    let mut tv_b = Transcript::<QM31>::new(b"nc-0632-b").map_err(dbg_err)?;
    match verify_fresh_at_point(&mut tv_b, &source, 4, &point, wrong_val, &forged_b) {
        Err(RecursiveError::ValueMismatch) => Ok(()),
        other => Err(format!("Variant B expected ValueMismatch, got {other:?}")),
    }
}

fn nc_0633() -> Result<(), String> {
    let plan_a = RecursivePlan::new(
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
        4,
        100,
    )
    .map_err(dbg_err)?;
    let plan_b = RecursivePlan::new(vec![LevelSpec::new(2, 4, 2)], 4, 100).map_err(dbg_err)?;
    let plan_c = RecursivePlan::new(
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(1, 3, 2)],
        4,
        100,
    )
    .map_err(dbg_err)?;
    let msg = seeded_m31(64, 633);
    let prep_a =
        PreparedRecursive::<QM31>::commit(633, plan_a.clone(), msg.clone()).map_err(dbg_err)?;
    let prep_b = PreparedRecursive::<QM31>::commit(633, plan_b, msg.clone()).map_err(dbg_err)?;
    let prep_c = PreparedRecursive::<QM31>::commit(633, plan_c, msg).map_err(dbg_err)?;
    let point = seeded_point(6, b"nc-0633-p")?;
    let value = prep_a.evaluate(&point).map_err(dbg_err)?;

    let mut th = Transcript::<QM31>::new(b"nc-0633").map_err(dbg_err)?;
    let honest = prep_a
        .open_fresh_at_point(&mut th, 5, &point, value)
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0633").map_err(dbg_err)?;
    verify_fresh_at_point(&mut tvh, prep_a.source(), 5, &point, value, &honest)
        .map_err(|e| format!("honest failed: {e:?}"))?;

    let mut tb = Transcript::<QM31>::new(b"nc-0633").map_err(dbg_err)?;
    let proof_b = prep_b
        .open_fresh_at_point(&mut tb, 5, &point, value)
        .map_err(dbg_err)?;
    let mut tc = Transcript::<QM31>::new(b"nc-0633").map_err(dbg_err)?;
    let proof_c = prep_c
        .open_fresh_at_point(&mut tc, 5, &point, value)
        .map_err(dbg_err)?;
    let mut tampered_hdr = honest;
    tampered_hdr[4] ^= 1;

    for (label, bad) in [
        ("wrong level count", &proof_b),
        ("wrong (ell, m, b)", &proof_c),
        ("tampered header", &tampered_hdr),
    ] {
        let mut tv = Transcript::<QM31>::new(b"nc-0633").map_err(dbg_err)?;
        let before = tv.usage();
        match verify_fresh_at_point(&mut tv, prep_a.source(), 5, &point, value, bad) {
            Err(RecursiveError::ProofShape) if tv.usage() == before => {}
            other => {
                return Err(format!(
                    "{label}: expected ProofShape with zero transcript work, got {other:?}"
                ));
            }
        }
    }
    Ok(())
}

fn nc_0634() -> Result<(), String> {
    let plan = RecursivePlan::new(
        vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
        4,
        100,
    )
    .map_err(dbg_err)?;
    let msg = seeded_m31(plan.level0_elements().map_err(dbg_err)?, 634);
    let prepared = PreparedRecursive::<QM31>::commit(634, plan.clone(), msg).map_err(dbg_err)?;
    let source = prepared.source().clone();
    let p_claim = seeded_point(6, b"nc-0634-claim")?;
    let v_claim = prepared.evaluate(&p_claim).map_err(dbg_err)?;

    let mut tp = Transcript::<QM31>::new(b"nc-0634-t").map_err(dbg_err)?;
    let honest = prepared
        .open_fresh_claims(&mut tp, 6, &[(&p_claim, v_claim)])
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0634-t").map_err(dbg_err)?;
    verify_fresh_claims(&mut tvh, &source, 6, &[(&p_claim, v_claim)], &honest)
        .map_err(|e| format!("honest failed: {e:?}"))?;

    // Open at a different point r_other != r* (not the batching sumcheck's derived point).
    let vars = plan.level0_vars();
    let elem = 16usize;
    let sc_bytes = vars * 3 * elem;
    let mut forged = honest[..sc_bytes].to_vec();
    let r_other = seeded_point(6, b"nc-0634-other-point")?;
    let v_other = prepared.evaluate(&r_other).map_err(dbg_err)?;
    forged.extend_from_slice(&v_other.to_le_bytes());

    let mut tf = Transcript::<QM31>::new(b"nc-0634-t").map_err(dbg_err)?;
    let sb = source.bytes().map_err(dbg_err)?;
    tf.absorb(AbsorbLabel::FieldSources, &sb).map_err(dbg_err)?;
    let mut chdr = Vec::new();
    chdr.extend_from_slice(&6u64.to_le_bytes());
    chdr.extend_from_slice(&1u32.to_le_bytes());
    for c in &p_claim {
        chdr.extend_from_slice(&c.to_le_bytes());
    }
    chdr.extend_from_slice(&v_claim.to_le_bytes());
    tf.absorb(AbsorbLabel::Batch, &chdr).map_err(dbg_err)?;
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&6u64.to_le_bytes());
    ihdr.push(0xff);
    ihdr.push(vars as u8);
    ihdr.push(2);
    ihdr.extend_from_slice(&v_claim.to_le_bytes());
    tf.absorb(AbsorbLabel::Instance, &ihdr).map_err(dbg_err)?;
    for rnd in 0..vars {
        let slice = &honest[rnd * 3 * elem..(rnd + 1) * 3 * elem];
        let mut rb = Vec::new();
        rb.extend_from_slice(&6u64.to_le_bytes());
        rb.extend_from_slice(&(rnd as u32).to_le_bytes());
        rb.extend_from_slice(slice);
        tf.absorb(AbsorbLabel::Round, &rb).map_err(dbg_err)?;
        let _ = tf.challenge(ChallengeLabel::Sumcheck).map_err(dbg_err)?;
    }
    tf.absorb(AbsorbLabel::Final, &v_other.to_le_bytes())
        .map_err(dbg_err)?;
    let rec_other = prepared
        .open_fresh_at_point(&mut tf, 6, &r_other, v_other)
        .map_err(dbg_err)?;
    forged.extend_from_slice(&rec_other);

    let mut tv = Transcript::<QM31>::new(b"nc-0634-t").map_err(dbg_err)?;
    match verify_fresh_claims(&mut tv, &source, 6, &[(&p_claim, v_claim)], &forged) {
        Err(RecursiveError::RoundSumMismatch) => Ok(()),
        other => Err(format!("expected RoundSumMismatch, got {other:?}")),
    }
}

fn nc_0635() -> Result<(), String> {
    // Certified mode: a certificate for another radius offered for the expected source -> CertificateContext.
    let plan_expected = CertifiedPlan::new(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        4,
        100,
        24,
    )
    .map_err(dbg_err)?;
    let plan_other = CertifiedPlan::new(
        vec![LevelSpec::new(2, 5, 2), LevelSpec::new(2, 3, 2)],
        4,
        100,
        16,
    )
    .map_err(dbg_err)?;
    let msg = seeded_m31(4 * 32, 635);
    let m_expected =
        CertifiedModelSource::<QM31>::register(635, plan_expected, &msg).map_err(dbg_err)?;
    let m_other = CertifiedModelSource::<QM31>::register(635, plan_other, &msg).map_err(dbg_err)?;

    // Honest certificate and opening pass cleanly.
    let cert_expected =
        verify_certified_registration(m_expected.source().clone(), m_expected.certificate_proof())
            .map_err(|e| format!("honest cert failed: {e:?}"))?;
    let rw = seeded_point(4, b"nc-0635-rw")?;
    let cp = seeded_point(5, b"nc-0635-cp")?;
    let val = m_expected
        .evaluate_functional(&msg, &rw, ColumnFunctional::Tensor(&cp))
        .map_err(dbg_err)?;
    let mut tp = Transcript::<QM31>::new(b"nc-0635").map_err(dbg_err)?;
    let honest_open = m_expected
        .open_certified(&msg, &mut tp, 635, &rw, ColumnFunctional::Tensor(&cp), val)
        .map_err(dbg_err)?;
    let mut tvh = Transcript::<QM31>::new(b"nc-0635").map_err(dbg_err)?;
    verify_certified_opening(
        &mut tvh,
        &cert_expected,
        m_expected.source(),
        635,
        &rw,
        ColumnFunctional::Tensor(&cp),
        val,
        &honest_open,
    )
    .map_err(|e| format!("honest opening failed: {e:?}"))?;

    // (a) Raw certificate proof for radius 16 offered to expected source with radius 24 -> CertificateContext.
    match verify_certified_registration(m_expected.source().clone(), m_other.certificate_proof()) {
        Err(RecursiveError::CertificateContext) => {}
        other => {
            return Err(format!(
                "raw cert for wrong radius expected CertificateContext, got {other:?}"
            ));
        }
    }

    // (b) VerifiedCertifiedSource for radius 16 offered to verify_certified_opening expecting radius 24 -> CertificateContext (zero transcript work).
    let cert_other =
        verify_certified_registration(m_other.source().clone(), m_other.certificate_proof())
            .map_err(dbg_err)?;
    let mut tv_bad = Transcript::<QM31>::new(b"nc-0635").map_err(dbg_err)?;
    let before = tv_bad.usage();
    match verify_certified_opening(
        &mut tv_bad,
        &cert_other,
        m_expected.source(),
        635,
        &rw,
        ColumnFunctional::Tensor(&cp),
        val,
        &honest_open,
    ) {
        Err(RecursiveError::CertificateContext) if tv_bad.usage() == before => {}
        other => {
            return Err(format!(
                "wrong-radius handle expected CertificateContext with zero transcript work, got {other:?}"
            ));
        }
    }

    // (c) Opening proof built under radius 16 offered to expected source with radius 24 -> CertificateContext.
    let mut tp_other = Transcript::<QM31>::new(b"nc-0635").map_err(dbg_err)?;
    let open_other = m_other
        .open_certified(
            &msg,
            &mut tp_other,
            635,
            &rw,
            ColumnFunctional::Tensor(&cp),
            val,
        )
        .map_err(dbg_err)?;
    let mut tv_bad2 = Transcript::<QM31>::new(b"nc-0635").map_err(dbg_err)?;
    let before2 = tv_bad2.usage();
    match verify_certified_opening(
        &mut tv_bad2,
        &cert_expected,
        m_expected.source(),
        635,
        &rw,
        ColumnFunctional::Tensor(&cp),
        val,
        &open_other,
    ) {
        Err(RecursiveError::CertificateContext) if tv_bad2.usage() == before2 => Ok(()),
        other => Err(format!(
            "wrong-radius opening expected CertificateContext with zero transcript work, got {other:?}"
        )),
    }
}

/// Dispatch NC-0630..0635 through the actual recursive opening verifiers.
pub fn run(id: u16) -> Result<(), String> {
    match id {
        630 => nc_0630(),
        631 => nc_0631(),
        632 => nc_0632(),
        633 => nc_0633(),
        634 => nc_0634(),
        635 => nc_0635(),
        _ => Err(format!("unknown recursive PCS control NC-{id:04}")),
    }
}
