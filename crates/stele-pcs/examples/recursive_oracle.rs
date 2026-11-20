//! RFC-0029 & RFC-0010 A17 — emit QM31 recursive opening vectors for independent Python
//! verification (`--vectors`) and measure actual opening bytes on `2^20..2^28` sources (`--measure`).
#![forbid(unsafe_code)]

use std::time::Instant;
use stele_field::{Field, Serialize, M31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::recursive::{
    level_descriptor, verify_fresh_at_point, verify_fresh_claims, LevelSpec, PreparedRecursive,
    RecursiveError, RecursivePlan, RecursiveSource, DEFAULT_TARGET_BITS,
};
use stele_pcs::CircleCoeff;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
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

fn seeded_point(len: usize, seed: &[u8]) -> Vec<QM31> {
    let mut t = Transcript::<QM31>::new(seed).expect("seed");
    (0..len)
        .map(|_| t.challenge(ChallengeLabel::Sumcheck).expect("coord"))
        .collect()
}

fn encode_point(pts: &[QM31]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pts.len() * 16);
    for p in pts {
        out.extend_from_slice(&p.to_le_bytes());
    }
    out
}

fn decision_name(
    res: &Result<stele_pcs::recursive::VerifiedRecursiveOpening<QM31>, RecursiveError>,
) -> &'static str {
    match res {
        Ok(_) => "Accept",
        Err(RecursiveError::UnsupportedSource) => "UnsupportedSource",
        Err(RecursiveError::ProofShape) => "ProofShape",
        Err(RecursiveError::NoncanonicalField) => "NoncanonicalField",
        Err(RecursiveError::MessageShape) => "MessageShape",
        Err(RecursiveError::Encoder(_)) => "Encoder",
        Err(RecursiveError::Merkle(merkle::Error::RootMismatch)) => "RootMismatch",
        Err(RecursiveError::Merkle(_)) => "Merkle",
        Err(RecursiveError::Transcript(_)) => "Transcript",
        Err(RecursiveError::ColumnMismatch) => "ColumnMismatch",
        Err(RecursiveError::ValueMismatch) => "ValueMismatch",
        Err(RecursiveError::RoundSumMismatch) => "RoundSumMismatch",
        Err(RecursiveError::Capacity) => "Capacity",
    }
}

fn emit_at_point_case(
    name: &str,
    public: &[u8],
    source: &RecursiveSource<QM31>,
    opening_id: u64,
    point: &[QM31],
    value: QM31,
    proof: &[u8],
) {
    let mut tv = Transcript::<QM31>::new(public).expect("tv");
    let res = verify_fresh_at_point(&mut tv, source, opening_id, point, value, proof);
    let cont = if res.is_ok() {
        hex(&tv
            .challenge(ChallengeLabel::Sumcheck)
            .expect("cont")
            .to_le_bytes())
    } else {
        String::new()
    };
    let val = serde_json::json!({
        "name": name,
        "kind": "at_point",
        "public_hex": hex(public),
        "source_bytes_hex": hex(&source.bytes().expect("src")),
        "opening_id": opening_id,
        "point_hex": hex(&encode_point(point)),
        "value_hex": hex(&value.to_le_bytes()),
        "proof_hex": hex(proof),
        "rust_decision": decision_name(&res),
        "continuation_hex": cont,
    });
    println!("{val}");
}

fn emit_claims_case(
    name: &str,
    public: &[u8],
    source: &RecursiveSource<QM31>,
    opening_id: u64,
    claims: &[(&[QM31], QM31)],
    proof: &[u8],
) {
    let mut tv = Transcript::<QM31>::new(public).expect("tv");
    let res = verify_fresh_claims(&mut tv, source, opening_id, claims, proof);
    let cont = if res.is_ok() {
        hex(&tv
            .challenge(ChallengeLabel::Sumcheck)
            .expect("cont")
            .to_le_bytes())
    } else {
        String::new()
    };
    let claims_json: Vec<_> = claims
        .iter()
        .map(|&(p, v)| {
            serde_json::json!({
                "point_hex": hex(&encode_point(p)),
                "value_hex": hex(&v.to_le_bytes()),
            })
        })
        .collect();
    let val = serde_json::json!({
        "name": name,
        "kind": "fresh_claims",
        "public_hex": hex(public),
        "source_bytes_hex": hex(&source.bytes().expect("src")),
        "opening_id": opening_id,
        "claims": claims_json,
        "proof_hex": hex(proof),
        "rust_decision": decision_name(&res),
        "continuation_hex": cont,
    });
    println!("{val}");
}

fn commit_m31_raw(
    source_id: u64,
    spec: LevelSpec,
    message: &[M31],
) -> (Vec<u8>, merkle::Tree, merkle::Descriptor) {
    let rows = spec.rows().expect("rows");
    let cols = spec.columns().expect("cols");
    let n = spec.codeword_len().expect("n");
    let code = CircleCoeff::new(u32::from(spec.m), u32::from(spec.b)).expect("code");
    let mut col_bytes = vec![0u8; n * rows * 4];
    for (r, row) in message.chunks_exact(cols).enumerate() {
        let enc = code.encode(row).expect("enc");
        for (j, val) in enc.iter().enumerate() {
            let off = j * rows * 4 + r * 4;
            col_bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
    let desc = level_descriptor(source_id, 0, spec, 4).expect("desc");
    let leaves: Vec<&[u8]> = col_bytes.chunks_exact(rows * 4).collect();
    let tree =
        merkle::Tree::new_with_usage(desc, &leaves, &mut HashUsage::default()).expect("tree");
    (col_bytes, tree, desc)
}

fn emit_vectors() {
    // 1. Honest L = 1, L = 2, L = 3 `at_point` cases across blowups 1, 2, 3, 4.
    let configs = [
        ("honest_l1_b1", vec![LevelSpec::new(2, 3, 1)], 101u64),
        (
            "honest_l2_b2_b3",
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 3)],
            102u64,
        ),
        (
            "honest_l3_b2_b3_b4",
            vec![
                LevelSpec::new(2, 6, 2),
                LevelSpec::new(2, 4, 3),
                LevelSpec::new(2, 2, 4),
            ],
            103u64,
        ),
    ];
    for (name, levels, seed) in configs {
        let plan = RecursivePlan::new(levels, 4, DEFAULT_TARGET_BITS).expect("plan");
        let msg = seeded_m31(plan.level0_elements().expect("elems"), seed);
        let prep = PreparedRecursive::<QM31>::commit(seed, plan.clone(), msg).expect("commit");
        let point = seeded_point(plan.level0_vars(), name.as_bytes());
        let value = prep.evaluate(&point).expect("eval");
        let pub_bytes = format!("py-vec-{name}").into_bytes();
        let mut tp = Transcript::<QM31>::new(&pub_bytes).expect("tp");
        let proof = prep
            .open_fresh_at_point(&mut tp, seed + 10, &point, value)
            .expect("prove");
        emit_at_point_case(
            name,
            &pub_bytes,
            prep.source(),
            seed + 10,
            &point,
            value,
            &proof,
        );
    }

    // 2. Honest `fresh_claims` (1-claim and 2-claim) on L = 2.
    {
        let plan = RecursivePlan::new(
            vec![LevelSpec::new(2, 4, 2), LevelSpec::new(2, 2, 2)],
            4,
            DEFAULT_TARGET_BITS,
        )
        .expect("plan");
        let msg = seeded_m31(plan.level0_elements().expect("elems"), 201);
        let prep = PreparedRecursive::<QM31>::commit(201, plan.clone(), msg).expect("commit");
        let p0 = seeded_point(plan.level0_vars(), b"claim-0");
        let p1 = seeded_point(plan.level0_vars(), b"claim-1");
        let v0 = prep.evaluate(&p0).expect("v0");
        let v1 = prep.evaluate(&p1).expect("v1");

        let mut t1 = Transcript::<QM31>::new(b"py-claims-1").expect("t1");
        let pr1 = prep
            .open_fresh_claims(&mut t1, 211, &[(&p0, v0)])
            .expect("pr1");
        emit_claims_case(
            "honest_fresh_1claim",
            b"py-claims-1",
            prep.source(),
            211,
            &[(&p0, v0)],
            &pr1,
        );

        let mut t2 = Transcript::<QM31>::new(b"py-claims-2").expect("t2");
        let pr2 = prep
            .open_fresh_claims(&mut t2, 212, &[(&p0, v0), (&p1, v1)])
            .expect("pr2");
        emit_claims_case(
            "honest_fresh_2claims",
            b"py-claims-2",
            prep.source(),
            212,
            &[(&p0, v0), (&p1, v1)],
            &pr2,
        );

        // NC-0634 vector: open at a different point r_other != r*.
        let vars = plan.level0_vars();
        let sc_bytes = vars * 3 * 16;
        let mut forged = pr1[..sc_bytes].to_vec();
        let r_other = seeded_point(vars, b"py-nc-0634-other");
        let v_other = prep.evaluate(&r_other).expect("v_other");
        forged.extend_from_slice(&v_other.to_le_bytes());
        let mut tf = Transcript::<QM31>::new(b"py-claims-1").expect("tf");
        tf.absorb(
            AbsorbLabel::FieldSources,
            &prep.source().bytes().expect("sb"),
        )
        .expect("abs");
        let mut chdr = Vec::new();
        chdr.extend_from_slice(&211u64.to_le_bytes());
        chdr.extend_from_slice(&1u32.to_le_bytes());
        chdr.extend_from_slice(&encode_point(&p0));
        chdr.extend_from_slice(&v0.to_le_bytes());
        tf.absorb(AbsorbLabel::Batch, &chdr).expect("abs");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&211u64.to_le_bytes());
        ihdr.push(0xff);
        ihdr.push(vars as u8);
        ihdr.push(2);
        ihdr.extend_from_slice(&v0.to_le_bytes());
        tf.absorb(AbsorbLabel::Instance, &ihdr).expect("abs");
        for rnd in 0..vars {
            let slice = &pr1[rnd * 48..(rnd + 1) * 48];
            let mut rb = Vec::new();
            rb.extend_from_slice(&211u64.to_le_bytes());
            rb.extend_from_slice(&(rnd as u32).to_le_bytes());
            rb.extend_from_slice(slice);
            tf.absorb(AbsorbLabel::Round, &rb).expect("abs");
            let _ = tf.challenge(ChallengeLabel::Sumcheck).expect("r");
        }
        tf.absorb(AbsorbLabel::Final, &v_other.to_le_bytes())
            .expect("abs");
        let rec = prep
            .open_fresh_at_point(&mut tf, 211, &r_other, v_other)
            .expect("rec");
        forged.extend_from_slice(&rec);
        emit_claims_case(
            "nc_0634_wrong_point",
            b"py-claims-1",
            prep.source(),
            211,
            &[(&p0, v0)],
            &forged,
        );
    }

    // 3. Tampered NC-0630, NC-0631, NC-0632 (ValueMismatch), NC-0633 vectors.
    {
        let plan = RecursivePlan::new(vec![LevelSpec::new(2, 3, 2)], 4, DEFAULT_TARGET_BITS)
            .expect("plan");
        let msg = seeded_m31(plan.level0_elements().expect("elems"), 301);
        let prep =
            PreparedRecursive::<QM31>::commit(301, plan.clone(), msg.clone()).expect("commit");
        let source = prep.source().clone();
        let point = seeded_point(5, b"py-tamper-p");
        let value = prep.evaluate(&point).expect("eval");
        let (col0, tree0, desc0) = commit_m31_raw(301, plan.levels()[0], &msg);
        let eq_row = stele_poly::eq_table(&point[..2]).expect("eq");
        let mut u_honest = vec![QM31::from_i64(0); 8];
        for (row, &a) in msg.chunks_exact(8).zip(&eq_row) {
            for (dst, &v) in u_honest.iter_mut().zip(row) {
                *dst = *dst + a.mul_m31(v);
            }
        }

        // NC-0630: u_1 corrupted by +1 -> ColumnMismatch.
        let mut u_bad = u_honest.clone();
        u_bad[0] = u_bad[0] + QM31::from_i64(1);
        let mut tp = Transcript::<QM31>::new(b"py-nc-0630").expect("tp");
        let mut stmt = Vec::new();
        stmt.extend_from_slice(&310u64.to_le_bytes());
        stmt.extend_from_slice(&source.bytes().expect("sb"));
        stmt.extend_from_slice(&encode_point(&point));
        stmt.extend_from_slice(&value.to_le_bytes());
        tp.absorb(AbsorbLabel::Opening, &stmt).expect("abs");
        let mut p630 = vec![4, 1, 2, 3, 2];
        let us = p630.len();
        for v in &u_bad {
            p630.extend_from_slice(&v.to_le_bytes());
        }
        tp.absorb(AbsorbLabel::PcsLevelRoot, &p630[us..])
            .expect("abs");
        let rs = p630.len();
        for _ in 0..plan.queries()[0] {
            let idx = tp.opening_column(desc0.count).expect("idx");
            let w = desc0.width as usize;
            p630.extend_from_slice(&col0[idx as usize * w..(idx as usize + 1) * w]);
            for sib in tree0.path(idx).expect("path") {
                p630.extend_from_slice(&sib);
            }
        }
        tp.absorb(AbsorbLabel::OpeningColumns, &p630[rs..])
            .expect("abs");
        emit_at_point_case(
            "nc_0630_bad_u1",
            b"py-nc-0630",
            &source,
            310,
            &point,
            value,
            &p630,
        );

        // NC-0631: query 0 swapped with another index's column -> RootMismatch.
        let mut t_h = Transcript::<QM31>::new(b"py-nc-0631").expect("th");
        let mut p631 = prep
            .open_fresh_at_point(&mut t_h, 311, &point, value)
            .expect("honest");
        let q0_off = plan.header_bytes() + 8 * 16;
        p631[q0_off] ^= 1;
        emit_at_point_case(
            "nc_0631_wrong_col",
            b"py-nc-0631",
            &source,
            311,
            &point,
            value,
            &p631,
        );

        // NC-0632 (ValueMismatch): honest u_L with wrong claimed scalar -> ValueMismatch.
        let wrong_v = value + QM31::from_i64(1);
        let mut tp2 = Transcript::<QM31>::new(b"py-nc-0632").expect("tp2");
        let mut stmt2 = Vec::new();
        stmt2.extend_from_slice(&312u64.to_le_bytes());
        stmt2.extend_from_slice(&source.bytes().expect("sb"));
        stmt2.extend_from_slice(&encode_point(&point));
        stmt2.extend_from_slice(&wrong_v.to_le_bytes());
        tp2.absorb(AbsorbLabel::Opening, &stmt2).expect("abs");
        let mut p632 = vec![4, 1, 2, 3, 2];
        let us2 = p632.len();
        for v in &u_honest {
            p632.extend_from_slice(&v.to_le_bytes());
        }
        tp2.absorb(AbsorbLabel::PcsLevelRoot, &p632[us2..])
            .expect("abs");
        let rs2 = p632.len();
        for _ in 0..plan.queries()[0] {
            let idx = tp2.opening_column(desc0.count).expect("idx");
            let w = desc0.width as usize;
            p632.extend_from_slice(&col0[idx as usize * w..(idx as usize + 1) * w]);
            for sib in tree0.path(idx).expect("path") {
                p632.extend_from_slice(&sib);
            }
        }
        tp2.absorb(AbsorbLabel::OpeningColumns, &p632[rs2..])
            .expect("abs");
        emit_at_point_case(
            "nc_0632_value_mismatch",
            b"py-nc-0632",
            &source,
            312,
            &point,
            wrong_v,
            &p632,
        );

        // NC-0633: wrong plan header -> ProofShape.
        let mut t_h3 = Transcript::<QM31>::new(b"py-nc-0633").expect("th3");
        let mut p633 = prep
            .open_fresh_at_point(&mut t_h3, 313, &point, value)
            .expect("honest");
        p633[4] = 3; // blowup mismatch
        emit_at_point_case(
            "nc_0633_wrong_plan",
            b"py-nc-0633",
            &source,
            313,
            &point,
            value,
            &p633,
        );
    }
}

fn measure_sizes(min_bits: u8, max_bits: u8) {
    println!("| Entries | Levels `(ell, m, b)` | E19-01 model (B) | Measured body (B) | Header (B) | Total proof (B) | Commit (ms) | Open (ms) | Verify (ms) |");
    println!("|---|---|---:|---:|---:|---:|---:|---:|---:|");
    for bits in (min_bits..=max_bits).step_by(2) {
        let plan = RecursivePlan::fresh_for_size(bits, 4, DEFAULT_TARGET_BITS, true, &[2, 3, 4])
            .expect("plan");
        let msg = seeded_m31(plan.level0_elements().expect("elems"), u64::from(bits));
        let t0 = Instant::now();
        let prep =
            PreparedRecursive::<QM31>::commit(u64::from(bits), plan.clone(), msg).expect("commit");
        let commit_ms = t0.elapsed().as_millis();

        let point = seeded_point(plan.level0_vars(), format!("measure-{bits}").as_bytes());
        let value = prep.evaluate(&point).expect("eval");

        let t1 = Instant::now();
        let mut tp = Transcript::<QM31>::new(b"e19-03-measure").expect("tp");
        let proof = prep
            .open_fresh_at_point(&mut tp, u64::from(bits), &point, value)
            .expect("open");
        let open_ms = t1.elapsed().as_millis();

        let t2 = Instant::now();
        let mut tv = Transcript::<QM31>::new(b"e19-03-measure").expect("tv");
        let _verified = verify_fresh_at_point(
            &mut tv,
            prep.source(),
            u64::from(bits),
            &point,
            value,
            &proof,
        )
        .expect("verify");
        let verify_ms = t2.elapsed().as_millis();

        let header = plan.header_bytes();
        let model_body = plan.body_bytes().expect("body");
        let measured_body = proof.len() - header;
        assert_eq!(measured_body, model_body);
        let chain: Vec<String> = plan
            .levels()
            .iter()
            .map(|l| format!("({},{},{})", l.ell, l.m, l.b))
            .collect();
        println!(
            "| `2^{bits}` | `{}` | {model_body} | {measured_body} | {header} | {} | {commit_ms} | {open_ms} | {verify_ms} |",
            chain.join(" -> "),
            proof.len()
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--vectors") => emit_vectors(),
        Some("--measure") => {
            let min_b = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            let max_b = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(28);
            measure_sizes(min_b, max_b);
        }
        _ => {
            eprintln!("usage: recursive_oracle --vectors | --measure [min_bits max_bits]");
            std::process::exit(2);
        }
    }
}
