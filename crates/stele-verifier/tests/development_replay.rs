//! Parity of the independent byte-5 replay (RFC-0026 A15, task E8-02f1) with
//! production's `verify-dev`, on honest proofs and on one-byte tampers.
//!
//! `STELE_DEV_REPLAY_DIR` names a directory of windows, each a directory holding
//! `public.bin`, `proof.bin` and `relation.bin` (the A15 §5 encoding), as production's
//! test-only dump writes them. `STELE_BIN`, when set, names the `stele` binary, and
//! every case's decision is compared with `verify-dev`'s. `cqis_id` is read from the
//! container header: deriving it from the model is E8-02f2. `STELE_DEV_REPLAY_ALL`
//! tampers every section, not only the first and last of each list.

use std::path::Path;
use std::process::Command;
use std::time::Instant;
use stele_field::{Field, Inverse, Serialize, QM31};
use stele_verifier::development::{verify, Error};
use stele_verifier::{fraction, logup, pcs, plan::Plan, relation::Relation, sumcheck};

struct Window {
    public: Vec<u8>,
    proof: Vec<u8>,
    relation: Vec<u8>,
}

fn cqis(proof: &[u8]) -> [u8; 32] {
    proof
        .get(18..50)
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; 32])
}

fn ours(w: &Window) -> Result<(), Error> {
    verify(&w.public, &w.proof, &w.relation, &cqis(&w.proof))
}

/// `verify-dev`'s verdict on the files, or `None` without `STELE_BIN`.
fn production(w: &Window, scratch: &Path) -> Option<bool> {
    let bin = std::env::var("STELE_BIN").ok()?;
    std::fs::write(scratch.join("public.bin"), &w.public).expect("replay fixture");
    std::fs::write(scratch.join("proof.bin"), &w.proof).expect("replay fixture");
    let out = Command::new(bin)
        .args(["verify-dev", "--public"])
        .arg(scratch.join("public.bin"))
        .arg("--proof")
        .arg(scratch.join("proof.bin"))
        .output()
        .expect("replay fixture");
    let text = String::from_utf8_lossy(&out.stdout);
    Some(text.lines().last() == Some("YES"))
}

/// The byte offsets of each container section (A15 §4), for one-byte tampers.
fn sections(proof: &[u8]) -> Vec<(String, usize, usize)> {
    let mut at = 82;
    let mut out = vec![("header".to_string(), 18, 82)];
    let u32 = |at: usize| {
        u32::from_le_bytes(proof[at..at + 4].try_into().expect("replay fixture")) as usize
    };
    for name in [
        "groups",
        "multiplicities",
        "identities",
        "lookups",
        "matmuls",
        "openings",
    ] {
        let n = u32(at);
        at += 4;
        for i in 0..n {
            let len = u32(at);
            out.push((format!("{name}[{i}]"), at + 4, len));
            at += 4 + len;
        }
    }
    out
}

fn k_at(b: &[u8], at: usize) -> QM31 {
    QM31::from_le_bytes(b[at..at + 16].try_into().expect("16 bytes")).expect("canonical")
}

fn map_k(b: &mut [u8], at: usize, f: impl Fn(QM31) -> QM31) {
    let v = f(k_at(b, at));
    b[at..at + 16].copy_from_slice(&v.to_le_bytes());
}

/// Semantic tampers, each aimed at one check of A15 §6.4 and expected to fail there:
/// `(name, mutate, expected)`.
type Tamper = (String, Box<dyn Fn(&mut Vec<u8>)>, Error);

fn semantic(w: &Window) -> Vec<Tamper> {
    let rel = Relation::decode(&w.relation).expect("relation");
    let plan = Plan::derive(&rel).expect("plan");
    let list = sections(&w.proof);
    let find = |kind: &str, i: usize| {
        list.iter()
            .find(|(n, _, _)| *n == format!("{kind}[{i}]"))
            .map(|(_, at, _)| *at)
            .expect("section")
    };
    let one = QM31::from_i64(1);
    let mut out: Vec<Tamper> = Vec::new();
    let tree = |v: usize| 2 + 2 * v * v + 3 * v;
    for (i, check) in plan.checks.iter().enumerate().take(3) {
        let (m, k, c) = (usize::from(check.m), usize::from(check.k), check.c);
        let base = find("lookups", i) + 8 * usize::from(check.k_lu >= 1);
        let members = base + 16 * (tree(m) + tree(k) + 4 * m + c + 2);
        let pieces = members + 16 * check.members.len() * c;
        // A3 member split: one member value moved.
        out.push((
            format!("member value of check {i}"),
            Box::new(move |b: &mut Vec<u8>| map_k(b, members, |x| x + one)),
            Error::MemberSumMismatch,
        ));
        // formal/native-lookup.md §2: one piece value moved.
        out.push((
            format!("piece value of check {i}"),
            Box::new(move |b: &mut Vec<u8>| map_k(b, pieces, |x| x + one)),
            Error::PieceSumMismatch,
        ));
        if check.k_lu >= 1 {
            // A14 item 5: the least nonce minus one fails the predicate.
            let at = find("lookups", i);
            out.push((
                format!("nonce of check {i}"),
                Box::new(move |b: &mut Vec<u8>| {
                    let n = u64::from_le_bytes(b[at..at + 8].try_into().expect("nonce"));
                    b[at..at + 8].copy_from_slice(&n.wrapping_sub(1).to_le_bytes());
                }),
                Error::Logup(logup::Error::Transcript(stele_hash::Error::GrindMismatch)),
            ));
        }
    }
    // A15 §6.4 step 6: eq·2 and lhs/2 keep the product, so only the eq check sees it.
    if let Some((i, _)) =
        rel.matmuls.iter().enumerate().find(|(_, mm)| {
            (0..mm.free).any(|d| mm.lhs.vars.contains(&d) && mm.rhs.vars.contains(&d))
        })
    {
        let at = find("matmuls", i);
        let len = list
            .iter()
            .find(|(n, _, _)| *n == format!("matmuls[{i}]"))
            .expect("matmul")
            .2;
        let eq = at + len - 48;
        out.push((
            format!("eq final of matmul {i}"),
            Box::new(move |b: &mut Vec<u8>| {
                let two = QM31::from_i64(2);
                map_k(b, eq, |x| x * two);
                let half = two.inverse().expect("inverse");
                map_k(b, eq + 16, |x| x * half);
            }),
            Error::EqMismatch,
        ));
    }
    // A1 round sums: the first matmul's out~(ρ), the first zerocheck's first round.
    let mm = find("matmuls", 0);
    out.push((
        "out of matmul 0".into(),
        Box::new(move |b: &mut Vec<u8>| map_k(b, mm, |x| x + one)),
        Error::Sumcheck(sumcheck::Error::RoundSumMismatch),
    ));
    let id = find("identities", 0);
    out.push((
        "first zerocheck round".into(),
        Box::new(move |b: &mut Vec<u8>| map_k(b, id, |x| x + one)),
        Error::Sumcheck(sumcheck::Error::RoundSumMismatch),
    ));
    // A noncanonical limb in a tree value.
    let lk = find("lookups", 0) + 8 * usize::from(plan.checks[0].k_lu >= 1);
    out.push((
        "noncanonical tree root".into(),
        Box::new(move |b: &mut Vec<u8>| {
            b[lk..lk + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes())
        }),
        Error::Fraction(fraction::Error::NoncanonicalField),
    ));
    // The stacked root: its certificate's tensor nonce no longer passes (A14 item 4).
    let g = find("groups", 0);
    out.push((
        "stacked root".into(),
        Box::new(move |b: &mut Vec<u8>| b[g] ^= 1),
        Error::Pcs(pcs::Error::Transcript(stele_hash::Error::GrindMismatch)),
    ));
    out
}

/// The container with its section lists edited and re-encoded (A15 §4).
fn reshape(proof: &[u8], edit: impl FnOnce(&mut [Vec<Vec<u8>>])) -> Vec<u8> {
    let mut lists: Vec<Vec<Vec<u8>>> = vec![Vec::new(); 6];
    let mut current = 0;
    for (name, at, len) in sections(proof).into_iter().skip(1) {
        let order = [
            "groups",
            "multiplicities",
            "identities",
            "lookups",
            "matmuls",
            "openings",
        ];
        current = order
            .iter()
            .position(|o| name.starts_with(o))
            .unwrap_or(current);
        lists[current].push(proof[at..at + len].to_vec());
    }
    edit(&mut lists);
    let mut out = proof[..82].to_vec();
    for list in &lists {
        out.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for blob in list {
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            out.extend_from_slice(blob);
        }
    }
    out
}

/// A15 §4/§6.4: a long, short, missing or extra section is ProofShape.
fn shapes(proof: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![("unchanged re-encoding".to_string(), reshape(proof, |_| {}))];
    for (l, name) in [
        "groups",
        "multiplicities",
        "identities",
        "lookups",
        "matmuls",
        "openings",
    ]
    .iter()
    .enumerate()
    {
        out.push((
            format!("{name}[0] one byte long"),
            reshape(proof, |s| s[l][0].push(0)),
        ));
        out.push((
            format!("{name}[0] one byte short"),
            reshape(proof, |s| {
                s[l][0].pop();
            }),
        ));
        out.push((
            format!("{name} missing its last"),
            reshape(proof, |s| {
                s[l].pop();
            }),
        ));
        out.push((
            format!("{name} with an extra"),
            reshape(proof, |s| {
                let first = s[l][0].clone();
                s[l].push(first);
            }),
        ));
    }
    out
}

#[test]
fn matches_reference_verify_dev_on_byte5_windows_and_tampers() {
    let Ok(root) = std::env::var("STELE_DEV_REPLAY_DIR") else {
        eprintln!("STELE_DEV_REPLAY_DIR unset: no windows to replay");
        return;
    };
    let scratch = std::env::temp_dir().join(format!("stele-f1-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("replay fixture");
    let mut windows: Vec<_> = std::fs::read_dir(&root)
        .expect("replay fixture")
        .map(|e| e.expect("replay fixture").path())
        .filter(|p| p.join("relation.bin").is_file())
        .collect();
    windows.sort();
    assert!(!windows.is_empty(), "no window under {root}");
    for dir in windows {
        let read = |f: &str| std::fs::read(dir.join(f)).expect("replay fixture");
        let honest = Window {
            public: read("public.bin"),
            proof: read("proof.bin"),
            relation: read("relation.bin"),
        };
        let start = Instant::now();
        let decision = ours(&honest);
        eprintln!(
            "{}: honest {:?} in {:?}",
            dir.display(),
            decision,
            start.elapsed()
        );
        assert_eq!(decision, Ok(()), "{}", dir.display());
        if let Some(yes) = production(&honest, &scratch) {
            assert!(yes);
        }
        // One byte flipped in each section (its first, middle and last byte), in the
        // public file and in the relation: every one must be rejected, as by verify-dev.
        // Without STELE_DEV_REPLAY_ALL, only the first and last section of each list.
        let all = std::env::var("STELE_DEV_REPLAY_ALL").is_ok();
        let list = sections(&honest.proof);
        let kind = |n: &str| n.split('[').next().unwrap_or("").to_string();
        let mut cases = Vec::new();
        for (i, (name, start, len)) in list.iter().cloned().enumerate() {
            let edge = i == 0
                || i + 1 == list.len()
                || kind(&list[i - 1].0) != kind(&name)
                || kind(&list[i + 1].0) != kind(&name);
            if !all && !edge {
                continue;
            }
            for at in [start, start + len / 2, start + len.saturating_sub(1)] {
                if len > 0 {
                    cases.push((format!("{name}@{}", at - start), 'p', at));
                }
            }
        }
        for at in [19, honest.public.len() / 2, honest.public.len() - 1] {
            cases.push((format!("public@{at}"), 'f', at));
        }
        for at in [31, honest.relation.len() / 2, honest.relation.len() - 1] {
            cases.push((format!("relation@{at}"), 'r', at));
        }
        let mut agree = 0;
        for (name, file, at) in &cases {
            let mut w = Window {
                public: honest.public.clone(),
                proof: honest.proof.clone(),
                relation: honest.relation.clone(),
            };
            let target = match file {
                'p' => &mut w.proof,
                'f' => &mut w.public,
                _ => &mut w.relation,
            };
            target[*at] ^= 1;
            let result = ours(&w);
            eprintln!("  {name}: {result:?}");
            assert!(result.is_err(), "{name} accepted");
            // The relation is not in verify-dev's input; only proof and public tampers compare.
            if *file != 'r' {
                if let Some(yes) = production(&w, &scratch) {
                    assert!(!yes, "{name}: verify-dev accepted");
                    agree += 1;
                }
            }
        }
        // Shape tampers: each must be ProofShape (the re-encoding itself must verify).
        for (name, proof) in shapes(&honest.proof) {
            let w = Window {
                public: honest.public.clone(),
                proof,
                relation: honest.relation.clone(),
            };
            let result = ours(&w);
            eprintln!("  {name}: {result:?}");
            if name.starts_with("unchanged") {
                assert_eq!(result, Ok(()));
                continue;
            }
            assert_eq!(result, Err(Error::ProofShape), "{name}");
            if let Some(yes) = production(&w, &scratch) {
                assert!(!yes, "{name}: verify-dev accepted");
                agree += 1;
            }
        }
        // Semantic tampers: each must fail at the check it aims at, and verify-dev must
        // also reject it.
        for (name, mutate, expected) in semantic(&honest) {
            let mut w = Window {
                public: honest.public.clone(),
                proof: honest.proof.clone(),
                relation: honest.relation.clone(),
            };
            mutate(&mut w.proof);
            let result = ours(&w);
            eprintln!("  {name}: {result:?}");
            assert_eq!(result, Err(expected), "{name}");
            if let Some(yes) = production(&w, &scratch) {
                assert!(!yes, "{name}: verify-dev accepted");
                agree += 1;
            }
        }
        eprintln!(
            "{}: {} tampers rejected, {agree} compared with verify-dev",
            dir.display(),
            cases.len()
        );
    }
}
