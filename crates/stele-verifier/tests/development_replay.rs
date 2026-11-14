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
use stele_verifier::development::{verify, Error};

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
        eprintln!(
            "{}: {} tampers rejected, {agree} compared with verify-dev",
            dir.display(),
            cases.len()
        );
    }
}
