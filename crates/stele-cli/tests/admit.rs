//! E8-05f review: `stele verify-dev --admit` at the command line. A dev-zk bundle is
//! refused before it is parsed or verified (usage error, exit 2); without `--admit`,
//! the same bytes reach the parser.
use std::process::Command;

fn run(public: &std::path::Path, admit: bool) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_stele"));
    c.args(["verify-dev", "--public"])
        .arg(public)
        .arg("--proof")
        .arg(public);
    if admit {
        c.arg("--admit");
    }
    let out = c.output().expect("run stele");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn rejects_admit_on_dev_zk_bundles_before_verifying() {
    let dir = std::env::temp_dir().join(format!("stele-admit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let public = dir.join("public.bin");
    // Only the magic is valid: the refusal must come before parsing.
    std::fs::write(&public, b"stele-dev-zk-public-v2 not a bundle").expect("write");
    let (code, out) = run(&public, true);
    assert_eq!(code, 2, "{out}");
    assert_eq!(out.trim_end(), format!("NO: {}", stele_cli::ADMIT_NOT_ZK));
    // Without --admit the same bytes are parsed and rejected as a bundle.
    let (code, out) = run(&public, false);
    assert_eq!(code, 1, "{out}");
    assert!(!out.contains(stele_cli::ADMIT_NOT_ZK), "{out}");
    std::fs::remove_dir_all(&dir).ok();
}
