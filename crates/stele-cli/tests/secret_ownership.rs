//! RFC-0013 A6 item 5: cooperating CLI processes must own one model state exclusively.
use std::path::Path;
use std::process::Command;

#[test]
fn rejects_concurrent_secret_readers_and_accepts_sequential_proofs() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = Command::new("python3")
        .arg(manifest.join("tests/secret_ownership.py"))
        .arg(env!("CARGO_BIN_EXE_stele"))
        .arg(manifest.join("../.."))
        .output()
        .expect("run the standard-library process harness");
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("STELE_SECRET_OWNERSHIP_PASSED"));
}
