//! RFC-0026 A16 §5: actual CLI publication and independent registered verification.
use std::path::Path;
use std::process::Command;

fn run(mode: &str, windows: Option<&std::ffi::OsStr>) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new("python3");
    command
        .arg(manifest.join("tests/registered.py"))
        .arg(env!("CARGO_BIN_EXE_stele"))
        .arg(manifest.join("../.."))
        .arg(mode);
    if let Some(windows) = windows {
        command.arg(windows);
    }
    let result = command.output().expect("run CLI process harness");
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(output.contains("STELE_REGISTERED_CLI_PASSED"));
    eprint!("{output}");
}

#[test]
fn rejects_registry_cli_options_and_wrong_entry() {
    run("options", None);
}

#[test]
#[ignore = "native gate supplies freshly proved L0/L1 windows through STELE_DUMP_DIR"]
fn matches_reference_registered_cli_windows() {
    let windows = std::env::var_os("STELE_DUMP_DIR").expect("fresh reference windows required");
    run("windows", Some(&windows));
}
