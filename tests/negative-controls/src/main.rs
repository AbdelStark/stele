//! RFC-0002 §7 — execute registered controls and report catalog coverage.
#![forbid(unsafe_code)]
use stele_negative_controls::catalog::{parse, report, RegisteredControl};

// No protocol controls exist yet. The harness self-control is not an inference binding.
const CONTROLS: &[RegisteredControl] = &[];

fn main() -> std::process::ExitCode {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--coverage"] {
        eprintln!("usage: stele-controls --coverage");
        return std::process::ExitCode::FAILURE;
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.md");
    let result = std::fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|text| {
            let entries = parse(&text)
                .map_err(|error| format!("catalog line {}: {}", error.line, error.reason))?;
            report(&entries, CONTROLS)
        });
    match result {
        Ok(output) => {
            print!("{output}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
