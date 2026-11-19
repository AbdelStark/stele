//! RFC-0018 §1, A2 — bounded benchmark ledger validation and scoreboard CLI (task E17-02).
#![forbid(unsafe_code)]
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: stele-bench ledger validate <file.json> [file.json ...] | \
stele-bench scoreboard [--write | --check] [--ledger-dir DIR] [--out FILE]";

fn run_validate(paths: &[OsString]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for path in paths {
        let result = std::fs::File::open(path)
            .and_then(|file| {
                let mut bytes = Vec::new();
                file.take((stele_bench::MAX_LEDGER_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                Ok(bytes)
            })
            .map_err(|error| error.to_string())
            .and_then(|bytes| stele_bench::validate_ledger(&bytes));
        match result {
            Ok(()) => println!("valid ledger: {}", Path::new(path).display()),
            Err(error) => {
                eprintln!("invalid ledger {}: {error}", Path::new(path).display());
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run_scoreboard(args: &[OsString]) -> ExitCode {
    let mut write = false;
    let mut check = false;
    let mut ledger_dir = PathBuf::from("bench/ledger");
    let mut out_path = PathBuf::from("bench/scoreboard.md");
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--write") => {
                write = true;
                i += 1;
            }
            Some("--check") => {
                check = true;
                i += 1;
            }
            Some("--ledger-dir") => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("{USAGE}");
                    return ExitCode::FAILURE;
                };
                ledger_dir = PathBuf::from(val);
                i += 2;
            }
            Some("--out") => {
                let Some(val) = args.get(i + 1) else {
                    eprintln!("{USAGE}");
                    return ExitCode::FAILURE;
                };
                out_path = PathBuf::from(val);
                i += 2;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }
    if write && check {
        eprintln!("cannot pass both --write and --check");
        return ExitCode::FAILURE;
    }
    let rendered = match stele_bench::render_scoreboard(&ledger_dir) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("scoreboard failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if write {
        if let Err(error) = std::fs::write(&out_path, rendered) {
            eprintln!("write {}: {error}", out_path.display());
            return ExitCode::FAILURE;
        }
    } else if check {
        let existing = std::fs::File::open(&out_path).and_then(|file| {
            let mut bytes = Vec::new();
            file.take((rendered.len() + 1) as u64)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        if existing.ok().as_deref() != Some(rendered.as_bytes()) {
            eprintln!(
                "{} is stale; run cargo run -p stele-bench -- scoreboard --write",
                out_path.display()
            );
            return ExitCode::FAILURE;
        }
    } else {
        print!("{rendered}");
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|s| s.to_str()) {
        Some("ledger") if args.get(1).and_then(|s| s.to_str()) == Some("validate") => {
            run_validate(&args[2..])
        }
        Some("scoreboard") => run_scoreboard(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}
