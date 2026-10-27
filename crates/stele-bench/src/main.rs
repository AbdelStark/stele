//! RFC-0018 §1 — bounded, read-only benchmark ledger validation CLI.
#![forbid(unsafe_code)]
use std::io::Read;

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 3 || args[0] != "ledger" || args[1] != "validate" {
        eprintln!("usage: stele-bench ledger validate <file.json> [file.json ...]");
        return std::process::ExitCode::FAILURE;
    }
    let mut failed = false;
    for path in &args[2..] {
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
            Ok(()) => println!("valid ledger: {}", std::path::Path::new(path).display()),
            Err(error) => {
                eprintln!(
                    "invalid ledger {}: {error}",
                    std::path::Path::new(path).display()
                );
                failed = true;
            }
        }
    }
    if failed {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
