//! RFC-0018 §1, A2 — bounded benchmark ledger validation and scoreboard CLI (task E17-02).
#![forbid(unsafe_code)]
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: stele-bench ledger validate <file.json> [file.json ...] | \
stele-bench scoreboard [--write | --check] [--ledger-dir DIR] [--out FILE] | \
stele-bench accounting --model M --scales S [--artifact A | --public P] --length T \
[--checked R..E] [--ledger-out FILE --rung R --suffix S --name NAME --commit SHA --device DEV --toolchain TC [--note TEXT]]";

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

fn parse_range(raw: &str) -> Result<core::ops::Range<usize>, String> {
    let (a, b) = raw
        .split_once("..")
        .ok_or_else(|| format!("invalid checked range {raw:?}, expected START..END"))?;
    let start: usize = a
        .parse()
        .map_err(|_| format!("invalid range start in {raw:?}"))?;
    let end: usize = b
        .parse()
        .map_err(|_| format!("invalid range end in {raw:?}"))?;
    Ok(start..end)
}

fn run_accounting(args: &[OsString]) -> ExitCode {
    let mut model_path: Option<PathBuf> = None;
    let mut scales_path: Option<PathBuf> = None;
    let mut artifact_path: Option<PathBuf> = None;
    let mut public_path: Option<PathBuf> = None;
    let mut length: Option<usize> = None;
    let mut checked: Option<core::ops::Range<usize>> = None;
    let mut ledger_out: Option<PathBuf> = None;
    let mut rung: Option<String> = None;
    let mut suffix: Option<String> = None;
    let mut model_name: Option<String> = None;
    let mut commit: Option<String> = None;
    let mut device: Option<String> = None;
    let mut toolchain: Option<String> = None;
    let mut extra_note = String::new();

    let mut i = 0;
    while i < args.len() {
        let Some(flag) = args[i].to_str() else {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        };
        let Some(val) = args.get(i + 1) else {
            eprintln!("missing value for {flag}\n{USAGE}");
            return ExitCode::FAILURE;
        };
        fn require_utf8<'a>(flag: &str, v: &'a OsString) -> Result<&'a str, ExitCode> {
            v.to_str().ok_or_else(|| {
                eprintln!("non-UTF-8 value for {flag}\n{USAGE}");
                ExitCode::FAILURE
            })
        }
        match flag {
            "--model" => model_path = Some(PathBuf::from(val)),
            "--scales" => scales_path = Some(PathBuf::from(val)),
            "--artifact" => artifact_path = Some(PathBuf::from(val)),
            "--public" => public_path = Some(PathBuf::from(val)),
            "--length" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                match val_str.parse::<usize>() {
                    Ok(n) => length = Some(n),
                    Err(_) => {
                        eprintln!("invalid --length {val_str:?}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--checked" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                match parse_range(val_str) {
                    Ok(r) => checked = Some(r),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--ledger-out" => ledger_out = Some(PathBuf::from(val)),
            "--rung" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                rung = Some(val_str.to_string());
            }
            "--suffix" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                suffix = Some(val_str.to_string());
            }
            "--name" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                model_name = Some(val_str.to_string());
            }
            "--commit" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                commit = Some(val_str.to_string());
            }
            "--device" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                device = Some(val_str.to_string());
            }
            "--toolchain" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                toolchain = Some(val_str.to_string());
            }
            "--note" => {
                let Ok(val_str) = require_utf8(flag, val) else {
                    return ExitCode::FAILURE;
                };
                extra_note = val_str.to_string();
            }
            _ => {
                eprintln!("unknown argument {flag}\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
        i += 2;
    }

    let (Some(model_p), Some(scales_p), Some(len)) = (model_path, scales_path, length) else {
        eprintln!("--model, --scales, and --length are required\n{USAGE}");
        return ExitCode::FAILURE;
    };
    let checked_range = checked.unwrap_or(0..len);
    let checked_label = format!("{}..{}", checked_range.start, checked_range.end);
    let t0 = std::time::Instant::now();
    let (acc, shape, exact_vectors) = match stele_bench::accounting::account_from_files(
        &model_p,
        &scales_p,
        artifact_path.as_deref(),
        public_path.as_deref(),
        len,
        checked_range,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("accounting failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let elapsed_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    print!(
        "{}",
        stele_bench::accounting::format_report(&acc, &shape, exact_vectors)
    );

    if let Some(out) = ledger_out {
        let (
            Some(rung),
            Some(suffix),
            Some(model_name),
            Some(commit),
            Some(device),
            Some(toolchain),
        ) = (rung, suffix, model_name, commit, device, toolchain)
        else {
            eprintln!(
                "--ledger-out requires --rung, --suffix, --name, --commit, --device, --toolchain"
            );
            return ExitCode::FAILURE;
        };
        let meta = stele_bench::accounting::LedgerMeta {
            workload_suffix: &suffix,
            target_rung: &rung,
            model_name: &model_name,
            commit: &commit,
            device: &device,
            toolchain: &toolchain,
            checked_label: &checked_label,
            exact_vectors,
            elapsed_ns,
            extra_note: &extra_note,
        };
        let json = match stele_bench::accounting::build_micro_ledger(&acc, &shape, &meta) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ledger build failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = std::fs::write(&out, json) {
            eprintln!("write {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
        println!("wrote validated ledger: {}", out.display());
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
        Some("accounting") => run_accounting(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}
