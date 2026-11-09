//! `stele` command line: development-profile prove and verify (RFC-0026 §8).
//!
//! ```text
//! stele prove-dev --model M --preparation P --scales S --artifact A --tokens 1,2,3,4 [--length T]
//!                 [--checked R..E] [--next Y] --public OUT --proof OUT
//! stele verify-dev --public FILE --proof FILE
//! ```
//! The last line of output is the verdict: `YES`, or `NO: <reason>`.
//! Exit codes: 0 accepted (or proof written), 1 rejected, 2 usage or I/O error.
use std::collections::BTreeMap;
use std::process::ExitCode;
use stele_prover::development::{bundle, prove_window, verify, Statement};

const USAGE: &str = "usage: stele prove-dev --model M --preparation P --scales S --artifact A \
--tokens x0,x1,... [--length T] [--checked R..E] [--next Y] --public OUT --proof OUT | \
stele verify-dev --public FILE --proof FILE";

enum Failure {
    Usage(String),
    Reject(String),
}

fn usage(reason: impl Into<String>) -> Failure {
    Failure::Usage(reason.into())
}

fn options(args: &[String]) -> Result<BTreeMap<&str, &str>, Failure> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(key) = it.next() {
        let name = key
            .strip_prefix("--")
            .ok_or_else(|| usage(format!("unexpected argument {key}")))?;
        let value = it
            .next()
            .ok_or_else(|| usage(format!("--{name} needs a value")))?;
        out.insert(name, value.as_str());
    }
    Ok(out)
}

fn get<'a>(o: &BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, Failure> {
    o.get(key)
        .copied()
        .ok_or_else(|| usage(format!("missing --{key}")))
}

fn read(path: &str) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| usage(format!("read {path}: {e}")))
}

fn number(s: &str) -> Result<u32, Failure> {
    s.trim()
        .parse()
        .map_err(|_| usage(format!("not a number: {s}")))
}

fn prove_dev(o: &BTreeMap<&str, &str>) -> Result<String, Failure> {
    let tokens = get(o, "tokens")?
        .split(',')
        .map(number)
        .collect::<Result<Vec<_>, _>>()?;
    let (start, end) = match o.get("checked") {
        Some(range) => {
            let (r, e) = range
                .split_once("..")
                .ok_or_else(|| usage("--checked is R..E"))?;
            (number(r)?, number(e)?)
        }
        None => (0, tokens.len() as u32),
    };
    let next = o.get("next").map(|y| number(y)).transpose()?;
    let statement = Statement {
        tokens,
        start,
        end,
        next,
    };
    let (public, statement, proof) = prove_window(
        &read(get(o, "model")?)?,
        &read(get(o, "preparation")?)?,
        &read(get(o, "scales")?)?,
        &read(get(o, "artifact")?)?,
        statement,
        o.get("length").map(|t| number(t)).transpose()?.unwrap_or(0) as usize,
    )
    .map_err(|e| Failure::Reject(format!("{e:?}")))?;
    let write = |key: &str, bytes: &[u8]| -> Result<(), Failure> {
        let path = get(o, key)?;
        std::fs::write(path, bytes).map_err(|e| usage(format!("write {path}: {e}")))
    };
    write("public", &bundle::encode(&public, &statement))?;
    write("proof", &proof)?;
    Ok(format!(
        "proof {} bytes; next token {:?}",
        proof.len(),
        statement.next
    ))
}

fn verify_dev(o: &BTreeMap<&str, &str>) -> Result<String, Failure> {
    let (public, statement) =
        bundle::decode(&read(get(o, "public")?)?).map_err(|e| Failure::Reject(format!("{e:?}")))?;
    let ledger = verify(&public, &statement, &read(get(o, "proof")?)?)
        .map_err(|e| Failure::Reject(format!("{e:?}")))?;
    Ok(format!("{ledger}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("prove-dev") => options(&args[1..]).and_then(|o| prove_dev(&o)),
        Some("verify-dev") => options(&args[1..]).and_then(|o| verify_dev(&o)),
        _ => Err(usage(USAGE)),
    };
    match result {
        Ok(report) => {
            println!("{report}");
            println!("YES");
            ExitCode::SUCCESS
        }
        Err(Failure::Reject(reason)) => {
            println!("NO: {reason}");
            ExitCode::from(1)
        }
        Err(Failure::Usage(reason)) => {
            println!("NO: {reason}");
            ExitCode::from(2)
        }
    }
}
