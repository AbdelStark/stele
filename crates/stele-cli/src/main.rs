//! `stele` command line: development-profile prove and verify (RFC-0026 §8).
//!
//! ```text
//! stele prove-dev --model M --preparation P --scales S --artifact A --tokens 1,2,3,4 [--length T]
//!                 [--checked R..E] [--next Y] --public OUT --proof OUT [--zk]
//! stele verify-dev --public FILE --proof FILE [--expect-model HEX]
//! ```
//! `--zk` proves under the dev-zk profile (RFC-0013 A5, RFC-0026 A9 profile byte 1)
//! with a seed from the OS RNG (`/dev/urandom`); its model commitment is the proof's
//! own hiding weight source, for this proof only. `verify-dev` reads the profile
//! from the public file and prints it.
//! A proof shows only that the model `public.bin` names ran on the statement it names.
//! `verify-dev` therefore prints the `cqis_id`, the model digest, `T`, the tokens,
//! `[r, e)` and `y` before its verdict; compare them with trusted values, or pass
//! `--expect-model`. The verdict is the last line: `YES`, or `NO: <reason>`.
//! `prove-dev` ends with `PROOF WRITTEN`, which is not a verdict.
//! Exit codes: 0 accepted or proof written, 1 rejected, 2 usage or I/O error.
use std::collections::BTreeMap;
use std::process::ExitCode;
use stele_prover::development::{
    bundle, model_identity, prove_window_profile, verify, zk, Public, Statement,
};

const USAGE: &str = "usage: stele prove-dev --model M --preparation P --scales S --artifact A \
--tokens x0,x1,... [--length T] [--checked R..E] [--next Y] --public OUT --proof OUT [--zk] | \
stele verify-dev --public FILE --proof FILE [--expect-model HEX]";

enum Failure {
    Usage(String),
    Reject(String),
}

fn usage(reason: impl Into<String>) -> Failure {
    Failure::Usage(reason.into())
}

fn reject(reason: impl core::fmt::Debug) -> Failure {
    Failure::Reject(format!("{reason:?}"))
}

fn options<'a>(
    args: &'a [String],
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, Failure> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(key) = it.next() {
        let name = key
            .strip_prefix("--")
            .filter(|n| allowed.contains(n))
            .ok_or_else(|| usage(format!("unexpected argument {key}")))?;
        let value = it
            .next()
            .ok_or_else(|| usage(format!("--{name} needs a value")))?;
        if out.insert(name, value.as_str()).is_some() {
            return Err(usage(format!("--{name} given twice")));
        }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The statement lines a user compares with trusted values; returns the model digest.
fn identity(public: &Public, statement: &Statement) -> Result<[u8; 32], Failure> {
    let (cqis_id, model) = model_identity(public).map_err(reject)?;
    println!("cqis_id {}", hex(&cqis_id));
    println!("model {}", hex(&model));
    println!("T {}", statement.tokens.len());
    let tokens: Vec<String> = statement.tokens.iter().map(u32::to_string).collect();
    println!("tokens {}", tokens.join(","));
    println!("checked {}..{}", statement.start, statement.end);
    match statement.next {
        Some(y) => println!("next {y}"),
        None => println!("next none"),
    }
    Ok(model)
}

/// 32 bytes from the OS RNG: the dev-zk seed (RFC-0013 A5 item 8).
fn os_seed() -> Result<zk::Seed, Failure> {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| usage(format!("OS RNG: {e}")))?;
    Ok(zk::Seed::new(bytes))
}

fn prove_dev(o: &BTreeMap<&str, &str>, zk: bool) -> Result<String, Failure> {
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
    let seed = zk.then(os_seed).transpose()?;
    let (public, statement, proof) = prove_window_profile(
        &read(get(o, "model")?)?,
        &read(get(o, "preparation")?)?,
        &read(get(o, "scales")?)?,
        &read(get(o, "artifact")?)?,
        statement,
        o.get("length").map(|t| number(t)).transpose()?.unwrap_or(0) as usize,
        seed,
    )
    .map_err(reject)?;
    let write = |key: &str, bytes: &[u8]| -> Result<(), Failure> {
        let path = get(o, key)?;
        std::fs::write(path, bytes).map_err(|e| usage(format!("write {path}: {e}")))
    };
    let profile = if zk { zk::PROFILE } else { 0 };
    write(
        "public",
        &bundle::encode_profile(&public, &statement, profile),
    )?;
    write("proof", &proof)?;
    println!("profile {}", if zk { "dev-zk" } else { "development" });
    identity(&public, &statement)?;
    println!("proof {} bytes", proof.len());
    Ok("PROOF WRITTEN".into())
}

fn verify_dev(o: &BTreeMap<&str, &str>) -> Result<String, Failure> {
    let expected = o
        .get("expect-model")
        .map(|h| {
            let bytes: Option<Vec<u8>> = (0..h.len())
                .step_by(2)
                .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
                .collect();
            bytes
                .filter(|b| b.len() == 32)
                .ok_or_else(|| usage("--expect-model is 64 hex digits"))
        })
        .transpose()?;
    let (public, statement, profile) =
        bundle::decode_profile(&read(get(o, "public")?)?).map_err(reject)?;
    let proof = read(get(o, "proof")?)?;
    let zk_profile = profile == zk::PROFILE;
    println!(
        "profile {}",
        if zk_profile { "dev-zk" } else { "development" }
    );
    let model = identity(&public, &statement)?;
    if expected.is_some_and(|e| e != model) {
        return Err(Failure::Reject("model differs from --expect-model".into()));
    }
    if zk_profile {
        println!(
            "{}",
            zk::verify(&public, &statement, &proof).map_err(reject)?
        );
    } else {
        println!("{}", verify(&public, &statement, &proof).map_err(reject)?);
    }
    Ok("YES".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("prove-dev") => {
            let zk = rest.iter().any(|a| a == "--zk");
            let rest: Vec<String> = rest.iter().filter(|a| *a != "--zk").cloned().collect();
            options(
                &rest,
                &[
                    "model",
                    "preparation",
                    "scales",
                    "artifact",
                    "tokens",
                    "length",
                    "checked",
                    "next",
                    "public",
                    "proof",
                ],
            )
            .and_then(|o| prove_dev(&o, zk))
        }
        Some("verify-dev") => {
            options(rest, &["public", "proof", "expect-model"]).and_then(|o| verify_dev(&o))
        }
        _ => Err(usage(USAGE)),
    };
    match result {
        Ok(last) => {
            println!("{last}");
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
