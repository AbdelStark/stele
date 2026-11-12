//! `stele` command line: development-profile prove and verify (RFC-0026 §8).
//!
//! ```text
//! stele commit-model --zk --model M --preparation P --scales S --artifact A --length T
//!                    --proofs N --commitment OUT --secret OUT [--zk-profile 4|1]
//! stele prove-dev --model M --preparation P --scales S --artifact A --tokens 1,2,3,4 [--length T]
//!                 [--checked R..E] [--next Y] --public OUT --proof OUT
//!                 [--zk --commitment FILE --secret FILE]
//! stele verify-dev --public FILE --proof FILE [--expect-model HEX]
//! ```
//! `commit-model --zk` commits the model once for at most `N` dev-zk proofs
//! (RFC-0013 A6): a hiding weight source from a model seed drawn from the
//! OS RNG (`/dev/urandom`). The published `--commitment` file names it; the
//! `--secret` file (seed, proof counter, earlier openings) must stay private. It is
//! written with owner-only permissions.
//!
//! The commitment's profile byte is 4 (RFC-0013 A8, balanced policy-2 sources) unless
//! `--zk-profile 1` asks for the A5/A6/A7 sources; each commitment draws a fresh seed.
//!
//! `prove-dev --zk` proves under the dev-zk profile (RFC-0013 A5, RFC-0026 A9 profile
//! byte 1 or 4, the commitment's) against that commitment. It takes the next proof index from the secret
//! file and writes the advanced counter back before it proves. It refuses once the
//! budget is spent. Each proof's own seed also comes from the OS RNG.
//!
//! A development proof shows only that the model `public.bin` names ran on the statement it names.
//! `verify-dev` therefore prints the `cqis_id`, the model digest, `T`, the tokens,
//! `[r, e)` and `y` before its verdict; compare them with trusted values, or pass
//! `--expect-model`. A development proof is on RFC-0026 A12 Circle Policy 2 sources,
//! multiplicity sources included (`sources CircleAll`, `stele-dev-public-v3`); an A11
//! `stele-dev-public-v2` file (`sources Circle`) and a pre-A11 `stele-dev-public-v1`
//! file (`sources Expander`) still verify. Under dev-zk the model digest covers the published commitment,
//! so `--expect-model` pins a proof to it. The verdict is the last line: `YES`, or
//! `NO: <reason>`. `prove-dev` ends with `PROOF WRITTEN`, which is not a verdict.
//! Exit codes: 0 accepted or proof written, 1 rejected, 2 usage or I/O error.
use std::collections::BTreeMap;
use std::process::ExitCode;
use stele_prover::development::{
    bundle, model_identity, prove_window_profile, verify, zk, Statement,
};

const USAGE: &str = "usage: stele commit-model --zk --model M --preparation P --scales S \
--artifact A --length T --proofs N --commitment OUT --secret OUT [--zk-profile 4|1] | \
stele prove-dev --model M --preparation P --scales S --artifact A \
--tokens x0,x1,... [--length T] [--checked R..E] [--next Y] --public OUT --proof OUT \
[--zk --commitment FILE --secret FILE] | \
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

/// The statement lines a user compares with trusted values. `model` is the model
/// digest: under dev-zk, that of the published commitment.
fn identity(cqis_id: &[u8; 32], model: &[u8; 32], statement: &Statement) {
    println!("cqis_id {}", hex(cqis_id));
    println!("model {}", hex(model));
    println!("T {}", statement.tokens.len());
    let tokens: Vec<String> = statement.tokens.iter().map(u32::to_string).collect();
    println!("tokens {}", tokens.join(","));
    println!("checked {}..{}", statement.start, statement.end);
    match statement.next {
        Some(y) => println!("next {y}"),
        None => println!("next none"),
    }
}

/// 32 bytes from the OS RNG: a dev-zk proof or model seed (RFC-0013 A5 item 8).
fn os_bytes() -> Result<[u8; 32], Failure> {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| usage(format!("OS RNG: {e}")))?;
    Ok(bytes)
}

/// Write the secret model state with owner-only permissions, replacing the file
/// atomically, so a crash never leaves a counter behind a published proof.
fn write_secret(path: &str, state: &zk::ModelState) -> Result<(), Failure> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let temporary = format!("{path}.tmp");
    let fail = |e: std::io::Error| usage(format!("write {path}: {e}"));
    // A stale temporary from a crash is replaced, never reused.
    match std::fs::remove_file(&temporary) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(fail(e)),
        _ => {}
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(fail)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(fail)?;
    file.write_all(&state.encode()).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    std::fs::rename(&temporary, path).map_err(fail)?;
    // The rename is durable only once the directory entry is.
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(fail)
}

fn window(o: &BTreeMap<&str, &str>) -> Result<Statement, Failure> {
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
    Ok(Statement {
        tokens,
        start,
        end,
        next,
    })
}

fn commit_model(o: &BTreeMap<&str, &str>) -> Result<String, Failure> {
    let length = number(get(o, "length")?)?;
    let mut out = None;
    // RFC-0013 A8: new commitments are byte 4 (balanced policy-2 sources), from a
    // fresh model seed; byte-1 commitments keep proving and verifying.
    let profile = match o.get("zk-profile").copied() {
        None | Some("4") => zk::PROFILE_BALANCED,
        Some("1") => zk::PROFILE,
        Some(other) => return Err(usage(format!("--zk-profile {other}: expected 4 or 1"))),
    };
    let window = zk::Window::Commit {
        proofs: number(get(o, "proofs")?)?,
        seed: os_bytes()?,
        profile,
        out: &mut out,
    };
    let statement = Statement {
        tokens: vec![1],
        start: 0,
        end: 1,
        next: Some(1),
    };
    let (public, _, _) = prove_window_profile(
        &read(get(o, "model")?)?,
        &read(get(o, "preparation")?)?,
        &read(get(o, "scales")?)?,
        &read(get(o, "artifact")?)?,
        statement,
        length as usize,
        Some(window),
    )
    .map_err(reject)?;
    let (commitment, state) = out.ok_or_else(|| reject("no commitment"))?;
    write_secret(get(o, "secret")?, &state)?;
    let path = get(o, "commitment")?;
    std::fs::write(path, commitment.encode()).map_err(|e| usage(format!("write {path}: {e}")))?;
    let model = zk::model_digest(&public, &commitment).map_err(reject)?;
    println!("model {}", hex(&model));
    println!("proofs {}", commitment.proofs);
    Ok("COMMITMENT WRITTEN".into())
}

fn prove_dev(o: &BTreeMap<&str, &str>, zk: bool) -> Result<String, Failure> {
    let statement = window(o)?;
    let write = |key: &str, bytes: &[u8]| -> Result<(), Failure> {
        let path = get(o, key)?;
        std::fs::write(path, bytes).map_err(|e| usage(format!("write {path}: {e}")))
    };
    let read_files = || -> Result<[Vec<u8>; 4], Failure> {
        Ok([
            read(get(o, "model")?)?,
            read(get(o, "preparation")?)?,
            read(get(o, "scales")?)?,
            read(get(o, "artifact")?)?,
        ])
    };
    let length = o.get("length").map(|t| number(t)).transpose()?.unwrap_or(0) as usize;
    if !zk {
        let [m, p, s, a] = read_files()?;
        let (public, statement, proof) =
            prove_window_profile(&m, &p, &s, &a, statement, length, None).map_err(reject)?;
        write("public", &bundle::encode(&public, &statement))?;
        write("proof", &proof)?;
        println!("profile development");
        // RFC-0026 A11: the source set the public input binds.
        println!("sources {:?}", public.sources);
        let (cqis_id, model) = model_identity(&public).map_err(reject)?;
        identity(&cqis_id, &model, &statement);
        println!("proof {} bytes", proof.len());
        return Ok("PROOF WRITTEN".into());
    }
    // Read and validate every input before the index is taken (RFC-0013 A6 item 5).
    let commitment = zk::ModelCommitment::decode(&read(get(o, "commitment")?)?).map_err(reject)?;
    let secret = get(o, "secret")?;
    let mut state = zk::ModelState::decode(&read(secret)?).map_err(reject)?;
    let [m, p, s, a] = read_files()?;
    for key in ["public", "proof"] {
        get(o, key)?;
    }
    let seed = zk::Seed::new(os_bytes()?);
    let mut index = 0;
    let mut saved = Ok(());
    let mut persist = |state: &zk::ModelState| {
        saved = write_secret(secret, state);
        saved
            .as_ref()
            .map(|_| ())
            .map_err(|_| stele_prover::development::Error::Witness)
    };
    let window = zk::Window::Prove {
        seed,
        commitment: &commitment,
        state: &mut state,
        persist: &mut persist,
        index: &mut index,
    };
    let proved = prove_window_profile(&m, &p, &s, &a, statement, length, Some(window));
    saved?;
    let (public, statement, proof) = proved.map_err(reject)?;
    write(
        "public",
        &bundle::encode_zk(&public, &statement, &commitment, index),
    )?;
    write("proof", &proof)?;
    println!("profile dev-zk");
    println!("proof index {index} of {}", commitment.proofs);
    let (cqis_id, _) = model_identity(&public).map_err(reject)?;
    let model = zk::model_digest(&public, &commitment).map_err(reject)?;
    identity(&cqis_id, &model, &statement);
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
    let bytes = read(get(o, "public")?)?;
    let (public, statement, profile) = bundle::decode_profile(&bytes).map_err(reject)?;
    let proof = read(get(o, "proof")?)?;
    let (cqis_id, development_model) = model_identity(&public).map_err(reject)?;
    let zk = if matches!(profile, zk::PROFILE | zk::PROFILE_BALANCED) {
        let (_, _, commitment, index) = bundle::decode_zk(&bytes).map_err(reject)?;
        Some((commitment, index))
    } else {
        None
    };
    let model = match &zk {
        Some((commitment, index)) => {
            println!("profile dev-zk");
            println!("zk sources {:?}", commitment.geometry());
            println!("proof index {index} of {}", commitment.proofs);
            zk::model_digest(&public, commitment).map_err(reject)?
        }
        None => {
            println!("profile development");
            println!("sources {:?}", public.sources);
            development_model
        }
    };
    identity(&cqis_id, &model, &statement);
    if expected.is_some_and(|e| e != model) {
        return Err(Failure::Reject("model differs from --expect-model".into()));
    }
    match &zk {
        Some((commitment, index)) => println!(
            "{}",
            zk::verify(&public, &statement, &proof, commitment, *index).map_err(reject)?
        ),
        None => println!("{}", verify(&public, &statement, &proof).map_err(reject)?),
    }
    Ok("YES".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let zk = rest.iter().any(|a| a == "--zk");
    let rest: Vec<String> = rest.iter().filter(|a| *a != "--zk").cloned().collect();
    let files = ["model", "preparation", "scales", "artifact"];
    let result = match args.first().map(String::as_str) {
        Some("commit-model") if zk => options(
            &rest,
            &[
                &files[..],
                &["length", "proofs", "commitment", "secret", "zk-profile"],
            ]
            .concat(),
        )
        .and_then(|o| commit_model(&o)),
        Some("commit-model") => Err(usage("commit-model needs --zk (RFC-0013 A6)")),
        Some("prove-dev") => {
            let mut allowed = [
                &files[..],
                &["tokens", "length", "checked", "next", "public", "proof"],
            ]
            .concat();
            if zk {
                allowed.extend(["commitment", "secret"]);
            }
            options(&rest, &allowed).and_then(|o| prove_dev(&o, zk))
        }
        Some("verify-dev") if !zk => {
            options(&rest, &["public", "proof", "expect-model"]).and_then(|o| verify_dev(&o))
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
