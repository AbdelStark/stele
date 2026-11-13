//! E16-35 benchmark: one full masked sumcheck (every round and fold) of a shape.
//!
//! `stele-masked-gpu-bench <relation|gkr> <log2 entries> <cpu|gpu|check> [seed]`
//!
//! - `cpu`: the production summand on rayon's pool (all cores);
//! - `gpu`: the device path (`--features cuda`); upload and device build timed apart
//!   from the rounds;
//! - `check`: both, every round polynomial and every folded table compared as field
//!   elements; exits 1 on the first difference.
//!
//! Prints `key=value` lines; times are integer nanoseconds.
use std::process::ExitCode;
use std::time::Instant;
use stele_masked_gpu_bench::{challenge, cpu, fnv, shape, FNV_START};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "cuda")]
    if args.first().map(String::as_str) == Some("h2d") {
        return device::h2d(args.get(1).and_then(|a| a.parse().ok()).unwrap_or(28));
    }
    let parsed = (
        args.first().map(String::as_str),
        args.get(1).and_then(|a| a.parse::<usize>().ok()),
        args.get(2).map(String::as_str),
        args.get(3)
            .and_then(|a| a.parse::<u64>().ok())
            .unwrap_or(35),
    );
    let (Some(name), Some(n), Some(mode), seed) = parsed else {
        eprintln!(
            "usage: stele-masked-gpu-bench <relation|gkr> <log2 entries> <cpu|gpu|check> [seed]"
        );
        return ExitCode::from(2);
    };
    let start = Instant::now();
    let Some(shape) = shape(name, n, seed) else {
        eprintln!("unknown shape {name}");
        return ExitCode::from(2);
    };
    println!(
        "shape={name}\nlog2_entries={n}\nfactors={}\ndegree={}\nseed={seed}",
        shape.factors.len(),
        shape.degree
    );
    println!("host_inputs_ns={}", start.elapsed().as_nanos());
    match mode {
        "cpu" => run_cpu(&shape),
        #[cfg(feature = "cuda")]
        "gpu" => device::run(&shape, false),
        #[cfg(feature = "cuda")]
        "check" => device::run(&shape, true),
        _ => {
            eprintln!("mode {mode} needs --features cuda, or is unknown");
            ExitCode::from(2)
        }
    }
}

fn run_cpu(shape: &stele_masked_gpu_bench::Shape) -> ExitCode {
    let threads = std::thread::available_parallelism().map_or(0, |n| n.get());
    println!("cpu_threads={threads}");
    let start = Instant::now();
    let mut summand = cpu(shape);
    println!("cpu_build_ns={}", start.elapsed().as_nanos());
    let mut digest = FNV_START;
    let mut total = 0u128;
    for i in 0..shape.n {
        let start = Instant::now();
        let Ok(round) = summand.round() else {
            eprintln!("cpu round {i} failed");
            return ExitCode::from(1);
        };
        let r = start.elapsed().as_nanos();
        let start = Instant::now();
        if summand.fold(challenge(i)).is_err() {
            eprintln!("cpu fold {i} failed");
            return ExitCode::from(1);
        }
        let f = start.elapsed().as_nanos();
        println!("cpu_round_ns[{i}]={r}\ncpu_fold_ns[{i}]={f}");
        total += r + f;
        digest = fnv(digest, &round);
    }
    let finals: Vec<_> = summand.tables().map(|(x, _)| x[0]).collect();
    println!(
        "cpu_rounds_total_ns={total}\nfnv={:016x}",
        fnv(digest, &finals)
    );
    ExitCode::SUCCESS
}

#[cfg(feature = "cuda")]
mod device {
    use super::*;
    use stele_masked_gpu_bench::gpu::{available, Device};
    use stele_masked_gpu_bench::Shape;

    /// `h2d <log2 words>`: one pageable and one pinned copy of `2^log2` u32s.
    pub fn h2d(log2: usize) -> ExitCode {
        match Device::new().and_then(|d| d.h2d(1 << log2)) {
            Ok((pageable, pinned)) => {
                println!(
                    "h2d_bytes={}\nh2d_pageable_ns={}\nh2d_pinned_ns={}",
                    4u64 << log2,
                    pageable.as_nanos(),
                    pinned.as_nanos()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("device error: {e:?}");
                ExitCode::from(1)
            }
        }
    }

    pub fn run(shape: &Shape, check: bool) -> ExitCode {
        if !available() {
            eprintln!("no CUDA driver or NVRTC on this host");
            return ExitCode::from(2);
        }
        match go(shape, check) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("device error: {e:?}");
                ExitCode::from(1)
            }
        }
    }

    fn go(shape: &Shape, check: bool) -> Result<bool, stele_masked_gpu_bench::gpu::Error> {
        let dev = Device::new()?;
        println!("device={}", dev.name);
        let (mut masked, upload, build) = dev.build(shape)?;
        println!(
            "gpu_upload_ns={}\ngpu_build_ns={}",
            upload.as_nanos(),
            build.as_nanos()
        );
        let start = Instant::now();
        masked.prepare()?;
        println!("gpu_compile_ns={}", start.elapsed().as_nanos());
        let mut reference = check.then(|| cpu(shape));
        if let Some(c) = &reference {
            if !same(c, &masked.tables()?, "built") {
                return Ok(false);
            }
        }
        let mut digest = FNV_START;
        let mut total = 0u128;
        for i in 0..shape.n {
            let start = Instant::now();
            let round = masked.round()?;
            let r = start.elapsed().as_nanos();
            let start = Instant::now();
            masked.fold(challenge(i))?;
            dev.sync()?;
            let f = start.elapsed().as_nanos();
            println!("gpu_round_ns[{i}]={r}\ngpu_fold_ns[{i}]={f}");
            total += r + f;
            digest = fnv(digest, &round);
            if let Some(c) = &mut reference {
                let Ok(expected) = c.round() else {
                    return Ok(false);
                };
                if expected != round {
                    println!("bit_equal=false\nfirst_difference=round {i}");
                    return Ok(false);
                }
                if c.fold(challenge(i)).is_err()
                    || !same(c, &masked.tables()?, &format!("fold {i}"))
                {
                    return Ok(false);
                }
            }
        }
        let finals: Vec<_> = masked.tables()?.iter().map(|(x, _)| x[0]).collect();
        println!(
            "gpu_rounds_total_ns={total}\nfnv={:016x}",
            fnv(digest, &finals)
        );
        if check {
            println!(
                "bit_equal=true\nrounds_compared={}\ntable_sets_compared={}",
                shape.n,
                shape.n + 1
            );
        }
        Ok(true)
    }

    fn same(
        c: &stele_reductions::zk::claims::bench::Masked<stele_masked_gpu_bench::K>,
        device: &[(
            Vec<stele_masked_gpu_bench::K>,
            Vec<stele_masked_gpu_bench::K>,
        )],
        at: &str,
    ) -> bool {
        let equal = c.tables().count() == device.len()
            && c.tables()
                .zip(device)
                .all(|((x, r), (dx, dr))| x == &dx[..] && r == &dr[..]);
        if !equal {
            println!("bit_equal=false\nfirst_difference=tables after {at}");
        }
        equal
    }
}
