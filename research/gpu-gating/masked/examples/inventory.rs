//! RFC-0014 §5/§6: bounded masked-round qualification; no integrated proof claim.
use std::{process::ExitCode, time::Instant};
use stele_masked_gpu_bench::{challenge, cpu, fnv, inventory::Inventory, Shape, FNV_START};

const CASES: usize = 1000;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("inventory qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !matches!(args[1].as_str(), "cpu" | "check") {
        return Err("usage: inventory shapes.txt <cpu|check>".into());
    }
    if std::fs::metadata(&args[0])
        .map_err(|e| e.to_string())?
        .len()
        > 8 * 1024 * 1024
    {
        return Err("inventory exceeds harness limit".into());
    }
    let text = std::fs::read_to_string(&args[0]).map_err(|e| e.to_string())?;
    let inventory = Inventory::parse(&text)?;
    println!(
        "mode={}\nshapes={}\nexpected_cases={CASES}\ndomains=reduced\ncompact_finals=not_exercised",
        args[1],
        inventory.len()
    );
    let start = Instant::now();
    if args[1] == "cpu" {
        campaign(&inventory, run_cpu)?;
    } else {
        #[cfg(feature = "cuda")]
        {
            if !stele_masked_gpu_bench::gpu::available() {
                return Err("check requires a CUDA driver and NVRTC".into());
            }
            let setup = Instant::now();
            let dev = stele_masked_gpu_bench::gpu::Device::new().map_err(|e| format!("{e:?}"))?;
            println!(
                "device={}\ngpu_setup_ns={}",
                dev.name,
                setup.elapsed().as_nanos()
            );
            campaign(&inventory, |shape| device::compare(&dev, shape))?;
        }
        #[cfg(not(feature = "cuda"))]
        return Err("check requires --features cuda and a real CUDA device".into());
    }
    println!(
        "campaign_ns={}\ncompleted_cases={CASES}\nMASKED_INVENTORY_PASSED",
        start.elapsed().as_nanos()
    );
    Ok(())
}

fn campaign(
    inventory: &Inventory,
    mut execute: impl FnMut(&Shape) -> Result<u64, String>,
) -> Result<(), String> {
    let mut digest = FNV_START;
    for index in 0..CASES {
        // Rng::new sets the low bit, so use distinct odd seeds rather than adjacent pairs.
        let seed = 0x40d0001 + 2 * index as u64;
        let case = inventory.case(index, seed);
        println!("case_start={index} shape={} seed={seed} representation={} original_vars={} executed_vars={} compact={}",
            index % inventory.len(), case.representation, case.original_variables, case.shape.n, case.compact);
        let start = Instant::now();
        let result = execute(&case.shape).map_err(|e| format!("case {index}: {e}"))?;
        digest = (digest ^ result).wrapping_mul(0x100000001b3);
        println!(
            "case_pass={index} rounds={} elapsed_ns={} fnv={result:016x}",
            case.shape.n,
            start.elapsed().as_nanos()
        );
    }
    println!("campaign_fnv={digest:016x}");
    Ok(())
}

fn run_cpu(shape: &Shape) -> Result<u64, String> {
    let mut reference = cpu(shape);
    let mut digest = FNV_START;
    for round in 0..shape.n {
        digest = fnv(digest, &reference.round().map_err(|e| format!("{e:?}"))?);
        reference
            .fold(challenge(round))
            .map_err(|e| format!("{e:?}"))?;
    }
    let finals: Vec<_> = reference.tables().map(|(x, _)| x[0]).collect();
    Ok(fnv(digest, &finals))
}

#[cfg(feature = "cuda")]
mod device {
    use super::*;
    use stele_masked_gpu_bench::{
        gpu::{Device, DeviceMasked},
        K,
    };
    use stele_reductions::zk::claims::bench::Masked;

    fn tables_equal(reference: &Masked<K>, device: &DeviceMasked<'_>) -> Result<(), String> {
        let actual = device.tables().map_err(|e| format!("{e:?}"))?;
        let expected: Vec<_> = reference.tables().collect();
        if actual.len() != expected.len()
            || actual
                .iter()
                .zip(expected)
                .any(|((x, r), (ex, er))| x != ex || r != er)
        {
            return Err("unequal factor or mask table".into());
        }
        Ok(())
    }

    pub fn compare(dev: &Device, shape: &Shape) -> Result<u64, String> {
        let (mut device, upload, build) = dev.build(shape).map_err(|e| format!("{e:?}"))?;
        let compile = Instant::now();
        device.prepare().map_err(|e| format!("{e:?}"))?;
        println!(
            "gpu_upload_ns={} gpu_build_ns={} gpu_prepare_ns={}",
            upload.as_nanos(),
            build.as_nanos(),
            compile.elapsed().as_nanos()
        );
        let mut reference = cpu(shape);
        tables_equal(&reference, &device)?;
        let mut digest = FNV_START;
        for round in 0..shape.n {
            let actual = device.round().map_err(|e| format!("{e:?}"))?;
            if actual != reference.round().map_err(|e| format!("{e:?}"))? {
                return Err(format!("unequal polynomial at round {round}"));
            }
            digest = fnv(digest, &actual);
            device
                .fold(challenge(round))
                .map_err(|e| format!("{e:?}"))?;
            reference
                .fold(challenge(round))
                .map_err(|e| format!("{e:?}"))?;
            tables_equal(&reference, &device).map_err(|e| format!("round {round}: {e}"))?;
        }
        let tables = device.tables().map_err(|e| format!("{e:?}"))?;
        let finals: Vec<_> = tables.iter().map(|(x, _)| x[0]).collect();
        Ok(fnv(digest, &finals))
    }
}
