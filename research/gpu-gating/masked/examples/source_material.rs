//! RFC-0014 §4/A1 (E16-40b): cold source preparation, downloads and host salts.
use std::process::ExitCode;
use std::time::Instant;
use stele_masked_gpu_bench::source::{Shape, BLOWUP};
use stele_masked_gpu_bench::QM31;
use stele_reductions::stele_hash::HashUsage;
use stele_reductions::stele_pcs::{verify_certificate, Policy, PreparedSource};

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: source_material <ell> <m> <cpu|gpu|check> <seed>".into());
    }
    let ell: u8 = args[0].parse().map_err(|_| "ell")?;
    let m: u8 = args[1].parse().map_err(|_| "m")?;
    let seed: u64 = args[3].parse().map_err(|_| "seed")?;
    let mode = args[2].as_str();
    if !matches!(mode, "cpu" | "gpu" | "check")
        || !(3..=11).contains(&ell)
        || !(9..=17).contains(&m)
    {
        return Err("unsupported mode or benchmark shape (ell 3..11, m 9..17)".into());
    }
    let shape = Shape::new(ell, m, seed);
    let source = shape.source().ok_or("unsupported source")?;
    let start = Instant::now();
    let message = shape.message();
    println!(
        "source_ell={ell}\nsource_m={m}\nseed={seed}\nhost_message_ns={}",
        start.elapsed().as_nanos()
    );
    let reference = if mode != "gpu" {
        let start = Instant::now();
        let prepared = PreparedSource::<QM31>::hiding_with(
            shape.id,
            ell,
            m,
            BLOWUP,
            &message,
            &shape.seed,
            &mut HashUsage::default(),
            Policy::Two,
        )
        .map_err(|e| format!("{e:?}"))?;
        println!(
            "cpu_prepare_ns={}\ncpu_root={}",
            start.elapsed().as_nanos(),
            hex(&prepared.source().root())
        );
        let start = Instant::now();
        let certificate = prepared.certificate().map_err(|e| format!("{e:?}"))?.0;
        verify_certificate(*prepared.source(), &certificate).map_err(|e| format!("{e:?}"))?;
        println!("cpu_certify_ns={}", start.elapsed().as_nanos());
        Some(prepared)
    } else {
        None
    };
    if mode == "cpu" {
        return Ok(());
    }
    #[cfg(feature = "cuda")]
    {
        use stele_masked_gpu_bench::gpu::{available, Device};
        use stele_masked_gpu_bench::gpu_source::prepare_material;
        if !available() {
            return Err("required CUDA driver and NVRTC absent".into());
        }
        let start = Instant::now();
        let dev = Device::new().map_err(|e| format!("{e:?}"))?;
        println!(
            "device={}\ngpu_setup_ns={}",
            dev.name,
            start.elapsed().as_nanos()
        );
        let start = Instant::now();
        let (material, t) =
            prepare_material(&dev, &shape, &message).map_err(|e| format!("{e:?}"))?;
        println!("gpu_material_ns={}\ngpu_root={}\ngpu_upload_ns={}\ngpu_encode_ns={}\ngpu_merkle_ns={}\ngpu_download_ns={}\nhost_assemble_ns={}",
            start.elapsed().as_nanos(), hex(&material.root()), t.upload.as_nanos(), t.encode.as_nanos(), t.merkle.as_nanos(), t.download.as_nanos(), t.assemble.as_nanos());
        println!("upload_bytes={}\ndownload_bytes={}\ndevice_retained_bytes={}\ndevice_buffer_peak_bytes={}\nhost_material_owned_bytes={}",
            t.upload_bytes, t.download_bytes, t.retained_bytes, t.buffer_peak_bytes, material.owned_bytes());
        if let Some(expected) = reference {
            if material.root() != expected.source().root() {
                return Err("root mismatch".into());
            }
            for index in 0..source.descriptor().count {
                let (payload, path) = material
                    .response(index)
                    .ok_or("missing material response")?;
                let response = expected.response(index).map_err(|e| format!("{e:?}"))?;
                if payload != response.payload || path != response.siblings {
                    return Err(format!("response mismatch at {index}"));
                }
            }
            println!(
                "bit_equal=true\ncolumns_and_paths_compared={}",
                source.descriptor().count
            );
        }
        Ok(())
    }
    #[cfg(not(feature = "cuda"))]
    {
        let _ = (source, reference);
        Err("gpu/check requires --features cuda".into())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
