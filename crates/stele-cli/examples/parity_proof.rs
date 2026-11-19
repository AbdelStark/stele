//! RFC-0014 A2. Complete proofs for the 50 fixed, publicly seeded hardware gate models.
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use stele_prover::development::{bundle, prove_window_profile, zk, Statement};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [corpus, out, mode] = args.as_slice() else {
        return Err("expected corpus, new directory and cpu/cuda".into());
    };
    let root = PathBuf::from(corpus);
    let output = PathBuf::from(out);
    let gpu = match mode.to_str() {
        Some("cpu") => false,
        Some("cuda") => true,
        _ => return Err("unknown backend".into()),
    };
    #[cfg(feature = "cuda")]
    let device = if gpu {
        Some(stele_gpu::Cuda::new()?)
    } else {
        None
    };
    #[cfg(not(feature = "cuda"))]
    if gpu {
        return Err("CUDA feature required".into());
    }
    fs::create_dir(&output)?;
    for index in (0..50u32).chain([0]) {
        let dest = if index == 0 && output.join("0").exists() {
            output.join("replay")
        } else {
            output.join(index.to_string())
        };
        let src = root.join(index.to_string());
        let [model, prep, scales, artifact] = read_inputs(&src)?;
        let request = Statement {
            tokens: vec![index + 1],
            start: 0,
            end: 1,
            next: None,
        };
        let seed = |file: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
            fs::read(src.join(file))?
                .try_into()
                .map_err(|_| "invalid public fixture seed".into())
        };
        let mut committed = None;
        let commit = zk::Window::Commit {
            proofs: 1,
            seed: seed("model-seed.bin")?,
            profile: zk::PROFILE_BALANCED,
            out: &mut committed,
        };
        prove_window_profile(
            &model,
            &prep,
            &scales,
            &artifact,
            request.clone(),
            2,
            Some(commit),
        )
        .map_err(|e| format!("fixture commitment: {e:?}"))?;
        let (commitment, mut state) = committed.ok_or("missing fixture commitment")?;
        let mut used = u32::MAX;
        let mut persisted = Vec::new();
        let mut persist = |s: &zk::ModelState| {
            persisted = s.encode();
            Ok(())
        };
        let window = zk::Window::Prove {
            seed: zk::Seed::new(seed("proof-seed.bin")?),
            commitment: &commitment,
            state: &mut state,
            persist: &mut persist,
            index: &mut used,
        };
        fs::create_dir(&dest)?;
        let cpu = |window| {
            prove_window_profile(
                &model,
                &prep,
                &scales,
                &artifact,
                request.clone(),
                2,
                Some(window),
            )
        };
        #[cfg(feature = "cuda")]
        let produced = if let Some(context) = &device {
            let session = context.session();
            let result = stele_prover::development::prove_window_with_backend(
                &model,
                &prep,
                &scales,
                &artifact,
                request.clone(),
                2,
                window,
                zk::BatchExecution::new(&session),
            );
            let c = session.counts();
            fs::write(
                dest.join("device.txt"),
                format!(
                    "{} {} {} {} {} {} {}\n",
                    c.originals,
                    c.batches,
                    c.expected_rounds,
                    c.rounds,
                    c.folds,
                    c.finals,
                    c.downloaded_bytes
                ),
            )?;
            result
        } else {
            cpu(window)
        };
        #[cfg(not(feature = "cuda"))]
        let produced = cpu(window);
        let (public, statement, proof) = produced.map_err(|e| format!("fixture proof: {e:?}"))?;
        if used != 0 || persisted != state.encode() {
            return Err("fixture lifetime persistence mismatch".into());
        }
        let identity =
            zk::model_digest(&public, &commitment).map_err(|e| format!("model identity: {e:?}"))?;
        fs::write(
            dest.join("model.txt"),
            identity.map(|b| format!("{b:02x}")).concat(),
        )?;
        fs::write(
            dest.join("public.bin"),
            bundle::encode_zk(&public, &statement, &commitment, used),
        )?;
        fs::write(dest.join("proof.bin"), proof)?;
    }
    Ok(())
}

fn read_inputs(path: &Path) -> std::io::Result<[Vec<u8>; 4]> {
    Ok([
        fs::read(path.join("model.bin"))?,
        fs::read(path.join("preparation.bin"))?,
        fs::read(path.join("scales.bin"))?,
        fs::read(path.join("artifact.bin"))?,
    ])
}
