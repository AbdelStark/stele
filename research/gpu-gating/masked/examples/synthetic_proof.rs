//! RFC-0014 §5. Fixed public seeds are for synthetic parity fixtures only.
use std::{env, fs, path::PathBuf};
use stele_prover::development::{bundle, zk, Public, Statement, Weights};
use stele_reductions::{
    relation::Sources,
    stele_cqis::{
        execution::Executor,
        model::{Model, Preparation, Scales},
    },
    stele_hash::blake3_digest,
};

fn main() {
    let mut args = env::args_os().skip(1);
    let root = PathBuf::from(args.next().expect("synthetic corpus"));
    let index: u8 = args.next().unwrap().into_string().unwrap().parse().unwrap();
    let output = PathBuf::from(args.next().expect("new output directory"));
    assert!(index < 50 && args.next().is_none());
    let input = root.join(index.to_string());
    let read = |name| fs::read(input.join(name)).expect("generated synthetic fixture");
    let (model_bytes, preparation, scales_bytes, artifact) = (
        read("model.bin"),
        read("preparation.bin"),
        read("scales.bin"),
        read("artifact.bin"),
    );
    let model = Model::decode(&model_bytes).expect("model");
    let prep = Preparation::decode(&model, &preparation).expect("preparation");
    let scales = Scales::decode(&model, &scales_bytes).expect("scales");
    let artifact_id = blake3_digest(&artifact);
    let executor = || {
        Executor::new(&model, &prep, &scales, &artifact, &artifact_id, 1 << 36).expect("executor")
    };
    let weights = Weights::from_artifact(&model, &artifact).expect("weights");
    let mut public = Public {
        model: model_bytes.clone(),
        preparation: preparation.clone(),
        scales: scales_bytes.clone(),
        vectors: zk::published(&model_bytes, &weights.vectors).expect("public records"),
        commitment: Vec::new(),
        sources: Sources::Expander,
    };
    // A different public starting token and a complete greedy two-token window per case.
    let mut runner = executor();
    let token = u32::from(index) + 1;
    let (first, cache) = runner.step(token, None).expect("first token");
    let argmax = |logits: &[i16]| {
        let maximum = logits.iter().max().expect("nonempty vocabulary");
        logits.iter().position(|x| x == maximum).unwrap() as u32
    };
    let second = argmax(first.logits());
    let (last, _) = runner.step(second, Some(&cache)).expect("second token");
    let statement = Statement {
        tokens: vec![token, second],
        start: 0,
        end: 2,
        next: Some(argmax(last.logits())),
    };
    let seed = |role: u8| {
        blake3_digest(
            &[
                b"stele/synthetic/parity/".as_slice(),
                &[role, index],
                &artifact_id,
            ]
            .concat(),
        )
    };
    let (commitment, mut state) = zk::commit(
        &public,
        &mut executor(),
        &weights,
        2,
        1,
        seed(0),
        zk::PROFILE_BALANCED,
    )
    .expect("model commitment");
    public.commitment.push((commitment.root, Vec::new()));
    let (proof, used) = zk::prove_next(
        &public,
        &mut executor(),
        &weights,
        &statement,
        zk::Seed::new(seed(1)),
        &commitment,
        &mut state,
        &mut |_| Ok(()),
    )
    .expect("complete checked proof");
    assert_eq!(used, 0);
    let bytes = bundle::encode_zk(&public, &statement, &commitment, used);
    let identity = zk::model_digest(&public, &commitment).expect("dev-zk model identity");
    fs::create_dir(&output).expect("fresh fixture output directory");
    fs::write(output.join("public.bin"), bytes).unwrap();
    fs::write(output.join("proof.bin"), proof).unwrap();
    fs::write(
        output.join("model.txt"),
        identity.map(|b| format!("{b:02x}")).concat(),
    )
    .unwrap();
}
