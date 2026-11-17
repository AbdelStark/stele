//! Execute actual CUDA expressions as C++ for CPU-only differential tests.
use std::{
    fs,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn run(source: &str, input: &[u32]) -> Vec<u32> {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let dir = Directory(std::env::temp_dir().join(format!(
            "stele-kernel-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    fs::create_dir(&dir.0).expect("temporary directory");
    fs::write(dir.0.join("probe.cpp"), source).expect("source");
    let compiled = Command::new("c++")
        .args([
            "-std=c++17",
            "-O2",
            "-fno-strict-aliasing",
            "probe.cpp",
            "-o",
            "probe",
        ])
        .current_dir(&dir.0)
        .output()
        .expect("host C++ compiler required");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    fs::write(
        dir.0.join("input"),
        input
            .iter()
            .flat_map(|x| x.to_ne_bytes())
            .collect::<Vec<_>>(),
    )
    .expect("inputs");
    let ran = Command::new(dir.0.join("probe"))
        .stdin(Stdio::from(
            fs::File::open(dir.0.join("input")).expect("input file"),
        ))
        .stdout(Stdio::from(
            fs::File::create(dir.0.join("output")).expect("output file"),
        ))
        .status()
        .expect("host helper execution");
    assert!(ran.success(), "host helper failed");
    let bytes = fs::read(dir.0.join("output")).expect("outputs");
    assert_eq!(bytes.len() % 4, 0);
    bytes
        .chunks_exact(4)
        .map(|w| u32::from_ne_bytes(w.try_into().unwrap()))
        .collect()
}

pub(crate) fn helpers() -> &'static str {
    let source = include_str!("kernels.cu");
    assert_eq!(
        source.matches("#define GRID_STRIDE").count(),
        1,
        "field/helper boundary moved"
    );
    source.split_once("#define GRID_STRIDE").unwrap().0
}
