"""Install only the CPU batch observer in a disposable source archive."""
from pathlib import Path
import shutil
import sys


def install(root):
    here = Path(__file__).resolve().parent
    root = Path(root).resolve()
    if (root / ".git").exists():
        raise ValueError("expected a disposable archive")

    def replace(path, old, new):
        f = root / path
        text = f.read_text()
        if text.count(old) != 1:
            raise ValueError(f"unexpected source at {path}: {old[:50]}")
        f.write_text(text.replace(old, new))

    # Copy the wrapper to preserve all normal slice-taking callers. Vec references
    # in the observed copy allow a checked, borrowed Any downcast at the QM31 boundary.
    replace("crates/stele-hash/src/lib.rs", "pub trait ChallengeField: sealed::Target",
            "pub trait ChallengeField: 'static + sealed::Target")
    claims = root / "crates/stele-reductions/src/zk_claims.rs"
    body = claims.read_text().split("pub fn prove_batch<", 1)[1].split("\n}", 1)[0]
    body = body.replace("claims: &[Claim<K>],", "claims: &Vec<Claim<K>>,")
    anchor = 'detail.lap("zk/detail/batch_prefix");'
    if body.count(anchor) != 1:
        raise ValueError("original batch prefix missing")
    body = body.replace(anchor, anchor + "\n    host_sample::batch(id, prepared, claims, &gammas);")
    with claims.open("a") as out:
        out.write('\n#[path="host_sample.rs"]\npub mod host_sample;\n#[allow(clippy::ptr_arg, reason="Any must borrow the original sized Vec without copying private weights")]\nfn sample_batch<' + body + "\n}\n")
    replace(claims, "let (batch, point) = prove_batch(\n            plan.masks[index].0,",
            "let (batch, point) = sample_batch(\n            plan.masks[index].0,")
    shutil.copyfile(here / "observer.rs", claims.parent / "host_sample.rs")
    # Only CPU modules are built; the research package has no CUDA feature here.
    lib = "research/gpu-gating/masked/src/lib.rs"
    for module in ["mod batch;", "pub mod host_pack;"]:
        replace(lib, '#[cfg(any(test, feature = "cuda"))]\n' + module, module)
    # The serial baseline uses the original lookup encoding helper. The rest of
    # that module builds CUDA lookup inputs and has no caller in this CPU study.
    lookup = (root / "research/gpu-gating/masked/src/lookup.rs").read_text()
    words = "pub(crate) fn words(" + lookup.split("pub(crate) fn words(", 1)[1].split("\n}", 1)[0] + "\n}"
    with (root / lib).open("a") as out:
        out.write('\n#[cfg(not(any(test,feature="cuda")))]\nmod lookup {use crate::{K, Serialize};\n'+words+'\n}\n')
        out.write("\npub use stele_reductions::zk::claims::host_sample::OBSERVER as HOST_OBSERVER;\n")
    replace("Cargo.toml", 'resolver = "2"', 'resolver = "2"\nexclude = ["research/gpu-gating/masked"]')
    replace("crates/stele-cli/Cargo.toml", "[dependencies]", '''[dependencies]
stele-masked-gpu-bench = { path = "../../research/gpu-gating/masked" }''')
    replace("Cargo.lock", 'name = "stele-cli"\nversion = "0.1.0"\ndependencies = [\n "stele-bench",',
            'name = "stele-cli"\nversion = "0.1.0"\ndependencies = [\n "stele-bench",\n "stele-masked-gpu-bench",')
    replace("Cargo.lock", '[[package]]\nname = "stele-pcs"', '''[[package]]
name = "stele-masked-gpu-bench"
version = "0.1.0"
dependencies = [
 "stele-reductions",
]

[[package]]
name = "stele-pcs"''')
    replace("crates/stele-cli/src/main.rs", "fn main() -> ExitCode {", '''fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("prove-dev") {
        stele_masked_gpu_bench::HOST_OBSERVER.set(stele_masked_gpu_bench::host_pack::compare)
            .expect("single required CPU observer");
    }''')


if __name__ == "__main__":
    install(sys.argv[1])
