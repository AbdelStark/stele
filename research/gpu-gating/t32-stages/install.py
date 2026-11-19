"""Build-only diagnostics for a fresh source archive. Never apply to a working checkout."""
from pathlib import Path
import shutil
import subprocess
import sys


def install_batch(root,replace,module):
    claims = "crates/stele-reductions/src/zk_claims.rs"
    # Keep the ordinary prove_batch wrapper and every borrow; this sampling copy
    # takes Vec references so Any can retain the actual ragged claims without copying.
    start = (root / claims).read_text().split("pub fn prove_batch<", 1)[1].split("\n}", 1)[0]
    observed = ("fn sample_batch<" + start + "\n}").replace(
        "claims: &[Claim<K>],", "claims: &Vec<Claim<K>>,").replace(
        'detail.lap("zk/detail/batch_prefix");', '''detail.lap("zk/detail/batch_prefix");
    {module}::batch(id, prepared, claims, &gammas);
    let cpu = std::time::Instant::now();''')
    observed = observed.replace('detail.lap("zk/detail/batch_weights");', 'std::eprintln!("t32_cpu_weights id={id} ns={}", cpu.elapsed().as_nanos());\n    detail.lap("zk/detail/batch_weights");')
    with (root / claims).open("a") as f:
        f.write("\n" + observed.replace("{module}",module) + "\n")
    replace(claims, "let (batch, point) = prove_batch(\n            plan.masks[index].0,",
            "let (batch, point) = sample_batch(\n            plan.masks[index].0,")
    replace(claims, 'detail.lap("zk/detail/batch_face");\n    let (sumcheck, point)',
            'detail.lap("zk/detail/batch_face");\n    let dense = {module}::Measured(dense);\n    let (sumcheck, point)'.replace("{module}",module))
    replace(claims, "let i = batch_instance(id, prepared.source(), claims, gammas);",
            "let cpu = std::time::Instant::now();\n    let i = batch_instance(id, prepared.source(), claims, gammas);")
    replace(claims, 'detail.lap("zk/detail/batch_face");', 'std::eprintln!("t32_cpu_face id={id} ns={}", cpu.elapsed().as_nanos());\n    detail.lap("zk/detail/batch_face");')


def install(root, gkr=False, source=False):
    root = Path(root).resolve()
    if (root / ".git").exists():
        raise ValueError("instrument a disposable source archive")
    here = Path(__file__).resolve().parent

    def replace(path, old, new):
        file = root / path
        text = file.read_text()
        if text.count(old) != 1:
            raise ValueError(f"unexpected source at {path}: {old[:70]}")
        file.write_text(text.replace(old, new))

    if source:
        import runpy
        device = runpy.run_path(str(here.parent / "t32-source/install.py"))["install"](root, replace)
    elif gkr:
        import runpy
        device = runpy.run_path(str(here.parent / "t32-gkr/install.py"))["install"](root, replace)
    else:
        device = here / "device.rs"
        reductions = "crates/stele-reductions/src/"
        claims = reductions + "zk_claims.rs"
        # Both closed ChallengeField implementations (QM31 and OM31) are static.
        # Any downcasts below borrow the exact CPU data; a non-QM31 field fails closed.
        replace("crates/stele-hash/src/lib.rs", "pub trait ChallengeField: sealed::Target",
                "pub trait ChallengeField: 'static + sealed::Target")
        shutil.copyfile(here / "observer.rs", root / (reductions + "t32_sample.rs"))
        with (root / claims).open("a") as f:
            f.write('\n#[path="t32_sample.rs"]\npub mod t32_sample;\n')
        lookup = reductions + "zk_lookup.rs"
        with (root / lookup).open("a") as f:
            f.write((here / "lookup.inc.rs").read_text())
        replace(claims, 'let layers = lookup::tree(lp, &data, beta, alpha);\n        detail.lap("zk/detail/top_tree");',
                'let lookup_cpu = std::time::Instant::now();\n        let layers = lookup::tree(lp, &data, beta, alpha);\n        detail.lap("zk/detail/top_tree");')
        replace(claims, "let [p, q, mut h] = lookup::top(lp, &layers)?;\n        drop(layers);",
                """let [p, q, mut h] = lookup::top(lp, &layers)?;
            std::eprintln!("t32_cpu_lookup kind=top id={l} ns={}", lookup_cpu.elapsed().as_nanos());
            lookup::sample(l, lp, &data, beta, alpha, &layers, Some([&p, &q, &h]));
            drop(layers);""")
        replace(claims, "tree = Some((l, lookup::tree(lp, &data, runs[l].beta, runs[l].alpha)));",
                """let lookup_cpu = std::time::Instant::now();
                let layers = lookup::tree(lp, &data, runs[l].beta, runs[l].alpha);
                std::eprintln!("t32_cpu_lookup kind=rebuild id={l} ns={}", lookup_cpu.elapsed().as_nanos());
                lookup::sample(l, lp, &data, runs[l].beta, runs[l].alpha, &layers, None);
                tree = Some((l, layers));""")
        install_batch(root, replace, "t32_sample")
        # std is scoped locally in the no_std reductions crate even in this executable.
        replace(claims, "\nuse alloc::vec::Vec;", "\nextern crate std;\nuse alloc::vec::Vec;")
    subprocess.run(["patch", "-p0", "-i", str(here / "cargo-lock.patch")], cwd=root, check=True)
    masked = "research/gpu-gating/masked/src/"
    replace("Cargo.toml", 'resolver = "2"', 'resolver = "2"\nexclude = ["research/gpu-gating/masked"]')
    shutil.copyfile(device, root / (masked + "t32_timing.rs"))
    with (root / (masked + "lib.rs")).open("a") as f:
        f.write("\npub mod t32_timing;\n")
    replace("crates/stele-cli/Cargo.toml", "[dependencies]", """[dependencies]
stele-masked-gpu-bench = { path = "../../research/gpu-gating/masked", features = ["cuda"] }""")
    replace("crates/stele-cli/src/main.rs", "fn main() -> ExitCode {", """fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("prove-dev") && std::env::args().any(|v| v == "--zk") {
        stele_masked_gpu_bench::t32_timing::install();
    }""")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("root")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gkr", action="store_true")
    mode.add_argument("--source", action="store_true")
    args = parser.parse_args()
    install(args.root, args.gkr, args.source)
