"""Record the scalar chained-multiplication ratio (RFC-0018 §1, task E1-02)."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 bench/field_mul.py bench/ledger/<run>.json")
    if run("git", "status", "--porcelain"):
        raise SystemExit("commit benchmark sources before measuring; worktree must be clean")
    output = pathlib.Path(sys.argv[1])
    if not output.is_absolute():
        output = ROOT / output
    if output.exists():
        raise SystemExit("refusing to overwrite a benchmark ledger")
    plan = {"operation": "chained multiplication", "iterations": 1_000_000,
            "samples": 5, "warmup_per_field": 10_000,
            "fields": ["M31", "QM31"], "order": "alternating", "build": "release",
            "m31_seed_factor": [1729, 7919], "qm31_seed": [3, 5, 7, 11],
            "qm31_factor": [13, 17, 19, 23]}
    commit = run("git", "rev-parse", "HEAD")
    lines = run("cargo", "run", "-p", "stele-field", "--example", "field_mul",
                "--release", "--locked", "--offline", "--", str(plan["iterations"])).splitlines()
    total_label, total = lines[0].split()
    assert total_label == "total" and len(lines) == plan["samples"] + 1
    samples = []
    for line in lines[1:]:
        label, m31, qm31 = line.split()
        assert label == "sample" and int(m31) > 0 and int(qm31) > 0
        samples.append([int(m31), int(qm31)])
    totals = [sum(x[i] for x in samples) for i in range(2)]
    assert sum(totals) <= int(total)
    if commit != run("git", "rev-parse", "HEAD") or run("git", "status", "--porcelain"):
        raise SystemExit("source state changed during measurement")
    device = platform.machine()
    if platform.system() == "Darwin":
        device += " " + run("sysctl", "-n", "machdep.cpu.brand_string")
    elif pathlib.Path("/proc/cpuinfo").exists():
        names = [x.split(":", 1)[1].strip() for x in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
                 if x.startswith("model name")]
        if names:
            device += " " + names[0]
    ledger = {
        "schema_version": 1, "kind": "micro", "workload": "micro/field-mul",
        "commit": commit, "toolchain": run("rustc", "-Vv"), "device": device,
        "driver": "not-applicable", "model_config": {"plan": plan, "os": platform.platform(),
            "sample_times_ns": samples, "ratio_numerator": totals[1], "ratio_denominator": totals[0]},
        "plan_digest": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "profile": "standard", "bindings_all_on": True, "batch_size": 1,
        "prompt_tokens": 0, "generated_tokens": 0, "prover_time_ns": int(total), "witness_recompute_ns": 0,
        "stage_times_ns": {"m31": totals[0], "qm31": totals[1]},
        "kernel_counters": {"m31_multiplications": plan["iterations"]*plan["samples"],
                            "qm31_multiplications": plan["iterations"]*plan["samples"]},
        "proof_size_bytes": 0, "verifier_time_ns": {"rust": 0, "python": 0},
        "controls": {"total": 0, "passed": 0, "failed": 0},
        "note": "Scalar CPU dependency-chain multiplication with black_box per result; ratio is total QM31 time / total M31 time. Warmup excluded; total includes all timed samples. SHA-256 of compact sorted JSON plan. No proof, inference, GPU, constant-time or cost-model fit claim; no applicable proof binding is disabled."
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(ledger, stream, indent=2)
        stream.write("\n")
    subprocess.run(["cargo", "run", "-p", "stele-bench", "--locked", "--offline", "--",
                    "ledger", "validate", str(output)], cwd=ROOT, check=True)
    print(f"QM31:M31 measured ratio = {totals[1]}/{totals[0]}; ledger: {output}")


if __name__ == "__main__":
    main()
