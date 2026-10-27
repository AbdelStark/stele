"""Run native parity, then record packed SIMD throughput (RFC-0018 §1, E1-04)."""
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 bench/simd_ops.py <new-ledger.json>")
    if run("git", "status", "--porcelain"):
        raise SystemExit("commit benchmark sources before measuring; worktree must be clean")
    output = pathlib.Path(sys.argv[1]).absolute()
    if output.exists():
        raise SystemExit("refusing to overwrite a ledger")
    commit = run("git", "rev-parse", "HEAD")
    subprocess.run(["cargo", "test", "-p", "stele-simd", "--release", "--locked", "--offline", "--", "--nocapture"], cwd=ROOT, check=True)
    plan = {"operation": "cache-resident packed field ops", "iterations": 100_000,
            "samples": 3, "lanes": 16, "warmup_per_case": 1000,
            "fields": ["m31", "qm31"], "operations": ["Add", "Sub", "Mul"],
            "order": "rotate backend each sample", "build": "release",
            "input_a": "(column*16+lane+1)*8191", "input_b": "(column*16+lane+17)*65521"}
    lines = run("cargo", "run", "-p", "stele-simd", "--example", "simd_ops", "--release", "--locked", "--offline", "--", str(plan["iterations"])).splitlines()
    label, total = lines[0].split()
    assert label == "total"
    samples = {}
    for line in lines[1:]:
        label, case, ns = line.split()
        assert label == "sample" and int(ns) > 0
        samples.setdefault(case, []).append(int(ns))
    backends = sorted({key.split("/")[0] for key in samples})
    assert "Scalar" in backends and len(backends) >= 2, "native SIMD execution required"
    assert set(samples) == {f"{b}/{f}/{op}" for b in backends for f in plan["fields"] for op in plan["operations"]}
    assert all(len(v) == plan["samples"] for v in samples.values())
    totals = {key: sum(value) for key, value in samples.items()}
    assert sum(totals.values()) <= int(total)
    device = platform.machine()
    if platform.system() == "Darwin":
        device += " " + run("sysctl", "-n", "machdep.cpu.brand_string")
    elif pathlib.Path("/proc/cpuinfo").exists():
        names = [x.split(":", 1)[1].strip() for x in pathlib.Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")]
        if names: device += " " + names[0]
    if commit != run("git", "rev-parse", "HEAD") or run("git", "status", "--porcelain"):
        raise SystemExit("source state changed during measurement")
    elements = plan["iterations"]*plan["samples"]*plan["lanes"]
    counters = {f"{case}/elements": elements for case in totals}
    counters.update({f"{case}/logical_bytes": elements*(12 if "/m31/" in case else 48) for case in totals})
    rates = {case: {"elements_per_second": elements*1_000_000_000//ns,
                    "logical_bytes_per_second": counters[f"{case}/logical_bytes"]*1_000_000_000//ns} for case, ns in totals.items()}
    ledger = {"schema_version": 1, "kind": "micro", "workload": "micro/simd-ops", "commit": commit,
        "toolchain": run("rustc", "-Vv"), "device": device, "driver": "not-applicable",
        "model_config": {"plan": plan, "os": platform.platform(), "executed_backends": backends,
                         "required_backends": os.environ.get("STELE_REQUIRE_SIMD", "available native"),
                         "sample_times_ns": samples, "rates_floor": rates},
        "plan_digest": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "profile": "standard", "bindings_all_on": True, "batch_size": 1, "prompt_tokens": 0, "generated_tokens": 0,
        "prover_time_ns": int(total), "witness_recompute_ns": 0, "stage_times_ns": totals, "kernel_counters": counters,
        "proof_size_bytes": 0, "verifier_time_ns": {"rust": 0, "python": 0}, "controls": {"total": 0, "passed": 0, "failed": 0},
        "note": "Native parity precedes measurement. Timed calls include dispatch and canonicalization; checked construction, warmup and export excluded. Black-box inputs prevent hoisting. Logical bytes count two reads and one write, not measured DRAM traffic. Rates use aggregate samples with integer floor. SHA-256 compact sorted JSON plan. No proof/GPU/inference/constant-time/cost-model fit claim; no applicable proof binding is disabled."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(ledger, stream, indent=2); stream.write("\n")
    subprocess.run(["cargo", "run", "-p", "stele-bench", "--locked", "--offline", "--", "ledger", "validate", str(output)], cwd=ROOT, check=True)
    print(f"Validated SIMD ledger for {', '.join(backends)}: {output}")


if __name__ == "__main__":
    main()
