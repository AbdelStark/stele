"""Measure E1-05 polynomial kernels on macOS; RFC-0018 §1."""
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    if len(sys.argv) != 2 or platform.system() != "Darwin":
        raise SystemExit("usage (macOS /usr/bin/time -l): python3 bench/partial_eval.py <new-ledger.json>")
    output = pathlib.Path(sys.argv[1]).absolute()
    if output.exists() or run("git", "status", "--porcelain"):
        raise SystemExit("requires a clean committed checkout and a new ledger path")
    commit = run("git", "rev-parse", "HEAD")
    subprocess.run(["cargo", "test", "-p", "stele-poly", "--release", "--locked", "--offline"], cwd=ROOT, check=True)
    subprocess.run(["cargo", "build", "-p", "stele-poly", "--example", "partial_eval", "--release", "--locked", "--offline"], cwd=ROOT, check=True)
    plan = {"operation": "trailing partial evaluation", "field": "QM31", "rows": 4, "columns": 16384,
            "bits": [4, 8, 16], "strategies": ["naive", "bucketed"], "iterations": 10, "samples": 3,
            "warmup_calls": 1, "order": "reverse cases on odd samples", "build": "release",
            "values": "((index*73+19) % 2^bits) - 2^(bits-1)",
            "point": "QM31(CM31(i+3,i+17),CM31(i+29,i+43)), i in 0..14"}
    cases = [(b, s) for b in plan["bits"] for s in plan["strategies"]]
    times, rss, payloads, outputs = {}, {}, {}, {}
    with tempfile.TemporaryDirectory() as directory:
        stats = pathlib.Path(directory) / "time.txt"
        for sample in range(plan["samples"]):
            for bits, strategy in cases[::(-1 if sample % 2 else 1)]:
                lines = run("/usr/bin/time", "-l", "-o", str(stats), str(ROOT / "target/release/examples/partial_eval"), str(bits), strategy).splitlines()
                result = dict(line.split() for line in lines)
                assert set(result) == {"time_ns", "payload_bytes", "output"}
                key = f"int{bits}/{strategy}"
                ns, size = int(result["time_ns"]), int(result["payload_bytes"])
                peaks = [int(line.split()[0]) for line in stats.read_text().splitlines() if "maximum resident set size" in line]
                assert ns > 0 and len(peaks) == 1 and peaks[0] > 0
                assert size == plan["rows"]*plan["columns"]*bits//8
                assert len(result["output"]) == plan["rows"]*16*2
                assert bytes.fromhex(result["output"])
                assert outputs.setdefault(bits, result["output"]) == result["output"], "strategy output mismatch"
                payloads[key] = size
                times.setdefault(key, []).append(ns)
                rss.setdefault(key, []).append(peaks[0])
    assert len(times) == 6 and all(len(v) == 3 for v in times.values())
    if commit != run("git", "rev-parse", "HEAD") or run("git", "status", "--porcelain"):
        raise SystemExit("source state changed during measurement")
    totals = {k: sum(v) for k, v in times.items()}
    elements = plan["rows"]*plan["columns"]
    ratios = {str(b): {"bucketed_ns": totals[f"int{b}/bucketed"], "naive_ns": totals[f"int{b}/naive"]} for b in plan["bits"]}
    ledger = {"schema_version": 1, "kind": "micro", "workload": "micro/partial-eval", "commit": commit,
        "toolchain": run("rustc", "-Vv"), "device": platform.machine()+" "+run("sysctl", "-n", "machdep.cpu.brand_string"),
        "driver": "not-applicable", "model_config": {"plan": plan, "os": platform.platform(),
            "sample_times_ns": times, "peak_process_rss_bytes": rss, "input_payload_bytes": payloads,
            "bytes_per_element_denominator": elements, "bucketed_to_naive_ratio": ratios},
        "plan_digest": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "profile": "standard", "bindings_all_on": True, "batch_size": 1, "prompt_tokens": 0, "generated_tokens": 0,
        "prover_time_ns": sum(totals.values()), "witness_recompute_ns": 0, "stage_times_ns": totals,
        "kernel_counters": {k+"/elements": elements*plan["samples"]*plan["iterations"] for k in totals},
        "proof_size_bytes": 0, "verifier_time_ns": {"rust": 0, "python": 0}, "controls": {"total": 0, "passed": 0, "failed": 0},
        "note": "Native CPU microbenchmark. Timed calls include eq-table construction, workspace allocation and partial evaluation; exclude input construction, warmup and output encoding. Total sums measured samples. Payload excludes spare capacity/allocator metadata. macOS time -l maximum RSS is bytes for each separate case process, including setup, warmup, code and allocator; it is not kernel scratch size or DRAM traffic. Each process runs one strategy. Outputs match byte-for-byte across strategies and samples. Targets c_w; no inference, GPU, soundness or cost-model fit claim. No applicable proof binding disabled."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(ledger, stream, indent=2); stream.write("\n")
    subprocess.run(["cargo", "run", "-p", "stele-bench", "--locked", "--offline", "--", "ledger", "validate", str(output)], cwd=ROOT, check=True)
    print(f"Validated partial-evaluation ledger: {output}")


if __name__ == "__main__":
    main()
