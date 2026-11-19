"""RFC-0018 A2. Reproduce the H100 original-column GKR evidence from public receipts."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import runpy


HERE = Path(__file__).resolve().parent
SHARED = runpy.run_path(str(HERE.parent / "t32-original/ledger.py"))


def seeded_counts(raw):
    """Count exactly the suites this allocation ran, including lazy representatives."""
    observed = {}
    for suite, prefix in (("provenance", "host_gkr_original_cases"), ("gathered", "original_gkr_statements"),
                          ("gkr", "periodic_rounds"), ("batch", "parallel_pack_cases")):
        output = raw[f"machine/{suite}.out"].decode()
        assert "1 passed; 0 failed; 0 ignored;" in output
        rows = [line for line in raw[f"machine/{suite}.err"].decode().splitlines()
                if line.startswith(prefix + "=")]
        assert len(rows) == 1
        counts = dict((key, int(val)) for key, val in re.findall(r"(\w+)=(\d+)(?= |$)", rows[0]))
        counts.pop("seed", None)
        assert counts and all(v > 0 for v in counts.values())
        observed.update({suite + "/" + key: val for key, val in counts.items()})
    required = {"provenance/host_gkr_original_cases": 32, "gathered/original_gkr_statements": 1000,
                "gathered/leaf_representations": 2000, "gathered/raw_original_statements": 1000,
                "gathered/controls": 2, "gkr/constructed_gkr_statements": 1000, "gkr/steps": 2728,
                "gkr/representations": 5456, "batch/parallel_pack_cases": 2000,
                "batch/pinned_batch_owner_cases": 2000, "batch/batch_device_cases": 1000}
    assert all(observed[k] == v for k, v in required.items())
    return {**observed, **SHARED["periodic_counts"](raw)}


def ledger(archive, verified):
    out = SHARED["ledger"](archive, verified, seeded_counts=seeded_counts)
    raw = SHARED["read_receipts"](archive, verified)
    log = raw["run/prove.err"].decode()
    replay = runpy.run_path(str(HERE / "receipt.py"))["summarize"](log)
    inputs = replay.pop("gkr_source_inputs")
    assert inputs == json.loads(raw["machine/gkr-originals.json"])
    assert replay.pop("lookup_original_views") == json.loads(raw["machine/alias.json"])
    assert replay == json.loads(raw["run/result.json"])["stages"]
    ac_name = "e16-40ac-t32-original-residency-h100.json"
    ac = json.loads((HERE.parents[2] / "bench/ledger" / ac_name).read_text())
    model = out["model_config"]
    assert ac["model_config"]["inputs"] == model["inputs"]
    assert ac["model_config"]["verifier_sha256"] == model["verifier_sha256"]
    assert model["job"] + "|COMPLETED|0:0|" in raw["stage/slurm-final.txt"].decode()
    schedule = raw["stage/slurm-final.txt"].decode()
    assert all(tag in schedule for tag in ("Requeue=0", "Restarts=0", "NumCPUs=16", "gres/gpu=1"))
    counters = out["kernel_counters"]
    times = out["stage_times_ns"]
    def rows(tag):
        return [{key: int(value) for key, value in row.items()} for row in SHARED["parse_rows"](log, tag)]
    steps = rows("t32_gkr_step")
    for key, value in inputs.items():
        counters["gkr_construction/" + key] = value
    counters["gkr/round_h2d_bytes"] = sum(step["round_h2d_bytes"] for step in steps)
    assert counters["gkr/h2d_bytes"] == (inputs["inputs"] + inputs["descriptors"] + counters["gkr/round_h2d_bytes"])
    assert inputs["addressable_bytes"] == counters["alias/unique_bytes_per_family"]
    assert inputs["original_views"] == counters["alias/original_legs_per_family"]
    for key in ("build_ns", "round_ns", "fold_ns", "finish_ns"):
        times["gkr/" + key] = sum(step[key] for step in steps)
    assert times["gkr/device"] == sum(times["gkr/" + k] for k in ("build_ns", "round_ns", "fold_ns", "finish_ns"))
    batches = rows("t32_batch")
    assert [r["id"] for r in batches] == [1265, 1266, 1267]
    assert [r["positions"] >= 1 << 27 for r in batches] == [True, True, False]
    for b in batches:
        label = f"batch/{b['id']}/"
        for key in ("positions", "host_pack_bytes", "h2d_bytes", "group_ns", "index_ns", "wall_ns"):
            (times if key.endswith("_ns") else counters)[label + key] = b[key]
    memory = list(csv.reader(io.StringIO(raw["machine/gpu-memory.csv"].decode())))
    used = [int(row[1].strip().split()[0]) << 20 for row in memory[1:] if row]
    counters["sampled_device_used_high_bytes"] = max(used)
    counters["device_memory_samples"] = len(used)
    assert max(used) <= counters["pool/budget_bytes"]
    gpu = list(csv.reader(io.StringIO(raw["machine/gpu.txt"].decode())))
    name, uuid, driver, size = [s.strip() for s in gpu[1]]
    assert len(gpu) == 2 and f"{name}, {uuid}, {size}" == ac["device"] and driver == ac["driver"]
    out["device"] = f"{name}, {uuid}, {size}"
    out["driver"] = driver
    model["baselines"].append(ac_name)
    model["evidence_location"] = f"lucid-cluster:~/stele-codex/e16-40af-gkr-originals/public-{model['job']}.tar.gz"
    model["plan"]["stages"].extend(["gkr_original_source_gathers", "selected_larger_batch_host_packing"])
    out["plan_digest"] = hashlib.sha256(json.dumps(model["plan"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    counters["whole_gpu_authored_proof_pairs"] = 0
    out["workload"] = "micro/dev-zk-stories42m-t32-gkr-originals-h100"
    out["note"] = ("GKR reads original lookup columns from pinned messages and charges all explicit construction and round uploads. "
                   "The three ordinary batches use two parallel host preparations and one serial preparation. "
                   "The full prove clock includes the CPU prover and device qualification. GPU high water includes separately sampled device usage.")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "verified", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    record = ledger(args.archive, json.loads(args.verified.read_text()))
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
