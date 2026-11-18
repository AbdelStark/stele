"""RFC-0018 A2. Reproduce checked original-mask and live-relation evidence from Lucid."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import tarfile

HERE = Path(__file__).resolve().parent
SHARED = runpy.run_path(str(HERE.parent / "t32-original/ledger.py"))
PRIVATE = runpy.run_path(str(HERE / "receipt.py"))


def seeded(raw):
    expected = {
        "bound": {"bound_masked_cases": 1000, "device_rounds": 13000, "changed_round_controls": 1},
        "host": {"host_private_gkr_statements": 32},
        "private": {"private_gkr_statements": 1000, "raw_private_statements": 1000,
                    "representations": 5456, "bad_window_controls": 1},
    }
    counts = {}
    for suite, required in expected.items():
        assert "1 passed; 0 failed; 0 ignored;" in raw[f"machine/{suite}.out"].decode()
        marker = next(iter(required)) + "="
        line, = [s for s in raw[f"machine/{suite}.err"].decode().splitlines() if s.startswith(marker)]
        observed = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)(?: |$)", line)}
        assert all(observed[k] == v for k, v in required.items())
        counts.update({suite + "/" + k: v for k, v in observed.items()})
    assert counts["host/compared_original_windows"] > 32
    assert counts["private/checked_rounds"] > counts["private/representations"]
    for suite in ("bound", "private"):
        assert re.fullmatch(r"[a-f0-9]{64}", raw[f"machine/{suite}.sha256"].decode().split()[0])
        assert b"Exit status: 0" in raw[f"machine/{suite}.time"]
    return counts


def ledger(archive, verified, baseline):
    raw = SHARED["read_receipts"](archive, verified)
    out = SHARED["ledger"](archive, verified, seeded_counts=seeded)
    model = out["model_config"]
    logs = raw["run/prove.err"].decode()
    observations = PRIVATE["summarize"](logs)
    masks = observations.pop("private_gkr_views")
    original = observations.pop("gkr_source_inputs")
    assert observations.pop("lookup_original_views") == json.loads(raw["machine/alias.json"])
    assert observations == json.loads(raw["run/result.json"])["stages"]
    previous_name = "e16-40af-t32-gkr-originals-h100.json"
    previous = json.loads((HERE.parents[2] / "bench/ledger" / previous_name).read_text())
    assert previous["model_config"]["inputs"] == model["inputs"]
    assert previous["model_config"]["evidence_sha256"] == hashlib.sha256(baseline.read_bytes()).hexdigest()
    with tarfile.open(baseline) as prior:
        removed = PRIVATE["compare_reference"](logs, prior.extractfile("run/prove.err").read().decode())
    receipt = json.loads(raw["machine/gkr-private.json"])
    assert receipt["private"] == masks and receipt["removed"] == removed == 179520
    assert original["mask"] == original["block_mask"] == 0
    assert original["block_challenge"] == 16 * masks["block_views"]
    schedule = raw["stage/slurm-final.txt"].decode()
    assert model["job"]+"|COMPLETED|0:0|" in schedule
    assert all(s in schedule for s in ("NodeList=h100-nvl-1-1-cc", "NumCPUs=16", "gres/gpu=1", "Requeue=0", "Restarts=0"))
    name, uuid, driver, size = [s.strip() for s in list(csv.reader(io.StringIO(raw["machine/gpu.txt"].decode())))[1]]
    assert f"{name}, {uuid}, {size}" == previous["device"] and driver == previous["driver"]
    out["device"], out["driver"] = previous["device"], driver
    stages = list(SHARED["parse_rows"](logs, "relation_gpu"))
    terminal, = SHARED["parse_rows"](logs, "relation_gpu_complete")
    assert [int(r["id"]) for r in stages] == list(range(876)) and terminal == receipt["relation"]
    assert int(terminal["relations"]) == len(stages)
    assert all(r["admitted"] == "1" and r["cpu_returned"] == "0" for r in stages)
    assert all(sum(int(r[k]) for r in stages) == int(terminal[k]) for k in ("rounds", "folds", "finals"))
    counters, times = out["kernel_counters"], out["stage_times_ns"]
    for key, value in masks.items():
        (times if key.endswith("_ns") else counters)["private_gkr/" + key] = value
    counters["private_gkr/avoided_h2d_bytes"] = removed
    counters.update({"gkr_construction/" + k: v for k, v in original.items()})
    counters.update({"device_relations/" + k: int(v) for k,v in terminal.items()})
    counters["whole_gpu_authored_proof_pairs"] = 0
    model["baselines"].append(previous_name)
    model["evidence_location"] = f"lucid-cluster:~/stele-codex/e16-40ai-mask-originals/public-{model['job']}.tar.gz"
    model["scope"] = ("The device returns all relation sumcheck messages before Fiat–Shamir. The CPU constructs the outer proof "
                      "and its GKR sumchecks, while the device independently compares every GKR construction and fold.")
    model["seeded_executable_sha256"] = {k: raw[f"machine/{k}.sha256"].decode().split()[0] for k in ("bound","private")}
    model["plan"]["stages"].extend(["original_gkr_columns_and_private_masks", "live_masked_relations"])
    out["plan_digest"] = hashlib.sha256(json.dumps(model["plan"], sort_keys=True, separators=(",",":")).encode()).hexdigest()
    out["workload"] = "micro/dev-zk-stories42m-t32-gkr-private-windows-h100"
    out["note"] = ("The GKR input census accounts every occurrence and shared layer mask window against the preceding "
                   "physical transfer on the same device. The whole clock includes both the selected and comparison work.")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "verified", "baseline", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    result = ledger(args.archive, json.loads(args.verified.read_text()), args.baseline)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
