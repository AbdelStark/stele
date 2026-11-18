"""Recompute the T32 compact-input component ledger from a selected public receipt."""
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import runpy
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(archive, baseline, verified):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if any(not x.isfile() or x.size > 32_000_000 for x in members):
            raise ValueError("unexpected public archive member")
        files = {entry.name: tar.extractfile(entry).read() for entry in members}
    if len(files) != len(members) or sha(archive.read_bytes()) != verified["archive_sha256"]:
        raise ValueError("public archive identity")
    result = json.loads(files["run/result.json"])
    source = files["stage/commit.txt"].decode().strip()
    pins = dict((name, digest) for digest, name in
                (line.split() for line in files["stage/SHA256SUMS"].decode().splitlines()))
    if (verified["source"] != source or verified["source_sha256"] != pins["source.tar.gz"]
            or result["job"] != verified["job"] or result["proof_sha256"] != verified["proof_sha256"]
            or result["inputs"] != baseline["model_config"]["inputs"]
            or result["verifier_sha256"] != baseline["model_config"]["verifier_sha256"]):
        raise ValueError("workload or binary identity")
    if (files["run/verify.out"].decode().splitlines()[-1] != "YES"
            or files["run/wrong.out"].decode().splitlines()[-1] != "NO: model differs from --expect-model"):
        raise ValueError("ordinary verifier / wrong-model control")
    script = Path(__file__).resolve().parent.parent / "t32-resident/receipt.py"
    log = files["run/prove.err"].decode()
    report = runpy.run_path(str(script))["summarize"](log)
    # The frozen 40u timer duplicated four batch sums. The final 40v parser
    # validates these from the ordered runs and reports allocation maxima.
    embedded = dict(result["stages"])
    embedded["batch_prepare"] = {k: v for k, v in embedded["batch_prepare"].items()
                                 if k not in ("runs","run_checks","host_pack_bytes","device_build_bytes")}
    if report != embedded:
        raise ValueError("stage replay differs")
    times = {"gpu_context_compile": report["gkr"]["cold_ns"]}
    counters = {}
    for name in ("top","rebuild","batch_prepare","batch_dense","batch_packing"):
        for k,v in report[name].items():
            if k.endswith("_ns"):
                times[name+"/"+k[:-3]] = v
            else:
                counters[name+"/"+k] = v
    for k,v in report["gkr"]["charged"].items():
        (times if k.endswith("_ns") else counters)["gkr/"+k] = v
    for k in ("steps","on_device","budget_rejections","pool_reserved_high","pool_used_high"):
        counters["gkr/"+k] = report["gkr"][k]
    for k,v in report.items():
        if isinstance(v,int):
            counters["resident/"+k] = v
    totals = {int(re.search(r" total_bytes=(\d+)",line)[1])
              for line in log.splitlines() if line.startswith("t32_selected ")}
    if len(totals) != 1:
        raise ValueError("device memory geometry changed during the lookup schedule")
    counters["device_total_bytes"] = totals.pop()
    counters["resident_budget_bytes"] = 2*(counters["device_total_bytes"]//5)
    for kind in ("top","rebuild"):
        for k in ("normalize_ns","wall_ns","stage_ns","upload_ns","tree_ns","top_ns","download_ns","assemble_ns"):
            rows = [dict(word.split("=") for word in line.split()[1:]) for line in log.splitlines()
                    if line.startswith(f"t32_selected kind={kind} ")]
            assert len(rows) == 21
            times[f"{kind}/detail_{k[:-3]}"] = sum(int(r[k]) for r in rows)
    gkr_inputs = [int(re.search(r" original_inputs_ns=(\d+)",line)[1])
                  for line in log.splitlines() if line.startswith(("t32_gkr_step ","t32_gkr_skip "))]
    assert len(gkr_inputs) == 385
    times["gkr/detail_original_construction_inputs"] = sum(gkr_inputs)
    timing = files["run/prove.time"].decode()
    wall = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)",timing)[1]
    secs = Decimal(0)
    for part in wall.split(":"):
        secs = 60*secs+Decimal(part)
    counters["whole_measured_process_peak_rss_bytes"] = 1024*int(re.search(r"Maximum resident set size \(kbytes\): (\d+)",timing)[1])
    mem = files["machine/gpu-memory.csv"].decode().splitlines()[1:]
    counters["whole_sampled_device_used_high_bytes"] = 1024**2 * max(int(r.split(",")[1].split()[0]) for r in mem)
    for line in files["machine/device.err"].decode().splitlines():
        if line.startswith("compact_lookup_cases="):
            for word in line.split(" device=")[0].split():
                k,v = word.split("=")
                counters["hardware/"+k] = int(v)
    if counters.get("hardware/complete_trees") != 2000:
        raise ValueError("missing original-input hardware parity")
    plan = dict(baseline["model_config"]["plan"], lookup_representation="original M31 columns and public members")
    data = {k:v for k,v in baseline.items() if k not in ("model_config","note","plan_digest","stage_times_ns","kernel_counters")}
    data.update(commit=source,workload="micro/dev-zk-stories42m-t32-compact-lookup-h100",
                plan_digest=sha(json.dumps(plan,sort_keys=True,separators=(",",":")).encode()),
                stage_times_ns=times,kernel_counters=counters,prover_time_ns=int(secs*1_000_000_000))
    config = {k:result[k] for k in ("job","workload","profile","affinity","inputs","cli_sha256","verifier_sha256","proof_sha256","public_sha256")}
    config.update(plan=plan,baseline="e16-40v-t32-resident-gkr-batch-h100.json", source_archive_sha256=verified["source_sha256"],
                  evidence_sha256=verified["archive_sha256"],public_receipt_sha256={k:sha(v) for k,v in files.items()},
                  evidence_location=f"lucid-cluster:~/stele-codex/e16-40y-compact-lookup/public-{result['job']}.tar.gz",
                  stderr_filesystem=files["machine/prove-stderr-filesystem.txt"].decode().splitlines(),
                  whole_gpu_proofs_compared=0)
    data["model_config"] = config
    data["note"] = ("Matched original CPU and H100 component timings in a complete CPU-authored development proof. "
                    "The 40v comparison uses the same pinned workload, host, thread count and visit schedule with fresh proof randomness. "
                    "The compact lookup path reads original M31 multiplicities and tuple columns with validated public projections, "
                    "and computes the table denominator on the device. All 21 original visits and 21 rebuilds are charged, "
                    "including host descriptor construction, packing, H2D, CUDA allocations, release and consumed D2H. "
                    "Independent full-tree qualification bytes and latency are reported separately. Detail timers are nested. "
                    "Proof stderr was captured on node-local storage and child-view logging follows the timed GKR build.")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("archive","baseline","verification","output"):
        parser.add_argument(arg,type=Path)
    args = parser.parse_args()
    ledger = build(args.archive,json.loads(args.baseline.read_text()),json.loads(args.verification.read_text()))
    args.output.write_text(json.dumps(ledger,indent=2,sort_keys=True)+"\n")
