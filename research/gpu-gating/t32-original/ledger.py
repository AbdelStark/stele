"""Recheck the combined H100 source lifetimes, CPU verification and timing receipts."""
import argparse
import hashlib
import json
import re
import runpy
import tarfile
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_rows(log, tag):
    for line in log.splitlines():
        if line.startswith(tag + " "):
            yield dict(field.split("=") for field in line.split()[1:])


def read_receipts(archive, verified):
    assert digest(archive.read_bytes()) == verified["archive_sha256"]
    raw = {}
    with tarfile.open(archive) as t:
        for m in t.getmembers():
            assert m.isfile() and m.size < 40_000_000 and m.name not in raw
            raw[m.name] = t.extractfile(m).read()
    assert len(raw) == verified["files"]
    pins = {name: h for h, name in (l.split() for l in raw["stage/SHA256SUMS"].decode().splitlines())}
    for item in ("campaign.sbatch", "worker.py", "commit.txt"):
        assert digest(raw["stage/" + item]) == pins[item]
    assert raw["stage/commit.txt"].decode().strip() == verified["source"]
    assert pins["source.tar.gz"] == verified["source_sha256"]
    return raw


def clock_ns(gnu):
    value = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)", gnu)[1]
    seconds = 0.
    for part in value.split(":"):
        seconds = 60 * seconds + float(part)
    return round(seconds * 1e9)


def ledger(archive, verified):
    here = Path(__file__).resolve().parent
    repo = here.parents[2]
    z_name = "e16-40z-t32-gkr-memory-h100.json"
    w_name = "e16-40w-t32-source-visits-h100.json"
    z = json.loads((repo / "bench/ledger" / z_name).read_text())
    w = json.loads((repo / "bench/ledger" / w_name).read_text())
    raw = read_receipts(archive, verified)
    result = json.loads(raw["run/result.json"])
    assert result["job"] == verified["job"] and result["proof_sha256"] == verified["proof_sha256"]
    assert result["inputs"] == z["model_config"]["inputs"] == w["model_config"]["inputs"]
    assert raw["run/verify.out"].splitlines()[-1] == b"YES"
    assert raw["run/wrong.out"].splitlines()[-1] == b"NO: model differs from --expect-model"
    physical = json.loads(raw["machine/physical.json"])
    assert physical["proof"]["bytes"] == 21_411_006
    assert all(result[k + "_sha256"] == entry["sha256"] for k, entry in physical.items())
    assert result["verifier_sha256"] == z["model_config"]["verifier_sha256"]
    log = raw["run/prove.err"].decode()
    st = runpy.run_path(str(here / "receipt.py"))["summarize"](log)
    assert st == result["stages"]
    steps = runpy.run_path(str(here.parent / "t32-resident/test_memory.py"))["check_memory"](log)
    source = st["source"]
    # Each CPU alias oracle compares every unique original column per lookup. Compare
    # the individual projections to the worker's independently parsed alias receipt.
    alias = json.loads(raw["machine/alias.json"])
    projections = [{k: int(v) for k, v in row.items()} for row in parse_rows(log, "alias_lookup")]
    assert projections == alias["lookups"] and [r["id"] for r in projections] == list(range(21))
    assert sum(r["checked_bytes"] for r in projections) == alias["original_checked_bytes"]
    for kind in ("top", "rebuild"):
        assert st[kind]["h2d_bytes"] == alias["h2d_by_family"][kind]
        assert st[kind]["h2d_bytes"] == (z["kernel_counters"][kind + "/h2d_bytes"]
                                       - alias["original_checked_bytes"] + alias["view_bytes_per_family"])
    shapes = [m.groups() for line in log.splitlines() if (m:=re.match(
        r"^shape (gkr_\w+) field=\d+ vars=(\d+) .* compact=([01])$", line))]
    assert len(shapes) == len(steps) == 385
    compact = []
    for row, (kind, variables, flag) in zip(steps.values(), shapes):
        assert row["variables"] == int(variables)
        if flag == "1":
            assert kind == "gkr_leaf"
            compact.append(row["cpu_factors_ns"])
    assert len(compact) == 21
    charged = st["gkr"]["charged"]
    counters = {"original/uploads": st["original_uploads"], "original/upload_bytes": st["original_payload_bytes"],
                "original/gkr_live_bytes": st["original_live_bytes_during_gkr"], "gkr/steps": len(steps),
                "gkr/fallbacks": 0, "gkr/final_child_handoffs": sum(r["released_bytes"] > 0 for r in steps.values()),
                "gkr/child_views": st["child_views"], "gkr/child_addressable_bytes": st["child_addressable_bytes"],
                "gkr/h2d_bytes": charged["h2d_bytes"], "gkr/d2h_bytes": charged["d2h_bytes"],
                "alias/original_legs_per_family": alias["original_legs"],
                "alias/unique_bytes_per_family": alias["original_checked_bytes"],
                "alias/descriptor_bytes_per_family": alias["view_bytes_per_family"]}
    counters["original/old_payload_bytes"] = (w["kernel_counters"]["source_message_upload_bytes"]
                                              + z["kernel_counters"]["batch_packing/message_bytes"])
    times = {"whole_measured_cli":clock_ns(raw["run/prove.time"].decode()), "cold/context":st["gkr"]["cold_ns"],
             "gkr/reference_factors":charged["cpu_factors_ns"], "gkr/reference_rounds":charged["cpu_rounds_wall_ns"],
             "gkr/device": charged["device_path_ns"], "gkr/retained_cpu": charged["retained_cpu_ns"],
             "gkr/compact_routing_upper":sum(compact), "alias/layout":alias["charged_layout_ns"],
             "alias/qualification":alias["qualification_ns"]}
    times["gkr/candidate_with_routing_upper"] = times["gkr/compact_routing_upper"] + times["gkr/device"] + times["gkr/retained_cpu"]
    for key, val in source.items():
        if isinstance(val, int):
            (times if key.endswith("_ns") else counters)["source/" + key] = val
    visits = source["sources"]
    times["source/original_upload_ns"] = sum(r["original_upload_ns"] for r in visits)
    times["source/lock_wait_upper_ns"] = sum(r["lock_wait_ns"] for r in visits)
    times["source/charged_with_lock_upper_ns"] = source["device_ns"] + times["source/lock_wait_upper_ns"]
    for name in ("top","rebuild","batch_prepare","batch_dense","batch_packing"):
        for key,val in st[name].items():
            (times if key.endswith("_ns") else counters)[name+"/"+key] = val
    counters["whole_cli_peak_rss_bytes"] = 1024*int(re.search(r"Maximum resident set size \(kbytes\): (\d+)",raw["run/prove.time"].decode())[1])
    source_high = max(r["outside_pool"] + r["reserved_high"] for r in visits)
    gkr_high = max(r["pool_reserved_high"] + max(0,r["total_bytes"]-r["free_bytes"]-r["pool_reserved_bytes"]) for r in steps.values())
    counters["pool/reserved_plus_observed_outside_high"] = max(source_high,gkr_high)
    counters["pool/reserved_high"] = max(st["batch_packing"]["pool_reserved_high_through_batches"],source["max_pool_reserved_bytes"])
    counters["pool/used_high"] = max(st["batch_packing"]["pool_used_high_through_batches"],max(r["used_high"] for r in visits))
    counters["pool/budget_bytes"] = steps[96]["total_bytes"]*2//5
    assert counters["pool/used_high"] <= counters["pool/reserved_high"] <= counters["pool/reserved_plus_observed_outside_high"] <= counters["pool/budget_bytes"]
    for i in (96,97):
        for k in ("variables","construction_bytes","first_fold_bytes","input_bytes","released_bytes"):
            counters[f"gkr/{i}/{k}"] = steps[i][k]
    seeded = dict(pcs=1000,batch_owners=2000,gkr=1000,gkr_steps=2728,
                  gkr_representations=5456,canonical_original_lookups=1000,raw_original_lookups=1000)
    m = re.search(rb"periodic_rounds=(\d+) period_transitions=(\d+)", raw["machine/gkr.err"])
    seeded.update(periodic_rounds=int(m[1]),period_transitions=int(m[2]))
    assert seeded["periodic_rounds"] > seeded["period_transitions"] > 0
    plan = dict(z["model_config"]["plan"], stages=["pinned_pcs_originals","lookup_columns_from_originals",
                "periodic_gkr_with_live_originals","ordinary_batches_from_originals","selected_pcs_openings"])
    model=dict(plan=plan,job=result["job"],workload=result["workload"],profile=result["profile"],affinity=result["affinity"],
               inputs=result["inputs"],baselines=[w_name,z_name],ledger_source=verified["source"],
               evidence_sha256=verified["archive_sha256"],source_archive_sha256=verified["source_sha256"],
               evidence_location=f"lucid-cluster:~/stele-codex/e16-40ac-originals/public-{result['job']}.tar.gz",
               physical=physical,seeded=seeded,slurm_elapsed=verified["slurm_elapsed"],
               receipt_sha256={name:digest(value) for name,value in raw.items() if name.startswith(("machine/","run/"))},
               scope="The H100 checks component outputs. The CPU-authored development proof uses the ordinary verifier and wrong-model control. The production GPU proof remains unqualified.")
    out = {k:v for k,v in z.items() if k not in ("model_config","kernel_counters","stage_times_ns","plan_digest","note")}
    out.update(commit=verified["source"],workload="micro/dev-zk-stories42m-t32-original-residency-h100",
               prover_time_ns=times["whole_measured_cli"],kernel_counters=counters,stage_times_ns=times,model_config=model,
               plan_digest=digest(json.dumps(plan,separators=(",",":"),sort_keys=True).encode()),
               note="One shared CUDA context retains all original allocations through their actual consumers. The process includes CPU and device comparisons. Source lock wait and compact routing have separately reported conservative bounds.")
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("archive","verified","output"):
        p.add_argument(name,type=Path)
    args=p.parse_args()
    out=ledger(args.archive,json.loads(args.verified.read_text()))
    args.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
