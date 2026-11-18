"""ADR-127. Project a resident T32 proof from disjoint measured operations on both hosts."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
REPLACED = ("sources_prepare", "top_prepare", "top_tree", "gkr_tree", "gkr_factors",
            "gkr_rounds", "batch_face", "batch_weights")


def project(cpu_ns, laps, host_gkr_ns, device_ns, cold_ns, qualification_ns):
    removed = {name: laps["lap_zk_detail_" + name] for name in REPLACED}
    retained = cpu_ns - sum(removed.values())
    if min(removed.values()) < 0 or min(retained, host_gkr_ns, device_ns, cold_ns) <= 0 or qualification_ns < 0:
        raise ValueError("invalid disjoint timing")
    # In particular the full original ordinary batch rounds stay charged. Only their dense
    # arithmetic moved. This bounds the unmeasured portion for masking and the transcript.
    warm = retained + host_gkr_ns + device_ns
    return dict(cpu_ns=cpu_ns, replaced_laps_ns=removed, retained_cpu_ns=retained,
                calibrated_host_gkr_ns=host_gkr_ns, measured_h100_ns=device_ns,
                warm_projected_ns=warm, cold_projected_ns=warm+cold_ns,
                including_oracle_readbacks_ns=warm+qualification_ns,
                warm_reaches_three=cpu_ns >= 3*warm, cold_reaches_three=cpu_ns >= 3*(warm+cold_ns))


def calculate(mac, calibration, hardware, log, result):
    if result["profile"] != "dev-zk" or result["workload"] != "dev/stories42m-t32":
        raise ValueError("wrong original proof")
    h = hardware["model_config"]
    original = result["inputs"]
    if (result["proof_sha256"] != h["proof_sha256"] or result["inputs"] != h["inputs"]
            or hashlib.sha256(log).hexdigest() != h["public_receipt_sha256"]["run/prove.err"]):
        raise ValueError("hardware receipt changed")
    text = log.decode()
    resident = runpy.run_path(str(HERE.parent / "t32-original/receipt.py"))["summarize"](text)
    views = runpy.run_path(str(HERE.parent / "t32-alias/receipt.py"))["device_summary"](text)
    gkr = resident["gkr"]
    if gkr["on_device"] != 385 or gkr["budget_rejections"] or resident["original_uploads"] != 5:
        raise ValueError("incomplete device coverage")
    source = resident["source"]
    # The source visit starts after taking a process-local lock. Charging all measured waits
    # is conservative when CPU certificate workers wait for another recorded GPU visit.
    waits = sum(r["lock_wait_ns"] for r in source["sources"])
    charges = dict(source_visits=source["device_ns"], source_lock_wait=waits,
                   original_column_layout=views["charged_layout_ns"], lookup_tops=resident["top"]["gpu_ns"],
                   lookup_rebuilds=resident["rebuild"]["gpu_ns"], gkr=gkr["charged"]["device_path_ns"],
                   ordinary_batch_prepare=resident["batch_prepare"]["gpu_ns"],
                   ordinary_batch_dense=resident["batch_dense"]["gpu_ns"])
    qualifications = source["host_oracle_compare_ns"] + views["qualification_ns"] + sum(
        resident[k]["qualification_ns"] for k in ("top", "rebuild"))
    c = calibration["model_config"]
    host = c["samples"]
    if (c["process"]["input_sha256"] != original or [r["index"] for r in host] != [0, 1, 2]
            or any(r["load_before_thousandths"][0] >= 3000 for r in host)):
        raise ValueError("wrong laps-host calibration")
    host_ns = max(r["stages"]["host_factor_ns"] + r["stages"]["host_round_ns"] for r in host)
    if ([r["model_config"]["proof_index"] for r in mac] != [0, 1, 2]
            or len({r["commit"] for r in mac}) != 1
            or len({r["model_config"]["proof_sha256"] for r in mac}) != 3):
        raise ValueError("expected three distinct checks from the same CPU producer")
    out = []
    for r in mac:
        m = r["model_config"]
        if (r["kind"] != "inference" or r["profile"] != "development" or not r["bindings_all_on"]
                or r["workload"] != result["workload"] or m["profile_byte"] != 4 or m["threads"] != 16
                or m["evidence"]["input_hashes"] != original or m["statement"]["checked"] != "23..32"
                or int(m["statement"]["T"]) != 32 or r["controls"]["passed"] < 1
                or r["controls"]["failed"] != 0 or r["verifier_time_ns"]["rust"] <= 0):
            raise ValueError("wrong CPU reference or statement")
        out.append(project(r["prover_time_ns"], r["stage_times_ns"], host_ns, sum(charges.values()),
                           gkr["cold_ns"] + source["cold_ns"], qualifications))
    return dict(cpu_commit=mac[0]["commit"], h100_commit=hardware["commit"], calibration_commit=calibration["commit"],
                charges_ns=charges, oracle_qualification_ns=qualifications, samples=out,
                whole_prover_type="cross-host projection", measured_full_gpu_inference_proofs=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hardware_ledger", "prove_log", "result", "mac_gkr_ledger"):
        parser.add_argument(name, type=Path)
    parser.add_argument("cpu_ledgers", nargs=3, type=Path)
    args = parser.parse_args()
    def read(p):
        return json.loads(p.read_bytes())
    report = calculate([read(p) for p in args.cpu_ledgers], read(args.mac_gkr_ledger),
                       read(args.hardware_ledger), args.prove_log.read_bytes(), read(args.result))
    print(json.dumps(report, sort_keys=True, indent=2))
