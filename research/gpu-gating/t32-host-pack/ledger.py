"""Replay a collected CPU-only T32 run into paired RFC-0018 component records."""
import hashlib
import json
import re
import statistics
import sys
import tarfile
from pathlib import Path
from receipt import summarize


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(archive, checked):
    if sha(archive.read_bytes()) != checked["archive_sha256"]:
        raise ValueError("published evidence hash mismatch")
    with tarfile.open(archive) as bundle:
        def read(member):
            return bundle.extractfile(member).read().decode()
        result = json.loads(read("run/result.json"))
        report = summarize(read("run/prove.err"))
        if (report != result["stages"].get("pack",result["stages"]) or checked["job"] != result["job"] or
            checked["source"] != read("stage/commit.txt").strip() or
            checked["source_sha256"] != read("stage/SHA256SUMS").split()[0] or
            read("run/verify.out").splitlines()[-1] != "YES" or
            read("run/wrong.out").splitlines()[-1] != "NO: model differs from --expect-model"):
            raise ValueError("CPU run did not replay")
        peak = 1024*int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", read("run/prove.time"))[1])
        cpu = re.search(r"^Model name:\s*([^\n]+)", read("machine/cpu.txt"), flags=re.M)[1]
        rust = read("machine/toolchain.txt").splitlines()[0]
        hashes = {member.name: sha(bundle.extractfile(member).read()) for member in bundle}
    ids = [r["id"] for r in report["elementwise_matches"]]
    config = {k:result[k] for k in ("job","profile","workload","affinity","inputs","cli_sha256","verifier_sha256","proof_sha256","public_sha256")}
    config.update(source_archive_sha256=checked["source_sha256"],evidence_sha256=checked["archive_sha256"],
                  evidence_location=checked["evidence_location"],
                  public_file_hashes=hashes,measured_ids=ids,complete_cpu_proof_bytes=21411006,
                  measured_complete_gpu_proof_pairs=0,all_payloads_equal=True,cpu_time_scope="one enclosing proof, four balanced preparations per original ordinary source per method",
                  all_pairs_parallel_faster=report["parallel_wins_all_pairs"])
    plan = json.dumps(dict(ids=ids,workload=result["workload"],tile=128,reps=4,threads=16),sort_keys=True,separators=(",",":")).encode()
    counter = dict(elements_checked_groups=len(ids), positions=sum(r["positions"] for r in report["elementwise_matches"]),
                   peak_proof_and_separate_two_output_equality_rss=peak)
    match_keys = ["message_bytes","claim_headers_bytes","descriptor_bytes","gamma_bytes","tuples_bytes","tuple_capacity_bytes","payload_bytes","runs","offsets"]
    for key in match_keys:
        counter[key]=sum(r[key] for r in report["elementwise_matches"])
    records = {}
    for method in ["serial","parallel"]:
        config_m = dict(config, method=method,three_batch_totals_ns=report["three_batch_totals_ns"][method])
        totals={"all_three_including_source_decode_drop_and_encode": int(statistics.median(config_m["three_batch_totals_ns"]))}
        rows = [r for r in report["samples"] if r["method"]==method]
        for phase in ["wall","decode","group","index","alloc","split","runs","weights","message","drop"]:
            totals[phase]=int(statistics.median(sum(r[phase+"_ns"] for r in rows if r["rep"]==rep) for rep in range(4)))
        maxima = {f"maximum_single_source_{k}":max(r[k] for r in rows) for k in ("output_bytes","scratch_bytes")}
        records[method]=dict(schema_version=1,kind="micro",workload="micro/dev-zk-stories42m-t32-host-pack-"+method,
            commit=checked["source"],plan_digest=sha(plan),profile="standard",toolchain=rust,
            device=cpu+f' ({checked["node"]}, CPU only, 16 pinned CPUs)',driver="CPU",bindings_all_on=True,model_config=config_m,
            batch_size=1,prompt_tokens=0,generated_tokens=0,proof_size_bytes=0,verifier_time_ns=dict(rust=0,python=0),witness_recompute_ns=0,
            prover_time_ns=totals["all_three_including_source_decode_drop_and_encode"],stage_times_ns=totals,
            kernel_counters={**counter,**maxima},controls=dict(total=0,passed=0,failed=0),
            note="Paired constituent host preparation of three original T32 ordinary batches. All output words and scalars matched in a separate two-output comparison. The verifier accepted the complete CPU proof and rejected a changed expected model. Timers are nested, and the allocator may first touch zero pages during packing. The serial runs timer also packs weights; parallel has a distinct pass over the original tuples. Source capacity fields describe the inner ragged tuples. Other input byte counts describe visible borrowed slices. No GPU was allocated.")
    return records


if __name__ == "__main__":
    archive, receipt, output = map(Path,sys.argv[1:])
    for method,data in build(archive,json.loads(receipt.read_text())).items():
        (output/("e16-40ab-t32-host-pack-"+method+".json")).write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
