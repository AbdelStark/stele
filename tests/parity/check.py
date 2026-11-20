"""RFC-0014 A2/A3. Compare ordinary CUDA operations and both complete checked proof producers."""
import filecmp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "bench"))
from hiding_source_counts import proof_inventory, check_source_work
from lookup_tree_counts import FIELDS as LOOKUP_FIELDS, check_lookup_work

REFERENCE_SHA256 = "357505bd55ce0ffe1c152cf36634ab6e7bb322ae00394b7c1cd9ef5ef467b23a"


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def build(kind, dest, cuda=False, package="stele-cli"):
    args = ["cargo", "build", "--release", "--locked", "--offline", "-p", package,
            "--no-default-features", "--message-format=json", *kind]
    if cuda:
        args += ["--features", "cuda"]
    records = map(json.loads, run(args, stdout=subprocess.PIPE, text=True).stdout.splitlines())
    producers = [r["executable"] for r in records if r.get("executable")]
    if len(producers) != 1:
        raise ValueError("expected one independently built executable")
    shutil.copy2(producers[0], dest)


def hiding_sources(work):
    paths = []
    for package, example, cuda in (("stele-pcs", "scalar_hiding_source", False),
                                   ("stele-gpu", "cuda_hiding_source", True)):
        binary = work / example
        build(["--example", example], binary, cuda=cuda, package=package)
        path = work / (example + ".bin")
        with path.open("wb") as output:
            result = run([binary], stdout=output, stderr=subprocess.PIPE, text=True)
        if "hiding_source_cases=1000 selected_columns=4000" not in result.stderr.splitlines():
            raise ValueError("incomplete hiding-source operation inventory")
        paths.append(path)
    if not paths[0].stat().st_size or not filecmp.cmp(*paths, shallow=False):
        raise ValueError("CUDA hiding source root, column or Merkle path differed from CPU")
    print("cuda_hiding_source_matches=1000 selected_columns=4000", flush=True)


def relation_counts(text, schedule):
    steps, planned, rounds, folds, finals, upload, download, values, masks, budget, peak = map(int, text.split())
    count, nrounds, nodes, fields = schedule
    if (count <= 0 or nrounds < count or (steps, finals) != (count, count)
            or (planned, rounds, folds) != (nrounds,) * 3 or download != 16 * (nodes + fields)
            or min(values, masks, budget, peak) <= 0 or values + masks > upload):
        raise ValueError("device relation calls disagree with the authenticated proof schedule")
    return steps, rounds


def gkr_counts(text, expected):
    steps, planned, rounds, folds, finals, upload, download, layer, budget, peak = map(int, text.split())
    nsteps, nrounds, evaluations = expected
    if (nsteps <= 0 or nrounds < nsteps or steps != nsteps or finals != nsteps
            or (planned, rounds, folds) != (nrounds,) * 3 or upload <= 0 or not 0 <= layer <= upload
            or download < 16 * (evaluations + nsteps) or download % 16 or min(budget, peak) <= 0):
        raise ValueError("device calls disagree with the authenticated GKR schedule")
    return steps, rounds


def hardware_counts(text, batches, source_originals=None):
    originals, selected, planned, rounds, folds, finals, downloaded = map(int, text.split())
    if (selected != batches or originals != (selected if source_originals is None else source_originals) or finals != selected or selected <= 0
            or planned != rounds or planned != folds or planned <= 0 or downloaded != 48 * rounds + 32 * finals):
        raise ValueError("device calls disagree with the authenticated ordinary batches")
    return selected, rounds


def verify(binary, case, identity, changed_model):
    argv = [binary, "verify-dev", "--public", case / "public.bin", "--proof", case / "proof.bin",
            "--expect-model", identity]
    lines = run(argv, capture_output=True, text=True).stdout.splitlines()
    if lines[-1:] != ["YES"] or "proof index 0 of 1" not in lines:
        raise ValueError("ordinary verifier rejected or used a different index")
    [audited] = [s for s in lines if s.startswith("dev-zk: ")]
    m = re.fullmatch(r"dev-zk: (\d+) relation instances, (\d+) GKR steps, (\d+) batches, (\d+) proof bytes", audited)
    if m is None or int(m[4]) != (case / "proof.bin").stat().st_size:
        raise ValueError("missing verified batch inventory")
    if changed_model:
        argv[-1] = ("1" if identity[0] == "0" else "0") + identity[1:]
        result = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT)
        if result.returncode != 1 or result.stdout.splitlines()[-1:] != ["NO: model differs from --expect-model"]:
            raise ValueError("wrong-model control failed")
    return (int(m[1]), int(m[2]), int(m[3])), "\n".join(lines)


def rejection_controls(work):
    case = work / "fixtures" / "0"
    arguments = [option for name in ("model", "preparation", "scales", "artifact")
                 for option in ("--" + name, case / (name + ".bin"))]
    public, proof = work / "absent-public", work / "absent-proof"
    commitment, secret = work / "control-commitment", work / "control-secret"
    common = [*arguments, "--length", "2", "--commitment", commitment, "--secret", secret]
    run([work / "verifier", "commit-model", "--zk", *common, "--proofs", "1"], capture_output=True)
    before = secret.read_bytes()
    result = subprocess.run(
        [work / "cuda-cli", "prove-dev", "--zk", *common, "--tokens", "1", "--public", public,
         "--proof", proof, "--backend", "cuda"],
        cwd=ROOT, env={**os.environ, "CUDA_VISIBLE_DEVICES": ""}, capture_output=True, text=True,
    )
    if (result.returncode != 2 or not result.stdout.startswith("NO: CUDA proving failed:")
            or public.exists() or proof.exists() or secret.read_bytes() != before):
        raise ValueError("unavailable CUDA did not fail before reservation and proof output")
    print("rejected_unavailable_cuda=1 reservation_unchanged=1", flush=True)

    for args, marker in (([], "rejected_cuda_round"), (["gkr"], "rejected_cuda_gkr_round"),
                         (["relation"], "rejected_cuda_relation")):
        result = run([work / "reject-round", case, commitment, secret, *args], capture_output=True, text=True)
        expected = marker + "=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1"
        if result.stdout.splitlines() != [expected]:
            raise ValueError("changed CUDA round did not reach the checked masked prover")
        print(expected, flush=True)

    for stage in ("source-root", "source-sibling", "lookup-denominator", "standalone-root", "standalone-sibling"):
        result = run([work / "reject-round", case, commitment, secret, stage], capture_output=True, text=True)
        cause = "DenominatorZero" if stage == "lookup-denominator" else "RootMismatch"
        expected = f"rejected_cuda_{stage}={cause} injected=1 reservation_restored=1"
        if result.stdout.splitlines()[-1:] != [expected] or secret.read_bytes() != before:
            raise ValueError("changed CUDA source material did not reject and roll back")
        print(expected, flush=True)

    result = run([work / "reject-round", case, commitment, secret, "shared"], capture_output=True, text=True)
    marker = "rejected_cuda_shared=RoundSumMismatch target_rounds=1 target_folds=0 reservation_restored=1"
    if result.stdout.splitlines()[-1:] != [marker] or secret.read_bytes() != before:
        raise ValueError("changed shared round or reservation rollback differed")
    print(marker, flush=True)


def compare(work, pins):
    total_batches = total_rounds = total_steps = total_gkr_rounds = 0
    total_relations = total_relation_rounds = total_visits = total_responses = 0
    for i in [*range(50), "replay"]:
        index = 0 if i == "replay" else i
        row = pins["reference_cases"][index]
        cpu, gpu = (work / b / str(i) for b in ("cpu", "cuda"))
        identity = row["model_id"]
        for path in (cpu, gpu):
            if (path / "model.txt").read_text() != identity:
                raise ValueError(f"model differs in case {i}")
        for name in ("public", "proof"):
            left = (cpu / (name + ".bin")).read_bytes()
            if (hashlib.sha256(left).hexdigest() != row[name + "_sha256"]
                    or left != (gpu / (name + ".bin")).read_bytes()):
                raise ValueError(f"{name} bytes differ in case {i}")
        expected, report = verify(work / "verifier", cpu, identity, i == 0)
        if verify(work / "verifier", gpu, identity, i == 0) != (expected, report):
            raise ValueError("different verifier inventories")
        rel_schedule, (steps, gkr_rounds, evaluations), (selected, batch_rounds), _, shared_rounds = proof_inventory((cpu / "proof.bin").read_bytes())
        if expected != (rel_schedule[0], steps, selected):
            raise ValueError("decoded schedule and independent verifier disagree")
        dense, gkr, relations, source, lookup = (gpu / "device.txt").read_text().splitlines()
        keys = ("originals", "original_h2d_bytes", "visits", "responses", "hashes", "h2d_bytes", "d2h_bytes",
                "host_salt_bytes", "observed_peak_bytes", "total_bytes")
        fields = dict(zip(keys, map(int, source.split()), strict=True))
        lookup_fields = dict(zip(LOOKUP_FIELDS, map(int, lookup.split()), strict=True))
        lookup_counts = check_lookup_work(lookup_fields, report, fields["total_bytes"] * 2 // 5)
        if int(gkr.split()[7]) != 0:
            raise ValueError("host child layers were uploaded during retained lookup execution")
        work_counts = check_source_work(fields, (cpu / "proof.bin").read_bytes(), report, fields["total_bytes"] * 2 // 5, standalone=True)
        batches, rounds = hardware_counts(dense, expected[2], work_counts["originals"])
        if rounds != batch_rounds:
            raise ValueError("device batch rounds differ from the reference proof")
        gkr_counts(gkr, (steps, gkr_rounds, evaluations))
        nrel, rel_rounds = relation_counts(relations, rel_schedule)
        print(json.dumps(dict(case=i, model=identity, proof_sha256=row["proof_sha256"],
                              selected_batches=batches, device_rounds=rounds, shared_rounds=shared_rounds, original_h2d_bytes=fields["original_h2d_bytes"], gkr_steps=steps, gkr_rounds=gkr_rounds, relations=nrel, relation_rounds=rel_rounds, source_work=work_counts, lookup_work=lookup_counts)), flush=True)
        if i != "replay":
            total_visits += work_counts["visits"]
            total_responses += work_counts["responses"]
            total_batches += batches
            total_rounds += rounds
            total_relations += nrel
            total_relation_rounds += rel_rounds
            total_steps += steps
            total_gkr_rounds += gkr_rounds
    return total_batches, total_rounds, total_steps, total_gkr_rounds, total_relations, total_relation_rounds, total_visits, total_responses


def main():
    source = (HERE / "cpu-reference.json").read_bytes()
    if hashlib.sha256(source).hexdigest() != REFERENCE_SHA256:
        raise ValueError("CPU reference manifest changed")
    pinned = json.loads(source)
    rows = pinned["reference_cases"]
    if ([r["index"] for r in rows] != list(range(50)) or
            any(len({r[k] for r in rows}) != 50 for k in ("artifact_sha256", "model_id", "proof_sha256"))):
        raise ValueError("expected 50 distinct ordered models")
    result = run(["cargo", "test", "-p", "stele-gpu", "--release", "--locked", "--offline", "--features", "cuda",
                  "--lib", "--test", "dense", "--", "--ignored", "--nocapture", "--test-threads=1", "--skip", "accepts_primed_source_backing"],
                 text=True, stdout=subprocess.PIPE)
    print(result.stdout, flush=True)
    required = ("device::tests::matches_reference_original_across_staging_chunks",
                "device::tests::matches_reference_raw_lazy_device_boundaries",
                "lookup_tests::matches_reference_cuda_lookup", "gkr_tests::matches_reference_cuda_gkr", "relation_tests::matches_reference_cuda_relations",
                "matches_reference_cuda_dense_batches", "rejects_foreign_source_and_invalid_dense_transitions")
    completed = re.findall(r"^test (\S+) \.\.\. (?:[^\n]+\n)?ok$", result.stdout, flags=re.MULTILINE)
    if ("cuda_lookup_cases=1000 raw_cuda_lookup_cases=1000 complete_trees=2000 checked_child_views=24000 last_child_releases=2000" not in result.stdout
            or sorted(completed) != sorted(required)
            or "5 passed; 0 failed; 0 ignored" not in result.stdout or "2 passed; 0 failed; 0 ignored" not in result.stdout
            or not re.search(r"cuda_dense_cases=1000 rounds=([1-9]\d*) folds=\1 finals=1000", result.stdout)
            or "cuda_dense_lazy_cases=1000" not in result.stdout):
        raise ValueError("required H100 operation comparisons or controls missing")
    if not re.search(r"cuda_gkr_cases=1000 raw_cuda_gkr_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000", result.stdout):
        raise ValueError("required H100 GKR comparisons or controls missing")
    if "cuda_relation_cases=1000 raw_cuda_relation_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000" not in result.stdout:
        raise ValueError("required relation arithmetic comparisons missing")
    for mode in ("LAZY", "EAGER"):
        tests = run(["cargo", "test", "-p", "stele-gpu", "--features", "cuda", "--frozen", "--release",
                     "--lib", "runtime::source_budget_tests::", "--", "--include-ignored", "--test-threads=1"],
                    env={**os.environ, "CUDA_MODULE_LOADING": mode}, capture_output=True, text=True)
        if ("test result: ok. 2 passed; 0 failed; 0 ignored" not in tests.stdout or
                "accepts_primed_source_backing_before_any_private_original ... ok" not in tests.stdout or
                "rejects_driver_backing_hidden_by_unused_pool_reservation ... ok" not in tests.stdout):
            raise ValueError("missing fresh-context hiding source capacity controls")
        print(f"cuda_source_fresh_context={mode} capacity_controls=2", flush=True)
    with tempfile.TemporaryDirectory(prefix="stele-cuda-parity-") as tmp:
        work = Path(tmp)
        hiding_sources(work)
        run(["uv", "run", "--locked", "--script", HERE / "fixtures.py", work / "fixtures"])
        build(["--bin", "stele"], work / "verifier")
        build(["--example", "parity_proof"], work / "cpu-prove")
        build(["--example", "parity_proof"], work / "cuda-prove", cuda=True)
        build(["--bin", "stele"], work / "cuda-cli", cuda=True)
        build(["--example", "reject_cuda_round"], work / "reject-round", cuda=True, package="stele-gpu")
        rejection_controls(work)
        for name in ("cpu", "cuda"):
            run([work / (name + "-prove"), work / "fixtures", work / name, name])
        batches, rounds, steps, gkr_rounds, relations, relation_rounds, visits, responses = compare(work, pinned)
    print(f"cuda_complete_byte_matches=50 selected_batches={batches} device_rounds={rounds} gkr_steps={steps} gkr_rounds={gkr_rounds} relations={relations} relation_rounds={relation_rounds} source_visits={visits} source_responses={responses} replay=0 changed_model=0", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        sys.exit(str(e))
