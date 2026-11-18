"""RFC-0014 A2/A3. Compare ordinary CUDA operations and both complete checked proof producers."""
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
REFERENCE_SHA256 = "8ba50f05e567ceb8fb2652cf9ba22d9e0e7096a2b6471796d94fee2837b35bbd"


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


def proof_schedule(proof):
    """Read only authenticated byte-4 round lengths (RFC-0026 A9, QM31 wire width 16)."""
    magic = b"stele-dev-zk-v1"
    if not proof.startswith(magic):
        raise ValueError("wrong proof header")
    cursor = len(magic) + 64  # CQIS id and statement digest

    def take(n):
        nonlocal cursor
        start = cursor
        cursor += n
        if cursor > len(proof):
            raise ValueError("truncated proof inventory")
        return start

    def count():
        start = take(4)
        return int.from_bytes(proof[start:start + 4], "little")

    def sumcheck():
        take(16)  # mask sum
        n = count()
        values = 0
        for _ in range(n):
            width = count()
            take(16 * width)
            values += width
        finals = count()
        take(16 * finals + 16)  # original finals and mask final
        return n, values, finals

    for _ in range(2):  # original sources and certificates
        for _ in range(count()):
            take(count())
    relations = count()
    rel_rounds = rel_nodes = rel_finals = 0
    for _ in range(relations):
        n, values, finals = sumcheck()
        rel_rounds += n
        rel_nodes += values
        rel_finals += finals
    steps = count()
    rounds = evaluations = 0
    for _ in range(steps):
        n, width, _ = sumcheck()
        rounds += n
        evaluations += width
    batches = count()
    batch_rounds = 0
    for _ in range(batches):
        batch_rounds += sumcheck()[0]
        take(count())  # source opening
    return (relations, rel_rounds, rel_nodes, rel_finals), (steps, rounds, evaluations), (batches, batch_rounds)


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


def hardware_counts(text, batches):
    originals, selected, planned, rounds, folds, finals, downloaded = map(int, text.split())
    if (selected != batches - 1 or originals != selected or finals != selected or selected <= 0
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
    return int(m[1]), int(m[2]), int(m[3])


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

    result = run([work / "reject-round", case, commitment, secret], capture_output=True, text=True)
    expected = "rejected_cuda_round=RoundSumMismatch device_rounds=1 folds=0 reservation_restored=1"
    if result.stdout.splitlines()[-1:] != [expected]:
        raise ValueError("genuine corrupted CUDA round did not reach the checked masked prover")
    print(expected, flush=True)


def compare(work, pins):
    total_batches = total_rounds = total_steps = total_gkr_rounds = 0
    total_relations = total_relation_rounds = 0
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
        expected = verify(work / "verifier", cpu, identity, i == 0)
        if verify(work / "verifier", gpu, identity, i == 0) != expected:
            raise ValueError("different verifier inventories")
        rel_schedule, (steps, gkr_rounds, evaluations), (selected, batch_rounds) = proof_schedule((cpu / "proof.bin").read_bytes())
        if expected != (rel_schedule[0], steps, selected + 1):
            raise ValueError("decoded schedule and independent verifier disagree")
        dense, gkr, relations = (gpu / "device.txt").read_text().splitlines()
        batches, rounds = hardware_counts(dense, expected[2])
        if rounds != batch_rounds:
            raise ValueError("device batch rounds differ from the reference proof")
        gkr_counts(gkr, (steps, gkr_rounds, evaluations))
        nrel, rel_rounds = relation_counts(relations, rel_schedule)
        print(json.dumps(dict(case=i, model=identity, proof_sha256=row["proof_sha256"],
                              selected_batches=batches, device_rounds=rounds, gkr_steps=steps, gkr_rounds=gkr_rounds, relations=nrel, relation_rounds=rel_rounds)), flush=True)
        if i != "replay":
            total_batches += batches
            total_rounds += rounds
            total_relations += nrel
            total_relation_rounds += rel_rounds
            total_steps += steps
            total_gkr_rounds += gkr_rounds
    return total_batches, total_rounds, total_steps, total_gkr_rounds, total_relations, total_relation_rounds


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
                  "--lib", "--test", "dense", "--", "--ignored", "--nocapture", "--test-threads=1"],
                 text=True, stdout=subprocess.PIPE)
    print(result.stdout, flush=True)
    if not re.search(r"cuda_dense_cases=1000 rounds=[1-9]\d+ folds=[1-9]\d+ finals=1000", result.stdout) or "2 passed; 0 failed; 0 ignored" not in result.stdout or "cuda_dense_lazy_cases=1000" not in result.stdout:
        raise ValueError("required H100 operation comparisons or controls missing")
    if not re.search(r"cuda_gkr_cases=1000 raw_cuda_gkr_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000", result.stdout):
        raise ValueError("required H100 GKR comparisons or controls missing")
    if "cuda_relation_cases=1000 raw_cuda_relation_cases=1000 field_rounds=8000 field_folds=8000 field_finals=2000" not in result.stdout:
        raise ValueError("required relation arithmetic comparisons missing")
    with tempfile.TemporaryDirectory(prefix="stele-cuda-parity-") as tmp:
        work = Path(tmp)
        run(["uv", "run", "--locked", "--script", HERE / "fixtures.py", work / "fixtures"])
        build(["--bin", "stele"], work / "verifier")
        build(["--example", "parity_proof"], work / "cpu-prove")
        build(["--example", "parity_proof"], work / "cuda-prove", cuda=True)
        build(["--bin", "stele"], work / "cuda-cli", cuda=True)
        build(["--example", "reject_cuda_round"], work / "reject-round", cuda=True, package="stele-gpu")
        rejection_controls(work)
        for name in ("cpu", "cuda"):
            run([work / (name + "-prove"), work / "fixtures", work / name, name])
        batches, rounds, steps, gkr_rounds, relations, relation_rounds = compare(work, pinned)
    print(f"cuda_complete_byte_matches=50 selected_batches={batches} device_rounds={rounds} gkr_steps={steps} gkr_rounds={gkr_rounds} relations={relations} relation_rounds={relation_rounds} replay=0 changed_model=0", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        sys.exit(str(e))
