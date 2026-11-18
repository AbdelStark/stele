"""RFC-0014 A2. Compare ordinary CUDA operations and both complete checked proof producers."""
import hashlib
import json
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


def build(kind, dest, cuda=False):
    args = ["cargo", "build", "--release", "--locked", "--offline", "-p", "stele-cli",
            "--no-default-features", "--message-format=json", *kind]
    if cuda:
        args += ["--features", "cuda"]
    records = map(json.loads, run(args, stdout=subprocess.PIPE, text=True).stdout.splitlines())
    producers = [r["executable"] for r in records if r.get("executable")]
    if len(producers) != 1:
        raise ValueError("expected one independently built executable")
    shutil.copy2(producers[0], dest)


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
    m = re.fullmatch(r"dev-zk: \d+ relation instances, \d+ GKR steps, (\d+) batches, (\d+) proof bytes", audited)
    if m is None or int(m[2]) != (case / "proof.bin").stat().st_size:
        raise ValueError("missing verified batch inventory")
    if changed_model:
        argv[-1] = ("1" if identity[0] == "0" else "0") + identity[1:]
        result = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT)
        if result.returncode != 1 or result.stdout.splitlines()[-1:] != ["NO: model differs from --expect-model"]:
            raise ValueError("wrong-model control failed")
    return int(m[1])


def compare(work, pins):
    total_batches = total_rounds = 0
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
        batches, rounds = hardware_counts((gpu / "device.txt").read_text(), expected)
        print(json.dumps(dict(case=i, model=identity, proof_sha256=row["proof_sha256"],
                              selected_batches=batches, device_rounds=rounds)), flush=True)
        if i != "replay":
            total_batches += batches
            total_rounds += rounds
    return total_batches, total_rounds


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
    with tempfile.TemporaryDirectory(prefix="stele-cuda-parity-") as tmp:
        work = Path(tmp)
        run(["uv", "run", "--locked", "--script", HERE / "fixtures.py", work / "fixtures"])
        build(["--bin", "stele"], work / "verifier")
        build(["--example", "parity_proof"], work / "cpu-prove")
        build(["--example", "parity_proof"], work / "cuda-prove", cuda=True)
        for name in ("cpu", "cuda"):
            run([work / (name + "-prove"), work / "fixtures", work / name, name])
        batches, rounds = compare(work, pinned)
    print(f"cuda_complete_byte_matches=50 selected_batches={batches} device_rounds={rounds} replay=0 changed_model=0", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        sys.exit(str(e))
