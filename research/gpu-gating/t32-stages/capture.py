"""One actual stories42M dev-zk T32 proof and read-only paired stage observations."""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from receipt import summarize


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def main():
    os.umask(0o077)
    root = Path.home() / "stele-codex"
    source = Path.cwd()
    work = source.parent / "run"
    work.mkdir(mode=0o700)
    cli = source / "target/release/stele"
    verifier = root / "e16-40a/source/target/release/stele"
    expected_verifier = json.loads((source / "bench/ledger/e16-40a-dev-zk-stories42m-t32-h100-0.json").read_text())["model_config"]["binary_sha256"]
    if digest(verifier) != expected_verifier:
        raise ValueError("unexpected independent verifier binary")
    if len(os.sched_getaffinity(0)) != 16 or os.environ["RAYON_NUM_THREADS"] != "16":
        raise ValueError("expected 16 pinned CPUs")
    def run(label, args, expected=0, limit=300):
        with (work / (label + ".out")).open("w") as out, (work / (label + ".err")).open("w") as err:
            cmd = ["/usr/bin/time", "-v", "-o", str(work / (label + ".time")), *map(str, args)]
            result = subprocess.run(cmd, stdout=out, stderr=err, timeout=limit)
        (work / (label + ".json")).write_text(json.dumps({"command":cmd, "exit":result.returncode}))
        if result.returncode != expected:
            raise RuntimeError(f"{label} exit {result.returncode}")
        return (work / (label + ".out")).read_text()
    inputs = root / "stories42m-check/inputs"
    pins = json.loads((root / "stories42m-inputs.json").read_text())
    flags = []
    for name in ("model", "preparation", "scales", "artifact"):
        p = inputs / (name + ".bin")
        if digest(p) != pins[name]:
            raise ValueError("unexpected workload input")
        flags.extend(["--" + name, str(p)])
    state = ["--commitment", work / "model.commit", "--secret", work / "secret.bin"]
    committed = run("commit", [verifier, "commit-model", "--zk", *flags, "--length", "32", "--proofs", "8", *state], limit=600)
    model, = re.findall(r"^model ([0-9a-f]{64})$", committed, flags=re.M)
    tokens = "1,9038,2501,263,931,29892,727,471,263,2217,7826,4257,365,2354,29889,2296,18012,304,1708,5377,297,278,14089,29889"
    outputs = ["--public", work / "public.bin", "--proof", work / "proof.bin"]
    proved = run("prove", [cli,"prove-dev","--zk",*flags,"--tokens",tokens,"--length","32","--checked","23..32",*state,*outputs],limit=2600)
    verified = run("verify", [verifier,"verify-dev",*outputs,"--expect-model",model],limit=600)
    wrong = ("0" if model[0] != "0" else "1") + model[1:]
    rejected = run("wrong", [verifier,"verify-dev",*outputs,"--expect-model",wrong],expected=1,limit=600)
    if any("proof index 0 of 8" not in message.splitlines() for message in (proved,verified)):
        raise ValueError("incorrect model lifetime index")
    if verified.splitlines()[-1] != "YES" or rejected.splitlines()[-1] != "NO: model differs from --expect-model":
        raise ValueError("ordinary verifier or wrong-model control failed")
    if any(line not in proved.splitlines() for line in ("profile dev-zk","T 32","checked 23..32","next 2654","proof 21411006 bytes")):
        raise ValueError("unexpected T32 workload")
    summary=summarize((work / "prove.err").read_text())
    result={"job":os.environ["SLURM_JOB_ID"],"profile":"dev-zk","workload":"dev/stories42m-t32","affinity":sorted(os.sched_getaffinity(0)),"inputs":pins,"cli_sha256":digest(cli),"verifier_sha256":expected_verifier,"proof_sha256":digest(work / "proof.bin"),"public_sha256":digest(work / "public.bin"),"stages":summary}
    (work / "result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
