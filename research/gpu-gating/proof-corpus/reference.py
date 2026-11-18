"""RFC-0014 §5. Preserve and verify the CPU half of the 50 complete-proof comparisons."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def compare_case(original, candidate, pin):
    """Compare the actual binary files against the separately committed CPU pins."""
    if (original / "model.txt").read_text() != pin["model_id"]:
        raise ValueError("changed reference model")
    if (candidate / "model.txt").read_text() != pin["model_id"]:
        raise ValueError("candidate model differs")
    for name in ("public", "proof"):
        path = original / (name + ".bin")
        if digest(path) != pin[name + "_sha256"]:
            raise ValueError(f"changed reference {name}")
        candidate_path = candidate / path.name
        if path.stat().st_size != candidate_path.stat().st_size or path.read_bytes() != candidate_path.read_bytes():
            raise ValueError(f"candidate {name} differs")


def collect(corpus, producer, verifier, output, compare_reference=None):
    cases = json.loads((corpus / "manifest.json").read_text())
    if [case["index"] for case in cases] != list(range(50)):
        raise ValueError("expected ordered cases 0..49")
    if compare_reference is not None:
        committed = Path(__file__).with_name("cpu-reference.json")
        if digest(compare_reference / "reference.json") != digest(committed):
            raise ValueError("wrong original CPU manifest")
        pinned = json.loads(committed.read_text())
        if (digest(corpus / "manifest.json") != pinned["corpus_sha256"]
                or digest(verifier) != pinned["verifier_sha256"]
                or [row["index"] for row in pinned["reference_cases"]] != list(range(50))):
            raise ValueError("changed CPU reference inputs or verifier")
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for case in cases:
        index = case["index"]
        inputs = corpus / str(index)
        fields = ("model", "preparation", "scales", "artifact")
        if {k: digest(inputs / (k + ".bin")) for k in fields} != case["sha256"]:
            raise ValueError(f"changed fixture {index}")
        dest = output / str(index)
        subprocess.run([producer, corpus, str(index), dest], check=True, timeout=600)
        identity = (dest / "model.txt").read_text()
        if len(identity) != 64 or len(bytes.fromhex(identity)) != 32:
            raise ValueError("invalid model identity")
        if compare_reference is not None:
            compare_case(compare_reference / str(index), dest, pinned["reference_cases"][index])
        verify = [verifier, "verify-dev", "--public", dest / "public.bin",
                  "--proof", dest / "proof.bin", "--expect-model"]
        result = subprocess.run([*verify, identity], capture_output=True, text=True, timeout=300, check=True)
        if result.stdout.splitlines()[-1] != "YES" or "proof index 0 of 1" not in result.stdout.splitlines():
            raise ValueError(f"verifier failed for case {index}")
        if index == 0:
            other = ("0" if identity[0] != "0" else "1") + identity[1:]
            wrong = subprocess.run([*verify, other], capture_output=True, text=True, timeout=300)
            if wrong.returncode != 1 or wrong.stdout.splitlines()[-1] != "NO: model differs from --expect-model":
                raise ValueError("wrong model control")
            replay = output / "replay"
            subprocess.run([producer, corpus, "0", replay], check=True, timeout=600)
            for name in ("public.bin", "proof.bin", "model.txt"):
                if (dest / name).read_bytes() != (replay / name).read_bytes():
                    raise ValueError(f"nondeterministic {name}")
        row = {"index": index, "artifact_sha256": case["sha256"]["artifact"], "model_id": identity,
               "proof_bytes": (dest / "proof.bin").stat().st_size, "proof_sha256": digest(dest / "proof.bin"),
               "public_sha256": digest(dest / "public.bin")}
        print(json.dumps(row, sort_keys=True), flush=True)
        records.append(row)
    if any(len({row[key] for row in records}) != 50 for key in ("artifact_sha256", "model_id", "proof_sha256")):
        raise ValueError("repeated corpus entries")
    manifest = {"producer_sha256": digest(producer), "verifier_sha256": digest(verifier),
                "corpus_sha256": digest(corpus / "manifest.json"), "reference_cases": records,
                "replayed_case": 0, "wrong_model_case": 0, "gpu_proofs_compared": 0}
    if compare_reference is not None:
        manifest["cpu_reference_manifest_sha256"] = digest(committed)
        manifest["complete_byte_matches"] = len(records)
    (output / ("comparison.json" if compare_reference is not None else "reference.json")).write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("corpus", "producer", "verifier", "output"):
        parser.add_argument(arg, type=Path)
    parser.add_argument("--compare-reference", type=Path, help="original CPU output directory for byte comparisons")
    args = parser.parse_args()
    collect(*(p.resolve() for p in (args.corpus, args.producer, args.verifier, args.output)),
            compare_reference=args.compare_reference)
