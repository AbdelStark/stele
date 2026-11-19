# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0014 §5 synthetic inputs for reproducible whole inference proofs."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cqis-model-contract"))
from synthetic_e2e import CASES, synthetic


def generate(root):
    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for index in range(50):
        params = dict(CASES[0][1], seed=0x5354454C + index)
        case = root / str(index)
        case.mkdir()
        hashes = {}
        for name, data in synthetic(**params).items():
            (case / (name + ".bin")).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        cases.append({"index": index, "params": params, "sha256": hashes})
    if len({c["sha256"]["artifact"] for c in cases}) != 50:
        raise ValueError("expected 50 distinct weight artifacts")
    (root / "manifest.json").write_text(json.dumps(cases, indent=2) + "\n")


if __name__ == "__main__":
    generate(Path(sys.argv[1]))
