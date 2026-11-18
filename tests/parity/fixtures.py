# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0014 A2. Generate only the public synthetic parity inputs."""
import hashlib
import json
from pathlib import Path
import sys
from blake3 import blake3

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research/cqis-model-contract"))
from synthetic_e2e import CASES, synthetic


def generate(root):
    pins = json.loads(Path(__file__).with_name("cpu-reference.json").read_bytes())
    root.mkdir()
    cases = []
    for index in range(50):
        params = dict(CASES[0][1], seed=0x5354454C + index)
        case = root / str(index)
        case.mkdir()
        inputs = synthetic(**params)
        hashes = {}
        for name, data in inputs.items():
            (case / (name + ".bin")).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        artifact_id = blake3(inputs["artifact"]).digest()
        for role, filename in enumerate(("model-seed.bin", "proof-seed.bin")):
            seed = blake3(b"stele/synthetic/parity/" + bytes([role, index]) + artifact_id).digest()
            (case / filename).write_bytes(seed)
        cases.append({"index": index, "params": params, "sha256": hashes})
    manifest = (json.dumps(cases, indent=2) + "\n").encode()
    if hashlib.sha256(manifest).hexdigest() != pins["corpus_sha256"]:
        raise ValueError("the generated models differ from the independently pinned CPU corpus")
    (root / "manifest.json").write_bytes(manifest)


if __name__ == "__main__":
    generate(Path(sys.argv[1]))
