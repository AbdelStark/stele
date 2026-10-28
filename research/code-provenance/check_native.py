# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A4: actual native codewords versus independent dense-map evaluation."""
from pathlib import Path
import subprocess
from sampler import materialize, manifest
from check_recursive import dense_word, base_generator
from recursive import sc
from identity import validate_catalog

def check():
    root = Path(__file__).resolve().parents[2]
    run = subprocess.run(['cargo','run','-q','-p','stele-code','--example','native_vectors','--locked','--offline'], cwd=root, capture_output=True, text=True, check=True)
    validate_catalog((root / 'crates/stele-code/codes.toml').read_bytes())
    base = base_generator()
    cases = 0
    expected_order = [(d,j,seed) for seed in (0,1) for j in (3,4,5) for d in (1,4,8)]
    lines = run.stdout.splitlines()
    assert len(lines) == len(expected_order)
    for line, expected_id in zip(lines,expected_order):
        d,j,seed,blocks,hexword = line.split()
        d,j,seed,blocks = map(int,(d,j,seed,blocks))
        assert (d,j,seed) == expected_id
        setup, expected_blocks = materialize(manifest(bytes([seed])*32,j))
        assert blocks == expected_blocks
        row = [tuple((i*37+k*17+9)%sc.P for k in range(d)) for i in range(4**j)]
        expected = b''.join(limb.to_bytes(4,'little') for word in dense_word(setup,row,base) for limb in word)
        assert bytes.fromhex(hexword) == expected, (d,j,seed)
        cases += 1
    print(f'{cases} full native codewords and setup-block counts match independent dense maps in M31/QM31/OM31.')
    print('No PCS, source commitment, profile or GPU parity credit.')
if __name__ == '__main__': check()
