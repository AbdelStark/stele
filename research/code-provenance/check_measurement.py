# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A5: independent dense-base fixture for full-output benchmark validation."""
from pathlib import Path
from check_recursive import base_generator
base = base_generator()
expected = b''.join(v.to_bytes(4, 'little') for row in base for v in row)
path = Path(__file__).resolve().parents[2]/'crates/stele-code/examples/support/circle-base.bin'
assert path.read_bytes() == expected
print('Benchmark base fixture matches independent direct Circle basis and inversion.')
