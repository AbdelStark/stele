"""RFC-0014 A2. The scalar-only admission cannot authorize a different kernel."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('gates', ROOT / 'scripts/gates/check.py')
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


class Surface(unittest.TestCase):
    def test_rejects_unreviewed_source_and_missing_scalar_oracle(self):
        admitted = json.loads((ROOT / 'scripts/gates/scalar-kernel-sources.json').read_text())
        scaffold = json.loads((ROOT / 'scripts/gates/bootstrap-sources.json').read_text())['stele-kernels']
        for name in ('src/scalar.rs', 'tests/dense.rs', 'Cargo.toml', 'src/device.rs'):
            wrong = dict(admitted)
            wrong[name] = '0' * 64
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'admitted interface'):
                gates.scalar_kernel_surface(ROOT, wrong, scaffold)
