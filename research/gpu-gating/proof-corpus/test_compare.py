import tempfile
import unittest
from pathlib import Path
from reference import compare_case, digest


class ByteComparison(unittest.TestCase):
    def test_rejects_changed_proof_and_common_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            original, candidate = Path(d) / 'original', Path(d) / 'candidate'
            for directory in (original, candidate):
                directory.mkdir()
                (directory / 'model.txt').write_text('ab' * 32)
                (directory / 'proof.bin').write_bytes(b'proof')
                (directory / 'public.bin').write_bytes(b'public')
            pin = dict(model_id='ab' * 32, proof_sha256=digest(original / 'proof.bin'),
                       public_sha256=digest(original / 'public.bin'))
            compare_case(original, candidate, pin)
            (candidate / 'proof.bin').write_bytes(b'proog')
            with self.assertRaisesRegex(ValueError, 'candidate proof differs'):
                compare_case(original, candidate, pin)
            (original / 'proof.bin').write_bytes(b'proog')
            with self.assertRaisesRegex(ValueError, 'changed reference proof'):
                compare_case(original, candidate, pin)
