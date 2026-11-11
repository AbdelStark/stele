"""ADR-108/ADR-111: standard and development Policy 2 entry points stay where allowed."""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/gates'))
import check  # noqa: E402


class QuarantineTests(unittest.TestCase):
    def test_accepts_repository(self):
        check.standard_quarantine(ROOT)

    def test_rejects_development_entry_point_in_forbidden_crate(self):
        for call in ('Source::<K>::from_code_id_development(0, 0, &c, r)',
                     'resolve_pcs_like(Profile::Development)', 'let s = Sources::Circle;'):
            with self.subTest(call=call), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                verifier = root / 'crates/stele-verifier/src/lib.rs'
                verifier.parent.mkdir(parents=True)
                verifier.write_text(f'fn f() {{ {call} }}\n')
                with self.assertRaisesRegex(ValueError, 'development Policy 2 entry point'):
                    check.standard_quarantine(root)


if __name__ == '__main__':
    unittest.main()
