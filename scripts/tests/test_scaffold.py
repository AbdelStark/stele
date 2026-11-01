"""RFC-0020 §§1-2: exercise bootstrap in an isolated checkout."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ScaffoldTests(unittest.TestCase):
    def test_matches_reference_clean_scaffold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'scripts').mkdir()
            shutil.copy(ROOT / 'scripts/scaffold.sh', root / 'scripts/scaffold.sh')
            shutil.copy(ROOT / 'Cargo.toml', root / 'Cargo.toml')
            subprocess.run(['bash', 'scripts/scaffold.sh'], cwd=root, check=True)
            generated = sorted(p.name for p in (root / 'crates').iterdir())
            self.assertIn('stele-py', generated)
            for name in generated:
                with self.subTest(crate=name):
                    source = (root / 'crates' / name / 'src/lib.rs').read_text()
                    self.assertTrue(source.startswith('//! '))
                    self.assertIn('RFC-', source)
                    if name not in {'stele-simd', 'stele-gpu'}:
                        self.assertIn('#![forbid(unsafe_code)]', source)
                    if name == 'stele-verifier':
                        self.assertIn('#![no_std]', source)
            verifier = tomllib.loads((root / 'crates/stele-verifier/Cargo.toml').read_text())
            self.assertEqual(set(verifier['dependencies']), {'stele-field', 'stele-hash'})
            pcs = tomllib.loads((root / 'crates/stele-pcs/Cargo.toml').read_text())
            self.assertEqual(set(pcs['dependencies']), {'stele-code', 'stele-field', 'stele-hash', 'stele-poly'})
            self.assertIn('#![no_std]', (root / 'crates/stele-pcs/src/lib.rs').read_text())
            gkr = tomllib.loads((root / 'crates/stele-gkr/Cargo.toml').read_text())
            self.assertEqual(set(gkr['dependencies']), {f'stele-{n}' for n in ('field', 'poly', 'hash', 'sumcheck')})
            reductions = tomllib.loads((root / 'crates/stele-reductions/Cargo.toml').read_text())
            self.assertEqual(set(reductions['dependencies']), {f'stele-{n}' for n in ('field', 'hash', 'sumcheck', 'gkr', 'lookup', 'pcs', 'ir')})
            self.assertIn('#![no_std]', (root / 'crates/stele-reductions/src/lib.rs').read_text())
            source = root / 'crates/stele-field/src/lib.rs'
            source.write_text(source.read_text() + '\n// preserved implementation\n')
            before = source.read_bytes()
            subprocess.run(['bash', 'scripts/scaffold.sh'], cwd=root, check=True)
            self.assertEqual(source.read_bytes(), before)

    def test_rejects_forbidden_dependency_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copy(ROOT / 'Cargo.toml', root / 'Cargo.toml')
            shutil.copy(ROOT / 'deny.toml', root / 'deny.toml')
            shutil.copy(ROOT / 'Cargo.lock', root / 'Cargo.lock')
            shutil.copytree(ROOT / 'tests/negative-controls', root / 'tests/negative-controls')
            for manifest in (ROOT / 'crates').glob('*/Cargo.toml'):
                crate = root / 'crates' / manifest.parent.name
                (crate / 'src').mkdir(parents=True)
                shutil.copy(manifest, crate / 'Cargo.toml')
                (crate / 'src/lib.rs').write_text('')
            command = ['cargo', 'deny', '--offline', 'check', 'bans']
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [
                ('stele-gkr', 'stele-cqis', 'dependencies'),
                ('stele-gkr', 'stele-pcs', 'dependencies'),
                ('stele-reductions', 'stele-code', 'dependencies'),
                ('stele-reductions', 'stele-poly', 'dependencies'),
                ('stele-reductions', 'stele-verifier', 'dependencies'),
                ('stele-lookup', 'stele-pcs', 'dependencies'),
                ('stele-pcs', 'stele-sumcheck', 'dependencies'),
                ('stele-pcs', 'stele-verifier', 'dependencies'),
                ('stele-lookup', 'stele-verifier', 'dev-dependencies'),
                ('stele-prover', 'stele-verifier', 'dependencies'),
                ('stele-verifier', 'stele-proof', 'dependencies'),
                ('stele-verifier', 'stele-cqis', 'build-dependencies'),
                ('stele-verifier', 'stele-cqis', 'dev-dependencies'),
                ('stele-dist', 'stele-cli', 'dependencies'),
                ('stele-cli', 'stele-negative-controls', 'dependencies'),
            ]
            for caller, dependency, section in cases:
                with self.subTest(caller=caller, dependency=dependency, section=section):
                    manifest = root / 'crates' / caller / 'Cargo.toml'
                    original = manifest.read_text()
                    path = "../../tests/negative-controls" if dependency == "stele-negative-controls" else f"../{dependency}"
                    entry = f'alias = {{ package = "{dependency}", path = "{path}" }}'
                    if f'[{section}]' in original:
                        mutated = original.replace(f'[{section}]', f'[{section}]\n{entry}')
                    else:
                        mutated = original + f'\n[{section}]\n{entry}\n'
                    manifest.write_text(mutated)
                    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
                    manifest.write_text(original)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('banned', result.stderr)
                    self.assertIn(dependency, result.stderr)


if __name__ == '__main__':
    unittest.main()
