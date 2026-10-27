"""RFC-0020 §4: compiler diagnostics and direct-token rejection controls."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('rust_policy', ROOT / 'scripts/rust_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class RustPolicyTests(unittest.TestCase):
    def test_rejects_direct_float_syntax(self):
        for token in ('f32', 'f64', '1.0', '1.', '1.0f32', '1f64', '1_f32', '2e3', '2E-3', '1.5e+2_f64'):
            with self.subTest(token=token):
                self.assertTrue(list(policy.violations(f'fn example() {{ sink({token}); }}')))

    def test_accepts_integer_syntax_and_quoted_data(self):
        source = '''// f64 1.0
/* f32 /* 3.0 */ 4e2 */
const N: u64 = 0xf32 + 0b1010 + 0o123 + 1_000u64;
let λf64 = 1; let tuple = (1, 2); let n = tuple.0; let range = 1..2;
let text = "f64 1.0 \\" f32";
let text = r###"f64 1.0 "## f32"###;
let text = br#"1.5"#; let text = cr#"2.5"#;
let x = '1'; let x = b'2'; let x = '\\u{32}';
fn borrowed<'a>(value: &'a str) -> &'a str { value }
'''
        self.assertEqual(list(policy.violations(source)), [])
        self.assertEqual([token for _, token in policy.violations(source + '\nlet x=1.5;')], ['1.5'])

    def test_rejects_unterminated_comment_or_raw_string(self):
        for source in ('/* outer /* nested */', 'r###"unterminated'):
            with self.assertRaises(ValueError):
                list(policy.violations(source))

    def test_rejects_float_literal_through_gate_entrypoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts/gates').mkdir(parents=True)
            shutil.copy(ROOT / 'scripts/rust_policy.py', root / 'scripts/rust_policy.py')
            shutil.copy(ROOT / 'scripts/gates/rust-policy.sh', root / 'scripts/gates/rust-policy.sh')
            source = root / 'crates/stele-prover/src/lib.rs'
            source.parent.mkdir(parents=True)
            source.write_text('pub fn bad() { std::hint::black_box(1.0); }')
            command = ['bash', str(root / 'scripts/gates/rust-policy.sh')]
            result = subprocess.run(command, cwd='/', capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('forbidden float token 1.0', result.stderr)
            source.write_text('pub fn good() { std::hint::black_box(1u32); }')
            self.assertEqual(subprocess.run(command, cwd='/', capture_output=True).returncode, 0)

    def test_rejects_float_types_and_lint_suppression_in_prover(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            shutil.copy(ROOT / 'clippy.toml', root / 'clippy.toml')
            lints = (ROOT / 'Cargo.toml').read_text().split('[workspace.lints.rust]')[1].split('[profile.release]')[0]
            (root / 'Cargo.toml').write_text('[workspace]\n[package]\nname="stele-prover-policy-fixture"\n'
                'version="0.0.0"\nedition="2021"\n[lints]\nworkspace=true\n[workspace.lints.rust]' + lints)
            for name in ('f32', 'f64'):
                for suppression in ('', '#![allow(clippy::disallowed_types)]\n'):
                    with self.subTest(type=name, suppression=bool(suppression)):
                        (root / 'src/lib.rs').write_text(suppression + f'pub const VALUE: {name} = 1.0;')
                        result = subprocess.run(['cargo', 'clippy', '--offline', '--manifest-path', str(root / 'Cargo.toml'),
                                                 '--', '-D', 'warnings'], capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue('disallowed type' in result.stderr or 'incompatible with previous forbid' in result.stderr,
                                        result.stderr)


if __name__ == '__main__':
    unittest.main()
