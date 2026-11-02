"""RFC-0020 §5: required checks cannot pass through missing/skipped results."""
import copy
import importlib.util
import itertools
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ci_result', ROOT / 'scripts/ci_result.py')
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class ReadinessTests(unittest.TestCase):
    def test_rejects_each_incomplete_required_check(self):
        for flags in itertools.product(('true', 'false'), repeat=3):
            scope = dict(zip(('tables', 'research', 'gpu'), flags))
            needs = {'plan': {'result': 'success', 'outputs': scope},
                     'native': {'result': 'success'},
                     'native-union': {'result': 'success'}}
            for job, name in (('table-parity', 'tables'), ('research', 'research'), ('gpu-parity', 'gpu')):
                needs[job] = {'result': 'success' if scope[name] == 'true' else 'skipped'}
            self.assertTrue(result.accepts(needs))
            for job in needs:
                for value in ('success', 'failure', 'cancelled', 'skipped', '', None):
                    bad = copy.deepcopy(needs)
                    bad[job]['result'] = value
                    self.assertEqual(result.accepts(bad), value == needs[job]['result'], (flags, job, value))
                bad = copy.deepcopy(needs)
                del bad[job]
                self.assertFalse(result.accepts(bad))
                bad = copy.deepcopy(needs)
                bad[job] = None
                self.assertFalse(result.accepts(bad))
            for name in scope:
                for value in ('', 'maybe', None):
                    bad = copy.deepcopy(needs)
                    bad['plan']['outputs'][name] = value
                    self.assertFalse(result.accepts(bad))
        self.assertFalse(result.accepts({}))

    def test_requires_readiness_and_complete_table_partition(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('ready_for_review, converted_to_draft', text)
        self.assertIn("if: github.event_name != 'pull_request' || github.event.pull_request.draft == false", text)
        self.assertIn('needs: [plan, native, native-union, table-parity, research, gpu-parity]', text)
        self.assertIn('NEEDS: ${{ toJSON(needs) }}', text)
        self.assertIn('run: python3 scripts/ci_result.py', text)
        shards = re.search(r'^        shard: \[([^]]+)\]', text, re.M)
        self.assertIsNotNone(shards)
        oracle = (ROOT / 'crates/stele-cqis/tests/support/table_mle.rs').read_text()
        count = re.search(r'pub const CASES: [^\n]*;\s*(\d+)\]', oracle)
        self.assertIsNotNone(count)
        self.assertEqual([int(x) for x in shards[1].split(',')], list(range(2 * int(count[1]))))
        self.assertNotIn('continue-on-error', text)
        self.assertNotIn('\n  push:', text)

    def test_preserves_independent_native_command_inventory(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text().split('\njobs:\n', 1)[1]
        jobs = dict(re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)', text, re.M | re.S))
        self.assertIn('native-union', jobs)
        expected = {
            'native': [
                'cargo install cargo-deny --version 0.20.2 --locked',
                'cargo fetch --locked',
                'cargo fmt --all --check',
                'cargo deny --offline check bans',
                'scripts/gates/rust-policy.sh',
                'python3 scripts/ci_tests.py',
                'cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings',
                'cargo test --workspace --all-features --locked --offline',
                'cargo test --workspace --examples --all-features --locked --offline',
                'cargo check -p stele-sumcheck -p stele-lookup -p stele-cqis --no-default-features --locked --offline',
                'cargo test -p stele-simd --release --locked --offline -- --nocapture',
                'scripts/gates/ledger-validate.sh',
                'scripts/gates/rfc-status.sh',
                'scripts/gates/docs-links.sh',
                'scripts/gates/glossary-lint.sh',
            ],
            'native-union': ['cargo fetch --locked', 'scripts/gates/native.sh'],
        }
        for name, commands in expected.items():
            body = jobs[name]
            self.assertEqual(re.findall(r'^    needs: (.+)$', body, re.M), ['plan'])
            self.assertEqual(re.findall(r'^      (?:- |  )run: (.+)$', body, re.M), commands)
            self.assertIn('- uses: actions/checkout@v4\n', body)
            self.assertNotRegex(body, re.compile(r'^\s+ref:', re.M),
                                'both jobs must use the event merge source')
            self.assertIn('toolchain: 1.90.0', body)
            self.assertIn('python-version: "3.12"', body)
            self.assertIn('version: "0.13.4"', body)
            role = 'native-core' if name == 'native' else name
            self.assertIn('key: ' + role + '-${{ runner.os }}', body)
            self.assertIn('restore-keys: ' + role + '-${{ runner.os }}', body)
        self.assertIn('STELE_REQUIRE_SIMD: avx2', jobs['native'])
        self.assertEqual(jobs['native'].count('if:'), 1)
        self.assertIn("- if: steps.cargo-deny.outputs.cache-hit != 'true'\n"
                      '        run: cargo install cargo-deny --version 0.20.2 --locked', jobs['native'])
        self.assertNotIn('if:', jobs['native-union'], 'a cache hit must not skip the native gate')


if __name__ == '__main__':
    unittest.main()
