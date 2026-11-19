"""RFC-0018 §1, RFC-0027 §3 (task E17-04): tests for bench/remote.py and #454 baseline JSON."""
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bench'))

import remote  # noqa: E402

SAMPLE_IMAGE = 'docker.io/library/rust@sha256:' + 'a' * 64


class RemoteRunnerTests(unittest.TestCase):
    def test_rejects_unpinned_images_and_invalid_rates(self):
        self.assertEqual(remote.validate_pinned_image(SAMPLE_IMAGE), SAMPLE_IMAGE)
        for bad in (
            'rust:1.90.0',
            'docker.io/library/rust:latest',
            '-oOption@sha256:' + 'a' * 64,
            'docker.io/library/rust@sha256:short',
            'docker.io/library/rust@sha256:' + 'A' * 64,
            '',
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    remote.validate_pinned_image(bad)
        for bad_rate in ('-1.0', 'NaN', 'inf', 'abc'):
            with self.subTest(bad_rate=bad_rate):
                with self.assertRaises(ValueError):
                    remote.parse_rate_usd_per_hour(bad_rate)

    def test_rejects_shell_option_and_mount_injections(self):
        for bad_host in ('-oProxyCommand=id', 'host name', 'host:22', 'host/path', ''):
            with self.subTest(bad_host=bad_host):
                with self.assertRaises(ValueError):
                    remote.validate_host(bad_host)
        for bad_dir in ('/', '', '/tmp/$(id)', '/tmp/a b', '/tmp/a;b', '-/tmp/x'):
            with self.subTest(bad_dir=bad_dir):
                with self.assertRaises(ValueError):
                    remote.validate_remote_dir(bad_dir)
        for bad_mount in ('/a,/b', '/a:/b', '/a$(id)', '/a\nrm -rf /', '/a b', '-/a'):
            with self.subTest(bad_mount=bad_mount):
                with self.assertRaises(ValueError):
                    remote.validate_host_mount_path('--cargo-cache-dir', bad_mount)
        for bad_slurm in ('main\nrm -rf /', 'main;id', '128G $(id)', '-p'):
            with self.subTest(bad_slurm=bad_slurm):
                with self.assertRaises(ValueError):
                    remote.validate_slurm_value('--slurm-partition', bad_slurm)

    def test_computes_exact_cost_note_without_float_drift(self):
        cost, note = remote.format_cost_note(180_000_000_000, Decimal('2.50'), SAMPLE_IMAGE)
        self.assertEqual(cost, '0.1250')
        self.assertIn('$0.1250 USD', note)
        self.assertIn('180.00 s at $2.50/hr', note)
        self.assertIn(SAMPLE_IMAGE, note)
        with self.assertRaises(ValueError):
            remote.format_cost_note(0, Decimal('1.00'), SAMPLE_IMAGE)

    def test_parses_gnu_time_over_one_hour_and_ignores_child_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            t_hour = Path(tmp) / 'hour.time'
            t_hour.write_text(
                'Exit status: 1\n'
                'Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.01\n'
                '\tElapsed (wall clock) time (h:mm:ss or m:ss): 1:02:03\n'
                '\tMaximum resident set size (kbytes): 2048\n'
                '\tExit status: 0\n'
            )
            wall_ns, rss, res_ns = remote.parse_gnu_time_with_resolution(t_hour)
            self.assertEqual(wall_ns, (3600 + 120 + 3) * 1_000_000_000)
            self.assertEqual(rss, 2048 * 1024)
            self.assertEqual(res_ns, 1_000_000_000)

            # Exact prove.wall_ns is used when within resolution and rejected outside it.
            (Path(tmp) / 'prove.wall_ns').write_text(f'{wall_ns + 500_000_000}\n')
            self.assertEqual(remote.resolve_prove_wall_ns(Path(tmp), wall_ns, res_ns), wall_ns + 500_000_000)
            (Path(tmp) / 'prove.wall_ns').write_text(f'{wall_ns + 2_000_000_000}\n')
            with self.assertRaises(ValueError):
                remote.resolve_prove_wall_ns(Path(tmp), wall_ns, res_ns)

    def test_stores_no_hostnames_or_credentials_in_source(self):
        src = (ROOT / 'bench/remote.py').read_text().lower()
        for forbidden in ('begin private key', 'ghp_', 'hf_', 'ssh-rsa', 'amazonaws.com'):
            self.assertNotIn(forbidden, src)

    def test_formats_cpu_device_from_actual_arch(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'arch.txt').write_text('aarch64\n')
            (d / 'cpu_model.txt').write_text('Neoverse-V2\n')
            self.assertEqual(remote.format_cpu_device(d), 'aarch64 Neoverse-V2')
            (d / 'cpu_model.txt').write_text('aarch64\n')
            self.assertEqual(remote.format_cpu_device(d), 'aarch64')
            (d / 'cpu_model.txt').write_text('\n')
            with self.assertRaises(ValueError):
                remote.format_cpu_device(d)

    def test_dry_run_requires_host_and_image_and_renders_slurm_and_ssh_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = [
                '--rung', 'L1',
                '--out-dir', str(Path(tmp) / 'logs'),
                '--ledger-out', str(Path(tmp) / 'out.json'),
                '--cost-usd-per-hour', '1.20',
                '--host-context', '24-core test host',
                '--commit', '0' * 40,
                '--dry-run',
            ]
            with patch.dict('os.environ', {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'remote host required'):
                    remote.main(base + ['--image', SAMPLE_IMAGE])
                with self.assertRaisesRegex(ValueError, 'pinned container image required'):
                    remote.main(base + ['--host', 'example-host'])
            for extra in (
                ['--host', 'example-host', '--image', SAMPLE_IMAGE, '--executor', 'slurm',
                 '--runtime', 'apptainer', '--rung', 'L2a', '--model-dir', '/models/s42',
                 '--cargo-cache-dir', '/cache/cargo'],
                ['--host', 'example-host', '--image', SAMPLE_IMAGE, '--executor', 'ssh',
                 '--runtime', 'docker', '--rung', 'gpu-parity'],
            ):
                argv = [a for i, a in enumerate(base) if i not in (0, 1)] + extra
                proc = subprocess.run(
                    [sys.executable, str(ROOT / 'bench/remote.py'), *argv],
                    cwd=ROOT, capture_output=True, text=True, check=True,
                )
                payload = json.loads(proc.stdout)
                self.assertTrue(payload['dry_run'])
                self.assertIn(SAMPLE_IMAGE, payload['outer_script'])
                if 'gpu-parity' in extra:
                    self.assertIn('scripts/gates/parity.sh', payload['inner_script'])
                    self.assertIn('--gpus all', payload['outer_script'])
                else:
                    self.assertIn('apptainer pull', payload['outer_script'])
                    self.assertIn('--bind /cache/cargo:/work/cargo:rw', payload['outer_script'])
                    self.assertIn('stele prove-dev', payload['inner_script'])

    def test_builds_validated_gpu_parity_ledger_and_rejects_missing_receipt_or_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / 'out'
            out_dir.mkdir()
            (out_dir / 'gpu.txt').write_text('NVIDIA H100 80GB HBM3, 580.173.02, 81559 MiB\n')
            (out_dir / 'toolchain.txt').write_text('rustc 1.90.0 (1159e78c4 2025-09-14)\n')
            parity_text = 'gate parity: ok\n'
            (out_dir / 'parity.out').write_text(parity_text)
            (out_dir / 'proof.sha256').write_text(hashlib.sha256(parity_text.encode()).hexdigest() + '\n')
            (out_dir / 'parity.err').write_text(
                '\tElapsed (wall clock) time (h:mm:ss or m:ss): 10:00.00\n'
                '\tMaximum resident set size (kbytes): 4096000\n'
                '\tExit status: 0\n'
            )
            (out_dir / 'parity.time').write_text((out_dir / 'parity.err').read_text())
            # Works even with relative paths from a subdirectory (cwd != ROOT).
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                digest, cost_str, wall_ns = remote.build_gpu_parity_ledger(
                    out_dir=Path('out'),
                    ledger_out=Path('parity.json'),
                    commit='1' * 40,
                    threads=12,
                    image=SAMPLE_IMAGE,
                    rate_usd_per_hour=Decimal('3.00'),
                    host_context='1x H100 80GB HBM3 remote host',
                )
            finally:
                os.chdir(old_cwd)
            self.assertEqual(wall_ns, 600_000_000_000)
            self.assertEqual(cost_str, '0.5000')
            self.assertEqual(digest, hashlib.sha256(parity_text.encode()).hexdigest())
            record = json.loads((Path(tmp) / 'parity.json').read_text())
            self.assertIn('$0.5000 USD', record['note'])
            self.assertEqual(record['kind'], 'micro')
            self.assertNotIn('rung', record['model_config'])

            # Tampered remote receipt digest fails.
            (out_dir / 'proof.sha256').write_text('0' * 64 + '\n')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                remote.build_gpu_parity_ledger(
                    out_dir=out_dir, ledger_out=Path(tmp) / 'bad.json', commit='1' * 40,
                    threads=12, image=SAMPLE_IMAGE, rate_usd_per_hour=Decimal('3.00'),
                    host_context='1x H100',
                )
            # Missing completion receipt fails.
            (out_dir / 'parity.out').write_text('incomplete\n')
            (out_dir / 'proof.sha256').write_text(hashlib.sha256(b'incomplete\n').hexdigest() + '\n')
            with self.assertRaisesRegex(ValueError, 'gate parity:'):
                remote.build_gpu_parity_ledger(
                    out_dir=out_dir, ledger_out=Path(tmp) / 'bad.json', commit='1' * 40,
                    threads=12, image=SAMPLE_IMAGE, rate_usd_per_hour=Decimal('3.00'),
                    host_context='1x H100',
                )
            # Empty gpu.txt fails with ValueError (not IndexError).
            (out_dir / 'gpu.txt').write_text('\n')
            with self.assertRaisesRegex(ValueError, 'empty GPU metadata'):
                remote.build_gpu_parity_ledger(
                    out_dir=out_dir, ledger_out=Path(tmp) / 'bad.json', commit='1' * 40,
                    threads=12, image=SAMPLE_IMAGE, rate_usd_per_hour=Decimal('3.00'),
                    host_context='1x H100',
                )

    def test_flashprove_baseline_artifact_is_internally_consistent(self):
        data = json.loads((ROOT / 'bench/baselines/flashprove-v016-maverick-h100.json').read_text())
        oracle = data['expected_token_oracle']
        self.assertEqual(len(oracle['windows']), 120)
        self.assertEqual(oracle['b24_b1_overlap_verified_windows'], 6)
        sizes = [w['proof_bytes'] for w in oracle['windows']]
        b24 = data['measurements']['batch_24']
        self.assertEqual(b24['proof_bytes']['min'], min(sizes))
        self.assertEqual(b24['proof_bytes']['max'], max(sizes))
        self.assertEqual(b24['proof_bytes']['mean'], round(sum(sizes) / len(sizes)))
        self.assertGreater(b24['verified_end_to_end']['rate_excl_shutdown_tokens_per_s'], 0)
        self.assertGreater(data['measurements']['batch_1']['verified_end_to_end']['rate_excl_shutdown_tokens_per_s'], 0)


if __name__ == '__main__':
    unittest.main()
