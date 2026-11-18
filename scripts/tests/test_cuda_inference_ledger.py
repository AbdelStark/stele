"""RFC-0014 A2. A CUDA ledger carries the actual counters from the proof process."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'bench'))
from dev_e2e import device_counters


class DeviceLedger(unittest.TestCase):
    receipt = ('cuda originals=3 batches=3 rounds=69 folds=69 finals=3 h2d_bytes=12345 d2h_bytes=3408\n'
               'cuda_memory total_bytes=1000 outside_pool_bytes=50 pool_high_bytes=300 observed_peak_bytes=370')
    verified = 'dev-zk: 876 relation instances, 385 GKR steps, 4 batches, 4197 proof bytes'

    def test_accepts_verified_cuda_work(self):
        self.assertEqual(device_counters(self.receipt, self.verified, 4, '580')['rounds'], 69)
        self.assertEqual(device_counters('', self.verified, 4, None), {})

    def test_rejects_misclassified_or_incomplete_device_run(self):
        for stderr, verified, driver in [(self.receipt, self.verified, None), ('', self.verified, '580'),
                                         (self.receipt, self.verified.replace('4 batches', '3 batches'), '580'),
                                         (self.receipt.replace('370', '401'), self.verified, '580'),
                                         (self.receipt.replace('folds=69', 'folds=0'), self.verified, '580')]:
            with self.subTest(stderr=stderr, verified=verified, driver=driver), self.assertRaises(ValueError):
                device_counters(stderr, verified, 4, driver)

    def test_requires_verified_gkr_steps_and_live_peak(self):
        row = ('cuda_gkr steps=385 expected_rounds=900 rounds=900 folds=900 finals=385 '
               'h2d_bytes=12345 d2h_bytes=48000 streamed_layer_bytes=9000 planned_peak_bytes=370 '
               'observed_peak_bytes=399')
        capture = self.receipt.replace('cuda_memory', row + '\ncuda_memory')
        values = device_counters(capture, self.verified, 4, '580')
        self.assertEqual((values['gkr_steps'], values['gkr_observed_peak_bytes']), (385, 399))
        for left, right in [('steps=385', 'steps=384'), ('folds=900', 'folds=899'),
                            ('planned_peak_bytes=370', 'planned_peak_bytes=401'),
                            ('bytes=399', 'bytes=401'), ('bytes=9000', 'bytes=13000')]:
            with self.subTest(left=left), self.assertRaises(ValueError):
                device_counters(capture.replace(left, right), self.verified, 4, '580')
