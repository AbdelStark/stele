import unittest
from receipt import summarize


class Calibration(unittest.TestCase):
    def test_matches_reference_and_rejects_overlaps(self):
        lookup = [min(i // 18, 20) for i in range(385)]
        mac, gpu = [], []
        for i, l in enumerate(lookup):
            leaf = int(i == 384 or lookup[i+1] != l)
            mac.append(f'mac_gkr step={i} lookup={l} vars=4 compact={leaf} factor_ns=9 '
                       'table_ns=5 rounds_ns=10 arithmetic_ns=7 calls=8')
            gpu.append(f't32_gkr_step step={i} lookup={l} variables=4')
        log, reference = '\n'.join(mac), '\n'.join(gpu)
        result = summarize(log, reference)
        self.assertEqual(result['host_factor_ns'], 4 * 385)
        self.assertEqual(result['compact_host_factor_ns'], 4 * 21)
        for bad in [log.replace('rounds_ns=10', 'rounds_ns=6', 1),
                    log.replace('calls=8', 'calls=7', 1),
                    log.replace('compact=1', 'compact=0', 1), '\n'.join(mac[:-1])]:
            with self.assertRaises(ValueError):
                summarize(bad, reference)
