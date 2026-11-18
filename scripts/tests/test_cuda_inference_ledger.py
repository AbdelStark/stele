"""RFC-0014 A2. A CUDA ledger carries the actual counters from the proof process."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'bench'))
from dev_e2e import device_counters
from hiding_source_counts import check_source_work, source_work


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

    def test_requires_verified_relations_and_live_peak(self):
        gkr = ('cuda_gkr steps=385 expected_rounds=900 rounds=900 folds=900 finals=385 '
               'h2d_bytes=12000 d2h_bytes=48000 streamed_layer_bytes=9000 planned_peak_bytes=370 observed_peak_bytes=399')
        rel = ('cuda_relations steps=876 expected_rounds=4900 rounds=4900 folds=4900 finals=876 '
               'h2d_bytes=4000 d2h_bytes=100000 value_bytes=2800 mask_bytes=700 planned_peak_bytes=390 observed_peak_bytes=398')
        capture = self.receipt.replace('cuda_memory', gkr + '\n' + rel + '\ncuda_memory')
        self.assertEqual(device_counters(capture, self.verified, 4, '580')['relations_rounds'], 4900)
        for before, after in [(gkr+'\n',''), ('steps=876','steps=875'), ('folds=4900','folds=4899'),
                              ('mask_bytes=700','mask_bytes=0'), ('value_bytes=2800','value_bytes=3900'),
                              ('d2h_bytes=100000','d2h_bytes=99999'), ('observed_peak_bytes=398','observed_peak_bytes=401')]:
            with self.subTest(before=before), self.assertRaises(ValueError):
                device_counters(capture.replace(before, after), self.verified, 4, '580')

    def test_reconciles_standalone_source_and_shared_batches(self):
        u32 = lambda n: n.to_bytes(4, "little")
        blob = lambda b: u32(len(b)) + b
        def source(i, log_rows):
            r, c = 1 << log_rows, 1024
            return (b'stele/v0.1/field-source' + bytes([3, 4]) + i.to_bytes(8, 'little')
                    + bytes([log_rows]) + b'stele/circle-m31/v1' + bytes([10, 2])
                    + r.to_bytes(8, 'little') + c.to_bytes(8, 'little') + bytes([0, 2]) + bytes(32))
        def dense(n):
            return bytes(16) + u32(n) + (u32(3) + bytes(48)) * n + u32(2) + bytes(48)
        original = source(0, 4)
        standalone = source(1, 4)
        proof = (b'stele-dev-zk-v1' + bytes(64) + u32(1) + blob(original) + u32(1) + blob(b'c')
                 + u32(0) * 3 + blob(standalone) + blob(b'c') + dense(13) + blob(b'o') + blob(b'o'))
        report = '\n'.join(f'PCS\t{label}\trow exponent 4, policy Two, q_c/q_o 222/92, k_t 0, k_q 16, 1 opening(s);'
                           for label in ['shared mask source', 'shared batch mask source'])
        expected = source_work(proof, report, standalone=True)
        self.assertEqual((expected['originals'], expected['original_h2d_bytes'], expected['visits'], expected['responses']),
                         (2, 2*16*1024*4, 4, 628))
        good = dict(expected, observed_peak_bytes=300)
        self.assertEqual(check_source_work(good, proof, report, 400, standalone=True), expected)
        for key in ('original_h2d_bytes', 'visits', 'hashes', 'responses'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_source_work(dict(good, **{key:good[key]-1}), proof, report, 400, standalone=True)
        for changed in [proof[:-1], proof+b'x', proof.replace(standalone, original),
                        proof.replace(dense(13), dense(12)), proof.replace(standalone, source(1, 5))]:
            with self.assertRaises(ValueError):
                source_work(changed, report, standalone=True)

    def test_requires_each_original_visit_and_selected_response(self):
        # One original plus the shared source. The verifier derives the query schedule.
        def context(source_id):
            return (b'stele/v0.1/field-source' + bytes([3, 4]) + source_id.to_bytes(8, 'little')
                    + bytes([4]) + b'stele/circle-m31/v1' + bytes([10, 2]) + (16).to_bytes(8, 'little')
                    + (1024).to_bytes(8, 'little') + bytes([0, 2]) + bytes(32))
        contexts = [context(123), context(124)]
        proof = (b'stele-dev-zk-v1' + bytes(64) + (2).to_bytes(4, 'little')
                 + b''.join(len(src).to_bytes(4, 'little') + src for src in contexts))
        report = '\n'.join(f'PCS\t{label}\trow exponent 4, policy Two, q_c/q_o 222/92, k_t 0, k_q 16, {n} opening(s);'
                           for label, n in [('source 0', 0), ('shared mask source', 1)])
        work = source_work(proof, report)
        self.assertEqual(work, dict(originals=2, visits=3, responses=536, hashes=24573, h2d_bytes=61962,
                                    d2h_bytes=240224, host_salt_bytes=17152))
        good = {**work, 'observed_peak_bytes': 399}
        self.assertEqual(check_source_work(good, proof, report, 400), work)
        for name in good:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_source_work({**good, name: 0}, proof, report, 400)
        for bad_proof, bad_report in [(proof[:-1], report), (proof, report.replace('source 0', 'source 1')),
                                      (proof, report.replace('policy Two', 'policy One')),
                                      (proof.replace(contexts[1], contexts[0]), report)]:
            with self.assertRaises(ValueError):
                source_work(bad_proof, bad_report)
