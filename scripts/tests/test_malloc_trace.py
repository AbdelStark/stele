"""Allocation bookkeeping checks only; these are not protocol controls."""
from pathlib import Path
import gzip
import tempfile
import unittest

from bench.malloc_trace import summarize


class MallocTraceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/'events.txt'
        self.trace = (
            'ALLOC 0x10-0x23 [size=20]: startup reused the future marker address\n'
            'FREE  0x10: startup release\n'
            'ALLOC 0x10-0x12 [size=3]: begin marker\n'
            'ALLOC 0x100-0x163 [size=100]: first buffer\n'
            'FREE  0x100: drop before second buffer\n'
            'ALLOC 0x200-0x23b [size=60]: second buffer\n'
            'VM_ALLOC 0x1000-0x1fff [size=4096]: separate VM scope\n'
            'ALLOC 0x20-0x24 [size=5]: end marker\n')
        self.markers = [dict(name='begin', address='0x10', bytes=3),
                        dict(name='end', address='0x20', bytes=5)]

    def test_accepts_actual_live_overlap_and_marker_address_reuse(self):
        self.path.write_text(self.trace)
        result = summarize(self.path, self.markers)
        self.assertEqual((result['allocations'], result['frees']), (5, 2))
        self.assertEqual(result['heap_requested_live_bytes'], 68)
        self.assertEqual(result['heap_requested_peak_bytes'], 103)
        self.assertEqual(result['stages'], [dict(start_marker='begin', end_marker='end',
            start_heap_requested_bytes=3, end_heap_requested_bytes=68, peak_heap_requested_bytes=103)])
        compressed = self.path.with_suffix('.gz')
        compressed.write_bytes(gzip.compress(self.trace.encode(), mtime=0))
        self.assertEqual(summarize(compressed, self.markers), result)

    def test_rejects_incomplete_or_inconsistent_trace(self):
        for extra, expected in (
            ('FREE  0x999: missing allocation\n', 'Free without allocation'),
            ('ALLOC 0x10-0x12 [size=3]: still live\n', 'Overlapping allocation'),
            ('ALLOC 0x999-0x99a [size=3]: wrong extent\n', 'Allocation extent'),
            ('UNKNOWN 0x999: unsupported event\n', 'Unknown memory event'),
            ('ALLOC invalid: malformed allocation\n', 'Unknown memory event'),
            ('FREE invalid: malformed release\n', 'Unknown memory event'),
            ('FREE  0x20: released marker\n', 'Marker not retained')):
            self.path.write_text(self.trace+extra)
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, expected):
                summarize(self.path, self.markers)
        self.path.write_text(self.trace)
        with self.assertRaisesRegex(ValueError, 'Unordered markers'):
            summarize(self.path, list(reversed(self.markers)))


if __name__ == '__main__':
    unittest.main()
