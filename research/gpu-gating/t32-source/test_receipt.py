"""Reject an incomplete phase or a source appearing under a different shape."""
import unittest
from receipt import summarize


class Sources(unittest.TestCase):
    def test_rejects_missing_visit(self):
        with self.assertRaisesRegex(ValueError, "source coverage"):
            summarize("t32_source_cold ns=1")

    def test_rejects_inconsistent_transfers(self):
        line = ("t32_source id=0 opening=0 rows=4096 cols=131072 queries=222 h2d=1 d2h=32 "
                "response_bytes=1 retained=2 peak=4 device_total=128 reserved_high=4 "
                "used_high=4 outside_pool=0 start=0 stop=8 observe_ns=2 cpu_start=1 cpu_stop=2")
        with self.assertRaisesRegex(ValueError, "transfer"):
            summarize("t32_source_cold ns=1\n" + line)
