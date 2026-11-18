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

    def test_accepts_all_encoded_visits_and_rejects_one_byte_short(self):
        lines = ["t32_source_cold ns=1"]
        clock = 3
        for id_, rows, cols in ((0,4096,131072),(1,4096,131072),(2,16,1024),(3,128,8192),(1268,16,1024)):
            lines.append(f"t32_source_prepare id={id_} cpu_start=1 cpu_stop=2")
            message = 4 * rows * cols
            count = 4 * cols
            nodes = (2 * count - 1) * 32
            encoded = rows * count * 4
            retained = encoded + nodes
            metadata = 4 * (cols - 1 + count - 1 + 24) + 86
            peak = encoded + max(message, nodes) + metadata
            for phase, queries in enumerate((222, 92)):
                wire = queries * (32 + 4 * rows + 32 * (count.bit_length() - 1))
                values = dict(id=id_,opening=phase,rows=rows,cols=cols,queries=queries,
                              h2d=message+metadata,d2h=32+wire-32*queries,response_bytes=wire,
                              retained=retained,peak=peak,device_total=100_000_000_000,
                              reserved_high=peak,used_high=peak,outside_pool=0,
                              start=clock,stop=clock+12,observe_ns=1,cpu_start=1,cpu_stop=2,
                              prepare_ns=4,release_ns=1,upload_ns=1,encode_ns=1,merkle_ns=1,
                              download_ns=2,assemble_ns=1)
                lines.append("t32_source " + " ".join(f"{k}={v}" for k, v in values.items()))
                clock += 13
        log = "\n".join(lines)
        self.assertEqual(summarize(log)["queries"], 1570)
        with self.assertRaisesRegex(ValueError, "geometry"):
            summarize(log.replace("rows=128 cols=8192", "rows=128 cols=4096"))
        upload = message + metadata
        with self.assertRaisesRegex(ValueError, "transfer"):
            summarize(log.replace(f"h2d={upload} ", f"h2d={upload - 1} "))
