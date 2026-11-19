import unittest
from receipt import SHAPES, summarize


def sample():
    lines = []
    for id, (r, c, claims, positions, runs) in SHAPES.items():
        offsets = (r*c//4 + 127)//128 + 1
        payload = r*c*4 + positions*16 + claims*16 + runs*32 + offsets*8
        lines.append(f"host_source id={id} encode_ns=1")
        for rep in range(4):
            for order in range(2):
                method = ("serial", "parallel")[(id + rep + order) % 2]
                scratch = 0 if method == "serial" else (claims+1)*8
                lines.append(f"host_pack id={id} rep={rep} order={order} method={method} "
                             f"wall_ns=60 decode_ns=1 group_ns=50 index_ns=1 alloc_ns=1 "
                             f"split_ns=1 runs_ns=1 message_ns=1 weights_ns=0 drop_ns=1 "
                             f"scratch_bytes={scratch} output_bytes={payload} h2d_payload_bytes={payload}")
        lines.append(f"host_match id={id} rows={r} columns={c} claims={claims} "
                     f"positions={positions} runs={runs} offsets={offsets} payload_bytes={payload} "
                     f"tuples_bytes={positions*24} tuple_width=24 tuple_capacity_bytes={positions*24} "
                     f"descriptor_bytes=105 message_bytes={r*c*4} gamma_bytes={claims*16} "
                     f"claim_headers_bytes={claims*40}")
    return "\n".join(lines)


class Receipt(unittest.TestCase):
    def test_accepts_balanced_three_batch_sample(self):
        self.assertEqual(summarize(sample())["three_batch_totals_ns"]["parallel"], [183]*4)
    def test_rejects_missing_elementwise_or_missing_timed_pair(self):
        for text in (sample().replace("host_match", "absent", 1),
                     sample().replace("host_pack", "absent", 1)):
            with self.assertRaises(ValueError):
                summarize(text)
    def test_rejects_wrong_payload_and_overlap(self):
        for text in (sample().replace("method=parallel", "method=serial", 1),
                     sample().replace("weights_ns=0", "weights_ns=100", 1),
                     sample().replace("positions=4536", "positions=4535", 1)):
            with self.assertRaises(ValueError):
                summarize(text)
