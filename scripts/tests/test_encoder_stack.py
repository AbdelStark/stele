"""RFC-0010 A5: compiler stack frames require consistent control-flow evidence."""
import importlib.util
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('encoder_stack',ROOT/'bench/encoder_stack.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
frame_bytes = MODULE.frame_bytes

class EncoderStackTests(unittest.TestCase):
    def test_matches_reference_conditional_frames(self):
        code = [(0,'cbz','x0, 0x10'),(4,'sub','sp, sp, #0x20'),
                (8,'add','sp, sp, #0x20'),(12,'b','0x18'),
                (16,'stp','x29, x30, [sp, #-0x10]!'),
                (20,'ldp','x29, x30, [sp], #0x10'),(24,'ret','')]
        self.assertEqual(frame_bytes(code),32)
        self.assertEqual(frame_bytes([(0,'b','0x8'),(4,'sub','sp, sp, #0x1000'),(8,'ret','')]),0)

    def test_rejects_dynamic_growing_or_unbalanced_frames(self):
        for code in [
            [(0,'sub','sp, sp, x0')],
            [(0,'sub','sp, sp, #0x10'),(4,'b','0x0')],
            [(0,'sub','sp, sp, #0x10'),(4,'ret','')],
            [(0,'br','x0')],
        ]:
            with self.assertRaises(AssertionError):
                frame_bytes(code)


if __name__ == '__main__':
    unittest.main()
