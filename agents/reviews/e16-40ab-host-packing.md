# E16-40ab ordinary batch preparation

The lane-Z reviewer checked the original prover operands, serial and parallel encodings, alternating single-output allocation lifetimes, and exact comparison of all output words and scalars in a separate qualification pass.

Lucid 6798 verified a CPU proof and rejected the wrong model. Four paired three-batch totals put the serial median at 7.854 s and parallel median at 2.860 s. The parallel preparation won every aggregate pair. The smallest batch favored serial. The research path selects parallel preparation only for multi-GiB sparse weight vectors. Actual device integration has a separate hardware gate.

The CPU telemetry covers explicit outputs, prefix scratch, original tuple allocations and the separate two-output equality pass. Full-process RSS includes the CPU proof and that simultaneous equality pass. The earlier failed CPU allocations 6790 and 6793 supplied no validated measurements.

See the paired RFC-0018 records in [serial](../../bench/ledger/e16-40ab-t32-host-pack-serial.json) and [parallel](../../bench/ledger/e16-40ab-t32-host-pack-parallel.json).
