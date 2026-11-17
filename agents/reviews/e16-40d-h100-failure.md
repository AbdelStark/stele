# E16-40d: terminal H100 inventory failure

Job 6685 is terminal `FAILED`, scheduler exit `1:0`. The unchanged capture
reported `AssertionError('check exited 124')`: its device command exceeded its
configured deadline. The source was `8038e131e93d59c08328c7c94a979f3c551058e1`.
The launcher-only correction after job 6640 did reach the CPU and device paths.

The CPU receipt completes all 1,000 original seeded cases. The device receipt
completes cases 0–8 with matching per-case digests, then starts case 9 without
emitting its build/prepare completion. No arithmetic inequality was reported;
these partial results do not qualify the candidate. The failed manifest's ten
payload hashes, exact failure result, CPU case sequence, completed device case
sequence and matching digests were checked. The digest pins are retained in
[e16-40d-h100-failure.json](e16-40d-h100-failure.json).

The failure was reported before any replacement device run or generator change.
The original evidence is retained under
`stele-validation/e16-40d-campaign/run-6685` and on the allocated host under
`stele-codex/e16-40d-inventory-8038e131/run-6685`; it is not imported as a successful
ledger. Automatic requeue was disabled and no restart occurred. A read-only
backtrace attempt could not run because `gdb` was absent; its exit 127 is separate
from the actual inventory timeout.

E16-40d's qualification remains unmet. E16-40k scopes a bounded diagnostic of
construction, NVRTC, module loading and execution, followed by at most one
reviewed implementation and one bounded qualification campaign. All original
1,000-case requirements remain. No core backend, proof, performance or ADR-127
GO claim follows from the failed run or its diagnostic.
