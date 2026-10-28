# E4-02 circle benchmark harness review

Reviewer: codex-root, also the author; benchmark-runner and soundness-auditor
passes. Not an independent audit. Scope: measurement and validation harness;
the production encoder is unchanged.

- Executes every required row: two k=2^29 at b=1, four k=2^28 at b=2,
  with N=2^30 in every case. Checks both per-rate input/output sums and exact
  row inventory; no reused timing or extrapolated row meets the receipt checks.
- Fixtures use four nonzero coefficients in the exact FFT span, with distinct
  row salts. Independent integer arithmetic generates the fixture and checks
  every output. Production arithmetic/domain/transform functions are not the
  oracle. Small tests compare recurrence against per-point exponentiation and
  direct repeated Chebyshev maps before comparing full encodings.
- Changed first/interior/last values, a missing value and a swapped pair reject.
  Python validates worker dimensions, capacities, positive times and the full
  checked-symbol count. A deliberately incomplete receipt rejects in preflight.
- Output validation and fixture preparation are included in total operation
  time, separately from complete encode. Encode includes normalization, copying,
  expansion, allocation, domains/twiddles and inversions; no setup is amortized.
  Those internal substeps are timed together, not individually instrumented.
- Native row processes do not overlap. RSS includes input/output capacity,
  internal allocation capacities/overlap, retained allocator memory and runtime.
  It excludes the Python controller. Raw resource reports are retained. Input
  and returned-output capacities are also reported explicitly. No isolated
  scratch, live-allocation, memory-bandwidth or total-system peak is claimed.
- Source SHA and cleanliness are checked before/after. Plan digest, toolchain,
  CPU/OS, all six receipts and resource reports are retained; existing output
  files cannot be overwritten. The existing ledger validator checks the result.
- No challenge, transcript, binding, profile admission or soundness loss changes.
  Encoder errors fail the worker; output mismatches fail before ledger emission.
  The harness has no bypass flag or production NC credit.
- One sample per distinct row, small separate-process warmup, no statistics or
  before/after comparison. CPU registration cost only; per-proof weight passes
  and cost-model constants do not change. Full measurements remain outstanding.

Sign-off: approve the harness for gated merge and a local frozen-source run.
Keep E4-02 in progress until the full validated ledger and evidence are merged.
