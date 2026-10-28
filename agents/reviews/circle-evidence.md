# E4-02 full circle benchmark evidence review

Reviewer: codex-root, also the author; benchmark-runner and soundness-auditor
passes. Not an independent audit. Scope: exact ledger import and task acceptance.

- Frozen measured source is `31e957a8f3f7c7e2ee4a5987a8f6e9e91ad4960a`.
  Its worktree was clean before and after measurement and remains unchanged.
  The committed ledger is byte-identical to the emitted file; schema validation,
  canonical plan digest, six-row inventory, counts and stage sums were checked.
- Both rates process 2^30 input symbols. Rate 1/2 runs two k=2^29 rows;
  rate 1/4 runs four k=2^28 rows. Every row returns N=2^30 outputs, all compared
  with independent integer arithmetic before its receipt is emitted.
  No measured row is substituted, reused or extrapolated for an unexecuted row.
- Timed encode includes copy/allocation, inverse normalization, coefficient
  expansion, all domain/twiddle work and forward transformation. Fixture
  preparation and exhaustive validation are separately timed and included in
  totals; final deallocation, process launch and JSON serialization are excluded.
- All six raw resource reports and per-row capacities/times are retained.
  Peak RSS is a native process high-water mark including input, internal
  capacities/overlap, returned output and runtime. Sequential peaks are not
  summed; the Python controller is excluded. No isolated scratch claim.
- Each distinct row has one sample, with specified four-coefficient high-basis
  fixtures. These are complete value-independent encodings, not random dense
  coefficient samples. No performance improvement or statistical claim follows.
- No protocol code, randomness, transcript label, claim consumer, binding,
  integer certificate, padding convention, profile admission or loss line changes.
  No new NC credit or GPU parity follows from the benchmark. Per-proof weight
  passes and fitted cost-model constants are unchanged.
- Direct-naive and extension-field parity, malformed requests and normalization
  mutations were reviewed in the encoder change. The full-size measurement now
  supplies the remaining E4-02 acceptance item, subject to the merge gates.

Sign-off: approve the evidence and E4-02 completion on gated merge. The separate
code registry, PCS, profile accounting, GPU and full-inference tasks remain open.
